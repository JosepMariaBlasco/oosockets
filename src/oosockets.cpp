/*----------------------------------------------------------------------------*/
/*                                                                            */
/* Copyright (c) 2026 Rexx Language Association. All rights reserved.         */
/*                                                                            */
/* This program and the accompanying materials are made available under       */
/* the terms of the Common Public License v1.0 which accompanies this         */
/* distribution. A copy is also available at the following address:           */
/* https://www.oorexx.org/license.html                                        */
/*                                                                            */
/* Redistribution and use in source and binary forms, with or                 */
/* without modification, are permitted provided that the following            */
/* conditions are met:                                                        */
/*                                                                            */
/* Redistributions of source code must retain the above copyright             */
/* notice, this list of conditions and the following disclaimer.              */
/* Redistributions in binary form must reproduce the above copyright          */
/* notice, this list of conditions and the following disclaimer in            */
/* the documentation and/or other materials provided with the distribution.   */
/*                                                                            */
/* Neither the name of Rexx Language Association nor the names                */
/* of its contributors may be used to endorse or promote products             */
/* derived from this software without specific prior written permission.      */
/*                                                                            */
/* THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS        */
/* "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT          */
/* LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS          */
/* FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT   */
/* OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,      */
/* SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED   */
/* TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA,        */
/* OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY     */
/* OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING    */
/* NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS         */
/* SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.               */
/*                                                                            */
/*----------------------------------------------------------------------------*/

/*
 * oosockets: the native layer of sockets.cls.
 *
 * Deliberately small. It opens, connects, listens, accepts, sends and
 * receives bytes (and UDP datagrams), with optional timeouts, on IPv4 and IPv6, on Linux,
 * macOS and Windows. Everything a Rexx programmer sees (streams, lines,
 * NOTREADY, SYNTAX 48.900 and its message) is done in sockets.cls.
 *
 * Results that can fail come back as an array whose first item is a
 * status word:
 *   "OK"       [, value]
 *   "EOF"                       (recv: the peer closed its side)
 *   "TIMEOUT"
 *   "AGAIN", ...                (the call waited SLICE_MS and must be made
 *                                again: see waitSlice)
 *   "ERROR", text, name, number, system's text, layer
 *                               (text in English, the same on the three
 *                                systems for the common errors; name as
 *                                POSIX's, e.g. "ECONNREFUSED"; number and
 *                                text the system's own; layer "SOCKET" or
 *                                "TLS", where it failed: Rony, 29/10/2026)
 *
 * The OS handle lives in a heap Sock, reached through CSELF.
 */

#include <string>
#include <vector>
#include <cstring>
#include <cctype>
#include <cstdio>
#include <cerrno>
#include <chrono>
#include <mutex>
#include <atomic>
#include <condition_variable>
#include <deque>
#include <map>
#include <memory>

#ifdef _WIN32
  #ifndef WIN32_LEAN_AND_MEAN
    #define WIN32_LEAN_AND_MEAN
  #endif
  #include <winsock2.h>
  #include <ws2tcpip.h>
  #include <windows.h>
  #include <wincrypt.h>                    // before OpenSSL, which undoes its X509_NAME
  #define SECURITY_WIN32
  #define SCHANNEL_USE_BLACKLISTS          // SCH_CREDENTIALS, TLS_PARAMETERS
  #include <subauth.h>                     // UNICODE_STRING, for schannel.h
  #include <schannel.h>                    // Schannel, Windows' own TLS
  #include <security.h>
  #include <sspi.h>
  #include <ncrypt.h>
  #include <mstcpip.h>
  #ifndef SIO_UDP_CONNRESET
    #define SIO_UDP_CONNRESET _WSAIOW(IOC_VENDOR, 12)
  #endif
  typedef SOCKET sock_t;
  typedef int socklen_type;
  #define BAD_SOCKET INVALID_SOCKET
  #define closesock closesocket
  #define pollsock WSAPoll
  static int lastError() { return WSAGetLastError(); }
  #define SEND_FLAGS 0
#else
  #include <sys/types.h>
  #include <sys/socket.h>
  #include <netinet/in.h>
  #include <netinet/tcp.h>
  #include <arpa/inet.h>
  #include <netdb.h>
  #include <poll.h>
  #include <fcntl.h>
  #include <unistd.h>
  typedef int sock_t;
  typedef socklen_t socklen_type;
  #define BAD_SOCKET (-1)
  #define closesock ::close
  #define pollsock ::poll
  static int lastError() { return errno; }
  #ifdef MSG_NOSIGNAL
    #define SEND_FLAGS MSG_NOSIGNAL          // Linux: no SIGPIPE
  #else
    #define SEND_FLAGS 0                     // macOS: SO_NOSIGPIPE instead
  #endif
#endif

// After winsock2.h: oorexxapi.h includes windows.h, which would otherwise
// bring the old winsock.h first.
#include "oorexxapi.h"

#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/x509v3.h>
#include <openssl/pem.h>
#include <openssl/pkcs12.h>
#include <openssl/hmac.h>
#include <openssl/rand.h>
#include "ossl.h"                           // OpenSSL loaded when first used

#ifdef __APPLE__
  #include <Security/Security.h>
#endif


// Why a certificate was refused: our text, the system's name and number.
struct TrustError
{
    bool set = false;
    std::string text;            // ours, the same on the three systems
    std::string name;
    long long code = 0;
    std::string sys;             // the system's own text for it
};

// Whom a TLS (or DTLS) connection must be with: the host name verified
// (client) and why the system refused its certificate. SSL_get_app_data
// of every SSL is one.
struct PeerCheck
{
    std::string host;            // the name verified (client)
    TrustError trust;            // why the system refused the certificate
};

#ifdef _WIN32
struct Sch;                      // a Schannel connection (see "Schannel")
struct SchCred;                  // Schannel's credentials
#endif

struct Sock : PeerCheck
{
    sock_t fd;
    // TLS, once started: the connection's own context and SSL. OpenSSL
    // does not allow two threads in one SSL at once, and a socket may be
    // read in one activity and written in another; so every SSL call is
    // made under mu, and mu is never held while waiting for the network.
    SSL_CTX *ctx = nullptr;
    SSL *ssl = nullptr;
#ifdef _WIN32
    Sch *sch = nullptr;          // Windows: TLS by Schannel instead (also under mu)
    std::shared_ptr<SchCred> schCred;  // TLSServerSocket with Schannel: for those it accepts
#endif
    std::mutex mu;
    int ioError = 0;             // the last socket error the BIO met
    std::atomic<bool> closing{false};  // close has started (UDP: a recv it
                                       // wakes must not read as a datagram)
    bool connected = false;      // UDP: connect was made
    // MulticastSocket: other sockets may share the port; on macOS, an
    // IPv4 socket on the same port that sends to IPv4 groups for an IPv6
    // one (see "MulticastSocket"), and the options it is to send with.
    bool shared = false;
    sock_t helper = BAD_SOCKET;
    int mcTtl = 1;
    int mcLoop = 1;
    unsigned mcIf = 0;
    // TCP connect in progress (socket_connect, socket_connect_more)
    std::vector<struct sockaddr_storage> addrs;
    std::vector<socklen_type> addrLens;
    size_t nextAddr = 0;
    sock_t trying = BAD_SOCKET;
    int connectErr = 0;
    Sock(sock_t f) : fd(f) { }
};


/*----------------------------------------------------------------------------*/
/* Errors                                                                     */
/*----------------------------------------------------------------------------*/

struct ErrInfo
{
    const char *name;
    const char *text;
};

// One entry per error a program is likely to meet; the text is ours, so
// that a message reads the same on the three systems.
static ErrInfo errInfo(int code)
{
#ifdef _WIN32
    switch (code)
    {
        case WSAECONNREFUSED:  return {"ECONNREFUSED",  "connection refused"};
        case WSAETIMEDOUT:     return {"ETIMEDOUT",     "timed out"};
        case WSAEHOSTUNREACH:  return {"EHOSTUNREACH",  "host unreachable"};
        case WSAENETUNREACH:   return {"ENETUNREACH",   "network unreachable"};
        case WSAEADDRINUSE:    return {"EADDRINUSE",    "address already in use"};
        case WSAEADDRNOTAVAIL: return {"EADDRNOTAVAIL", "address not available"};
        case WSAEACCES:        return {"EACCES",        "permission denied"};
        case WSAECONNRESET:    return {"ECONNRESET",    "connection reset by peer"};
        case WSAECONNABORTED:  return {"ECONNABORTED",  "connection aborted"};
        case WSAENOTCONN:      return {"ENOTCONN",      "not connected"};
        case WSAESHUTDOWN:     return {"EPIPE",         "connection closed for writing"};
        case WSAEAFNOSUPPORT:  return {"EAFNOSUPPORT",  "address family not supported"};
        case WSAENOTSOCK:      return {"ENOTSOCK",      "socket is closed"};
        case WSAEINVAL:        return {"EINVAL",        "invalid argument"};
        case WSAEMSGSIZE:      return {"EMSGSIZE",      "message too long"};
    }
#else
    switch (code)
    {
        case ECONNREFUSED:  return {"ECONNREFUSED",  "connection refused"};
        case ETIMEDOUT:     return {"ETIMEDOUT",     "timed out"};
        case EHOSTUNREACH:  return {"EHOSTUNREACH",  "host unreachable"};
        case ENETUNREACH:   return {"ENETUNREACH",   "network unreachable"};
        case EADDRINUSE:    return {"EADDRINUSE",    "address already in use"};
        case EADDRNOTAVAIL: return {"EADDRNOTAVAIL", "address not available"};
        case EACCES:        return {"EACCES",        "permission denied"};
        case ECONNRESET:    return {"ECONNRESET",    "connection reset by peer"};
        case ECONNABORTED:  return {"ECONNABORTED",  "connection aborted"};
        case ENOTCONN:      return {"ENOTCONN",      "not connected"};
        case EPIPE:         return {"EPIPE",         "connection closed for writing"};
        case EAFNOSUPPORT:  return {"EAFNOSUPPORT",  "address family not supported"};
        case EBADF:         return {"EBADF",         "socket is closed"};
        case ENOTSOCK:      return {"ENOTSOCK",      "socket is closed"};
        case EINVAL:        return {"EINVAL",        "invalid argument"};
        case EMSGSIZE:      return {"EMSGSIZE",      "message too long"};
    }
#endif
    return {"", nullptr};
}

// The system's own text for an error number, without a final period.
static std::string systemText(int code)
{
#ifdef _WIN32
    char buf[512] = "";
    FormatMessageA(FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
                   nullptr, (DWORD)code, 0, buf, sizeof(buf), nullptr);
    std::string text = buf;
#else
    std::string text = strerror(code);
#endif
    while (!text.empty() && (text.back() == '\n' || text.back() == '\r' || text.back() == ' ' || text.back() == '.'))
    {
        text.pop_back();
    }
    return text;
}

// The error result: "ERROR", text, name, number, the system's text, layer.
static RexxArrayObject errorArray(RexxMethodContext *context, const std::string &text,
                                  const std::string &name, long long code,
                                  const std::string &sys = "", const char *layer = "TLS")
{
    RexxArrayObject r = context->NewArray(6);
    context->ArrayAppendString(r, "ERROR", 5);
    context->ArrayAppendString(r, text.c_str(), text.size());
    context->ArrayAppendString(r, name.c_str(), name.size());
    context->ArrayAppend(r, context->Int64ToObject(code));
    context->ArrayAppendString(r, sys.c_str(), sys.size());
    context->ArrayAppendString(r, layer, strlen(layer));
    return r;
}

static RexxArrayObject errorResult(RexxMethodContext *context, int code)
{
    ErrInfo e = errInfo(code);
    std::string sys = systemText(code);
    std::string text = e.text != nullptr ? std::string(e.text) : sys;
    if (e.text == nullptr && !text.empty())
    {
        text[0] = (char)tolower((unsigned char)text[0]);
    }
    return errorArray(context, text, e.name, code, sys, "SOCKET");
}

// getaddrinfo's own errors
static RexxArrayObject gaiErrorResult(RexxMethodContext *context, int code)
{
    const char *name = "";
    std::string text;
    switch (code)
    {
        case EAI_NONAME: name = "EAI_NONAME"; text = "unknown host"; break;
        case EAI_AGAIN:  name = "EAI_AGAIN";  text = "temporary failure in name resolution"; break;
#if defined(EAI_NODATA) && EAI_NODATA != EAI_NONAME
        case EAI_NODATA: name = "EAI_NODATA"; text = "unknown host"; break;
#endif
        case EAI_SERVICE: name = "EAI_SERVICE"; text = "unknown port or service"; break;
        default:
#ifdef _WIN32
            text = gai_strerrorA(code);
#else
            text = gai_strerror(code);
#endif
            if (!text.empty())
            {
                text[0] = (char)tolower((unsigned char)text[0]);
            }
    }
#ifdef _WIN32
    std::string sys = gai_strerrorA(code);
#else
    std::string sys = gai_strerror(code);
#endif
    return errorArray(context, text, name, code, sys, "SOCKET");
}

static RexxArrayObject statusResult(RexxMethodContext *context, const char *status, RexxObjectPtr value = NULLOBJECT)
{
    RexxArrayObject r = context->NewArray(2);
    context->ArrayAppendString(r, status, strlen(status));
    if (value != NULLOBJECT)
    {
        context->ArrayAppend(r, value);
    }
    return r;
}

// "AGAIN", the bytes sent so far, the seconds left: a send to be made
// again with the rest.
static RexxArrayObject againSent(RexxMethodContext *context, size_t sent, double left)
{
    RexxArrayObject r = context->NewArray(3);
    context->ArrayAppendString(r, "AGAIN", 5);
    context->ArrayAppend(r, context->StringSize(sent));
    context->ArrayAppend(r, context->DoubleToObject(left));
    return r;
}

static RexxArrayObject closedResult(RexxMethodContext *context)
{
#ifdef _WIN32
    return errorResult(context, WSAENOTSOCK);
#else
    return errorResult(context, EBADF);
#endif
}


/*----------------------------------------------------------------------------*/
/* Helpers                                                                    */
/*----------------------------------------------------------------------------*/

// Not inherited by programs started with ADDRESS SYSTEM; on macOS, no
// SIGPIPE when writing to a closed connection.
static void prepareSocket(sock_t fd)
{
#ifdef _WIN32
    SetHandleInformation((HANDLE)fd, HANDLE_FLAG_INHERIT, 0);
#else
    fcntl(fd, F_SETFD, FD_CLOEXEC);
  #ifdef SO_NOSIGPIPE
    int one = 1;
    setsockopt(fd, SOL_SOCKET, SO_NOSIGPIPE, &one, sizeof(one));
  #endif
#endif
}

static void setBlocking(sock_t fd, bool blocking)
{
#ifdef _WIN32
    u_long mode = blocking ? 0 : 1;
    ioctlsocket(fd, FIONBIO, &mode);
#else
    int flags = fcntl(fd, F_GETFL, 0);
    fcntl(fd, F_SETFL, blocking ? (flags & ~O_NONBLOCK) : (flags | O_NONBLOCK));
#endif
}

static bool inProgress(int code)
{
#ifdef _WIN32
    return code == WSAEWOULDBLOCK;
#else
    return code == EINPROGRESS;
#endif
}

static bool interrupted(int code)
{
#ifdef _WIN32
    (void)code;
    return false;
#else
    return code == EINTR;
#endif
}

typedef std::chrono::steady_clock Clock;

// Milliseconds left until the deadline, for poll: -1 means no deadline.
static int msLeft(bool hasDeadline, Clock::time_point deadline)
{
    if (!hasDeadline)
    {
        return -1;
    }
    auto left = std::chrono::duration_cast<std::chrono::milliseconds>(deadline - Clock::now()).count();
    if (left < 0)
    {
        return 0;
    }
    if (left > 0x7fffffff)
    {
        return 0x7fffffff;
    }
    return (int)left;
}

// Waits until the socket is ready for events, or the deadline. Returns 1
// ready, 0 timeout, -1 error (code in *err).
static int waitFor(sock_t fd, short events, bool hasDeadline, Clock::time_point deadline, int *err)
{
    for (;;)
    {
        struct pollfd p;
        p.fd = fd;
        p.events = events;
        p.revents = 0;
        int rc = pollsock(&p, 1, msLeft(hasDeadline, deadline));
        if (rc > 0)
        {
            return 1;
        }
        if (rc == 0)
        {
            return 0;
        }
        int e = lastError();
        if (interrupted(e))
        {
            continue;
        }
        *err = e;
        return -1;
    }
}

static Clock::time_point deadlineFrom(double seconds)
{
    return Clock::now() + std::chrono::milliseconds((long long)(seconds * 1000.0 + 0.5));
}

// HALT. ooRexx's HALT (Ctrl-C, SIGTERM, a HALT from the API) is a flag on
// the Rexx activation that called a native method, seen only when that
// activation runs its next clause: a native call that waits for the
// network until something arrives would keep it waiting forever. So no
// native call waits more than SLICE_MS: it returns "AGAIN" (with the time
// left), and sockets.cls calls it again, running a clause in between,
// where a HALT is raised. On Unix, a signal also ends the wait at once
// (poll is interrupted).
static const int SLICE_MS = 100;

// As waitFor, but for SLICE_MS at most: 1 ready, 0 the deadline came, 2
// the slice ended first (or a signal came), -1 error (code in *err).
// fd2, if there is one, is waited for too.
static int waitSlice(sock_t fd, short events, bool hasDeadline, Clock::time_point deadline, int *err,
                     sock_t fd2 = BAD_SOCKET)
{
    int ms = msLeft(hasDeadline, deadline);
    bool sliced = false;
    if (ms < 0 || ms > SLICE_MS)
    {
        ms = SLICE_MS;
        sliced = true;
    }
    struct pollfd p[2];
    p[0].fd = fd;
    p[0].events = events;
    p[0].revents = 0;
    p[1].fd = fd2;
    p[1].events = events;
    p[1].revents = 0;
    int rc = pollsock(p, fd2 != BAD_SOCKET ? 2 : 1, ms);
    if (rc > 0)
    {
        return 1;
    }
    if (rc == 0)
    {
        return sliced ? 2 : 0;
    }
    int e = lastError();
    if (interrupted(e))
    {
        return 2;
    }
    *err = e;
    return -1;
}

// Seconds left until the deadline (never negative); -1 without one.
static double secondsLeft(bool hasDeadline, Clock::time_point deadline)
{
    if (!hasDeadline)
    {
        return -1;
    }
    double left = std::chrono::duration_cast<std::chrono::milliseconds>(deadline - Clock::now()).count() / 1000.0;
    return left < 0 ? 0 : left;
}

// An address as text: IPv6 as "::1", IPv4-mapped IPv6 as plain IPv4.
static void addressText(const struct sockaddr *sa, std::string &host, int &port)
{
    char buf[INET6_ADDRSTRLEN + 32] = "";
    host = "";
    port = 0;
    if (sa->sa_family == AF_INET6)
    {
        const struct sockaddr_in6 *s6 = (const struct sockaddr_in6 *)sa;
        port = ntohs(s6->sin6_port);
        const unsigned char *b = (const unsigned char *)&s6->sin6_addr;
        static const unsigned char mapped[12] = {0,0,0,0,0,0,0,0,0,0,0xff,0xff};
        if (memcmp(b, mapped, 12) == 0)
        {
            snprintf(buf, sizeof(buf), "%u.%u.%u.%u", b[12], b[13], b[14], b[15]);
            host = buf;
            return;
        }
        if (getnameinfo(sa, sizeof(struct sockaddr_in6), buf, sizeof(buf), nullptr, 0, NI_NUMERICHOST) == 0)
        {
            host = buf;
        }
    }
    else if (sa->sa_family == AF_INET)
    {
        const struct sockaddr_in *s4 = (const struct sockaddr_in *)sa;
        port = ntohs(s4->sin_port);
        if (getnameinfo(sa, sizeof(struct sockaddr_in), buf, sizeof(buf), nullptr, 0, NI_NUMERICHOST) == 0)
        {
            host = buf;
        }
    }
}

static void setCself(RexxMethodContext *context, Sock *s)
{
    context->SetObjectVariable("CSELF", context->NewPointer(s));
}

#ifdef _WIN32
static void schSayGoodbye(Sock *s, Sch *c);
  #define TLS_BY_SCHANNEL(s) ((s)->sch != nullptr)
#else
  #define TLS_BY_SCHANNEL(s) false
#endif

static void closeSock(Sock *s)
{
    if (s == nullptr)
    {
        return;
    }
    s->closing = true;
    std::lock_guard<std::mutex> guard(s->mu);
    if (s->trying != BAD_SOCKET)
    {
        closesock(s->trying);
        s->trying = BAD_SOCKET;
    }
    if (s->helper != BAD_SOCKET)
    {
        closesock(s->helper);
        s->helper = BAD_SOCKET;
    }
    if (s->fd != BAD_SOCKET)
    {
        // TLS: tell the peer (close_notify), if the socket takes it now.
#ifdef _WIN32
        if (s->sch != nullptr)
        {
            schSayGoodbye(s, s->sch);
        }
#endif
        if (s->ssl != nullptr || TLS_BY_SCHANNEL(s))
        {
            if (s->ssl != nullptr)
            {
                ERR_clear_error();
                SSL_shutdown(s->ssl);
                ERR_clear_error();
            }
            // What has arrived and was not read (TLS 1.3 session tickets,
            // typically) would make the close a reset (RST), and the peer
            // could lose what it has not read yet: drop it first.
            char junk[16384];
            for (int i = 0; i < 64; i++)
            {
                long n = (long)recv(s->fd, junk, sizeof(junk), 0);   // non-blocking
                if (n <= 0)
                {
                    break;
                }
            }
        }
        // shutdown first: on Linux, close alone does not wake a recv or an
        // accept blocked in another activity on this socket.
#ifdef _WIN32
        shutdown(s->fd, SD_BOTH);
#else
        shutdown(s->fd, SHUT_RDWR);
#endif
        closesock(s->fd);
        s->fd = BAD_SOCKET;
    }
}


/*----------------------------------------------------------------------------*/
/* TLS                                                                        */
/*                                                                            */
/* OpenSSL does the TLS (loaded when first used, ossl.h; on Windows only for  */
/* DTLS and OOSOCKETS_TLS=openssl: see "Schannel" below). Who                 */
/* decides whether the server's certificate is good:                          */
/*   - when the program trusts certificates explicitly (TLSOptions~trust),    */
/*     OpenSSL, with those as its only anchors, and the host name;            */
/*   - otherwise the system: Linux, OpenSSL with the system's store; macOS,   */
/*     SecTrustEvaluateWithError; Windows, CertGetCertificateChain and        */
/*     CertVerifyCertificateChainPolicy (both from inside the handshake, so   */
/*     that a refused certificate ends it with an alert).                     */
/* Revocation is not asked for (as Java and .NET by default).                 */
/*                                                                            */
/* Once TLS starts, the socket is non-blocking: each SSL call is made under   */
/* the Sock's lock, and the waiting (poll) is done outside it, so that one    */
/* activity can read while another writes.                                    */
/*----------------------------------------------------------------------------*/

static bool wouldBlock(int code)
{
#ifdef _WIN32
    return code == WSAEWOULDBLOCK;
#else
    return code == EAGAIN || code == EWOULDBLOCK;
#endif
}

// Our BIO: send and recv on the Sock's socket. Not OpenSSL's socket BIO,
// which writes with write(): on Linux, a SIGPIPE when the peer is gone.
static int bioWrite(BIO *b, const char *data, int len)
{
    Sock *s = (Sock *)BIO_get_data(b);
    BIO_clear_retry_flags(b);
    for (;;)
    {
        long n = (long)send(s->fd, data, len, SEND_FLAGS);
        if (n >= 0)
        {
            return (int)n;
        }
        int e = lastError();
        if (interrupted(e))
        {
            continue;
        }
        s->ioError = e;
        if (wouldBlock(e))
        {
            s->ioError = 0;
            BIO_set_retry_write(b);
        }
        return -1;
    }
}

static int bioRead(BIO *b, char *data, int len)
{
    Sock *s = (Sock *)BIO_get_data(b);
    BIO_clear_retry_flags(b);
    for (;;)
    {
        long n = (long)recv(s->fd, data, len, 0);
        if (n > 0)
        {
            return (int)n;
        }
        if (n == 0)
        {
#ifdef BIO_FLAGS_IN_EOF
            BIO_set_flags(b, BIO_FLAGS_IN_EOF);
#endif
            return 0;
        }
        int e = lastError();
        if (interrupted(e))
        {
            continue;
        }
        s->ioError = e;
        if (wouldBlock(e))
        {
            s->ioError = 0;
            BIO_set_retry_read(b);
        }
        return -1;
    }
}

static long bioCtrl(BIO *b, int cmd, long num, void *ptr)
{
    (void)num; (void)ptr;
    switch (cmd)
    {
        case BIO_CTRL_FLUSH:
            return 1;
#ifdef BIO_FLAGS_IN_EOF
        case BIO_CTRL_EOF:
            return BIO_test_flags(b, BIO_FLAGS_IN_EOF) != 0;
#endif
        default:
            (void)b;
            return 0;
    }
}

static int bioCreate(BIO *b)
{
    BIO_set_init(b, 1);
    return 1;
}

static BIO_METHOD *sockBioMethod()
{
    static std::once_flag once;
    static BIO_METHOD *method = nullptr;
    std::call_once(once, []()
    {
        method = BIO_meth_new(BIO_get_new_index() | BIO_TYPE_SOURCE_SINK, "oosockets");
        BIO_meth_set_write(method, bioWrite);
        BIO_meth_set_read(method, bioRead);
        BIO_meth_set_ctrl(method, bioCtrl);
        BIO_meth_set_create(method, bioCreate);
    });
    return method;
}

// What a TLS operation came to.
enum TlsStatus { TLS_OK, TLS_EOF, TLS_TIMEOUT, TLS_AGAIN, TLS_CLOSED, TLS_SOCKET_ERROR, TLS_SSL_ERROR };

struct TlsOutcome
{
    TlsStatus status = TLS_OK;
    int socketError = 0;          // TLS_SOCKET_ERROR
    unsigned long sslError = 0;   // TLS_SSL_ERROR: ERR_get_error()'s
    long verifyResult = X509_V_OK;
    bool handshaking = false;     // the handshake had not finished
    long schStatus = 0;           // Windows: Schannel's status, when it failed
};

// Runs call(ssl) until it succeeds, retrying when OpenSSL wants to read or
// write, waiting outside the lock (until the deadline, if there is one;
// TLS_AGAIN after SLICE_MS of waiting: see waitSlice; calling it again
// goes on where it was).
// call returns what SSL_xxx returns: > 0 success.
template <class Call>
static TlsOutcome tlsRun(Sock *s, bool hasDeadline, Clock::time_point deadline, Call call)
{
    TlsOutcome out;
    for (;;)
    {
        int rc, sslErr;
        sock_t fd;
        {
            std::lock_guard<std::mutex> guard(s->mu);
            if (s->fd == BAD_SOCKET || s->ssl == nullptr)
            {
                out.status = TLS_CLOSED;
                return out;
            }
            fd = s->fd;
            ERR_clear_error();
            s->ioError = 0;
            rc = call(s->ssl);
            if (rc > 0)
            {
                out.status = TLS_OK;
                return out;
            }
            sslErr = SSL_get_error(s->ssl, rc);
            out.handshaking = !SSL_is_init_finished(s->ssl);
            out.socketError = s->ioError;
            out.sslError = ERR_peek_last_error();
            out.verifyResult = SSL_get_verify_result(s->ssl);
            ERR_clear_error();
        }
        if (sslErr == SSL_ERROR_WANT_READ || sslErr == SSL_ERROR_WANT_WRITE)
        {
            int err = 0;
            int w = waitSlice(fd, sslErr == SSL_ERROR_WANT_READ ? POLLIN : POLLOUT, hasDeadline, deadline, &err);
            if (w == 0)
            {
                out.status = TLS_TIMEOUT;
                return out;
            }
            if (w == 2)
            {
                out.status = TLS_AGAIN;
                return out;
            }
            if (w < 0)
            {
                out.status = TLS_SOCKET_ERROR;
                out.socketError = err;
                return out;
            }
            continue;
        }
        if (sslErr == SSL_ERROR_ZERO_RETURN)
        {
            out.status = TLS_EOF;
        }
        else if (sslErr == SSL_ERROR_SYSCALL)
        {
            // A socket error; or none: the peer closed without close_notify.
            out.status = out.socketError != 0 ? TLS_SOCKET_ERROR : TLS_EOF;
        }
        else
        {
            out.status = TLS_SSL_ERROR;
        }
        return out;
    }
}


/* ---- is OpenSSL there? -------------------------------------------------- */

// OpenSSL is loaded the first time it is needed (ossl.h): from
// OOSOCKETS_OPENSSL's directory if it is set; else the system's (Linux), the
// OpenSSL 3 of Homebrew or MacPorts (macOS; Rony, 29/10/2026: the package
// manager keeps it current, ooSockets ships none), or the DLLs next to
// oosockets.dll (Windows, where only DTLS and OOSOCKETS_TLS=openssl need
// it). Without it the plain sockets work, and every way into OpenSSL's
// TLS or DTLS asks this first.
static bool opensslHere()
{
    std::string why;
    return osslLoad(why);
}

// The error for a way into TLS when OpenSSL is not there.
static RexxArrayObject opensslMissing(RexxMethodContext *context)
{
    std::string why;
    osslLoad(why);
    return errorArray(context, why, "OPENSSL", 0);
}

// OpenSSL's reason for an error, without its library prefix.
static std::string sslReason(unsigned long e)
{
    const char *r = e != 0 ? ERR_reason_error_string(e) : nullptr;
    if (r != nullptr)
    {
        return r;
    }
    char buf[256];
    ERR_error_string_n(e, buf, sizeof(buf));
    return buf;
}

// OpenSSL's whole text for an error ("error:0A000086:SSL routines::certificate
// verify failed"), the system's own.
static std::string sslText(unsigned long e)
{
    if (e == 0)
    {
        return "";
    }
    char buf[256];
    ERR_error_string_n(e, buf, sizeof(buf));
    return buf;
}

static TrustError opensslTrustError(long v);
static RexxArrayObject trustResult(RexxMethodContext *context, const TrustError &t);
#ifdef _WIN32
static RexxArrayObject secResult(RexxMethodContext *context, SECURITY_STATUS st, const char *prefix,
                                 const char *name = nullptr);
#endif

// The result of a TLS read or write that failed on an established connection.
static RexxArrayObject tlsIoResult(RexxMethodContext *context, const TlsOutcome &o)
{
    switch (o.status)
    {
        case TLS_EOF:     return statusResult(context, "EOF");
        case TLS_TIMEOUT: return statusResult(context, "TIMEOUT");
        case TLS_CLOSED:  return closedResult(context);
        case TLS_SOCKET_ERROR: return errorResult(context, o.socketError);
        default:
#ifdef _WIN32
            if (o.schStatus != 0)
            {
                return secResult(context, (SECURITY_STATUS)o.schStatus, o.handshaking ? "handshake failed: " : "", "TLS");
            }
#endif
            // "ERROR:TLS handshake failed: tlsv1 alert unknown ca" as the
            // description (the handshake of an accepted socket happens on
            // its first read or write).
            if (o.handshaking && o.verifyResult != X509_V_OK && o.verifyResult != X509_V_ERR_APPLICATION_VERIFICATION)
            {
                TrustError t = opensslTrustError(o.verifyResult);
                t.name = "TLS";
                return trustResult(context, t);
            }
            return errorArray(context, (o.handshaking ? "handshake failed: " : "") + sslReason(o.sslError),
                              "TLS", (long long)ERR_GET_REASON(o.sslError), sslText(o.sslError));
    }
}

/* ---- why a certificate was refused ---------------------------------------- */

// The common reasons read the same on the three systems.
static const char *CERT_EXPIRED   = "certificate has expired";
static const char *CERT_NOT_YET   = "certificate is not yet valid";
static const char *CERT_HOST      = "certificate does not match the host name";
static const char *CERT_UNTRUSTED = "certificate is not trusted";
static const char *CERT_REVOKED   = "certificate has been revoked";
static const char *CERT_USAGE     = "certificate is not for a TLS server";

static TrustError opensslTrustError(long v)
{
    TrustError t;
    t.sys = X509_verify_cert_error_string(v);
    t.set = true;
    t.code = v;
    switch (v)
    {
        case X509_V_ERR_CERT_HAS_EXPIRED:
            t.name = "X509_V_ERR_CERT_HAS_EXPIRED"; t.text = CERT_EXPIRED; break;
        case X509_V_ERR_CERT_NOT_YET_VALID:
            t.name = "X509_V_ERR_CERT_NOT_YET_VALID"; t.text = CERT_NOT_YET; break;
        case X509_V_ERR_HOSTNAME_MISMATCH:
            t.name = "X509_V_ERR_HOSTNAME_MISMATCH"; t.text = CERT_HOST; break;
        case X509_V_ERR_IP_ADDRESS_MISMATCH:
            t.name = "X509_V_ERR_IP_ADDRESS_MISMATCH"; t.text = CERT_HOST; break;
        case X509_V_ERR_DEPTH_ZERO_SELF_SIGNED_CERT:
            t.name = "X509_V_ERR_DEPTH_ZERO_SELF_SIGNED_CERT"; t.text = CERT_UNTRUSTED; break;
        case X509_V_ERR_SELF_SIGNED_CERT_IN_CHAIN:
            t.name = "X509_V_ERR_SELF_SIGNED_CERT_IN_CHAIN"; t.text = CERT_UNTRUSTED; break;
        case X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT_LOCALLY:
            t.name = "X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT_LOCALLY"; t.text = CERT_UNTRUSTED; break;
        case X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT:
            t.name = "X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT"; t.text = CERT_UNTRUSTED; break;
        case X509_V_ERR_UNABLE_TO_VERIFY_LEAF_SIGNATURE:
            t.name = "X509_V_ERR_UNABLE_TO_VERIFY_LEAF_SIGNATURE"; t.text = CERT_UNTRUSTED; break;
        case X509_V_ERR_CERT_UNTRUSTED:
            t.name = "X509_V_ERR_CERT_UNTRUSTED"; t.text = CERT_UNTRUSTED; break;
        case X509_V_ERR_CERT_REVOKED:
            t.name = "X509_V_ERR_CERT_REVOKED"; t.text = CERT_REVOKED; break;
        case X509_V_ERR_INVALID_PURPOSE:
            t.name = "X509_V_ERR_INVALID_PURPOSE"; t.text = CERT_USAGE; break;
        default:
            t.name = "X509_V_ERR";
            t.text = X509_verify_cert_error_string(v);
    }
    return t;
}

// Ours, and the system's own reason after it when it says more ("certificate
// is not trusted: self-signed certificate"; not "timed out" after "connection
// timed out"): Rony, 29/10/2026.
static std::string withReason(const std::string &ours, const std::string &sys)
{
    auto lower = [](std::string x)
    {
        for (char &ch : x)
        {
            ch = (char)tolower((unsigned char)ch);
        }
        return x;
    };
    std::string a = lower(ours), b = lower(sys);
    if (b.empty() || a.find(b) != std::string::npos || b.find(a) != std::string::npos)
    {
        return ours;
    }
    return ours + ": " + sys;
}

// A certificate the system (or OpenSSL) refused, as an error result.
static RexxArrayObject trustResult(RexxMethodContext *context, const TrustError &t)
{
    return errorArray(context, withReason(t.text, t.sys), t.name, t.code, t.sys, "TLS");
}

#ifdef __APPLE__

static const char *CERT_TOO_LONG  = "certificate is valid for longer than the system allows";

static std::string cfString(CFStringRef s)
{
    char buf[1024] = "";
    if (s != nullptr)
    {
        CFStringGetCString(s, buf, sizeof(buf), kCFStringEncodingUTF8);
    }
    return buf;
}

static SecCertificateRef toApple(X509 *x)
{
    unsigned char *der = nullptr;
    int len = i2d_X509(x, &der);
    if (len <= 0)
    {
        return nullptr;
    }
    CFDataRef d = CFDataCreate(nullptr, der, len);
    OPENSSL_free(der);
    SecCertificateRef c = SecCertificateCreateWithData(nullptr, d);
    CFRelease(d);
    return c;
}

// macOS decides, with its SSL policy for the host name.
static bool systemTrust(const std::vector<X509 *> &chain, const std::string &host, TrustError &why)
{
    CFMutableArrayRef certs = CFArrayCreateMutable(nullptr, 0, &kCFTypeArrayCallBacks);
    for (X509 *x : chain)
    {
        SecCertificateRef c = toApple(x);
        if (c != nullptr)
        {
            CFArrayAppendValue(certs, c);
            CFRelease(c);
        }
    }
    CFStringRef h = CFStringCreateWithCString(nullptr, host.c_str(), kCFStringEncodingUTF8);
    SecPolicyRef policy = SecPolicyCreateSSL(true, h);
    SecTrustRef trust = nullptr;
    bool ok = false;
    if (SecTrustCreateWithCertificates(certs, policy, &trust) == errSecSuccess)
    {
        CFErrorRef err = nullptr;
        ok = SecTrustEvaluateWithError(trust, &err);
        if (!ok)
        {
            long code = err != nullptr ? (long)CFErrorGetCode(err) : 0;
            why.set = true;
            why.code = code;
            CFStringRef desc = err != nullptr ? CFErrorCopyDescription(err) : nullptr;
            why.sys = cfString(desc);
            if (desc != nullptr)
            {
                CFRelease(desc);
            }
            switch (code)
            {
                case errSecCertificateExpired:
                    why.name = "errSecCertificateExpired"; why.text = CERT_EXPIRED; break;
                case errSecCertificateNotValidYet:
                    why.name = "errSecCertificateNotValidYet"; why.text = CERT_NOT_YET; break;
                case errSecHostNameMismatch:
                    why.name = "errSecHostNameMismatch"; why.text = CERT_HOST; break;
                case errSecNotTrusted:
                    why.name = "errSecNotTrusted"; why.text = CERT_UNTRUSTED; break;
                case errSecCertificateRevoked:
                    why.name = "errSecCertificateRevoked"; why.text = CERT_REVOKED; break;
                case errSecInvalidExtendedKeyUsage:
                    why.name = "errSecInvalidExtendedKeyUsage"; why.text = CERT_USAGE; break;
                case errSecCertificateValidityPeriodTooLong:
                    why.name = "errSecCertificateValidityPeriodTooLong"; why.text = CERT_TOO_LONG; break;
                default:
                {
                    why.name = "OSStatus";
                    why.text = why.sys;
                    if (why.text.empty())
                    {
                        why.text = CERT_UNTRUSTED;
                    }
                }
            }
        }
        if (err != nullptr)
        {
            CFRelease(err);
        }
    }
    else
    {
        why.set = true;
        why.name = "OSStatus";
        why.text = "the system could not evaluate the certificate";
    }
    if (trust != nullptr)
    {
        CFRelease(trust);
    }
    CFRelease(policy);
    CFRelease(h);
    CFRelease(certs);
    return ok;
}

#elif defined(_WIN32)

static PCCERT_CONTEXT toWindows(X509 *x)
{
    unsigned char *der = nullptr;
    int len = i2d_X509(x, &der);
    if (len <= 0)
    {
        return nullptr;
    }
    PCCERT_CONTEXT c = CertCreateCertificateContext(X509_ASN_ENCODING, der, (DWORD)len);
    OPENSSL_free(der);
    return c;
}

static void windowsTrustError(DWORD code, TrustError &why)
{
    why.set = true;
    why.code = (long long)code;
    char buf[512] = "";
    FormatMessageA(FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS, nullptr, code,
                   MAKELANGID(LANG_ENGLISH, SUBLANG_ENGLISH_US), buf, sizeof(buf), nullptr);
    why.sys = buf;
    while (!why.sys.empty() && (why.sys.back() == '\n' || why.sys.back() == '\r' || why.sys.back() == ' ' || why.sys.back() == '.'))
    {
        why.sys.pop_back();
    }
    switch (code)
    {
        case (DWORD)CERT_E_EXPIRED:
            why.name = "CERT_E_EXPIRED"; why.text = CERT_EXPIRED; return;
        case (DWORD)CERT_E_CN_NO_MATCH:
            why.name = "CERT_E_CN_NO_MATCH"; why.text = CERT_HOST; return;
        case (DWORD)CERT_E_UNTRUSTEDROOT:
            why.name = "CERT_E_UNTRUSTEDROOT"; why.text = CERT_UNTRUSTED; return;
        case (DWORD)CERT_E_CHAINING:
            why.name = "CERT_E_CHAINING"; why.text = CERT_UNTRUSTED; return;
        case (DWORD)CRYPT_E_REVOKED:
            why.name = "CRYPT_E_REVOKED"; why.text = CERT_REVOKED; return;
        case (DWORD)CERT_E_WRONG_USAGE:
            why.name = "CERT_E_WRONG_USAGE"; why.text = CERT_USAGE; return;
    }
    why.name = "HRESULT";
    why.text = why.sys;
    if (!why.text.empty())
    {
        why.text[0] = (char)tolower((unsigned char)why.text[0]);
    }
    else
    {
        why.text = CERT_UNTRUSTED;
    }
}

static bool isAddress(const std::string &host);

// Whether the certificate names the IP address host among its alternative
// names (Windows' SSL policy only matches DNS names).
static bool certHasAddress(PCCERT_CONTEXT leaf, const std::string &host)
{
    std::string h = host.substr(0, host.find('%'));
    unsigned char want[16];
    DWORD wantLen = 0;
    if (inet_pton(AF_INET, h.c_str(), want) == 1)
    {
        wantLen = 4;
    }
    else if (inet_pton(AF_INET6, h.c_str(), want) == 1)
    {
        wantLen = 16;
    }
    PCERT_EXTENSION ext = CertFindExtension(szOID_SUBJECT_ALT_NAME2, leaf->pCertInfo->cExtension,
                                            leaf->pCertInfo->rgExtension);
    if (wantLen == 0 || ext == nullptr)
    {
        return false;
    }
    CERT_ALT_NAME_INFO *info = nullptr;
    DWORD size = 0;
    if (!CryptDecodeObjectEx(X509_ASN_ENCODING, X509_ALTERNATE_NAME, ext->Value.pbData, ext->Value.cbData,
                             CRYPT_DECODE_ALLOC_FLAG, nullptr, &info, &size))
    {
        return false;
    }
    bool found = false;
    for (DWORD i = 0; i < info->cAltEntry; i++)
    {
        CERT_ALT_NAME_ENTRY &e = info->rgAltEntry[i];
        if (e.dwAltNameChoice == CERT_ALT_NAME_IP_ADDRESS && e.IPAddress.cbData == wantLen
            && memcmp(e.IPAddress.pbData, want, wantLen) == 0)
        {
            found = true;
        }
    }
    LocalFree(info);
    return found;
}

#ifndef SECURITY_FLAG_IGNORE_CERT_CN_INVALID
  #define SECURITY_FLAG_IGNORE_CERT_CN_INVALID 0x00001000
#endif

// Windows decides: the chain it builds for the server's certificate (with
// the others the server sent, in extra), and its SSL policy for the host
// name. engine: nullptr, the system's roots; or one whose only anchors are
// the certificates trusted explicitly (Schannel's explicit trust).
static bool windowsTrust(PCCERT_CONTEXT leaf, HCERTSTORE extra, HCERTCHAINENGINE engine,
                         const std::string &host, TrustError &why)
{
    char serverAuth[] = szOID_PKIX_KP_SERVER_AUTH;
    char *usage[] = { serverAuth };
    CERT_CHAIN_PARA para;
    memset(&para, 0, sizeof(para));
    para.cbSize = sizeof(para);
    para.RequestedUsage.dwType = USAGE_MATCH_TYPE_AND;
    para.RequestedUsage.Usage.cUsageIdentifier = 1;
    para.RequestedUsage.Usage.rgpszUsageIdentifier = usage;
    PCCERT_CHAIN_CONTEXT ctx = nullptr;
    bool ok = false;
    bool address = isAddress(host);
    if (!CertGetCertificateChain(engine, leaf, nullptr, extra, &para, 0, nullptr, &ctx))
    {
        windowsTrustError(GetLastError(), why);
    }
    else
    {
        std::wstring whost(host.size() + 1, L'\0');
        int n = MultiByteToWideChar(CP_UTF8, 0, host.c_str(), -1, &whost[0], (int)whost.size());
        whost.resize(n > 0 ? (size_t)n - 1 : 0);
        SSL_EXTRA_CERT_CHAIN_POLICY_PARA sslPara;
        memset(&sslPara, 0, sizeof(sslPara));
        sslPara.cbSize = sizeof(sslPara);
        sslPara.dwAuthType = AUTHTYPE_SERVER;
        sslPara.pwszServerName = &whost[0];
        if (address)
        {
            sslPara.fdwChecks = SECURITY_FLAG_IGNORE_CERT_CN_INVALID;   // checked below
        }
        CERT_CHAIN_POLICY_PARA policy;
        memset(&policy, 0, sizeof(policy));
        policy.cbSize = sizeof(policy);
        policy.pvExtraPolicyPara = &sslPara;
        CERT_CHAIN_POLICY_STATUS status;
        memset(&status, 0, sizeof(status));
        status.cbSize = sizeof(status);
        if (!CertVerifyCertificateChainPolicy(CERT_CHAIN_POLICY_SSL, ctx, &policy, &status))
        {
            windowsTrustError(GetLastError(), why);
        }
        else if (status.dwError != 0)
        {
            windowsTrustError(status.dwError, why);
        }
        else if (address && !certHasAddress(leaf, host))
        {
            windowsTrustError((DWORD)CERT_E_CN_NO_MATCH, why);
        }
        else
        {
            ok = true;
        }
        CertFreeCertificateChain(ctx);
    }
    return ok;
}

// OpenSSL's handshake, Windows deciding: its chain, as Windows' certificates.
static bool systemTrust(const std::vector<X509 *> &chain, const std::string &host, TrustError &why)
{
    PCCERT_CONTEXT leaf = toWindows(chain[0]);
    if (leaf == nullptr)
    {
        windowsTrustError((DWORD)CERT_E_CHAINING, why);
        return false;
    }
    HCERTSTORE extra = CertOpenStore(CERT_STORE_PROV_MEMORY, 0, 0, 0, nullptr);
    for (size_t i = 1; i < chain.size(); i++)
    {
        PCCERT_CONTEXT c = toWindows(chain[i]);
        if (c != nullptr)
        {
            CertAddCertificateContextToStore(extra, c, CERT_STORE_ADD_ALWAYS, nullptr);
            CertFreeCertificateContext(c);
        }
    }
    bool ok = windowsTrust(leaf, extra, nullptr, host, why);
    CertCloseStore(extra, 0);
    CertFreeCertificateContext(leaf);
    return ok;
}

#endif

#if defined(__APPLE__) || defined(_WIN32)
// OpenSSL's verification replaced by the system's (when nothing is trusted
// explicitly): called by OpenSSL inside the handshake.
static int systemVerify(X509_STORE_CTX *store, void *)
{
    SSL *ssl = (SSL *)X509_STORE_CTX_get_ex_data(store, SSL_get_ex_data_X509_STORE_CTX_idx());
    PeerCheck *s = (PeerCheck *)SSL_get_app_data(ssl);
    std::vector<X509 *> chain;
    X509 *leaf = X509_STORE_CTX_get0_cert(store);
    if (leaf != nullptr)
    {
        chain.push_back(leaf);
    }
    STACK_OF(X509) *others = X509_STORE_CTX_get0_untrusted(store);
    for (int i = 0; others != nullptr && i < sk_X509_num(others); i++)
    {
        X509 *x = sk_X509_value(others, i);
        if (leaf == nullptr || X509_cmp(x, leaf) != 0)
        {
            chain.push_back(x);
        }
    }
    if (chain.empty())
    {
        s->trust.set = true;
        s->trust.name = "X509_V_ERR";
        s->trust.text = "the server sent no certificate";
        X509_STORE_CTX_set_error(store, X509_V_ERR_APPLICATION_VERIFICATION);
        return 0;
    }
    if (!systemTrust(chain, s->host, s->trust))
    {
        X509_STORE_CTX_set_error(store, X509_V_ERR_APPLICATION_VERIFICATION);
        return 0;
    }
    return 1;
}
#endif

/* ---- certificate files -------------------------------------------------- */

static bool readFile(const char *path, std::string &data, std::string &why)
{
    FILE *f = fopen(path, "rb");
    if (f == nullptr)
    {
        why = strerror(errno);
        if (!why.empty())
        {
            why[0] = (char)tolower((unsigned char)why[0]);
        }
        return false;
    }
    char buf[8192];
    size_t n;
    while ((n = fread(buf, 1, sizeof(buf), f)) > 0)
    {
        data.append(buf, n);
    }
    fclose(f);
    return true;
}

// The certificates (and the private key, if asked for and there is one) in
// a file: PEM (any number), DER (one), or PKCS#12 with its password.
static bool loadCertificates(const std::string &data, const char *password,
                             std::vector<X509 *> &certs, EVP_PKEY **key, std::string &why)
{
    ERR_clear_error();
    // PEM
    if (data.find("-----BEGIN") != std::string::npos)
    {
        BIO *b = BIO_new_mem_buf(data.data(), (int)data.size());
        X509 *x;
        while ((x = PEM_read_bio_X509(b, nullptr, nullptr, nullptr)) != nullptr)
        {
            certs.push_back(x);
        }
        BIO_free(b);
        ERR_clear_error();
        if (key != nullptr)
        {
            b = BIO_new_mem_buf(data.data(), (int)data.size());
            *key = PEM_read_bio_PrivateKey(b, nullptr, nullptr, (void *)password);
            BIO_free(b);
            unsigned long e = ERR_peek_last_error();
            ERR_clear_error();
            if (*key == nullptr && data.find("PRIVATE KEY-----") != std::string::npos)
            {
                // There is one, but it cannot be read (a wrong password).
                why = "cannot read the private key: " + sslReason(e);
                return false;
            }
        }
        if (certs.empty())
        {
            why = "no certificate in the file";
            return false;
        }
        return true;
    }
    // DER: one certificate
    const unsigned char *p = (const unsigned char *)data.data();
    X509 *x = d2i_X509(nullptr, &p, (long)data.size());
    if (x != nullptr)
    {
        certs.push_back(x);
        return true;
    }
    ERR_clear_error();
    // PKCS#12
    p = (const unsigned char *)data.data();
    PKCS12 *p12 = d2i_PKCS12(nullptr, &p, (long)data.size());
    if (p12 == nullptr)
    {
        ERR_clear_error();
        why = "not a certificate file (PEM, DER or PKCS#12)";
        return false;
    }
    EVP_PKEY *k = nullptr;
    X509 *cert = nullptr;
    STACK_OF(X509) *ca = nullptr;
    int ok = PKCS12_parse(p12, password, &k, &cert, &ca);
    PKCS12_free(p12);
    if (!ok)
    {
        unsigned long e = ERR_peek_last_error();
        ERR_clear_error();
        why = ERR_GET_REASON(e) == PKCS12_R_MAC_VERIFY_FAILURE
              ? "wrong password for the PKCS#12 file"
              : "cannot read the PKCS#12 file: " + sslReason(e);
        return false;
    }
    if (cert != nullptr)
    {
        certs.push_back(cert);
    }
    while (ca != nullptr && sk_X509_num(ca) > 0)
    {
        certs.push_back(sk_X509_shift(ca));
    }
    sk_X509_free(ca);
    if (key != nullptr)
    {
        *key = k;
    }
    else if (k != nullptr)
    {
        EVP_PKEY_free(k);
    }
    if (certs.empty())
    {
        why = "no certificate in the PKCS#12 file";
        return false;
    }
    return true;
}

static bool isAddress(const std::string &host)
{
    unsigned char buf[16];
    std::string h = host.substr(0, host.find('%'));
    return inet_pton(AF_INET, h.c_str(), buf) == 1 || inet_pton(AF_INET6, h.c_str(), buf) == 1;
}

#ifdef _WIN32
static bool winLoadCertificates(const std::string &data, const char *password, std::vector<std::string> &ders,
                                std::string &why);
static bool winCheckIdentity(const char *file, const char *password, std::string &why);
static bool useSchannel();
#endif

// TLSOptions~nLoad(file, password): "OK" and the certificates in the file,
// each as DER bytes; or an error ("ERROR", text, "", 0). Windows reads the
// file itself (OpenSSL is not needed for it there).
RexxMethod2(RexxArrayObject, tls_load_certificates, CSTRING, file, OPTIONAL_CSTRING, password)
{
#ifdef _WIN32
    {
        std::string data, why;
        std::vector<std::string> ders;
        if (!readFile(file, data, why) ||
            !winLoadCertificates(data, password != nullptr ? password : "", ders, why))
        {
            return errorArray(context, why, "", 0);
        }
        RexxArrayObject r = context->NewArray(ders.size());
        for (const std::string &d : ders)
        {
            context->ArrayAppendString(r, d.data(), d.size());
        }
        return statusResult(context, "OK", r);
    }
#endif
    if (!opensslHere())
    {
        return opensslMissing(context);
    }
    std::string data, why;
    std::vector<X509 *> certs;
    bool ok = readFile(file, data, why) &&
              loadCertificates(data, password != nullptr ? password : "", certs, nullptr, why);
    if (!ok)
    {
        for (X509 *x : certs)
        {
            X509_free(x);
        }
        return errorArray(context, why, "", 0);
    }
    RexxArrayObject ders = context->NewArray(certs.size());
    for (X509 *x : certs)
    {
        unsigned char *der = nullptr;
        int len = i2d_X509(x, &der);
        if (len > 0)
        {
            context->ArrayAppendString(ders, (const char *)der, (size_t)len);
            OPENSSL_free(der);
        }
        X509_free(x);
    }
    return statusResult(context, "OK", ders);
}

// The handshake's failure, as a result: "ERROR", text, name, number.
static RexxArrayObject handshakeFailure(RexxMethodContext *context, PeerCheck *s, const TlsOutcome &o)
{
    if (o.status == TLS_TIMEOUT)
    {
        return statusResult(context, "TIMEOUT");
    }
    if (o.status == TLS_CLOSED)
    {
        return closedResult(context);
    }
    if (o.status == TLS_SOCKET_ERROR)
    {
        return errorResult(context, o.socketError);
    }
    if (o.status == TLS_EOF)
    {
        return errorArray(context, "the peer closed the connection during the handshake", "EOF", 0);
    }
    if (s->trust.set)
    {
        return trustResult(context, s->trust);
    }
#ifdef _WIN32
    if (o.schStatus != 0)
    {
        return secResult(context, (SECURITY_STATUS)o.schStatus, "handshake failed: ");
    }
#endif
    if (o.verifyResult != X509_V_OK)
    {
        return trustResult(context, opensslTrustError(o.verifyResult));
    }
    return errorArray(context, "handshake failed: " + sslReason(o.sslError), "SSL_ERROR_SSL",
                      (long long)ERR_GET_REASON(o.sslError), sslText(o.sslError));
}

static int minVersionOf(const char *v)
{
    return strcmp(v, "1.3") == 0 ? TLS1_3_VERSION : TLS1_2_VERSION;
}

// Either side's handshake, for SLICE_MS at most: "OK", "AGAIN" and the
// seconds left, "TIMEOUT", or the failure.
static RexxArrayObject handshakeStep(RexxMethodContext *context, Sock *s, double timeout)
{
    bool hasDeadline = timeout >= 0;
    Clock::time_point deadline = deadlineFrom(hasDeadline ? timeout : 0);
    TlsOutcome o = tlsRun(s, hasDeadline, deadline, [](SSL *ssl) { return SSL_do_handshake(ssl); });
    if (o.status == TLS_OK)
    {
        return statusResult(context, "OK");
    }
    if (o.status == TLS_AGAIN)
    {
        return statusResult(context, "AGAIN", context->DoubleToObject(secondsLeft(hasDeadline, deadline)));
    }
    return handshakeFailure(context, s, o);
}

#ifdef _WIN32

/*----------------------------------------------------------------------------*/
/* Schannel                                                                   */
/*                                                                            */
/* Windows' own TLS, which Windows Update keeps current (Rony, 27 and         */
/* 29/10/2026), for TLS's client and server. DTLS is OpenSSL's: the server    */
/* always (Schannel's cannot be made to work), the client when OpenSSL is     */
/* there (Rony, 30/10/2026: Schannel's cannot send close_notify), else        */
/* Schannel's. Measured in probes/schannel/. OOSOCKETS_TLS=openssl makes      */
/* Windows use OpenSSL for everything (Rony, 29/10/2026), =schannel           */
/* Schannel for the DTLS client too; Windows always decides trust.            */
/*                                                                            */
/* The server's certificate is validated by hand (SCH_CRED_MANUAL_CRED_       */
/* VALIDATION) as soon as Schannel shows it, before our next flight goes if   */
/* it can (TLS 1.3: before our Finished): with Windows' roots and SSL policy  */
/* (as OpenSSL's handshake does on Windows), or, when certificates are        */
/* trusted explicitly, with a chain engine whose only anchors are those. A    */
/* refused certificate ends the handshake with an alert, as OpenSSL's does.   */
/* DTLS: Schannel shows it only at the end (measured), so it is read from     */
/* the server's flight in clear (see "the client by Schannel" under DTLS).    */
/*                                                                            */
/* The model is OpenSSL's in tlsRun: each step is made under the Sock's       */
/* lock, on a non-blocking socket, and says whether it must wait to read or   */
/* to write; the waiting is done outside the lock, a slice at a time.         */
/*----------------------------------------------------------------------------*/

// OOSOCKETS_TLS, lowercase ("" when not set). Read each time a connection
// starts TLS.
static std::string tlsChoice()
{
    char buf[32] = "";
    DWORD n = GetEnvironmentVariableA("OOSOCKETS_TLS", buf, sizeof(buf));
    std::string v = n > 0 && n < sizeof(buf) ? buf : "";
    for (auto &ch : v)
    {
        ch = (char)tolower((unsigned char)ch);
    }
    return v;
}

// Whether Windows does TLS with Schannel: yes, unless OOSOCKETS_TLS is
// "openssl".
static bool useSchannel()
{
    return tlsChoice() != "openssl";
}

// Whether DTLS's client is Schannel's: only when OpenSSL cannot be loaded
// (Rony, 30/10/2026: Schannel's DTLS client cannot send close_notify), or
// when OOSOCKETS_TLS is "schannel"; never when it is "openssl".
static bool dtlsClientBySchannel()
{
    std::string v = tlsChoice();
    if (v == "openssl")
    {
        return false;
    }
    return v == "schannel" || !opensslHere();
}

// Schannel's credentials, shared by every connection a TLSServerSocket
// accepts (and freed with the last of them).
struct SchCred
{
    CredHandle h;
    SchCred(const CredHandle &c) : h(c) { }
    ~SchCred() { FreeCredentialsHandle(&h); }
};

struct Sch
{
    std::shared_ptr<SchCred> cred;
    CtxtHandle ctx;
    bool server = false;               // the server's side
    bool datagram = false;             // DTLS (the client)
    bool haveCtx = false;
    std::wstring target;               // the server's name (SNI); empty for an address
    std::vector<std::string> trusted;  // DER; empty: the system decides
    bool checked = false;              // the server's certificate has been checked
    bool done = false;                 // the handshake has finished
    bool needMore = false;             // in holds part of a record: read more
    bool postHandshake = false;        // TLS 1.3: a message after the handshake goes to ISC
    bool peerClosed = false;           // close_notify arrived
    bool sentClose = false;            // close_notify has been made
    SECURITY_STATUS failed = SEC_E_OK; // the handshake failed (its alert may be in out)
    bool notTls = false;               // ... because the peer does not speak TLS
    std::string in;                    // received, not yet used
    std::string out;                   // to send
    std::string plain;                 // decrypted, not yet read
    SecPkgContext_StreamSizes sizes;
    // DTLS: the last flight sent again when nothing comes back in time
    Clock::time_point resendAt;
    int resendMs = 0;
    int resends = 0;
    // DTLS: the server's Certificate message, read from its flight in clear
    // (Schannel shows the certificate only once the handshake is over), and
    // the highest sequence number we have sent in epoch 0 (for our alert)
    std::string certMsg;
    std::vector<bool> certHave;
    int certSeq = -1;
    std::vector<std::string> peerChain;
    unsigned long long sentSeq0 = 0;
    std::string checkedDer;            // the server's certificate as checked
    Sch() { memset(&sizes, 0, sizeof(sizes)); }
};

static void schFree(Sch *c)
{
    if (c == nullptr)
    {
        return;
    }
    if (c->haveCtx)
    {
        DeleteSecurityContext(&c->ctx);
    }
    delete c;
}

static const DWORD SCH_CLIENT_FLAGS = ISC_REQ_SEQUENCE_DETECT | ISC_REQ_REPLAY_DETECT | ISC_REQ_CONFIDENTIALITY |
    ISC_REQ_EXTENDED_ERROR | ISC_REQ_ALLOCATE_MEMORY | ISC_REQ_STREAM | ISC_REQ_USE_SUPPLIED_CREDS |
    ISC_REQ_MANUAL_CRED_VALIDATION;
static const DWORD SCH_DTLS_FLAGS = (SCH_CLIENT_FLAGS & ~(DWORD)ISC_REQ_STREAM) | ISC_REQ_DATAGRAM;
static const DWORD SCH_SERVER_FLAGS = ASC_REQ_SEQUENCE_DETECT | ASC_REQ_REPLAY_DETECT | ASC_REQ_CONFIDENTIALITY |
    ASC_REQ_EXTENDED_ERROR | ASC_REQ_ALLOCATE_MEMORY | ASC_REQ_STREAM;

static const DWORD SCH_EVERY_PROTOCOL = SP_PROT_TLS1_0 | SP_PROT_TLS1_1 | SP_PROT_TLS1_2 | SP_PROT_TLS1_3 |
    SP_PROT_SSL3 | SP_PROT_SSL2 | SP_PROT_DTLS1_0 | SP_PROT_DTLS1_2;

// Credentials: SCH_CREDENTIALS (Windows 10 1809 and later), with every
// protocol but those enabled disabled; before that, SCHANNEL_CRED.
static SECURITY_STATUS schCredentials(ULONG direction, DWORD flags, DWORD enabled, PCCERT_CONTEXT cert,
                                      std::shared_ptr<SchCred> &out, bool legacyOnly = false)
{
    TimeStamp expiry;
    CredHandle h;
    SCH_CREDENTIALS sc;
    TLS_PARAMETERS tp;
    memset(&sc, 0, sizeof(sc));
    memset(&tp, 0, sizeof(tp));
    sc.dwVersion = SCH_CREDENTIALS_VERSION;
    sc.dwFlags = flags;
    if (cert != nullptr)
    {
        sc.cCreds = 1;
        sc.paCred = &cert;
    }
    tp.grbitDisabledProtocols = SCH_EVERY_PROTOCOL & ~enabled;
    sc.cTlsParameters = 1;
    sc.pTlsParameters = &tp;
    SECURITY_STATUS st = SEC_E_UNSUPPORTED_FUNCTION;
    if (!legacyOnly)
    {
        st = AcquireCredentialsHandleW(nullptr, (LPWSTR)UNISP_NAME_W, direction, nullptr,
                                       &sc, nullptr, nullptr, &h, &expiry);
    }
    if (st != SEC_E_OK)
    {
        SCHANNEL_CRED lc;
        memset(&lc, 0, sizeof(lc));
        lc.dwVersion = SCHANNEL_CRED_VERSION;
        lc.dwFlags = flags;
        if (cert != nullptr)
        {
            lc.cCreds = 1;
            lc.paCred = &cert;
        }
        lc.grbitEnabledProtocols = enabled;
        st = AcquireCredentialsHandleW(nullptr, (LPWSTR)UNISP_NAME_W, direction, nullptr,
                                       &lc, nullptr, nullptr, &h, &expiry);
    }
    if (st == SEC_E_OK)
    {
        out = std::make_shared<SchCred>(h);
    }
    return st;
}

// Schannel's names for the statuses a program may meet.
static const char *secName(SECURITY_STATUS st)
{
    switch (st)
    {
        case SEC_E_ILLEGAL_MESSAGE:       return "SEC_E_ILLEGAL_MESSAGE";
        case SEC_E_ALGORITHM_MISMATCH:    return "SEC_E_ALGORITHM_MISMATCH";
        case SEC_E_UNSUPPORTED_FUNCTION:  return "SEC_E_UNSUPPORTED_FUNCTION";
        case SEC_E_INTERNAL_ERROR:        return "SEC_E_INTERNAL_ERROR";
        case SEC_E_INVALID_TOKEN:         return "SEC_E_INVALID_TOKEN";
        case SEC_E_MESSAGE_ALTERED:       return "SEC_E_MESSAGE_ALTERED";
        case SEC_E_DECRYPT_FAILURE:       return "SEC_E_DECRYPT_FAILURE";
        case SEC_E_CERT_UNKNOWN:          return "SEC_E_CERT_UNKNOWN";
        case SEC_E_CERT_EXPIRED:          return "SEC_E_CERT_EXPIRED";
        case SEC_E_UNTRUSTED_ROOT:        return "SEC_E_UNTRUSTED_ROOT";
        case SEC_E_WRONG_PRINCIPAL:       return "SEC_E_WRONG_PRINCIPAL";
        case SEC_E_NO_CREDENTIALS:        return "SEC_E_NO_CREDENTIALS";
        case SEC_E_UNKNOWN_CREDENTIALS:   return "SEC_E_UNKNOWN_CREDENTIALS";
        case SEC_E_INVALID_HANDLE:        return "SEC_E_INVALID_HANDLE";
        case SEC_E_INVALID_PARAMETER:     return "SEC_E_INVALID_PARAMETER";
        case SEC_E_INSUFFICIENT_MEMORY:   return "SEC_E_INSUFFICIENT_MEMORY";
        case SEC_E_CONTEXT_EXPIRED:       return "SEC_E_CONTEXT_EXPIRED";
        case SEC_E_INCOMPLETE_MESSAGE:    return "SEC_E_INCOMPLETE_MESSAGE";
        case SEC_E_OUT_OF_SEQUENCE:       return "SEC_E_OUT_OF_SEQUENCE";
    }
    return "SECURITY_STATUS";
}

// The system's text for a status, in English, without a final period.
static std::string secText(SECURITY_STATUS st)
{
    char buf[512] = "";
    if (FormatMessageA(FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS, nullptr, (DWORD)st,
                       MAKELANGID(LANG_ENGLISH, SUBLANG_ENGLISH_US), buf, sizeof(buf), nullptr) == 0)
    {
        FormatMessageA(FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS, nullptr, (DWORD)st,
                       0, buf, sizeof(buf), nullptr);
    }
    std::string text = buf;
    while (!text.empty() && (text.back() == '\n' || text.back() == '\r' || text.back() == ' ' || text.back() == '.'))
    {
        text.pop_back();
    }
    if (text.empty())
    {
        char hex[32];
        snprintf(hex, sizeof(hex), "0x%08lX", (unsigned long)st);
        text = std::string("Schannel status ") + hex;
    }
    return text;
}

// A Schannel failure as an error result; prefix: "handshake failed: " or "".
// name: Schannel's name for it; or, for a connection's read or write,
// "TLS", as OpenSSL's (its description reads "ERROR:TLS handshake failed:
// ..."; Schannel's own text is in the system's text).
static RexxArrayObject secResult(RexxMethodContext *context, SECURITY_STATUS st, const char *prefix,
                                 const char *name)
{
    std::string sys = secText(st);
    std::string text = sys;
    text[0] = (char)tolower((unsigned char)text[0]);
    return errorArray(context, prefix + text, name != nullptr ? name : secName(st), (long long)(DWORD)st, sys, "TLS");
}

static std::wstring wide(const std::string &s)
{
    std::wstring w(s.size() + 1, L'\0');
    int n = MultiByteToWideChar(CP_UTF8, 0, s.c_str(), -1, &w[0], (int)w.size());
    w.resize(n > 0 ? (size_t)n - 1 : 0);
    return w;
}

static std::string narrow(const wchar_t *w)
{
    char buf[256] = "";
    WideCharToMultiByte(CP_UTF8, 0, w, -1, buf, sizeof(buf), nullptr, nullptr);
    return buf;
}

// The client's credentials: TLS 1.2 and 1.3 (or only 1.3), no certificate
// of our own, the server's validated by hand.
static SECURITY_STATUS schClientCredentials(Sch *c, bool only13)
{
    return schCredentials(SECPKG_CRED_OUTBOUND,
                          SCH_USE_STRONG_CRYPTO | SCH_CRED_NO_DEFAULT_CREDS | SCH_CRED_MANUAL_CRED_VALIDATION,
                          SP_PROT_TLS1_3_CLIENT | (only13 ? 0 : SP_PROT_TLS1_2_CLIENT), nullptr, c->cred);
}

// What the server's certificate is to be checked with: the system, or the
// certificates trusted explicitly (only those, as anchors and as the
// server's own certificate itself, and the host name).
static bool schTrust(PeerCheck *s, Sch *c, PCCERT_CONTEXT leaf)
{
    if (c->trusted.empty())
    {
        return windowsTrust(leaf, leaf->hCertStore, nullptr, s->host, s->trust);
    }
    HCERTSTORE anchors = CertOpenStore(CERT_STORE_PROV_MEMORY, 0, 0, 0, nullptr);
    HCERTSTORE extra = CertOpenStore(CERT_STORE_PROV_MEMORY, 0, 0, 0, nullptr);
    for (const std::string &der : c->trusted)
    {
        PCCERT_CONTEXT t = nullptr;
        if (CertAddEncodedCertificateToStore(anchors, X509_ASN_ENCODING, (const BYTE *)der.data(), (DWORD)der.size(),
                                             CERT_STORE_ADD_ALWAYS, &t))
        {
            CertAddCertificateContextToStore(extra, t, CERT_STORE_ADD_ALWAYS, nullptr);
            CertFreeCertificateContext(t);
        }
    }
    PCCERT_CONTEXT x = nullptr;
    while ((x = CertEnumCertificatesInStore(leaf->hCertStore, x)) != nullptr)
    {
        CertAddCertificateContextToStore(extra, x, CERT_STORE_ADD_ALWAYS, nullptr);
    }
    CERT_CHAIN_ENGINE_CONFIG config;
    memset(&config, 0, sizeof(config));
    config.cbSize = sizeof(config);
    config.hExclusiveRoot = anchors;
    config.hExclusiveTrustedPeople = anchors;          // a server's own certificate, trusted as it is
    config.dwExclusiveFlags = CERT_CHAIN_EXCLUSIVE_ENABLE_CA_FLAG;   // a CA that is not a root
    HCERTCHAINENGINE engine = nullptr;
    bool ok;
    if (!CertCreateCertificateChainEngine(&config, &engine))
    {
        windowsTrustError(GetLastError(), s->trust);
        ok = false;
    }
    else
    {
        ok = windowsTrust(leaf, extra, engine, s->host, s->trust);
        CertFreeCertificateChainEngine(engine);
    }
    CertCloseStore(extra, 0);
    CertCloseStore(anchors, 0);
    return ok;
}

// The TLS alert that tells the server why its certificate was refused.
static DWORD alertFor(const TrustError &t)
{
    if (t.text == CERT_EXPIRED || t.text == CERT_NOT_YET)
    {
        return TLS1_ALERT_CERTIFICATE_EXPIRED;
    }
    if (t.text == CERT_UNTRUSTED)
    {
        return TLS1_ALERT_UNKNOWN_CA;
    }
    if (t.text == CERT_REVOKED)
    {
        return TLS1_ALERT_CERTIFICATE_REVOKED;
    }
    return TLS1_ALERT_BAD_CERTIFICATE;
}

// What Schannel makes after ApplyControlToken (an alert, close_notify).
static std::string schControl(Sch *c, void *token, unsigned long size)
{
    SecBuffer b = { size, SECBUFFER_TOKEN, token };
    SecBufferDesc d = { SECBUFFER_VERSION, 1, &b };
    if (ApplyControlToken(&c->ctx, &d) != SEC_E_OK)
    {
        return "";
    }
    SecBuffer ob = { 0, SECBUFFER_TOKEN, nullptr };
    SecBufferDesc od = { SECBUFFER_VERSION, 1, &ob };
    ULONG attrs = 0;
    TimeStamp expiry;
    if (c->server)
    {
        AcceptSecurityContext(&c->cred->h, &c->ctx, nullptr, SCH_SERVER_FLAGS, 0, nullptr, &od, &attrs, &expiry);
    }
    else
    {
        InitializeSecurityContextW(&c->cred->h, &c->ctx, nullptr, SCH_CLIENT_FLAGS, 0, 0, nullptr, 0, nullptr,
                                   &od, &attrs, &expiry);
    }
    std::string made;
    if (ob.pvBuffer != nullptr)
    {
        made.assign((const char *)ob.pvBuffer, ob.cbBuffer);
        FreeContextBuffer(ob.pvBuffer);
    }
    return made;
}

static std::string schAlert(Sch *c, DWORD number)
{
    SCHANNEL_ALERT_TOKEN t;
    t.dwTokenType = SCHANNEL_ALERT;
    t.dwAlertType = TLS1_ALERT_FATAL;
    t.dwAlertNumber = number;
    return schControl(c, &t, sizeof(t));
}

static std::string schCloseNotify(Sch *c)
{
    DWORD t = SCHANNEL_SHUTDOWN;
    return schControl(c, &t, sizeof(t));
}

// Sends what is waiting in out (non-blocking): 1 all of it, 0 the socket
// takes no more now, -1 an error (in err).
static int schFlush(Sock *s, Sch *c, int &err)
{
    while (!c->out.empty())
    {
        int chunk = c->out.size() > 0x40000000 ? 0x40000000 : (int)c->out.size();
        int n = send(s->fd, c->out.data(), chunk, SEND_FLAGS);
        if (n >= 0)
        {
            c->out.erase(0, (size_t)n);
            continue;
        }
        int e = lastError();
        if (wouldBlock(e))
        {
            return 0;
        }
        err = e;
        return -1;
    }
    return 1;
}

// Reads what has arrived into in (non-blocking): 1 something, 0 nothing yet,
// 2 the end (the peer closed), -1 an error (in err).
static int schFill(Sock *s, Sch *c, int &err)
{
    char buf[32768];
    int n = recv(s->fd, buf, sizeof(buf), 0);
    if (n > 0)
    {
        c->in.append(buf, (size_t)n);
        c->needMore = false;
        return 1;
    }
    if (n == 0)
    {
        return 2;
    }
    int e = lastError();
    if (wouldBlock(e))
    {
        return 0;
    }
    err = e;
    return -1;
}

// What a step came to: done (status in the outcome), or wait to read or write.
enum SchWant { SCH_DONE, SCH_READ, SCH_WRITE };

struct SchOutcome
{
    TlsStatus status = TLS_OK;
    int socketError = 0;               // TLS_SOCKET_ERROR
    SECURITY_STATUS sec = SEC_E_OK;    // TLS_SSL_ERROR
    bool handshaking = false;
    bool notTls = false;               // the peer does not speak TLS
};

static SchWant schSocketError(SchOutcome &o, int err)
{
    o.status = TLS_SOCKET_ERROR;
    o.socketError = err;
    return SCH_DONE;
}

static SchWant schFail(SchOutcome &o, SECURITY_STATUS st)
{
    o.status = TLS_SSL_ERROR;
    o.sec = st;
    return SCH_DONE;
}

// One call of InitializeSecurityContext (the client; with nothing, the first
// time) or AcceptSecurityContext (the server) with what is in in: its output
// goes to tok, what it did not use stays in in.
static SECURITY_STATUS schInitialize(Sch *c, std::string &tok)
{
    bool first = !c->haveCtx;
    bool input = !first || c->server;
    SecBuffer inb[2] = { { (unsigned long)c->in.size(), SECBUFFER_TOKEN, c->in.empty() ? nullptr : &c->in[0] },
                         { 0, SECBUFFER_EMPTY, nullptr } };
    SecBufferDesc ind = { SECBUFFER_VERSION, 2, inb };
    SecBuffer outb[2] = { { 0, SECBUFFER_TOKEN, nullptr }, { 0, SECBUFFER_ALERT, nullptr } };
    SecBufferDesc outd = { SECBUFFER_VERSION, 2, outb };
    ULONG attrs = 0;
    TimeStamp expiry;
    SEC_WCHAR *target = c->target.empty() ? nullptr : &c->target[0];
    SECURITY_STATUS st = c->server
        ? AcceptSecurityContext(&c->cred->h, first ? nullptr : &c->ctx, &ind, SCH_SERVER_FLAGS, 0,
                                &c->ctx, &outd, &attrs, &expiry)
        : InitializeSecurityContextW(&c->cred->h, first ? nullptr : &c->ctx, target, SCH_CLIENT_FLAGS,
                                     0, 0, first ? nullptr : &ind, 0, &c->ctx, &outd, &attrs, &expiry);
    if (first && (st == SEC_I_CONTINUE_NEEDED || st == SEC_E_OK))
    {
        c->haveCtx = true;
    }
    if (outb[0].pvBuffer != nullptr)
    {
        tok.append((const char *)outb[0].pvBuffer, outb[0].cbBuffer);
        FreeContextBuffer(outb[0].pvBuffer);
    }
    if (outb[1].pvBuffer != nullptr)
    {
        FreeContextBuffer(outb[1].pvBuffer);
    }
    if (st == SEC_E_INCOMPLETE_MESSAGE)
    {
        c->needMore = true;                  // in kept as it is
    }
    else if (input && st != SEC_I_INCOMPLETE_CREDENTIALS)
    {
        if (inb[1].BufferType == SECBUFFER_EXTRA && inb[1].cbBuffer > 0 && inb[1].cbBuffer <= c->in.size())
        {
            if (inb[1].cbBuffer == c->in.size() && st == SEC_I_CONTINUE_NEEDED)
            {
                c->needMore = true;              // nothing used: read more first, no spinning
            }
            c->in.erase(0, c->in.size() - inb[1].cbBuffer);
        }
        else
        {
            c->in.clear();
        }
    }
    return st;
}

// After a handshake message once connected (TLS 1.3's tickets, a
// renegotiation): the server's certificate must still be the one checked,
// since Schannel, validating nothing by itself here, would take another.
static bool schSameCertificate(Sch *c, const std::string &checked)
{
    if (c->server || checked.empty())
    {
        return true;
    }
    PCCERT_CONTEXT now = nullptr;
    bool same = QueryContextAttributesW(&c->ctx, SECPKG_ATTR_REMOTE_CERT_CONTEXT, &now) == SEC_E_OK
                && now != nullptr && now->cbCertEncoded == checked.size()
                && memcmp(now->pbCertEncoded, checked.data(), checked.size()) == 0;
    if (now != nullptr)
    {
        CertFreeCertificateContext(now);
    }
    return same;
}

// One step of the client's handshake.
static SchWant schHandshake(Sock *s, Sch *c, SchOutcome &o)
{
    o.handshaking = true;
    for (int rounds = 0; ; rounds++)
    {
        int err = 0;
        int f = schFlush(s, c, err);
        if (c->failed != SEC_E_OK)
        {
            // the alert goes first, if the socket takes it
            if (f == 0)
            {
                return SCH_WRITE;
            }
            o.notTls = c->notTls;
            return schFail(o, c->failed);
        }
        if (f < 0)
        {
            return schSocketError(o, err);
        }
        if (f == 0)
        {
            return SCH_WRITE;
        }
        if (c->done)
        {
            o.handshaking = false;
            o.status = TLS_OK;
            return SCH_DONE;
        }
        if ((c->haveCtx || c->server) && (c->in.empty() || c->needMore))
        {
            int r = schFill(s, c, err);
            if (r == 0)
            {
                return SCH_READ;
            }
            if (r < 0)
            {
                return schSocketError(o, err);
            }
            if (r == 2)
            {
                o.status = TLS_EOF;
                return SCH_DONE;
            }
        }
        // What a client in clear sends (a browser on http://, telnet) is not
        // a TLS record (22, a handshake): Schannel's text would not say so.
        bool clear = c->server && !c->haveCtx && !c->in.empty() && (unsigned char)c->in[0] != 22;
        std::string tok;
        SECURITY_STATUS st = schInitialize(c, tok);
        if (st == SEC_E_INCOMPLETE_MESSAGE)
        {
            continue;
        }
        if (st == SEC_I_INCOMPLETE_CREDENTIALS && rounds < 16)
        {
            // the server asks for a certificate of ours: there is none
            c->out += tok;
            continue;
        }
        if (st != SEC_I_CONTINUE_NEEDED && st != SEC_E_OK)
        {
            c->out += tok;                    // an alert, if Schannel made one
            c->failed = st;
            c->notTls = clear;
            continue;
        }
        if (!c->checked && !c->server)
        {
            // Before our next flight: is the server's certificate good?
            PCCERT_CONTEXT leaf = nullptr;
            if (QueryContextAttributesW(&c->ctx, SECPKG_ATTR_REMOTE_CERT_CONTEXT, &leaf) == SEC_E_OK
                && leaf != nullptr)
            {
                c->checked = true;
                c->checkedDer.assign((const char *)leaf->pbCertEncoded, leaf->cbCertEncoded);
                bool ok = schTrust(s, c, leaf);
                CertFreeCertificateContext(leaf);
                if (!ok)
                {
                    c->out += schAlert(c, alertFor(s->trust));
                    c->failed = SEC_E_CERT_UNKNOWN;
                    continue;
                }
            }
            else if (st == SEC_E_OK)
            {
                s->trust.set = true;
                s->trust.name = "SEC_E_CERT_UNKNOWN";
                s->trust.text = "the server sent no certificate";
                c->out += schAlert(c, TLS1_ALERT_BAD_CERTIFICATE);
                c->failed = SEC_E_CERT_UNKNOWN;
                continue;
            }
        }
        c->out += tok;
        if (st == SEC_E_OK)
        {
            QueryContextAttributesW(&c->ctx, SECPKG_ATTR_STREAM_SIZES, &c->sizes);
            c->done = true;                   // what is left in in is the server's data
        }
    }
}

// One step of a read: up to max bytes into got.
static SchWant schHandshake(Sock *s, Sch *c, SchOutcome &o);

// An accepted connection's handshake happens on its first read or write.
static bool schHandshaken(Sock *s, Sch *c, SchOutcome &o, SchWant &want)
{
    if (c->done)
    {
        return true;
    }
    want = schHandshake(s, c, o);
    return want == SCH_DONE && o.status == TLS_OK;
}

static SchWant schRecv(Sock *s, Sch *c, size_t max, std::string &got, SchOutcome &o)
{
    SchWant want = SCH_DONE;
    if (!schHandshaken(s, c, o, want))
    {
        return want;
    }
    for (;;)
    {
        if (!c->plain.empty())
        {
            size_t n = c->plain.size() < max ? c->plain.size() : max;
            got.assign(c->plain, 0, n);
            c->plain.erase(0, n);
            o.status = TLS_OK;
            return SCH_DONE;
        }
        if (c->peerClosed)
        {
            o.status = TLS_EOF;
            return SCH_DONE;
        }
        int err = 0;
        int f = schFlush(s, c, err);         // an answer after the handshake, say
        if (f < 0)
        {
            return schSocketError(o, err);
        }
        if (f == 0)
        {
            return SCH_WRITE;
        }
        if (!c->in.empty() && !c->needMore)
        {
            if (c->postHandshake)
            {
                // TLS 1.3: a message after the handshake (a session ticket, a
                // key update) goes to the handshake's function (probes/schannel)
                std::string tok;
                SECURITY_STATUS st = schInitialize(c, tok);
                c->out += tok;
                if (st == SEC_E_OK)
                {
                    c->postHandshake = false;
                    if (!schSameCertificate(c, c->checkedDer))
                    {
                        return schFail(o, SEC_E_CERT_UNKNOWN);   // another certificate: refused
                    }
                }
                else if (st != SEC_E_INCOMPLETE_MESSAGE && st != SEC_I_CONTINUE_NEEDED)
                {
                    return schFail(o, st);
                }
                continue;
            }
            SecBuffer b[4] = { { (unsigned long)c->in.size(), SECBUFFER_DATA, &c->in[0] },
                               { 0, SECBUFFER_EMPTY, nullptr }, { 0, SECBUFFER_EMPTY, nullptr },
                               { 0, SECBUFFER_EMPTY, nullptr } };
            SecBufferDesc d = { SECBUFFER_VERSION, 4, b };
            SECURITY_STATUS st = DecryptMessage(&c->ctx, &d, 0, nullptr);
            if (st == SEC_E_INCOMPLETE_MESSAGE)
            {
                c->needMore = true;
                continue;
            }
            if (st != SEC_E_OK && st != SEC_I_RENEGOTIATE && st != SEC_I_CONTEXT_EXPIRED)
            {
                return schFail(o, st);
            }
            if (st == SEC_I_CONTEXT_EXPIRED)
            {
                // close_notify: the buffers are left as they came (the
                // record itself as DATA, measured), and nothing follows it
                c->peerClosed = true;
                c->in.clear();
                continue;
            }
            std::string extra;
            for (int i = 0; i < 4; i++)
            {
                if (b[i].BufferType == SECBUFFER_DATA && b[i].cbBuffer > 0)
                {
                    c->plain.append((const char *)b[i].pvBuffer, b[i].cbBuffer);
                }
                else if (b[i].BufferType == SECBUFFER_EXTRA && b[i].cbBuffer > 0)
                {
                    extra.assign((const char *)b[i].pvBuffer, b[i].cbBuffer);
                }
            }
            c->in = extra;
            if (st == SEC_I_RENEGOTIATE)
            {
                c->postHandshake = true;
            }
            continue;
        }
        int r = schFill(s, c, err);
        if (r == 0)
        {
            return SCH_READ;
        }
        if (r < 0)
        {
            return schSocketError(o, err);
        }
        if (r == 2)
        {
            o.status = TLS_EOF;               // closed without close_notify: the end too
            return SCH_DONE;
        }
    }
}

// One step of a write: encrypts up to one record of p (n: how much), once
// what was waiting has gone; with left 0, only sends what is waiting.
static SchWant schSend(Sock *s, Sch *c, const char *p, size_t left, size_t &n, SchOutcome &o)
{
    n = 0;
    SchWant want = SCH_DONE;
    if (!schHandshaken(s, c, o, want))
    {
        return want;
    }
    int err = 0;
    int f = schFlush(s, c, err);
    if (f < 0)
    {
        return schSocketError(o, err);
    }
    if (f == 0)
    {
        return SCH_WRITE;
    }
    o.status = TLS_OK;
    if (left == 0)
    {
        return SCH_DONE;
    }
    if (c->sentClose || c->sizes.cbMaximumMessage == 0)
    {
        return schSocketError(o, WSAESHUTDOWN);
    }
    size_t chunk = left < c->sizes.cbMaximumMessage ? left : c->sizes.cbMaximumMessage;
    std::string rec(c->sizes.cbHeader + chunk + c->sizes.cbTrailer, '\0');
    memcpy(&rec[c->sizes.cbHeader], p, chunk);
    SecBuffer b[4] = { { c->sizes.cbHeader, SECBUFFER_STREAM_HEADER, &rec[0] },
                       { (unsigned long)chunk, SECBUFFER_DATA, &rec[c->sizes.cbHeader] },
                       { c->sizes.cbTrailer, SECBUFFER_STREAM_TRAILER, &rec[c->sizes.cbHeader + chunk] },
                       { 0, SECBUFFER_EMPTY, nullptr } };
    SecBufferDesc d = { SECBUFFER_VERSION, 4, b };
    SECURITY_STATUS st = EncryptMessage(&c->ctx, 0, &d, 0);
    if (st != SEC_E_OK)
    {
        return schFail(o, st);
    }
    c->out.append(rec.data(), b[0].cbBuffer + b[1].cbBuffer + b[2].cbBuffer);
    n = chunk;
    schFlush(s, c, err);                     // what does not go now, goes next
    return SCH_DONE;
}

// Runs step until it is done, waiting outside the lock (until the deadline,
// if there is one; TLS_AGAIN after SLICE_MS of waiting), as tlsRun.
template <class Step>
static SchOutcome schRun(Sock *s, bool hasDeadline, Clock::time_point deadline, Step step)
{
    for (;;)
    {
        SchOutcome out;
        SchWant want;
        sock_t fd;
        {
            std::lock_guard<std::mutex> guard(s->mu);
            if (s->fd == BAD_SOCKET || s->sch == nullptr)
            {
                out.status = TLS_CLOSED;
                return out;
            }
            fd = s->fd;
            want = step(s, s->sch, out);
        }
        if (want == SCH_DONE)
        {
            return out;
        }
        int err = 0;
        int w = waitSlice(fd, want == SCH_READ ? POLLIN : POLLOUT, hasDeadline, deadline, &err);
        if (w == 0)
        {
            out.status = TLS_TIMEOUT;
            return out;
        }
        if (w == 2)
        {
            out.status = TLS_AGAIN;
            return out;
        }
        if (w < 0)
        {
            out.status = TLS_SOCKET_ERROR;
            out.socketError = err;
            return out;
        }
    }
}

// A handshake that failed because the peer does not speak TLS: ours, and
// Schannel's own text as the system's.
static RexxArrayObject notTlsResult(RexxMethodContext *context, SECURITY_STATUS st, const char *name)
{
    return errorArray(context, "handshake failed: the peer does not speak TLS", name, (long long)(DWORD)st,
                      secText(st), "TLS");
}

// The result of a read or write that failed on an established connection.
static RexxArrayObject schIoResult(RexxMethodContext *context, const SchOutcome &o)
{
    if (o.status == TLS_SSL_ERROR && o.notTls)
    {
        return notTlsResult(context, o.sec, "TLS");
    }
    switch (o.status)
    {
        case TLS_EOF:          return statusResult(context, "EOF");
        case TLS_TIMEOUT:      return statusResult(context, "TIMEOUT");
        case TLS_CLOSED:       return closedResult(context);
        case TLS_SOCKET_ERROR: return errorResult(context, o.socketError);
        default:               return secResult(context, o.sec, o.handshaking ? "handshake failed: " : "", "TLS");
    }
}

// The client's handshake, for SLICE_MS at most: "OK", "AGAIN" and the
// seconds left, "TIMEOUT", or the failure.
static RexxArrayObject schHandshakeStep(RexxMethodContext *context, Sock *s, double timeout)
{
    bool hasDeadline = timeout >= 0;
    Clock::time_point deadline = deadlineFrom(hasDeadline ? timeout : 0);
    SchOutcome o = schRun(s, hasDeadline, deadline,
                          [](Sock *k, Sch *c, SchOutcome &oc) { return schHandshake(k, c, oc); });
    switch (o.status)
    {
        case TLS_OK:           return statusResult(context, "OK");
        case TLS_AGAIN:        return statusResult(context, "AGAIN", context->DoubleToObject(secondsLeft(hasDeadline, deadline)));
        case TLS_TIMEOUT:      return statusResult(context, "TIMEOUT");
        case TLS_CLOSED:       return closedResult(context);
        case TLS_SOCKET_ERROR: return errorResult(context, o.socketError);
        case TLS_EOF:          return errorArray(context, "the peer closed the connection during the handshake", "EOF", 0);
        default:
            if (s->trust.set)
            {
                return trustResult(context, s->trust);
            }
            if (o.notTls)
            {
                return notTlsResult(context, o.sec, secName(o.sec));
            }
            return secResult(context, o.sec, "handshake failed: ");
    }
}

// Socket~startTLS and TLSSocket with Schannel: the client's handshake.
static RexxArrayObject schStartClient(RexxMethodContext *context, Sock *s, const char *host,
                                      RexxArrayObject trusted, const char *minVersion, double timeout)
{
    Sch *c = new Sch();
    SECURITY_STATUS st = schClientCredentials(c, strcmp(minVersion, "1.3") == 0);
    if (st != SEC_E_OK)
    {
        schFree(c);
        return secResult(context, st, "cannot start TLS: ");
    }
    if (!isAddress(host))
    {
        c->target = wide(host);                 // SNI, for a name
    }
    size_t count = context->ArrayItems(trusted);
    for (size_t i = 1; i <= count; i++)
    {
        RexxObjectPtr item = context->ArrayAt(trusted, i);
        if (item != NULLOBJECT)
        {
            RexxStringObject der = context->ObjectToString(item);
            c->trusted.push_back(std::string(context->StringData(der), context->StringLength(der)));
        }
    }
    {
        // Checked again under the lock: two startTLS at once (which
        // sockets.cls's guarded methods prevent) cannot both start.
        std::lock_guard<std::mutex> guard(s->mu);
        if (s->sch != nullptr || s->ssl != nullptr)
        {
            schFree(c);
            return errorArray(context, "TLS has already started on this connection", "", 0);
        }
        s->host = host;
        s->trust = TrustError();
        s->sch = c;
        setBlocking(s->fd, false);
    }
    return schHandshakeStep(context, s, timeout);
}

static RexxArrayObject schRecvResult(RexxMethodContext *context, Sock *s, size_t max, double timeout)
{
    bool hasDeadline = timeout >= 0;
    Clock::time_point deadline = deadlineFrom(hasDeadline ? timeout : 0);
    std::string got;
    SchOutcome o = schRun(s, hasDeadline, deadline,
                          [&](Sock *k, Sch *c, SchOutcome &oc) { return schRecv(k, c, max, got, oc); });
    if (o.status == TLS_OK)
    {
        return statusResult(context, "OK", context->NewString(got.data(), got.size()));
    }
    if (o.status == TLS_AGAIN)
    {
        return statusResult(context, "AGAIN", context->DoubleToObject(secondsLeft(hasDeadline, deadline)));
    }
    return schIoResult(context, o);
}

static RexxArrayObject schSendResult(RexxMethodContext *context, Sock *s, const char *p, size_t left, double timeout)
{
    size_t sent = 0;
    bool hasDeadline = timeout >= 0;
    Clock::time_point deadline = deadlineFrom(hasDeadline ? timeout : 0);
    for (;;)
    {
        size_t n = 0;
        SchOutcome o = schRun(s, hasDeadline, deadline,
                              [&](Sock *k, Sch *c, SchOutcome &oc) { return schSend(k, c, p + sent, left, n, oc); });
        if (o.status == TLS_TIMEOUT)
        {
            return statusResult(context, "TIMEOUT", context->StringSize(sent));
        }
        if (o.status == TLS_AGAIN)
        {
            return againSent(context, sent, secondsLeft(hasDeadline, deadline));
        }
        if (o.status != TLS_OK)
        {
            return schIoResult(context, o);
        }
        if (left == 0)
        {
            return statusResult(context, "OK", context->StringSize(sent));   // all of it gone
        }
        sent += n;
        left -= n;
    }
}

// close_notify, sent if the socket takes it now: called under the lock, so
// it never waits (as OpenSSL's SSL_shutdown over our non-blocking BIO). A
// peer that reads nothing, its window full, gets no close_notify (or, as
// with OpenSSL, part of one: the end of the stream to it either way).
static void schSayGoodbye(Sock *s, Sch *c)
{
    if (!c->done || c->sentClose || c->failed != SEC_E_OK)
    {
        return;
    }
    c->sentClose = true;
    c->out += schCloseNotify(c);
    int err = 0;
    schFlush(s, c, err);
}

// nTLSInfo for Schannel: the protocol ("TLSv1.3") and the cipher suite.
static void schInfo(Sch *c, std::string &protocol, std::string &cipher)
{
    if (!c->done)
    {
        return;
    }
    SecPkgContext_ConnectionInfo ci;
    if (QueryContextAttributesW(&c->ctx, SECPKG_ATTR_CONNECTION_INFO, &ci) == SEC_E_OK)
    {
        if (ci.dwProtocol & SP_PROT_DTLS1_2)
        {
            protocol = "DTLSv1.2";
        }
        else if (ci.dwProtocol & SP_PROT_TLS1_3)
        {
            protocol = "TLSv1.3";
        }
        else if (ci.dwProtocol & SP_PROT_TLS1_2)
        {
            protocol = "TLSv1.2";
        }
        else
        {
            protocol = "TLS";
        }
    }
    SecPkgContext_CipherInfo info;
    memset(&info, 0, sizeof(info));
    if (QueryContextAttributesW(&c->ctx, SECPKG_ATTR_CIPHER_INFO, &info) == SEC_E_OK)
    {
        cipher = narrow(info.szCipherSuite);
    }
}

/* ---- certificate files, read by Windows ------------------------------------ */

// On Windows the certificate files are read by Windows itself (CryptoAPI and
// CNG), so that OpenSSL is needed only where it does the TLS (the DTLS
// server, OOSOCKETS_TLS=openssl). The same files as OpenSSL's reading takes:
// PEM (certificates, and a key: PKCS#8, encrypted or not, PKCS#1 RSA or SEC1
// EC), DER (one certificate), PKCS#12 with its password; the same texts.

// A PEM file's blocks: the label ("CERTIFICATE"), the bytes, and whether it
// is a key encrypted in OpenSSL's old way (a "Proc-Type: 4,ENCRYPTED" header).
struct PemBlock
{
    std::string label;
    std::string der;
    bool oldEncrypted = false;
};

static int base64Value(char c)
{
    if (c >= 'A' && c <= 'Z') return c - 'A';
    if (c >= 'a' && c <= 'z') return c - 'a' + 26;
    if (c >= '0' && c <= '9') return c - '0' + 52;
    if (c == '+') return 62;
    if (c == '/') return 63;
    return -1;
}

static std::vector<PemBlock> pemBlocks(const std::string &data)
{
    std::vector<PemBlock> blocks;
    size_t at = 0;
    for (;;)
    {
        size_t begin = data.find("-----BEGIN ", at);
        if (begin == std::string::npos)
        {
            break;
        }
        size_t labelEnd = data.find("-----", begin + 11);
        if (labelEnd == std::string::npos)
        {
            break;
        }
        PemBlock b;
        b.label = data.substr(begin + 11, labelEnd - begin - 11);
        std::string endLine = "-----END " + b.label + "-----";
        size_t end = data.find(endLine, labelEnd + 5);
        if (end == std::string::npos)
        {
            break;
        }
        at = end + endLine.size();
        // The body: header lines ("Name: value") are left out, the rest
        // is base64.
        unsigned bits = 0;
        int nbits = 0;
        size_t line = labelEnd + 5;
        while (line < end)
        {
            size_t eol = data.find('\n', line);
            if (eol == std::string::npos || eol > end)
            {
                eol = end;
            }
            std::string text = data.substr(line, eol - line);
            line = eol + 1;
            if (text.find(':') != std::string::npos)
            {
                b.oldEncrypted = b.oldEncrypted || text.find("ENCRYPTED") != std::string::npos;
                continue;
            }
            for (char c : text)
            {
                int v = base64Value(c);
                if (v < 0)
                {
                    continue;                  // '=', spaces, CR
                }
                bits = (bits << 6) | (unsigned)v;
                nbits += 6;
                if (nbits >= 8)
                {
                    nbits -= 8;
                    b.der.push_back((char)((bits >> nbits) & 0xFF));
                }
            }
        }
        blocks.push_back(b);
    }
    return blocks;
}

static bool isCertificateLabel(const std::string &label)
{
    return label == "CERTIFICATE" || label == "X509 CERTIFICATE";
}

// DER: a tag, a length, the contents.
static std::string derTlv(unsigned char tag, const std::string &contents)
{
    std::string out(1, (char)tag);
    size_t n = contents.size();
    if (n < 0x80)
    {
        out.push_back((char)n);
    }
    else
    {
        std::string len;
        for (; n > 0; n >>= 8)
        {
            len.insert(len.begin(), (char)(n & 0xFF));
        }
        out.push_back((char)(0x80 | len.size()));
        out += len;
    }
    return out + contents;
}

// Reads one DER element at p (of what is left, n): its tag, its contents
// (offset and size), and where the next element starts. False if malformed.
static bool derNext(const std::string &d, size_t p, unsigned char &tag, size_t &start, size_t &size, size_t &next)
{
    if (p + 2 > d.size())
    {
        return false;
    }
    tag = (unsigned char)d[p];
    size_t len = (unsigned char)d[p + 1];
    size_t q = p + 2;
    if (len & 0x80)
    {
        size_t k = len & 0x7F;
        if (k == 0 || k > 4 || k > d.size() - q)
        {
            return false;
        }
        len = 0;
        for (size_t i = 0; i < k; i++)
        {
            len = (len << 8) | (unsigned char)d[q + i];
        }
        q += k;
    }
    if (len > d.size() - q)            // (no q + len: it could wrap)
    {
        return false;
    }
    start = q;
    size = len;
    next = q + len;
    return true;
}

static const char OID_RSA[] = "\x2A\x86\x48\x86\xF7\x0D\x01\x01\x01";     // 1.2.840.113549.1.1.1
static const char OID_EC[] = "\x2A\x86\x48\xCE\x3D\x02\x01";             // 1.2.840.10045.2.1

// A key as PKCS#8 (what Windows imports): PKCS#1 (RSA) and SEC1 (EC) keys
// are wrapped in it. False if the key cannot be read.
static bool pkcs8Of(const PemBlock &k, std::string &out)
{
    if (k.label == "PRIVATE KEY" || k.label == "ENCRYPTED PRIVATE KEY")
    {
        out = k.der;
        return true;
    }
    std::string algorithm;
    if (k.label == "RSA PRIVATE KEY")
    {
        algorithm = derTlv(0x06, std::string(OID_RSA, sizeof(OID_RSA) - 1)) + derTlv(0x05, "");
    }
    else
    {
        // SEC1: SEQUENCE { version, privateKey, [0] curve, [1] publicKey };
        // PKCS#8 names the curve in the algorithm.
        unsigned char tag;
        size_t start, size, next;
        if (!derNext(k.der, 0, tag, start, size, next) || tag != 0x30)
        {
            return false;
        }
        size_t p = start, end = start + size;
        std::string curve;
        while (p < end && derNext(k.der, p, tag, start, size, next) && next <= end)
        {
            if (tag == 0xA0)
            {
                curve = k.der.substr(start, size);
            }
            p = next;
        }
        if (curve.empty())
        {
            return false;
        }
        algorithm = derTlv(0x06, std::string(OID_EC, sizeof(OID_EC) - 1)) + curve;
    }
    out = derTlv(0x30, derTlv(0x02, std::string(1, '\0')) + derTlv(0x30, algorithm) + derTlv(0x04, k.der));
    return true;
}

// A PKCS#12 file, imported by Windows, its keys never persisted (in memory
// only); exportable: CNG keys that can be exported (encrypted), for
// Schannel, which needs the key persisted under a name of ours (see
// WinIdentity). Persisting at the import would keep a key without a
// certificate for good, and the import names the keys after the file's
// friendly names (probes/schannel, "keys"). nullptr and why if it cannot be.
static HCERTSTORE importPkcs12(const std::string &data, const char *password, bool exportable, std::string &why)
{
    CRYPT_DATA_BLOB blob = { (DWORD)data.size(), (BYTE *)data.data() };
    DWORD flags = PKCS12_NO_PERSIST_KEY | (exportable ? PKCS12_ALWAYS_CNG_KSP | CRYPT_EXPORTABLE : 0);
    std::wstring pw = wide(password);
    HCERTSTORE store = PFXImportCertStore(&blob, pw.c_str(), flags);
    DWORD err = store == nullptr ? GetLastError() : 0;
    if (store == nullptr && pw.empty())
    {
        // No password: an empty one, or none at all (as OpenSSL tries both).
        store = PFXImportCertStore(&blob, nullptr, flags);
    }
    if (store == nullptr)
    {
        bool wrong = err == ERROR_INVALID_PASSWORD ||
                     (!PFXVerifyPassword(&blob, pw.c_str(), 0) &&
                      (!pw.empty() || !PFXVerifyPassword(&blob, nullptr, 0)));
        why = wrong
              ? "wrong password for the PKCS#12 file"
              : "cannot read the PKCS#12 file: " + secText((SECURITY_STATUS)HRESULT_FROM_WIN32(err));
    }
    return store;
}

static bool hasKey(PCCERT_CONTEXT c)
{
    DWORD n = 0;
    return CertGetCertificateContextProperty(c, CERT_KEY_PROV_INFO_PROP_ID, nullptr, &n) ||
           CertGetCertificateContextProperty(c, CERT_NCRYPT_KEY_HANDLE_PROP_ID, nullptr, &n) ||
           CertGetCertificateContextProperty(c, CERT_KEY_CONTEXT_PROP_ID, nullptr, &n);
}

// The certificates in a file, as DER (a PKCS#12 file's own certificate,
// the one with the key, first). False and why if there are none.
static bool winLoadCertificates(const std::string &data, const char *password, std::vector<std::string> &ders,
                                std::string &why)
{
    // PEM
    if (data.find("-----BEGIN") != std::string::npos)
    {
        for (const PemBlock &b : pemBlocks(data))
        {
            if (isCertificateLabel(b.label))
            {
                PCCERT_CONTEXT c = CertCreateCertificateContext(X509_ASN_ENCODING, (const BYTE *)b.der.data(),
                                                                (DWORD)b.der.size());
                if (c != nullptr)
                {
                    ders.push_back(b.der);
                    CertFreeCertificateContext(c);
                }
            }
        }
        if (ders.empty())
        {
            why = "no certificate in the file";
            return false;
        }
        return true;
    }
    // DER: one certificate
    PCCERT_CONTEXT c = CertCreateCertificateContext(X509_ASN_ENCODING, (const BYTE *)data.data(), (DWORD)data.size());
    if (c != nullptr)
    {
        ders.push_back(data);
        CertFreeCertificateContext(c);
        return true;
    }
    // PKCS#12
    CRYPT_DATA_BLOB blob = { (DWORD)data.size(), (BYTE *)data.data() };
    if (!PFXIsPFXBlob(&blob))
    {
        why = "not a certificate file (PEM, DER or PKCS#12)";
        return false;
    }
    HCERTSTORE store = importPkcs12(data, password, false, why);
    if (store == nullptr)
    {
        return false;
    }
    std::vector<std::string> others;
    PCCERT_CONTEXT x = nullptr;
    while ((x = CertEnumCertificatesInStore(store, x)) != nullptr)
    {
        std::string der((const char *)x->pbCertEncoded, x->cbCertEncoded);
        (hasKey(x) ? ders : others).push_back(der);
    }
    CertCloseStore(store, 0);
    ders.insert(ders.end(), others.begin(), others.end());
    if (ders.empty())
    {
        why = "no certificate in the PKCS#12 file";
        return false;
    }
    return true;
}

// A public key as Windows exports it, without its first field (the
// "magic", which tells ECDSA from ECDH for the same EC key).
static std::string publicBlob(NCRYPT_KEY_HANDLE key)
{
    DWORD n = 0;
    if (NCryptExportKey(key, 0, BCRYPT_PUBLIC_KEY_BLOB, nullptr, nullptr, 0, &n, 0) != ERROR_SUCCESS || n < 4)
    {
        return "";
    }
    std::string b(n, '\0');
    if (NCryptExportKey(key, 0, BCRYPT_PUBLIC_KEY_BLOB, nullptr, (PBYTE)&b[0], n, &n, 0) != ERROR_SUCCESS || n < 4)
    {
        return "";
    }
    return b.substr(4, n - 4);
}

static std::string publicBlob(PCCERT_CONTEXT cert)
{
    BCRYPT_KEY_HANDLE pub = nullptr;
    if (!CryptImportPublicKeyInfoEx2(X509_ASN_ENCODING, &cert->pCertInfo->SubjectPublicKeyInfo, 0, nullptr, &pub))
    {
        return "";
    }
    std::string b;
    ULONG n = 0;
    if (BCryptExportKey(pub, nullptr, BCRYPT_PUBLIC_KEY_BLOB, nullptr, 0, &n, 0) == 0 && n >= 4)
    {
        b.assign(n, '\0');
        if (BCryptExportKey(pub, nullptr, BCRYPT_PUBLIC_KEY_BLOB, (PUCHAR)&b[0], n, &n, 0) == 0 && n >= 4)
        {
            b = b.substr(4, n - 4);
        }
        else
        {
            b.clear();
        }
    }
    BCryptDestroyKey(pub);
    return b;
}

// A server's certificate and its key, as Windows holds them: the
// certificate (in a store with the rest of the chain) with its key. For
// Schannel the key must be persisted (it refuses an ephemeral one:
// probes/schannel); we persist it ourselves, under a name of ours
// (keyName), and delete it again when the WinIdentity goes, as the
// credentials made from it keep working without it.
struct WinIdentity
{
    HCERTSTORE store = nullptr;
    PCCERT_CONTEXT cert = nullptr;
    NCRYPT_KEY_HANDLE key = 0;         // the key, imported by us (persisted: for Schannel)
    bool persisted = false;
    ~WinIdentity()
    {
        if (key != 0)
        {
            if (!persisted || NCryptDeleteKey(key, 0) != ERROR_SUCCESS)
            {
                NCryptFreeObject(key);
            }
        }
        if (cert != nullptr)
        {
            CertFreeCertificateContext(cert);
        }
        if (store != nullptr)
        {
            CertCloseStore(store, 0);
        }
    }
};

static const wchar_t KEY_PREFIX[] = L"oosockets-";

// Random bytes as hex (wide), for a key's name or a password used once.
static std::wstring randomHex(int bytes)
{
    unsigned char rnd[32];
    BCryptGenRandom(nullptr, rnd, (ULONG)bytes, BCRYPT_USE_SYSTEM_PREFERRED_RNG);
    std::wstring s;
    for (int i = 0; i < bytes; i++)
    {
        wchar_t two[3];
        swprintf(two, 3, L"%02x", rnd[i]);
        s += two;
    }
    return s;
}

// The name of a key persisted for Schannel, new each time:
// "oosockets-<process id>-<32 hex>". The process id lets a later process
// tell the keys left by one that died before deleting them (sweepKeys).
static std::wstring keyName()
{
    wchar_t pid[16];
    swprintf(pid, 16, L"%lu", (unsigned long)GetCurrentProcessId());
    return std::wstring(KEY_PREFIX) + pid + L"-" + randomHex(16);
}

// Whether the process id of a key's name is a process that has ended:
// only then is the key nobody's. A process we cannot ask about is alive.
static bool processGone(unsigned long pid)
{
    HANDLE h = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, (DWORD)pid);
    if (h == nullptr)
    {
        return GetLastError() == ERROR_INVALID_PARAMETER;      // no such process
    }
    DWORD code = 0;
    bool gone = GetExitCodeProcess(h, &code) && code != STILL_ACTIVE;
    CloseHandle(h);
    return gone;
}

// Once per process, before the first key is persisted: the keys of ours
// that a process killed between importing a key and deleting it left in
// the user's key store, deleted. Keys of processes still running are
// theirs (their credentials are being made now), and are left alone.
static void sweepKeys()
{
    static std::once_flag once;
    std::call_once(once, []()
    {
        NCRYPT_PROV_HANDLE prov = 0;
        if (NCryptOpenStorageProvider(&prov, MS_KEY_STORAGE_PROVIDER, 0) != ERROR_SUCCESS)
        {
            return;
        }
        std::vector<std::wstring> stale;
        NCryptKeyName *k = nullptr;
        PVOID state = nullptr;
        size_t plen = wcslen(KEY_PREFIX);
        while (NCryptEnumKeys(prov, nullptr, &k, &state, NCRYPT_SILENT_FLAG) == ERROR_SUCCESS)
        {
            const wchar_t *n = k->pszName;
            if (n != nullptr && wcsncmp(n, KEY_PREFIX, plen) == 0)
            {
                const wchar_t *p = n + plen;
                unsigned long long pid = 0;
                int digits = 0;
                while (*p >= L'0' && *p <= L'9' && digits < 10)
                {
                    pid = pid * 10 + (unsigned long long)(*p - L'0');
                    p++;
                    digits++;
                }
                if (digits > 0 && pid <= 0xFFFFFFFFull && *p == L'-' && wcslen(p + 1) == 32 &&
                    pid != GetCurrentProcessId() && processGone((unsigned long)pid))
                {
                    stale.push_back(n);
                }
            }
            NCryptFreeBuffer(k);
            k = nullptr;
        }
        if (state != nullptr)
        {
            NCryptFreeBuffer(state);
        }
        for (const std::wstring &name : stale)
        {
            NCRYPT_KEY_HANDLE key = 0;
            if (NCryptOpenKey(prov, &key, name.c_str(), 0, NCRYPT_SILENT_FLAG) == ERROR_SUCCESS &&
                NCryptDeleteKey(key, 0) != ERROR_SUCCESS)
            {
                NCryptFreeObject(key);
            }
        }
        NCryptFreeObject(prov);
    });
}

// The key in pkcs8 (encrypted with secret, if not nullptr) imported into
// the user's key store, persisted under a new name of ours if persist (for
// Schannel: then sweepKeys first), and made id's certificate's key, once
// it is known to be that certificate's. False and why if it cannot be.
static bool attachKey(WinIdentity &id, const std::string &pkcs8, const wchar_t *secret, bool persist,
                      std::string &why)
{
    if (persist)
    {
        sweepKeys();
    }
    NCRYPT_PROV_HANDLE prov = 0;
    SECURITY_STATUS st = NCryptOpenStorageProvider(&prov, MS_KEY_STORAGE_PROVIDER, 0);
    if (st != ERROR_SUCCESS)
    {
        why = "cannot read the private key: " + secText(st);
        return false;
    }
    std::wstring name = keyName();
    std::wstring pw = secret != nullptr ? secret : L"";
    NCryptBuffer buffers[2];
    ULONG nb = 0;
    if (persist)
    {
        buffers[nb].BufferType = NCRYPTBUFFER_PKCS_KEY_NAME;
        buffers[nb].cbBuffer = (ULONG)((name.size() + 1) * sizeof(wchar_t));
        buffers[nb].pvBuffer = &name[0];
        nb++;
    }
    if (secret != nullptr)
    {
        buffers[nb].BufferType = NCRYPTBUFFER_PKCS_SECRET;
        buffers[nb].cbBuffer = (ULONG)((pw.size() + 1) * sizeof(wchar_t));
        buffers[nb].pvBuffer = &pw[0];
        nb++;
    }
    NCryptBufferDesc desc = { NCRYPTBUFFER_VERSION, nb, buffers };
    st = NCryptImportKey(prov, 0, NCRYPT_PKCS8_PRIVATE_KEY_BLOB, nb > 0 ? &desc : nullptr, &id.key,
                         (PBYTE)pkcs8.data(), (DWORD)pkcs8.size(), persist ? NCRYPT_DO_NOT_FINALIZE_FLAG : 0);
    if (st == ERROR_SUCCESS && persist)
    {
        st = NCryptFinalizeKey(id.key, 0);
    }
    NCryptFreeObject(prov);
    if (st != ERROR_SUCCESS)
    {
        if (id.key != 0)
        {
            NCryptFreeObject(id.key);      // not finalized: nothing was persisted
            id.key = 0;
        }
        why = "cannot read the private key: " + secText(st);
        return false;
    }
    std::string mine = publicBlob(id.key);
    if (mine.empty() || mine != publicBlob(id.cert))
    {
        why = "the private key is not the certificate's";
        return false;
    }
    if (persist)
    {
        CRYPT_KEY_PROV_INFO info;
        memset(&info, 0, sizeof(info));
        info.pwszContainerName = &name[0];
        info.pwszProvName = (LPWSTR)MS_KEY_STORAGE_PROVIDER;
        if (!CertSetCertificateContextProperty(id.cert, CERT_KEY_PROV_INFO_PROP_ID, 0, &info))
        {
            why = "Windows cannot use the private key: " +
                  secText((SECURITY_STATUS)HRESULT_FROM_WIN32(GetLastError()));
            return false;
        }
    }
    return true;
}

// The private key of a certificate imported from a PKCS#12 file (in memory,
// exportable), exported as PKCS#8 encrypted with secret: Windows exports
// such a key only encrypted (probes/schannel, "keys"). False and why if it
// cannot be.
static bool exportKey(PCCERT_CONTEXT c, const std::wstring &secret, std::string &out, std::string &why)
{
    HCRYPTPROV_OR_NCRYPT_KEY_HANDLE k = 0;
    DWORD spec = 0;
    BOOL mustFree = FALSE;
    if (!CryptAcquireCertificatePrivateKey(c, CRYPT_ACQUIRE_SILENT_FLAG | CRYPT_ACQUIRE_ONLY_NCRYPT_KEY_FLAG |
                                           CRYPT_ACQUIRE_CACHE_FLAG, nullptr, &k, &spec, &mustFree))
    {
        why = "cannot read the private key: " + secText((SECURITY_STATUS)HRESULT_FROM_WIN32(GetLastError()));
        return false;
    }
    // PKCS#12's own password-based encryption, as Windows' PKCS#8 export takes it
    unsigned char params[sizeof(CRYPT_PKCS12_PBE_PARAMS) + 16];
    CRYPT_PKCS12_PBE_PARAMS *pbe = (CRYPT_PKCS12_PBE_PARAMS *)params;
    pbe->iIterations = 2048;
    pbe->cbSalt = 16;
    BCryptGenRandom(nullptr, params + sizeof(CRYPT_PKCS12_PBE_PARAMS), 16, BCRYPT_USE_SYSTEM_PREFERRED_RNG);
    char oid[] = szOID_PKCS_12_pbeWithSHA1And3KeyTripleDES;
    std::wstring pw = secret;
    NCryptBuffer b[3];
    b[0].BufferType = NCRYPTBUFFER_PKCS_SECRET;
    b[0].cbBuffer = (ULONG)((pw.size() + 1) * sizeof(wchar_t));
    b[0].pvBuffer = &pw[0];
    b[1].BufferType = NCRYPTBUFFER_PKCS_ALG_OID;
    b[1].cbBuffer = (ULONG)sizeof(oid);
    b[1].pvBuffer = oid;
    b[2].BufferType = NCRYPTBUFFER_PKCS_ALG_PARAM;
    b[2].cbBuffer = (ULONG)sizeof(params);
    b[2].pvBuffer = params;
    NCryptBufferDesc desc = { NCRYPTBUFFER_VERSION, 3, b };
    NCRYPT_KEY_HANDLE key = (NCRYPT_KEY_HANDLE)k;
    DWORD n = 0;
    SECURITY_STATUS st = NCryptExportKey(key, 0, NCRYPT_PKCS8_PRIVATE_KEY_BLOB, &desc, nullptr, 0, &n, 0);
    if (st == ERROR_SUCCESS)
    {
        out.assign(n, '\0');
        st = NCryptExportKey(key, 0, NCRYPT_PKCS8_PRIVATE_KEY_BLOB, &desc, (PBYTE)&out[0], n, &n, 0);
        out.resize(st == ERROR_SUCCESS ? n : 0);
    }
    if (mustFree)
    {
        NCryptFreeObject(key);
    }
    if (st != ERROR_SUCCESS)
    {
        why = "cannot read the private key: " + secText(st);
        return false;
    }
    return true;
}

// The certificate and key in a file (PKCS#12 with its password, or PEM
// with both), read by Windows; persist: for Schannel. False and why if
// they cannot be used.
static bool winIdentity(const std::string &data, const char *password, bool persist, WinIdentity &id, std::string &why)
{
    id.persisted = persist;
    if (data.find("-----BEGIN") == std::string::npos)
    {
        CRYPT_DATA_BLOB blob = { (DWORD)data.size(), (BYTE *)data.data() };
        PCCERT_CONTEXT c = CertCreateCertificateContext(X509_ASN_ENCODING, (const BYTE *)data.data(), (DWORD)data.size());
        if (c != nullptr)
        {
            CertFreeCertificateContext(c);
            why = "no private key in the file";
            return false;
        }
        if (!PFXIsPFXBlob(&blob))
        {
            why = "not a certificate file (PEM, DER or PKCS#12)";
            return false;
        }
        HCERTSTORE p12 = importPkcs12(data, password, persist, why);
        if (p12 == nullptr)
        {
            return false;
        }
        bool any = false;
        PCCERT_CONTEXT leaf = nullptr;
        PCCERT_CONTEXT x = nullptr;
        while ((x = CertEnumCertificatesInStore(p12, x)) != nullptr)
        {
            any = true;
            if (hasKey(x))
            {
                leaf = CertDuplicateCertificateContext(x);
                CertFreeCertificateContext(x);
                break;
            }
        }
        if (leaf == nullptr)
        {
            CertCloseStore(p12, 0);
            why = any ? "no private key in the file" : "no certificate in the PKCS#12 file";
            return false;
        }
        if (!persist)
        {
            id.store = p12;                     // the key in memory: enough to check it
            id.cert = leaf;
            return true;
        }
        // For Schannel: the key, exported (encrypted with a password used
        // once), persisted under our name; the certificates copied to a store
        // of ours, as for PEM. The file's own keys go with its store.
        std::wstring secret = randomHex(16);
        std::string pkcs8;
        bool ok = exportKey(leaf, secret, pkcs8, why);
        if (ok)
        {
            id.store = CertOpenStore(CERT_STORE_PROV_MEMORY, 0, 0, 0, nullptr);
            CertAddEncodedCertificateToStore(id.store, X509_ASN_ENCODING, leaf->pbCertEncoded, leaf->cbCertEncoded,
                                             CERT_STORE_ADD_ALWAYS, &id.cert);
            x = nullptr;                        // (freed above: a new enumeration, from the start)
            while ((x = CertEnumCertificatesInStore(p12, x)) != nullptr)
            {
                if (!CertCompareCertificate(X509_ASN_ENCODING, x->pCertInfo, leaf->pCertInfo))
                {
                    CertAddEncodedCertificateToStore(id.store, X509_ASN_ENCODING, x->pbCertEncoded, x->cbCertEncoded,
                                                     CERT_STORE_ADD_ALWAYS, nullptr);
                }
            }
            if (id.cert == nullptr)
            {
                why = "Windows cannot use the certificate";
                ok = false;
            }
        }
        CertFreeCertificateContext(leaf);
        CertCloseStore(p12, 0);
        return ok && attachKey(id, pkcs8, secret.c_str(), true, why);
    }
    // PEM: the first certificate is the server's, the others its chain;
    // the first key is its key.
    std::vector<PemBlock> blocks = pemBlocks(data);
    id.store = CertOpenStore(CERT_STORE_PROV_MEMORY, 0, 0, 0, nullptr);
    const PemBlock *keyBlock = nullptr;
    for (const PemBlock &b : blocks)
    {
        if (isCertificateLabel(b.label))
        {
            PCCERT_CONTEXT c = nullptr;
            if (CertAddEncodedCertificateToStore(id.store, X509_ASN_ENCODING, (const BYTE *)b.der.data(),
                                                 (DWORD)b.der.size(), CERT_STORE_ADD_ALWAYS,
                                                 id.cert == nullptr ? &c : nullptr) && c != nullptr)
            {
                id.cert = c;
            }
        }
        else if (keyBlock == nullptr && (b.label == "PRIVATE KEY" || b.label == "ENCRYPTED PRIVATE KEY" ||
                                         b.label == "RSA PRIVATE KEY" || b.label == "EC PRIVATE KEY"))
        {
            keyBlock = &b;
        }
    }
    if (id.cert == nullptr)
    {
        why = "no certificate in the file";
        return false;
    }
    if (keyBlock == nullptr)
    {
        why = "no private key in the file";
        return false;
    }
    std::string pkcs8;
    if (keyBlock->oldEncrypted)
    {
        why = "cannot read the private key: encrypted in OpenSSL's old way"
              " (make it PKCS#8, \"openssl pkcs8 -topk8\", or PKCS#12)";
        return false;
    }
    if (!pkcs8Of(*keyBlock, pkcs8))
    {
        why = "cannot read the private key";
        return false;
    }
    std::wstring pw = wide(password);
    return attachKey(id, pkcs8, keyBlock->label == "ENCRYPTED PRIVATE KEY" ? pw.c_str() : nullptr, persist, why);
}

// A server's credentials, from the certificate and key in file (PKCS#12
// with its password, or PEM with both), read by Windows.
static bool schServerCredentials(const char *file, const char *password, const char *minVersion,
                                 std::shared_ptr<SchCred> &out, std::string &why)
{
    std::string data;
    if (!readFile(file, data, why))
    {
        return false;
    }
    WinIdentity id;
    if (!winIdentity(data, password, true, id, why))
    {
        return false;
    }
    DWORD enabled = SP_PROT_TLS1_3_SERVER | (strcmp(minVersion, "1.3") == 0 ? 0 : SP_PROT_TLS1_2_SERVER);
    SECURITY_STATUS st = schCredentials(SECPKG_CRED_INBOUND, SCH_USE_STRONG_CRYPTO | SCH_CRED_DISABLE_RECONNECTS,
                                        enabled, id.cert, out);
    if (st != SEC_E_OK)
    {
        why = "Schannel cannot use it: " + secText(st);
        return false;
    }
    return true;                       // the key is deleted with id
}

// TLSOptions~certificate's check, by Windows: the file has a certificate and
// its key (nothing persisted).
static bool winCheckIdentity(const char *file, const char *password, std::string &why)
{
    std::string data;
    WinIdentity id;
    return readFile(file, data, why) && winIdentity(data, password, false, id, why);
}

// A Sch for the server's side of a connection.
static Sch *schServer(const std::shared_ptr<SchCred> &cred)
{
    Sch *c = new Sch();
    c->server = true;
    c->cred = cred;
    return c;
}

#endif

// Whether TLS has started on the Sock (OpenSSL's or Schannel's).
static bool isTls(Sock *s)
{
    std::lock_guard<std::mutex> guard(s->mu);
#ifdef _WIN32
    if (s->sch != nullptr)
    {
        return true;
    }
#endif
    return s->ssl != nullptr;
}

// Puts the Sock in TLS: a new SSL over our BIO. False (and ctx freed) if
// TLS has started on it meanwhile: two startTLS at once, which sockets.cls's
// guarded methods prevent, cannot both attach (checked under the lock).
static bool attachSsl(Sock *s, SSL_CTX *ctx)
{
    std::lock_guard<std::mutex> guard(s->mu);
#ifdef _WIN32
    if (s->sch != nullptr)
    {
        SSL_CTX_free(ctx);
        return false;
    }
#endif
    if (s->ssl != nullptr)
    {
        SSL_CTX_free(ctx);
        return false;
    }
    s->ctx = ctx;
    s->ssl = SSL_new(ctx);
    BIO *bio = BIO_new(sockBioMethod());
    BIO_set_data(bio, s);
    SSL_set_bio(s->ssl, bio, bio);
    SSL_set_app_data(s->ssl, static_cast<PeerCheck *>(s));
    setBlocking(s->fd, false);
    return true;
}

// A client's context: trusted, an array of DER certificates (only these,
// and the host name: OpenSSL decides); empty, the system decides.
static SSL_CTX *clientContext(RexxMethodContext *context, const SSL_METHOD *method, int minProto,
                              RexxArrayObject trusted)
{
    SSL_CTX *ctx = SSL_CTX_new(method);
    SSL_CTX_set_min_proto_version(ctx, minProto);
#ifdef SSL_OP_IGNORE_UNEXPECTED_EOF
    SSL_CTX_set_options(ctx, SSL_OP_IGNORE_UNEXPECTED_EOF);
#endif
    SSL_CTX_set_mode(ctx, SSL_MODE_ENABLE_PARTIAL_WRITE | SSL_MODE_ACCEPT_MOVING_WRITE_BUFFER);
    size_t count = context->ArrayItems(trusted);
    if (count > 0)
    {
        // Only these, and the host name: OpenSSL decides. A certificate
        // that is not a root (a server's own) may be one of them.
        X509_STORE *store = SSL_CTX_get_cert_store(ctx);
        for (size_t i = 1; i <= count; i++)
        {
            RexxObjectPtr item = context->ArrayAt(trusted, i);
            if (item == NULLOBJECT)
            {
                continue;
            }
            RexxStringObject der = context->ObjectToString(item);
            const unsigned char *p = (const unsigned char *)context->StringData(der);
            X509 *x = d2i_X509(nullptr, &p, (long)context->StringLength(der));
            if (x != nullptr)
            {
                X509_STORE_add_cert(store, x);
                X509_free(x);
            }
        }
        X509_STORE_set_flags(store, X509_V_FLAG_PARTIAL_CHAIN);
    }
    else
    {
#if defined(__APPLE__) || defined(_WIN32)
        SSL_CTX_set_cert_verify_callback(ctx, systemVerify, nullptr);
#else
        SSL_CTX_set_default_verify_paths(ctx);
#endif
    }
    SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, nullptr);

    return ctx;
}

// The name the server's certificate must have (and SNI, for a name).
static void setPeerName(SSL *ssl, const std::string &h)
{
    if (isAddress(h))
    {
        X509_VERIFY_PARAM_set1_ip_asc(SSL_get0_param(ssl), h.substr(0, h.find('%')).c_str());
    }
    else
    {
        SSL_set_tlsext_host_name(ssl, h.c_str());   // SNI
        SSL_set1_host(ssl, h.c_str());
    }
}

// nStartTLS(host, trusted, minVersion, timeout): the client's handshake.
// trusted: an array of DER certificates; empty, the system decides.
// "OK"; "TIMEOUT"; or "ERROR", text, name, number.
RexxMethod5(RexxArrayObject, socket_starttls, CSELF, cself, CSTRING, host, RexxArrayObject, trusted,
            CSTRING, minVersion, double, timeout)
{
    Sock *s = (Sock *)cself;
    if (s == nullptr || s->fd == BAD_SOCKET)
    {
        return closedResult(context);
    }
    if (isTls(s))
    {
        return errorArray(context, "TLS has already started on this connection", "", 0);
    }
#ifdef _WIN32
    if (useSchannel())
    {
        return schStartClient(context, s, host, trusted, minVersion, timeout);
    }
#endif
    if (!opensslHere())
    {
        return opensslMissing(context);
    }
    SSL_CTX *ctx = clientContext(context, TLS_client_method(), minVersionOf(minVersion), trusted);
    if (!attachSsl(s, ctx))
    {
        return errorArray(context, "TLS has already started on this connection", "", 0);
    }
    {
        std::lock_guard<std::mutex> guard(s->mu);
        s->host = host;
        s->trust = TrustError();
        setPeerName(s->ssl, s->host);
    }
    SSL_set_connect_state(s->ssl);
    return handshakeStep(context, s, timeout);
}

// nTLSMore(timeout): goes on with a handshake that returned "AGAIN".
RexxMethod2(RexxArrayObject, socket_tls_more, CSELF, cself, double, timeout)
{
    Sock *s = (Sock *)cself;
#ifdef _WIN32
    if (s != nullptr && s->fd != BAD_SOCKET && s->sch != nullptr)
    {
        return schHandshakeStep(context, s, timeout);
    }
#endif
    if (s == nullptr || s->fd == BAD_SOCKET || s->ssl == nullptr)
    {
        return closedResult(context);
    }
    return handshakeStep(context, s, timeout);
}

// A server's TLS context, with the certificate and key in file (PKCS#12
// with its password, or PEM with both); nullptr and why if it cannot be.
static SSL_CTX *serverContext(const char *file, const char *password, const SSL_METHOD *method, int minProto,
                              std::string &why)
{
    std::string data;
    std::vector<X509 *> certs;
    EVP_PKEY *key = nullptr;
    if (!readFile(file, data, why) || !loadCertificates(data, password, certs, &key, why))
    {
        for (X509 *x : certs)
        {
            X509_free(x);
        }
        return nullptr;
    }
    if (key == nullptr)
    {
        for (X509 *x : certs)
        {
            X509_free(x);
        }
        why = "no private key in the file";
        return nullptr;
    }
    SSL_CTX *ctx = SSL_CTX_new(method);
    SSL_CTX_set_min_proto_version(ctx, minProto);
#ifdef SSL_OP_IGNORE_UNEXPECTED_EOF
    SSL_CTX_set_options(ctx, SSL_OP_IGNORE_UNEXPECTED_EOF);
#endif
    SSL_CTX_set_mode(ctx, SSL_MODE_ENABLE_PARTIAL_WRITE | SSL_MODE_ACCEPT_MOVING_WRITE_BUFFER);
    // No session resumption here, so no TLS 1.3 tickets: a client that
    // never reads them would close with a reset.
    SSL_CTX_set_num_tickets(ctx, 0);
    ERR_clear_error();
    bool ok = SSL_CTX_use_certificate(ctx, certs[0]) == 1 && SSL_CTX_use_PrivateKey(ctx, key) == 1
              && SSL_CTX_check_private_key(ctx) == 1;
    unsigned long e = ERR_peek_last_error();
    for (size_t i = 1; ok && i < certs.size(); i++)
    {
        SSL_CTX_add_extra_chain_cert(ctx, certs[i]);   // takes it
        certs[i] = nullptr;
    }
    ERR_clear_error();
    for (X509 *x : certs)
    {
        X509_free(x);
    }
    EVP_PKEY_free(key);
    if (!ok)
    {
        SSL_CTX_free(ctx);
        why = ERR_GET_REASON(e) == X509_R_KEY_VALUES_MISMATCH
              ? "the private key is not the certificate's"
              : sslReason(e);
        return nullptr;
    }
    return ctx;
}

// TLSOptions~nCheckIdentity(file, password): "OK" if the file has a
// certificate and its key; else "ERROR", why. On Windows with Schannel,
// read by Windows.
RexxMethod2(RexxArrayObject, tls_check_identity, CSTRING, file, CSTRING, password)
{
#ifdef _WIN32
    if (useSchannel())
    {
        std::string why;
        if (!winCheckIdentity(file, password, why))
        {
            return errorArray(context, why, "", 0);
        }
        return statusResult(context, "OK");
    }
#endif
    if (!opensslHere())
    {
        return opensslMissing(context);
    }
    std::string why;
    SSL_CTX *ctx = serverContext(file, password, TLS_server_method(), TLS1_2_VERSION, why);
    if (ctx == nullptr)
    {
        return errorArray(context, why, "", 0);
    }
    SSL_CTX_free(ctx);
    return statusResult(context, "OK");
}

// nStartTLSServer(file, password, minVersion, timeout): the server's
// handshake on a connected socket (STARTTLS, server side), now.
RexxMethod5(RexxArrayObject, socket_starttls_server, CSELF, cself, CSTRING, file,
            CSTRING, password, CSTRING, minVersion, double, timeout)
{
    Sock *s = (Sock *)cself;
    if (s == nullptr || s->fd == BAD_SOCKET)
    {
        return closedResult(context);
    }
    if (isTls(s))
    {
        return errorArray(context, "TLS has already started on this connection", "", 0);
    }
    std::string why;
#ifdef _WIN32
    if (useSchannel())
    {
        std::shared_ptr<SchCred> cred;
        if (!schServerCredentials(file, password, minVersion, cred, why))
        {
            return errorArray(context, "cannot use " + std::string(file) + ": " + why, "", 0);
        }
        {
            std::lock_guard<std::mutex> guard(s->mu);
            if (s->sch != nullptr || s->ssl != nullptr)
            {
                return errorArray(context, "TLS has already started on this connection", "", 0);
            }
            s->trust = TrustError();
            s->sch = schServer(cred);
            setBlocking(s->fd, false);
        }
        return schHandshakeStep(context, s, timeout);
    }
#endif
    if (!opensslHere())
    {
        return opensslMissing(context);
    }
    SSL_CTX *ctx = serverContext(file, password, TLS_server_method(), minVersionOf(minVersion), why);
    if (ctx == nullptr)
    {
        return errorArray(context, "cannot use " + std::string(file) + ": " + why, "", 0);
    }
    if (!attachSsl(s, ctx))
    {
        return errorArray(context, "TLS has already started on this connection", "", 0);
    }
    s->trust = TrustError();
    SSL_set_accept_state(s->ssl);
    return handshakeStep(context, s, timeout);
}

// TLSServerSocket's nTLS(file, password, minVersion): the context every
// accepted connection will share. "OK"; or "ERROR", why.
RexxMethod4(RexxArrayObject, server_tls, CSELF, cself, CSTRING, file, CSTRING, password, CSTRING, minVersion)
{
    Sock *s = (Sock *)cself;
    if (s == nullptr || s->fd == BAD_SOCKET)
    {
        return closedResult(context);
    }
    std::string why;
#ifdef _WIN32
    if (useSchannel())
    {
        std::shared_ptr<SchCred> cred;
        if (!schServerCredentials(file, password, minVersion, cred, why))
        {
            return errorArray(context, "cannot use " + std::string(file) + ": " + why, "", 0);
        }
        std::lock_guard<std::mutex> guard(s->mu);
        s->schCred = cred;
        if (s->ctx != nullptr)
        {
            SSL_CTX_free(s->ctx);          // (an earlier call with OOSOCKETS_TLS=openssl)
            s->ctx = nullptr;
        }
        return statusResult(context, "OK");
    }
#endif
    if (!opensslHere())
    {
        return opensslMissing(context);
    }
    SSL_CTX *ctx = serverContext(file, password, TLS_server_method(), minVersionOf(minVersion), why);
    if (ctx == nullptr)
    {
        return errorArray(context, "cannot use " + std::string(file) + ": " + why, "", 0);
    }
    std::lock_guard<std::mutex> guard(s->mu);
    if (s->ctx != nullptr)
    {
        SSL_CTX_free(s->ctx);
    }
    s->ctx = ctx;
#ifdef _WIN32
    s->schCred.reset();                // (an earlier call with Schannel)
#endif
    return statusResult(context, "OK");
}

// nTLSInfo: "OK", protocol ("TLSv1.3"), cipher, 1 if TLS is on (else 0).
// Protocol and cipher are "" until the handshake has finished.
RexxMethod1(RexxArrayObject, socket_tlsinfo, CSELF, cself)
{
    Sock *s = (Sock *)cself;
    std::string protocol, cipher;
    bool on = false;
    if (s != nullptr)
    {
        std::lock_guard<std::mutex> guard(s->mu);
#ifdef _WIN32
        if (s->sch != nullptr)
        {
            on = true;
            schInfo(s->sch, protocol, cipher);
        }
#endif
        on = on || s->ssl != nullptr;
        if (s->ssl != nullptr && SSL_is_init_finished(s->ssl))
        {
            protocol = SSL_get_version(s->ssl);
            const char *c = SSL_get_cipher_name(s->ssl);
            cipher = c != nullptr ? c : "";
        }
    }
    RexxArrayObject r = context->NewArray(4);
    context->ArrayAppendString(r, "OK", 2);
    context->ArrayAppendString(r, protocol.c_str(), protocol.size());
    context->ArrayAppendString(r, cipher.c_str(), cipher.size());
    context->ArrayAppend(r, context->WholeNumber(on ? 1 : 0));
    return r;
}


static RexxArrayObject tlsRecv(RexxMethodContext *context, Sock *s, size_t max, double timeout)
{
#ifdef _WIN32
    if (s->sch != nullptr)
    {
        return schRecvResult(context, s, max, timeout);
    }
#endif
    std::vector<char> buf(max);
    size_t got = 0;
    bool hasDeadline = timeout >= 0;
    Clock::time_point deadline = deadlineFrom(hasDeadline ? timeout : 0);
    TlsOutcome o = tlsRun(s, hasDeadline, deadline,
                          [&](SSL *ssl) { return SSL_read_ex(ssl, buf.data(), max, &got); });
    if (o.status == TLS_OK)
    {
        return statusResult(context, "OK", context->NewString(buf.data(), got));
    }
    if (o.status == TLS_AGAIN)
    {
        return statusResult(context, "AGAIN", context->DoubleToObject(secondsLeft(hasDeadline, deadline)));
    }
    return tlsIoResult(context, o);
}

static RexxArrayObject tlsSend(RexxMethodContext *context, Sock *s, const char *p, size_t left, double timeout)
{
#ifdef _WIN32
    if (s->sch != nullptr)
    {
        return schSendResult(context, s, p, left, timeout);
    }
#endif
    size_t sent = 0;
    bool hasDeadline = timeout >= 0;
    Clock::time_point deadline = deadlineFrom(hasDeadline ? timeout : 0);
    while (left > 0)
    {
        size_t n = 0;
        TlsOutcome o = tlsRun(s, hasDeadline, deadline,
                              [&](SSL *ssl) { return SSL_write_ex(ssl, p + sent, left, &n); });
        if (o.status == TLS_TIMEOUT)
        {
            return statusResult(context, "TIMEOUT", context->StringSize(sent));
        }
        if (o.status == TLS_AGAIN)
        {
            return againSent(context, sent, secondsLeft(hasDeadline, deadline));
        }
        if (o.status == TLS_EOF)
        {
            o.status = TLS_SOCKET_ERROR;
#ifdef _WIN32
            o.socketError = WSAECONNRESET;
#else
            o.socketError = EPIPE;
#endif
        }
        if (o.status != TLS_OK)
        {
            return tlsIoResult(context, o);
        }
        sent += n;
        left -= n;
    }
    return statusResult(context, "OK", context->StringSize(sent));
}


/*----------------------------------------------------------------------------*/
/* Socket                                                                     */
/*----------------------------------------------------------------------------*/

// One step of a connect: tries the addresses in turn, waiting SLICE_MS at
// most. "OK" (the Sock has its socket), "AGAIN" and the seconds left,
// "TIMEOUT", or the last address's error.
static RexxArrayObject connectStep(RexxMethodContext *context, Sock *s, double timeout)
{
    bool hasDeadline = timeout >= 0;
    Clock::time_point deadline = deadlineFrom(hasDeadline ? timeout : 0);
    for (;;)
    {
        if (s->trying == BAD_SOCKET)
        {
            if (s->nextAddr >= s->addrs.size())
            {
                return errorResult(context, s->connectErr);
            }
            size_t i = s->nextAddr++;
            const struct sockaddr *sa = (const struct sockaddr *)&s->addrs[i];
            sock_t fd = socket(sa->sa_family, SOCK_STREAM, IPPROTO_TCP);
            if (fd == BAD_SOCKET)
            {
                s->connectErr = lastError();
                continue;
            }
            prepareSocket(fd);
            setBlocking(fd, false);
            if (connect(fd, sa, s->addrLens[i]) == 0)
            {
                s->fd = fd;
                return statusResult(context, "OK");
            }
            int e = lastError();
            if (!inProgress(e))
            {
                s->connectErr = e;
                closesock(fd);
                continue;
            }
            s->trying = fd;
        }
        int err = 0;
        int w = waitSlice(s->trying, POLLOUT, hasDeadline, deadline, &err);
        if (w == 2)
        {
            return statusResult(context, "AGAIN", context->DoubleToObject(secondsLeft(hasDeadline, deadline)));
        }
        if (w == 0)
        {
            closesock(s->trying);
            s->trying = BAD_SOCKET;
            return statusResult(context, "TIMEOUT");   // the deadline is for the whole connect
        }
        if (w > 0)
        {
            int soerr = 0;
            socklen_type len = sizeof(soerr);
            getsockopt(s->trying, SOL_SOCKET, SO_ERROR, (char *)&soerr, &len);
            err = soerr;
        }
        if (err == 0)
        {
            s->fd = s->trying;
            s->trying = BAD_SOCKET;
            return statusResult(context, "OK");
        }
        s->connectErr = err;
        closesock(s->trying);
        s->trying = BAD_SOCKET;
    }
}

// nConnect(host, port, timeout): timeout < 0 means none (the system's).
// The Sock is made at once, without a socket; see connectStep.
RexxMethod3(RexxArrayObject, socket_connect, CSTRING, host, CSTRING, port, double, timeout)
{
    struct addrinfo hints;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_protocol = IPPROTO_TCP;
    hints.ai_flags = AI_ADDRCONFIG;

    struct addrinfo *list = nullptr;
    int rc = getaddrinfo(host, port, &hints, &list);
    if (rc == EAI_NONAME || rc == EAI_AGAIN || rc == EAI_FAIL
#ifdef EAI_ADDRFAMILY
        || rc == EAI_ADDRFAMILY
#endif
       )
    {
        // AI_ADDRCONFIG hides loopback addresses on a machine with no other
        // address of that family; try again without it.
        hints.ai_flags = 0;
        int rc2 = getaddrinfo(host, port, &hints, &list);
        if (rc2 == 0)
        {
            rc = 0;
        }
    }
    if (rc != 0)
    {
        return gaiErrorResult(context, rc);
    }
    Sock *s = new Sock(BAD_SOCKET);
    for (struct addrinfo *ai = list; ai != nullptr; ai = ai->ai_next)
    {
        struct sockaddr_storage ss;
        memset(&ss, 0, sizeof(ss));
        memcpy(&ss, ai->ai_addr, ai->ai_addrlen);
        s->addrs.push_back(ss);
        s->addrLens.push_back((socklen_type)ai->ai_addrlen);
    }
    freeaddrinfo(list);
    setCself(context, s);
    return connectStep(context, s, timeout);
}

// nConnectMore(timeout): goes on with a connect that returned "AGAIN".
RexxMethod2(RexxArrayObject, socket_connect_more, CSELF, cself, double, timeout)
{
    Sock *s = (Sock *)cself;
    if (s == nullptr)
    {
        return closedResult(context);
    }
    return connectStep(context, s, timeout);
}

// nAdopt(pointer): a socket that ServerSocket~accept made.
RexxMethod1(RexxObjectPtr, socket_adopt, POINTER, p)
{
    setCself(context, (Sock *)p);
    return NULLOBJECT;
}

// nRecv(max, timeout): up to max bytes, waiting at most timeout seconds
// (< 0: as long as it takes; 0: only what is already there); "AGAIN" and
// the seconds left after SLICE_MS.
RexxMethod3(RexxArrayObject, socket_recv, CSELF, cself, size_t, max, double, timeout)
{
    Sock *s = (Sock *)cself;
    if (s == nullptr || s->fd == BAD_SOCKET)
    {
        return closedResult(context);
    }
    if (max == 0)
    {
        max = 1;
    }
    if (isTls(s))
    {
        return tlsRecv(context, s, max, timeout);
    }
    bool hasDeadline = timeout >= 0;
    Clock::time_point deadline = deadlineFrom(hasDeadline ? timeout : 0);
    std::vector<char> buf(max);
    for (;;)
    {
        sock_t fd = s->fd;
        if (fd == BAD_SOCKET)
        {
            return closedResult(context);
        }
        long n = (long)recv(fd, buf.data(), (int)max, 0);
        if (n > 0)
        {
            return statusResult(context, "OK", context->NewString(buf.data(), (size_t)n));
        }
        if (n == 0)
        {
            return statusResult(context, "EOF");
        }
        int e = lastError();
        if (interrupted(e))
        {
            continue;
        }
        if (!wouldBlock(e))
        {
            return errorResult(context, e);
        }
        int err = 0;
        int w = waitSlice(fd, POLLIN, hasDeadline, deadline, &err);
        if (w == 0)
        {
            return statusResult(context, "TIMEOUT");
        }
        if (w == 2)
        {
            return statusResult(context, "AGAIN", context->DoubleToObject(secondsLeft(hasDeadline, deadline)));
        }
        if (w < 0)
        {
            return errorResult(context, err);
        }
    }
}

// nSend(data, timeout): all of data, or an error / timeout. The result
// has, after the status, how many bytes went out; "AGAIN", those, and the
// seconds left after SLICE_MS (to be called again with the rest).
RexxMethod3(RexxArrayObject, socket_send, CSELF, cself, RexxStringObject, data, double, timeout)
{
    Sock *s = (Sock *)cself;
    if (s == nullptr || s->fd == BAD_SOCKET)
    {
        return closedResult(context);
    }
    const char *p = context->StringData(data);
    size_t left = context->StringLength(data);
    if (isTls(s))
    {
        return tlsSend(context, s, p, left, timeout);
    }
    size_t sent = 0;
    bool hasDeadline = timeout >= 0;
    Clock::time_point deadline = deadlineFrom(hasDeadline ? timeout : 0);
    while (left > 0)
    {
        sock_t fd = s->fd;
        if (fd == BAD_SOCKET)
        {
            return closedResult(context);
        }
        int chunk = left > 0x40000000 ? 0x40000000 : (int)left;
        long n = (long)send(fd, p + sent, chunk, SEND_FLAGS);
        if (n >= 0)
        {
            sent += (size_t)n;
            left -= (size_t)n;
            continue;
        }
        int e = lastError();
        if (interrupted(e))
        {
            continue;
        }
        if (!wouldBlock(e))
        {
            return errorResult(context, e);
        }
        int err = 0;
        int w = waitSlice(fd, POLLOUT, hasDeadline, deadline, &err);
        if (w == 0)
        {
            return statusResult(context, "TIMEOUT", context->StringSize(sent));
        }
        if (w == 2)
        {
            return againSent(context, sent, secondsLeft(hasDeadline, deadline));
        }
        if (w < 0)
        {
            return errorResult(context, err);
        }
    }
    return statusResult(context, "OK", context->StringSize(sent));
}

// nNoDelay(value): TCP_NODELAY. value 1 or 0 sets it, -1 only asks.
// Returns "OK", 1 or 0 (the option as it is now).
RexxMethod2(RexxArrayObject, socket_nodelay, CSELF, cself, int, value)
{
    Sock *s = (Sock *)cself;
    if (s == nullptr || s->fd == BAD_SOCKET)
    {
        return closedResult(context);
    }
    if (value >= 0)
    {
        int flag = value ? 1 : 0;
        if (setsockopt(s->fd, IPPROTO_TCP, TCP_NODELAY, (const char *)&flag, sizeof(flag)) != 0)
        {
            return errorResult(context, lastError());
        }
    }
    int flag = 0;
    socklen_type len = sizeof(flag);
    if (getsockopt(s->fd, IPPROTO_TCP, TCP_NODELAY, (char *)&flag, &len) != 0)
    {
        return errorResult(context, lastError());
    }
    return statusResult(context, "OK", context->WholeNumber(flag ? 1 : 0));
}

// nShutdown: no more output (the peer reads end of stream).
RexxMethod1(RexxArrayObject, socket_shutdown, CSELF, cself)
{
    Sock *s = (Sock *)cself;
    if (s == nullptr || s->fd == BAD_SOCKET)
    {
        return closedResult(context);
    }
    if (isTls(s))
    {
        // close_notify first: the peer reads the end of the stream from TLS.
        std::lock_guard<std::mutex> guard(s->mu);
#ifdef _WIN32
        if (s->sch != nullptr)
        {
            schSayGoodbye(s, s->sch);
        }
        else
#endif
        {
            ERR_clear_error();
            SSL_shutdown(s->ssl);
            ERR_clear_error();
        }
    }
#ifdef _WIN32
    int rc = shutdown(s->fd, SD_SEND);
    {
        std::lock_guard<std::mutex> guard(s->mu);
        if (s->sch != nullptr)
        {
            s->sch->out.clear();         // nothing more can go: reading must not try
        }
    }
#else
    int rc = shutdown(s->fd, SHUT_WR);
#endif
    if (rc != 0)
    {
        return errorResult(context, lastError());
    }
    return statusResult(context, "OK");
}

// nClose: shared by Socket and ServerSocket. Closing twice is harmless.
RexxMethod1(RexxObjectPtr, sock_close, CSELF, cself)
{
    (void)context;
    closeSock((Sock *)cself);
    return NULLOBJECT;
}

// uninit: close, and free the Sock.
RexxMethod1(RexxObjectPtr, sock_free, CSELF, cself)
{
    Sock *s = (Sock *)cself;
    if (s != nullptr)
    {
        closeSock(s);
        if (s->ssl != nullptr)
        {
            SSL_free(s->ssl);
        }
        if (s->ctx != nullptr)
        {
            SSL_CTX_free(s->ctx);
        }
#ifdef _WIN32
        schFree(s->sch);
#endif
        delete s;
        context->SetObjectVariable("CSELF", context->NewPointer(nullptr));
    }
    return NULLOBJECT;
}

// nAddress(which): "R" the peer's, "L" ours. Returns an array (address,
// port), or an error result.
RexxMethod2(RexxArrayObject, sock_address, CSELF, cself, CSTRING, which)
{
    Sock *s = (Sock *)cself;
    if (s == nullptr || s->fd == BAD_SOCKET)
    {
        return closedResult(context);
    }
    struct sockaddr_storage ss;
    socklen_type len = sizeof(ss);
    int rc = (which[0] == 'R' || which[0] == 'r')
             ? getpeername(s->fd, (struct sockaddr *)&ss, &len)
             : getsockname(s->fd, (struct sockaddr *)&ss, &len);
    if (rc != 0)
    {
        return errorResult(context, lastError());
    }
    std::string host;
    int port;
    addressText((struct sockaddr *)&ss, host, port);
    RexxArrayObject r = context->NewArray(3);
    context->ArrayAppendString(r, "OK", 2);
    context->ArrayAppendString(r, host.c_str(), host.size());
    context->ArrayAppend(r, context->WholeNumber(port));
    return r;
}

// Socket~resolve(host): the host's addresses as strings, IPv6 and IPv4,
// in the order the system gives them, without duplicates.
RexxMethod1(RexxArrayObject, socket_resolve, CSTRING, host)
{
    struct addrinfo hints;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_protocol = IPPROTO_TCP;
    struct addrinfo *list = nullptr;
    int rc = getaddrinfo(host, nullptr, &hints, &list);
    if (rc != 0)
    {
        return gaiErrorResult(context, rc);
    }
    RexxArrayObject addrs = context->NewArray(4);
    std::vector<std::string> seen;
    for (struct addrinfo *ai = list; ai != nullptr; ai = ai->ai_next)
    {
        std::string text;
        int port;
        addressText(ai->ai_addr, text, port);
        bool dup = text.empty();
        for (auto &t : seen)
        {
            if (t == text)
            {
                dup = true;
            }
        }
        if (!dup)
        {
            seen.push_back(text);
            context->ArrayAppendString(addrs, text.c_str(), text.size());
        }
    }
    freeaddrinfo(list);
    return statusResult(context, "OK", addrs);
}


/*----------------------------------------------------------------------------*/
/* ServerSocket                                                               */
/*----------------------------------------------------------------------------*/

static int bindAndListen(sock_t fd, const struct sockaddr *sa, socklen_type len, int backlog)
{
#ifdef _WIN32
    int one = 1;
    setsockopt(fd, SOL_SOCKET, SO_EXCLUSIVEADDRUSE, (const char *)&one, sizeof(one));
#else
    int one = 1;
    setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
#endif
    if (bind(fd, sa, len) != 0)
    {
        return lastError();
    }
    if (listen(fd, backlog) != 0)
    {
        return lastError();
    }
    return 0;
}

// nListen(port, address, backlog): address "" means every address, IPv6
// and IPv4 on one socket (IPv4 only where there is no IPv6).
RexxMethod3(RexxArrayObject, server_listen, CSTRING, port, CSTRING, address, int, backlog)
{
    if (backlog <= 0)
    {
        backlog = SOMAXCONN;
    }
    if (address[0] == '\0')
    {
        int portNumber = atoi(port);
        sock_t fd = socket(AF_INET6, SOCK_STREAM, IPPROTO_TCP);
        if (fd != BAD_SOCKET)
        {
            prepareSocket(fd);
            int zero = 0;
            setsockopt(fd, IPPROTO_IPV6, IPV6_V6ONLY, (const char *)&zero, sizeof(zero));
            struct sockaddr_in6 sa;
            memset(&sa, 0, sizeof(sa));
            sa.sin6_family = AF_INET6;
            sa.sin6_addr = in6addr_any;
            sa.sin6_port = htons((unsigned short)portNumber);
            int err = bindAndListen(fd, (struct sockaddr *)&sa, sizeof(sa), backlog);
            if (err == 0)
            {
                setBlocking(fd, false);
                setCself(context, new Sock(fd));
                return statusResult(context, "OK");
            }
            closesock(fd);
            // In use, or not allowed, is the answer; anything else means no
            // usable IPv6 here: fall back to IPv4.
#ifdef _WIN32
            if (err == WSAEADDRINUSE || err == WSAEACCES)
#else
            if (err == EADDRINUSE || err == EACCES)
#endif
            {
                return errorResult(context, err);
            }
        }
        fd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
        if (fd == BAD_SOCKET)
        {
            return errorResult(context, lastError());
        }
        prepareSocket(fd);
        struct sockaddr_in sa4;
        memset(&sa4, 0, sizeof(sa4));
        sa4.sin_family = AF_INET;
        sa4.sin_addr.s_addr = htonl(INADDR_ANY);
        sa4.sin_port = htons((unsigned short)portNumber);
        int err = bindAndListen(fd, (struct sockaddr *)&sa4, sizeof(sa4), backlog);
        if (err != 0)
        {
            closesock(fd);
            return errorResult(context, err);
        }
        setBlocking(fd, false);
        setCself(context, new Sock(fd));
        return statusResult(context, "OK");
    }

    struct addrinfo hints;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_protocol = IPPROTO_TCP;
    hints.ai_flags = AI_PASSIVE;
    struct addrinfo *list = nullptr;
    int rc = getaddrinfo(address, port, &hints, &list);
    if (rc != 0)
    {
        return gaiErrorResult(context, rc);
    }
    int lastErr = 0;
    for (struct addrinfo *ai = list; ai != nullptr; ai = ai->ai_next)
    {
        sock_t fd = socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol);
        if (fd == BAD_SOCKET)
        {
            lastErr = lastError();
            continue;
        }
        prepareSocket(fd);
        int err = bindAndListen(fd, ai->ai_addr, (socklen_type)ai->ai_addrlen, backlog);
        if (err == 0)
        {
            freeaddrinfo(list);
            setBlocking(fd, false);
            setCself(context, new Sock(fd));
            return statusResult(context, "OK");
        }
        lastErr = err;
        closesock(fd);
    }
    freeaddrinfo(list);
    return errorResult(context, lastErr);
}

// nAccept(timeout): "OK" and a .Pointer for Socket's nAdopt, or
// "TIMEOUT", or "AGAIN" and the seconds left, or an error.
RexxMethod2(RexxArrayObject, server_accept, CSELF, cself, double, timeout)
{
    Sock *s = (Sock *)cself;
    if (s == nullptr || s->fd == BAD_SOCKET)
    {
        return closedResult(context);
    }
    bool hasDeadline = timeout >= 0;
    Clock::time_point deadline = deadlineFrom(hasDeadline ? timeout : 0);
    for (;;)
    {
        sock_t lfd = s->fd;
        if (lfd == BAD_SOCKET)
        {
            return closedResult(context);
        }
        sock_t fd = accept(lfd, nullptr, nullptr);
        if (fd != BAD_SOCKET)
        {
            prepareSocket(fd);
            setBlocking(fd, false);
            Sock *c = new Sock(fd);
            SSL_CTX *ctx;
            {
                std::lock_guard<std::mutex> guard(s->mu);
                ctx = s->ctx;
                if (ctx != nullptr)
                {
                    SSL_CTX_up_ref(ctx);
                }
#ifdef _WIN32
                if (s->schCred)
                {
                    // TLSServerSocket with Schannel: the handshake happens
                    // on the first read or write, as below.
                    c->sch = schServer(s->schCred);
                }
#endif
            }
            if (ctx != nullptr)
            {
                // TLSServerSocket: the handshake happens on the first read
                // or write, in whatever activity serves this client.
                if (attachSsl(c, ctx))
                {
                    SSL_set_accept_state(c->ssl);
                }
            }
            return statusResult(context, "OK", context->NewPointer(c));
        }
        int e = lastError();
        if (interrupted(e))
        {
            continue;
        }
        if (!wouldBlock(e))
        {
            return errorResult(context, e);
        }
        int err = 0;
        int w = waitSlice(lfd, POLLIN, hasDeadline, deadline, &err);
        if (w == 0)
        {
            return statusResult(context, "TIMEOUT");
        }
        if (w == 2)
        {
            return statusResult(context, "AGAIN", context->DoubleToObject(secondsLeft(hasDeadline, deadline)));
        }
        if (w < 0)
        {
            return errorResult(context, err);
        }
    }
}


/*----------------------------------------------------------------------------*/
/* UDPSocket (UDP)                                                            */
/*                                                                            */
/* One socket, bound at creation. Without an address, IPv6 and IPv4 on one    */
/* socket (IPv4 only where there is no IPv6), as ServerSocket. A host to      */
/* send to is resolved on every send; when it has IPv4 and IPv6 addresses,    */
/* IPv4 is used if the socket takes it (as Java does by default), since UDP,  */
/* unlike TCP, cannot try the next address when nobody answers.              */
/*----------------------------------------------------------------------------*/

// Windows reports an ICMP "port unreachable" as WSAECONNRESET on the next
// recvfrom, even on a socket that is not connected, where Linux and macOS
// say nothing: off until connect, which turns it on (so that "connection
// refused" is seen, as on the other two).
static void connReset(sock_t fd, bool on)
{
#ifdef _WIN32
    BOOL value = on ? TRUE : FALSE;
    DWORD bytes = 0;
    WSAIoctl(fd, SIO_UDP_CONNRESET, &value, sizeof(value), nullptr, 0, &bytes, nullptr, nullptr);
#else
    (void)fd;
    (void)on;
#endif
}

// A datagram of up to 65507 bytes (IPv4's maximum) must be able to go
// out and come in: macOS limits a datagram to the send buffer (9216
// bytes by default).
static void datagramBuffers(sock_t fd)
{
    int want = 2 * 65536;
    int opts[2] = {SO_SNDBUF, SO_RCVBUF};
    for (int opt : opts)
    {
        int size = 0;
        socklen_type len = sizeof(size);
        if (getsockopt(fd, SOL_SOCKET, opt, (char *)&size, &len) == 0 && size < want)
        {
            setsockopt(fd, SOL_SOCKET, opt, (const char *)&want, sizeof(want));
        }
    }
}

// shared (MulticastSocket): other sockets may take the same port, so that
// several programs on one machine receive a group's datagrams.
static int bindDatagram(sock_t fd, const struct sockaddr *sa, socklen_type len, bool shared)
{
    int one = 1;
    if (shared)
    {
        setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, (const char *)&one, sizeof(one));
#if defined(SO_REUSEPORT) && !defined(__linux__)
        // macOS: SO_REUSEADDR alone does not let a second socket bind
        // the port on every address (measured: probes/multicast).
        setsockopt(fd, SOL_SOCKET, SO_REUSEPORT, (const char *)&one, sizeof(one));
#endif
    }
    else
    {
#ifdef _WIN32
        setsockopt(fd, SOL_SOCKET, SO_EXCLUSIVEADDRUSE, (const char *)&one, sizeof(one));
#endif
        // No SO_REUSEADDR: for UDP it would let a second socket take the port.
    }
    if (bind(fd, sa, len) != 0)
    {
        return lastError();
    }
    return 0;
}

// A bound UDP socket: on port, address "" meaning every address (IPv6 and
// IPv4 on one socket, IPv4 alone where there is no IPv6). 0 and the socket
// in fd; or an error code (a getaddrinfo one if gai is set).
static int openDatagram(const char *port, const char *address, bool shared, sock_t &out, bool &gai)
{
    gai = false;
    out = BAD_SOCKET;
    if (address[0] == '\0')
    {
        int portNumber = atoi(port);
        sock_t fd = socket(AF_INET6, SOCK_DGRAM, IPPROTO_UDP);
        if (fd != BAD_SOCKET)
        {
            prepareSocket(fd);
            int zero = 0;
            setsockopt(fd, IPPROTO_IPV6, IPV6_V6ONLY, (const char *)&zero, sizeof(zero));
            struct sockaddr_in6 sa;
            memset(&sa, 0, sizeof(sa));
            sa.sin6_family = AF_INET6;
            sa.sin6_addr = in6addr_any;
            sa.sin6_port = htons((unsigned short)portNumber);
            int err = bindDatagram(fd, (struct sockaddr *)&sa, sizeof(sa), shared);
            if (err == 0)
            {
                out = fd;
                return 0;
            }
            closesock(fd);
#ifdef _WIN32
            if (err == WSAEADDRINUSE || err == WSAEACCES)
#else
            if (err == EADDRINUSE || err == EACCES)
#endif
            {
                return err;
            }
        }
        fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
        if (fd == BAD_SOCKET)
        {
            return lastError();
        }
        prepareSocket(fd);
        struct sockaddr_in sa4;
        memset(&sa4, 0, sizeof(sa4));
        sa4.sin_family = AF_INET;
        sa4.sin_addr.s_addr = htonl(INADDR_ANY);
        sa4.sin_port = htons((unsigned short)portNumber);
        int err = bindDatagram(fd, (struct sockaddr *)&sa4, sizeof(sa4), shared);
        if (err != 0)
        {
            closesock(fd);
            return err;
        }
        out = fd;
        return 0;
    }

    struct addrinfo hints;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_DGRAM;
    hints.ai_protocol = IPPROTO_UDP;
    hints.ai_flags = AI_PASSIVE;
    struct addrinfo *list = nullptr;
    int rc = getaddrinfo(address, port, &hints, &list);
    if (rc != 0)
    {
        gai = true;
        return rc;
    }
    int lastErr = 0;
    for (struct addrinfo *ai = list; ai != nullptr; ai = ai->ai_next)
    {
        sock_t fd = socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol);
        if (fd == BAD_SOCKET)
        {
            lastErr = lastError();
            continue;
        }
        prepareSocket(fd);
        int err = bindDatagram(fd, ai->ai_addr, (socklen_type)ai->ai_addrlen, shared);
        if (err == 0)
        {
            freeaddrinfo(list);
            out = fd;
            return 0;
        }
        lastErr = err;
        closesock(fd);
    }
    freeaddrinfo(list);
    return lastErr;
}

// Linux delivers to a socket bound to every address the datagrams of any
// group another socket on the machine joined (IP_MULTICAST_ALL, on by
// default); macOS and Windows only those of the groups it joined itself
// (measured: probes/multicast). Off, so that the three agree.
static void onlyJoinedGroups(sock_t fd)
{
#ifdef IP_MULTICAST_ALL
    int zero = 0;
    setsockopt(fd, IPPROTO_IP, IP_MULTICAST_ALL, (const char *)&zero, sizeof(zero));
  #ifdef IPV6_MULTICAST_ALL
    setsockopt(fd, IPPROTO_IPV6, IPV6_MULTICAST_ALL, (const char *)&zero, sizeof(zero));
  #endif
#else
    (void)fd;
#endif
}

// nOpen(port, address, shared): address "" means every address; shared
// (MulticastSocket) lets other sockets take the same port.
RexxMethod3(RexxArrayObject, udp_open, CSTRING, port, CSTRING, address, logical_t, shared)
{
    sock_t fd;
    bool gai;
    int err = openDatagram(port, address, shared != 0, fd, gai);
    if (err != 0)
    {
        return gai ? gaiErrorResult(context, err) : errorResult(context, err);
    }
    datagramBuffers(fd);
    connReset(fd, false);
    setBlocking(fd, false);
    if (shared)
    {
        onlyJoinedGroups(fd);
    }
    Sock *s = new Sock(fd);
    s->shared = shared != 0;
    setCself(context, s);
    return statusResult(context, "OK");
}

// The address to send to (or connect to): host and port resolved, in the
// form the socket takes (IPv4 as ::ffff:a.b.c.d on an IPv6 socket that
// takes IPv4). Returns nullptr and fills to/len, or an error result.
static RexxArrayObject datagramTarget(RexxMethodContext *context, Sock *s, const char *host, const char *port,
                                      struct sockaddr_storage &to, socklen_type &toLen)
{
    struct sockaddr_storage me;
    socklen_type meLen = sizeof(me);
    if (getsockname(s->fd, (struct sockaddr *)&me, &meLen) != 0)
    {
        return errorResult(context, lastError());
    }
    bool takes4 = me.ss_family == AF_INET;
    bool takes6 = me.ss_family == AF_INET6;
    if (takes6)
    {
        int v6only = 0;
        socklen_type len = sizeof(v6only);
        getsockopt(s->fd, IPPROTO_IPV6, IPV6_V6ONLY, (char *)&v6only, &len);
        takes4 = v6only == 0;
    }

    struct addrinfo hints;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_DGRAM;
    hints.ai_protocol = IPPROTO_UDP;
    struct addrinfo *list = nullptr;
    int rc = getaddrinfo(host, port, &hints, &list);
    if (rc != 0)
    {
        return gaiErrorResult(context, rc);
    }
    struct addrinfo *v4 = nullptr, *v6 = nullptr;
    for (struct addrinfo *ai = list; ai != nullptr; ai = ai->ai_next)
    {
        if (ai->ai_family == AF_INET && v4 == nullptr)
        {
            v4 = ai;
        }
        if (ai->ai_family == AF_INET6 && v6 == nullptr)
        {
            v6 = ai;
        }
    }
    memset(&to, 0, sizeof(to));
    bool found = true;
    if (v4 != nullptr && takes4 && me.ss_family == AF_INET)
    {
        memcpy(&to, v4->ai_addr, v4->ai_addrlen);
        toLen = (socklen_type)v4->ai_addrlen;
    }
    else if (v4 != nullptr && takes4)
    {
        const struct sockaddr_in *a = (const struct sockaddr_in *)v4->ai_addr;
        struct sockaddr_in6 *m = (struct sockaddr_in6 *)&to;
        m->sin6_family = AF_INET6;
        m->sin6_port = a->sin_port;
        unsigned char *b = (unsigned char *)&m->sin6_addr;
        b[10] = 0xff;
        b[11] = 0xff;
        memcpy(b + 12, &a->sin_addr, 4);
        toLen = sizeof(struct sockaddr_in6);
    }
    else if (v6 != nullptr && takes6)
    {
        memcpy(&to, v6->ai_addr, v6->ai_addrlen);
        toLen = (socklen_type)v6->ai_addrlen;
    }
    else
    {
        found = false;
    }
    freeaddrinfo(list);
    if (!found)
    {
#ifdef _WIN32
        return errorResult(context, WSAEAFNOSUPPORT);
#else
        return errorResult(context, EAFNOSUPPORT);
#endif
    }
    return nullptr;
}

// nConnect(host, port): from now on, send goes there and only its
// datagrams are received.
RexxMethod3(RexxArrayObject, udp_connect, CSELF, cself, CSTRING, host, CSTRING, port)
{
    Sock *s = (Sock *)cself;
    if (s == nullptr || s->fd == BAD_SOCKET)
    {
        return closedResult(context);
    }
    struct sockaddr_storage to;
    socklen_type toLen = 0;
    RexxArrayObject bad = datagramTarget(context, s, host, port, to, toLen);
    if (bad != nullptr)
    {
        return bad;
    }
    if (connect(s->fd, (struct sockaddr *)&to, toLen) != 0)
    {
        return errorResult(context, lastError());
    }
    s->connected = true;
    connReset(s->fd, true);
    return statusResult(context, "OK");
}

#ifdef __APPLE__
static int viaHelper(Sock *s, struct sockaddr_storage &to, socklen_type &toLen, sock_t &out);
#endif

// nSend(data, host, port): one datagram; host "" on a connected socket.
RexxMethod4(RexxArrayObject, udp_send, CSELF, cself, RexxStringObject, data, CSTRING, host, CSTRING, port)
{
    Sock *s = (Sock *)cself;
    if (s == nullptr || s->fd == BAD_SOCKET)
    {
        return closedResult(context);
    }
    const char *p = context->StringData(data);
    size_t size = context->StringLength(data);
    if (size > 0x7fffffff)
    {
#ifdef _WIN32
        return errorResult(context, WSAEMSGSIZE);
#else
        return errorResult(context, EMSGSIZE);
#endif
    }
    struct sockaddr_storage to;
    socklen_type toLen = 0;
    sock_t out = s->fd;
    if (host[0] != '\0')
    {
        RexxArrayObject bad = datagramTarget(context, s, host, port, to, toLen);
        if (bad != nullptr)
        {
            return bad;
        }
#ifdef __APPLE__
        int e = viaHelper(s, to, toLen, out);
        if (e != 0)
        {
            return errorResult(context, e);
        }
#endif
    }
    for (;;)
    {
        long n = host[0] != '\0'
                 ? (long)sendto(out, p, (int)size, SEND_FLAGS, (struct sockaddr *)&to, toLen)
                 : (long)send(s->fd, p, (int)size, SEND_FLAGS);
        if (n >= 0)
        {
            return statusResult(context, "OK");
        }
        int e = lastError();
        if (interrupted(e))
        {
            continue;
        }
        if (wouldBlock(e))
        {
            // The send buffer is full: it empties at the network's pace.
            int err = 0;
            if (waitFor(out, POLLOUT, false, Clock::now(), &err) < 0)
            {
                return errorResult(context, err);
            }
            continue;
        }
        return errorResult(context, e);
    }
}

// nReceive(timeout): "OK", data, address, port; or "TIMEOUT"; or "AGAIN"
// and the seconds left; or an error.
// timeout < 0: as long as it takes.
RexxMethod2(RexxArrayObject, udp_receive, CSELF, cself, double, timeout)
{
    Sock *s = (Sock *)cself;
    if (s == nullptr || s->fd == BAD_SOCKET || s->closing)
    {
        return closedResult(context);
    }
    sock_t fd = s->fd;
    bool hasDeadline = timeout >= 0;
    Clock::time_point deadline = deadlineFrom(hasDeadline ? timeout : 0);
    std::vector<char> buf(65536);
    for (;;)
    {
        struct sockaddr_storage from;
        socklen_type fromLen = sizeof(from);
        memset(&from, 0, sizeof(from));
        long n = (long)recvfrom(fd, buf.data(), (int)buf.size(), 0, (struct sockaddr *)&from, &fromLen);
        sock_t helper = s->helper;
        if (n < 0 && helper != BAD_SOCKET && wouldBlock(lastError()))
        {
            // macOS's helper (see "MulticastSocket"): what is sent to the
            // port over IPv4 may reach it rather than this socket.
            fromLen = sizeof(from);
            n = (long)recvfrom(helper, buf.data(), (int)buf.size(), 0, (struct sockaddr *)&from, &fromLen);
        }
        // close in another activity wakes the wait (Linux: as an empty
        // datagram); that is not something received.
        if (s->closing)
        {
            return closedResult(context);
        }
        if (n >= 0)
        {
            std::string host;
            int port = 0;
            addressText((struct sockaddr *)&from, host, port);
            RexxArrayObject r = context->NewArray(4);
            context->ArrayAppendString(r, "OK", 2);
            context->ArrayAppend(r, context->NewString(buf.data(), (size_t)n));
            context->ArrayAppendString(r, host.c_str(), host.size());
            context->ArrayAppend(r, context->WholeNumber(port));
            return r;
        }
        int e = lastError();
        if (interrupted(e))
        {
            continue;
        }
        if (wouldBlock(e))
        {
            int err = 0;
            int w = waitSlice(fd, POLLIN, hasDeadline, deadline, &err, s->helper);
            if (s->closing)
            {
                return closedResult(context);
            }
            if (w == 0)
            {
                return statusResult(context, "TIMEOUT");
            }
            if (w == 2)
            {
                return statusResult(context, "AGAIN", context->DoubleToObject(secondsLeft(hasDeadline, deadline)));
            }
            if (w < 0)
            {
                return errorResult(context, err);
            }
            continue;
        }
#ifdef _WIN32
        if (e == WSAECONNRESET && s->connected)
        {
            e = WSAECONNREFUSED;     // the "port unreachable" that Linux and macOS call so
        }
#endif
        return errorResult(context, e);
    }
}

// nBroadcast(value): SO_BROADCAST. value 1 or 0 sets it, -1 only asks.
RexxMethod2(RexxArrayObject, udp_broadcast, CSELF, cself, int, value)
{
    Sock *s = (Sock *)cself;
    if (s == nullptr || s->fd == BAD_SOCKET)
    {
        return closedResult(context);
    }
    if (value >= 0)
    {
        int flag = value ? 1 : 0;
        if (setsockopt(s->fd, SOL_SOCKET, SO_BROADCAST, (const char *)&flag, sizeof(flag)) != 0)
        {
            return errorResult(context, lastError());
        }
    }
    int flag = 0;
    socklen_type len = sizeof(flag);
    if (getsockopt(s->fd, SOL_SOCKET, SO_BROADCAST, (char *)&flag, &len) != 0)
    {
        return errorResult(context, lastError());
    }
    return statusResult(context, "OK", context->WholeNumber(flag ? 1 : 0));
}


/*----------------------------------------------------------------------------*/
/* MulticastSocket                                                            */
/*                                                                            */
/* A UDPSocket whose port other sockets may share, that joins groups. What    */
/* each system accepts differs (probes/multicast, measured on the four CI     */
/* systems): a socket of IPv6 that takes IPv4 joins an IPv4 group at the IP   */
/* level on Linux and Windows (MCAST_JOIN_GROUP), and only as ::ffff:a.b.c.d  */
/* at the IPv6 level on macOS (IPV6_JOIN_GROUP); a datagram such a socket     */
/* sends to an IPv4 group takes its TTL from IP_MULTICAST_TTL but its         */
/* loopback from IPV6_MULTICAST_LOOP on Linux. So each join tries the ways in */
/* turn, and each option is set at both levels.                              */
/*----------------------------------------------------------------------------*/

#ifdef _WIN32
  #include <iphlpapi.h>
#else
  #include <net/if.h>
  #include <ifaddrs.h>
#endif

#ifndef IPV6_JOIN_GROUP
  #define IPV6_JOIN_GROUP IPV6_ADD_MEMBERSHIP
  #define IPV6_LEAVE_GROUP IPV6_DROP_MEMBERSHIP
#endif

static int socketFamily(sock_t fd)
{
    struct sockaddr_storage me;
    socklen_type len = sizeof(me);
    if (getsockname(fd, (struct sockaddr *)&me, &len) != 0)
    {
        return AF_UNSPEC;
    }
    return me.ss_family;
}

static void setSaLen(struct sockaddr_storage &ss)
{
#if defined(__APPLE__) || defined(__FreeBSD__)
    ss.ss_len = ss.ss_family == AF_INET ? sizeof(struct sockaddr_in) : sizeof(struct sockaddr_in6);
#else
    (void)ss;
#endif
}

static bool sameAddress(const struct sockaddr *a, const struct sockaddr *b)
{
    if (a->sa_family != b->sa_family)
    {
        return false;
    }
    if (a->sa_family == AF_INET)
    {
        return memcmp(&((const struct sockaddr_in *)a)->sin_addr, &((const struct sockaddr_in *)b)->sin_addr, 4) == 0;
    }
    if (a->sa_family == AF_INET6)
    {
        return memcmp(&((const struct sockaddr_in6 *)a)->sin6_addr, &((const struct sockaddr_in6 *)b)->sin6_addr, 16) == 0;
    }
    return false;
}

// An interface, by index ("3"), name ("eth0", "en0"; on Windows also its
// friendly name, "Ethernet 3") or one of its addresses ("192.168.1.10").
// "" is 0, the system's choice. false if there is no such interface.
static bool interfaceIndex(const char *what, unsigned &index)
{
    index = 0;
    if (what[0] == '\0')
    {
        return true;
    }
    bool digits = true;
    for (const char *p = what; *p; p++)
    {
        digits = digits && *p >= '0' && *p <= '9';
    }
    if (digits)
    {
        index = (unsigned)strtoul(what, nullptr, 10);
        return index != 0;
    }
    index = if_nametoindex(what);
    if (index != 0)
    {
        return true;
    }
    struct addrinfo hints;
    memset(&hints, 0, sizeof(hints));
    hints.ai_flags = AI_NUMERICHOST;
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_DGRAM;
    struct addrinfo *list = nullptr;
    bool isAddr = getaddrinfo(what, nullptr, &hints, &list) == 0;
#ifdef _WIN32
    ULONG size = 16384;
    std::vector<char> buf(size);
    ULONG rc = GetAdaptersAddresses(AF_UNSPEC, 0, nullptr, (IP_ADAPTER_ADDRESSES *)buf.data(), &size);
    if (rc == ERROR_BUFFER_OVERFLOW)
    {
        buf.resize(size);
        rc = GetAdaptersAddresses(AF_UNSPEC, 0, nullptr, (IP_ADAPTER_ADDRESSES *)buf.data(), &size);
    }
    if (rc == NO_ERROR)
    {
        std::wstring wide;
        for (const char *p = what; *p; p++)
        {
            wide += (wchar_t)(unsigned char)*p;
        }
        for (IP_ADAPTER_ADDRESSES *a = (IP_ADAPTER_ADDRESSES *)buf.data(); a != nullptr && index == 0; a = a->Next)
        {
            if (!isAddr && a->FriendlyName != nullptr && _wcsicmp(a->FriendlyName, wide.c_str()) == 0)
            {
                index = a->IfIndex != 0 ? a->IfIndex : a->Ipv6IfIndex;
            }
            for (IP_ADAPTER_UNICAST_ADDRESS *u = a->FirstUnicastAddress; isAddr && u != nullptr; u = u->Next)
            {
                if (sameAddress(u->Address.lpSockaddr, list->ai_addr))
                {
                    index = list->ai_family == AF_INET ? a->IfIndex : a->Ipv6IfIndex;
                }
            }
        }
    }
#else
    struct ifaddrs *ifs = nullptr;
    if (isAddr && getifaddrs(&ifs) == 0)
    {
        for (struct ifaddrs *a = ifs; a != nullptr && index == 0; a = a->ifa_next)
        {
            if (a->ifa_addr != nullptr && sameAddress(a->ifa_addr, list->ai_addr))
            {
                index = if_nametoindex(a->ifa_name);
            }
        }
        freeifaddrs(ifs);
    }
#endif
    if (list != nullptr)
    {
        freeaddrinfo(list);
    }
    return index != 0;
}

// The IPv4 outgoing interface, by index (0: the system's choice).
static int setIf4(sock_t fd, unsigned index)
{
#if defined(_WIN32)
    DWORD v = htonl(index);              // "0.0.0.index": an index, not an address
    return setsockopt(fd, IPPROTO_IP, IP_MULTICAST_IF, (const char *)&v, sizeof(v)) == 0 ? 0 : lastError();
#elif defined(__APPLE__)
    unsigned v = index;
    return setsockopt(fd, IPPROTO_IP, IP_MULTICAST_IFINDEX, (const char *)&v, sizeof(v)) == 0 ? 0 : lastError();
#else
    struct ip_mreqn m;
    memset(&m, 0, sizeof(m));
    m.imr_ifindex = (int)index;
    return setsockopt(fd, IPPROTO_IP, IP_MULTICAST_IF, (const char *)&m, sizeof(m)) == 0 ? 0 : lastError();
#endif
}

#ifdef __APPLE__
// macOS: a socket of IPv6 that takes IPv4 cannot send to an IPv4 group
// (EHOSTUNREACH, whatever its options: measured, probes/multicast). A
// MulticastSocket sends those through a helper, an IPv4 socket on the same
// port (so the datagrams come from that port), made at its first such send,
// with the socket's options; receive reads it too, since what is sent to
// the port over IPv4 may reach it instead. 0, with out the socket to send
// on (and to as IPv4 when it is the helper), or an error.
static int viaHelper(Sock *s, struct sockaddr_storage &to, socklen_type &toLen, sock_t &out)
{
    out = s->fd;
    if (!s->shared || to.ss_family != AF_INET6)
    {
        return 0;
    }
    const unsigned char *b = (const unsigned char *)&((struct sockaddr_in6 *)&to)->sin6_addr;
    static const unsigned char mapped[12] = {0,0,0,0,0,0,0,0,0,0,0xff,0xff};
    if (memcmp(b, mapped, 12) != 0 || b[12] < 224 || b[12] > 239)
    {
        return 0;
    }
    if (s->helper == BAD_SOCKET)
    {
        struct sockaddr_storage me;
        socklen_type meLen = sizeof(me);
        if (getsockname(s->fd, (struct sockaddr *)&me, &meLen) != 0)
        {
            return lastError();
        }
        sock_t h = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
        if (h == BAD_SOCKET)
        {
            return lastError();
        }
        prepareSocket(h);
        struct sockaddr_in a;
        memset(&a, 0, sizeof(a));
        a.sin_family = AF_INET;
        a.sin_addr.s_addr = htonl(INADDR_ANY);
        a.sin_port = ((struct sockaddr_in6 *)&me)->sin6_port;
        int e = bindDatagram(h, (struct sockaddr *)&a, sizeof(a), true);
        if (e != 0)
        {
            closesock(h);
            return e;
        }
        datagramBuffers(h);
        setBlocking(h, false);
        setsockopt(h, IPPROTO_IP, IP_MULTICAST_TTL, (const char *)&s->mcTtl, sizeof(s->mcTtl));
        setsockopt(h, IPPROTO_IP, IP_MULTICAST_LOOP, (const char *)&s->mcLoop, sizeof(s->mcLoop));
        setIf4(h, s->mcIf);
        s->helper = h;
    }
    struct sockaddr_in v4;
    memset(&v4, 0, sizeof(v4));
    v4.sin_family = AF_INET;
    v4.sin_port = ((struct sockaddr_in6 *)&to)->sin6_port;
    memcpy(&v4.sin_addr, b + 12, 4);
    memset(&to, 0, sizeof(to));
    memcpy(&to, &v4, sizeof(v4));
    toLen = sizeof(v4);
    out = s->helper;
    return 0;
}
#endif

// nGroup(group, interface, join): joins (join 1) or leaves (0) group, on
// interface ("" the system's choice). "OK" or an error.
RexxMethod4(RexxArrayObject, mcast_group, CSELF, cself, CSTRING, group, CSTRING, iface, logical_t, join)
{
    Sock *s = (Sock *)cself;
    if (s == nullptr || s->fd == BAD_SOCKET)
    {
        return closedResult(context);
    }
    struct addrinfo hints;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_DGRAM;
    hints.ai_protocol = IPPROTO_UDP;
    struct addrinfo *list = nullptr;
    int rc = getaddrinfo(group, nullptr, &hints, &list);
    if (rc != 0)
    {
        return gaiErrorResult(context, rc);
    }
    int family = socketFamily(s->fd);
    bool takes4 = family == AF_INET;
    if (family == AF_INET6)
    {
        int v6only = 0;
        socklen_type len = sizeof(v6only);
        getsockopt(s->fd, IPPROTO_IPV6, IPV6_V6ONLY, (char *)&v6only, &len);
        takes4 = v6only == 0;
    }
    // The group's address of the family the socket takes (IPv4 first, for
    // a name with both).
    struct addrinfo *pick = nullptr;
    for (struct addrinfo *ai = list; ai != nullptr && pick == nullptr; ai = ai->ai_next)
    {
        if (ai->ai_family == AF_INET && takes4)
        {
            pick = ai;
        }
    }
    for (struct addrinfo *ai = list; ai != nullptr && pick == nullptr; ai = ai->ai_next)
    {
        if (ai->ai_family == AF_INET6 && family == AF_INET6)
        {
            pick = ai;
        }
    }
    struct sockaddr_storage g;
    memset(&g, 0, sizeof(g));
    if (pick != nullptr)
    {
        memcpy(&g, pick->ai_addr, pick->ai_addrlen);
    }
    bool any = list != nullptr;
    freeaddrinfo(list);
    if (pick == nullptr)
    {
#ifdef _WIN32
        return errorResult(context, any ? WSAEAFNOSUPPORT : WSAEINVAL);
#else
        return errorResult(context, any ? EAFNOSUPPORT : EINVAL);
#endif
    }
    bool multicast = g.ss_family == AF_INET
                     ? IN_MULTICAST(ntohl(((struct sockaddr_in *)&g)->sin_addr.s_addr))
                     : IN6_IS_ADDR_MULTICAST(&((struct sockaddr_in6 *)&g)->sin6_addr);
    if (!multicast)
    {
        return errorArray(context, "not a multicast address", "EINVAL", 0, "", "SOCKET");
    }
    unsigned index = 0;
    if (!interfaceIndex(iface, index))
    {
        return errorArray(context, std::string("no such network interface: ") + iface, "ENXIO", 0, "", "SOCKET");
    }
    setSaLen(g);

    int first = 0;
    // 1. RFC 3678's MCAST_JOIN_GROUP, at the group's own level.
    {
        struct group_req r;
        memset(&r, 0, sizeof(r));
        r.gr_interface = index;
        memcpy(&r.gr_group, &g, sizeof(g));
        int level = g.ss_family == AF_INET ? IPPROTO_IP : IPPROTO_IPV6;
        if (setsockopt(s->fd, level, join ? MCAST_JOIN_GROUP : MCAST_LEAVE_GROUP, (const char *)&r, sizeof(r)) == 0)
        {
            return statusResult(context, "OK");
        }
        first = lastError();
    }
    if (g.ss_family == AF_INET6)
    {
        // 2. IPV6_JOIN_GROUP.
        struct ipv6_mreq m;
        memset(&m, 0, sizeof(m));
        m.ipv6mr_multiaddr = ((struct sockaddr_in6 *)&g)->sin6_addr;
        m.ipv6mr_interface = index;
        if (setsockopt(s->fd, IPPROTO_IPV6, join ? IPV6_JOIN_GROUP : IPV6_LEAVE_GROUP, (const char *)&m, sizeof(m)) == 0)
        {
            return statusResult(context, "OK");
        }
        return errorResult(context, lastError());
    }
    if (family == AF_INET6)
    {
        // 2. An IPv4 group on a socket of IPv6 that takes IPv4 (macOS): as
        // ::ffff:a.b.c.d, at the IPv6 level.
        struct ipv6_mreq m;
        memset(&m, 0, sizeof(m));
        unsigned char *b = (unsigned char *)&m.ipv6mr_multiaddr;
        b[10] = 0xff;
        b[11] = 0xff;
        memcpy(b + 12, &((struct sockaddr_in *)&g)->sin_addr, 4);
        m.ipv6mr_interface = index;
        if (setsockopt(s->fd, IPPROTO_IPV6, join ? IPV6_JOIN_GROUP : IPV6_LEAVE_GROUP, (const char *)&m, sizeof(m)) == 0)
        {
            return statusResult(context, "OK");
        }
    }
    // 3. IP_ADD_MEMBERSHIP, on the system's choice of interface.
    if (index == 0)
    {
        struct ip_mreq m;
        memset(&m, 0, sizeof(m));
        m.imr_multiaddr = ((struct sockaddr_in *)&g)->sin_addr;
        m.imr_interface.s_addr = htonl(INADDR_ANY);
        if (setsockopt(s->fd, IPPROTO_IP, join ? IP_ADD_MEMBERSHIP : IP_DROP_MEMBERSHIP, (const char *)&m, sizeof(m)) == 0)
        {
            return statusResult(context, "OK");
        }
    }
    return errorResult(context, first);
}

// nOption(name, value): "TTL" (0..255), "LOOP" (0 or 1), "IF" (an
// interface: see interfaceIndex), set at the levels the socket has (both,
// for IPv6 that takes IPv4). "OK" when the socket's own family's level
// took it; or an error.
RexxMethod3(RexxArrayObject, mcast_option, CSELF, cself, CSTRING, name, CSTRING, value)
{
    Sock *s = (Sock *)cself;
    if (s == nullptr || s->fd == BAD_SOCKET)
    {
        return closedResult(context);
    }
    int family = socketFamily(s->fd);
    int e4 = 0, e6 = 0;
    if (strcmp(name, "IF") == 0)
    {
        unsigned index = 0;
        if (!interfaceIndex(value, index))
        {
            return errorArray(context, std::string("no such network interface: ") + value, "ENXIO", 0, "", "SOCKET");
        }
        e4 = setIf4(s->fd, index);
        s->mcIf = index;
        if (s->helper != BAD_SOCKET)
        {
            setIf4(s->helper, index);
        }
        if (family == AF_INET6)
        {
            e6 = setsockopt(s->fd, IPPROTO_IPV6, IPV6_MULTICAST_IF, (const char *)&index, sizeof(index)) == 0
                 ? 0 : lastError();
        }
        if (index == 0)
        {
            return statusResult(context, "OK");  // back to the system's choice: as it can
        }
    }
    else
    {
        int v = atoi(value);
        bool ttl = strcmp(name, "TTL") == 0;
        // Windows takes a DWORD for both, Linux and macOS an int (or a
        // byte): an int works on the three (measured).
        e4 = setsockopt(s->fd, IPPROTO_IP, ttl ? IP_MULTICAST_TTL : IP_MULTICAST_LOOP, (const char *)&v, sizeof(v)) == 0
             ? 0 : lastError();
        (ttl ? s->mcTtl : s->mcLoop) = v;
        if (s->helper != BAD_SOCKET)
        {
            setsockopt(s->helper, IPPROTO_IP, ttl ? IP_MULTICAST_TTL : IP_MULTICAST_LOOP, (const char *)&v, sizeof(v));
        }
        if (family == AF_INET6)
        {
            e6 = setsockopt(s->fd, IPPROTO_IPV6, ttl ? IPV6_MULTICAST_HOPS : IPV6_MULTICAST_LOOP,
                            (const char *)&v, sizeof(v)) == 0 ? 0 : lastError();
        }
    }
    int e = family == AF_INET6 ? e6 : e4;
    return e == 0 ? statusResult(context, "OK") : errorResult(context, e);
}

/*----------------------------------------------------------------------------*/
/* DTLS: TLS over UDP                                                         */
/*                                                                            */
/* OpenSSL does DTLS 1.2, as it does TLS, and trust is decided as for TLS.    */
/* One UDP socket (an "endpoint") carries the client's single connection, or  */
/* all of a server's: the server tells its clients apart by their address     */
/* and port, in user space, so that the same code works on the three systems  */
/* (none of them is relied on to hand each connected socket only its own      */
/* datagrams). A server first answers a client with a cookie                  */
/* (DTLSv1_listen, stateless), so that a forged address costs it nothing.     */
/*                                                                            */
/* Every SSL of an endpoint is used under the endpoint's lock. Whoever waits  */
/* (receive, accept, a handshake) reads the socket for everybody: one waiter  */
/* at a time polls it, outside the lock, and hands each datagram to its       */
/* connection, which OpenSSL then reads at once (handshake records, the       */
/* retransmissions of DTLS's timers, close_notify, data); the others wait on  */
/* a condition variable. No wait is longer than SLICE_MS (HALT: see           */
/* waitSlice).                                                                */
/*----------------------------------------------------------------------------*/

struct DtlsEndpoint;

// One DTLS connection: the client's, or one of a server's clients.
struct DtlsConn : PeerCheck
{
    enum State { HANDSHAKING, OPEN, FAILED, PEER_CLOSED, CLOSED };
    DtlsEndpoint *ep = nullptr;
    struct sockaddr_storage peer;
    socklen_type peerLen = 0;
    std::string key;                     // the peer's address and port, as bytes
    SSL *ssl = nullptr;
    std::deque<std::string> wire;        // datagrams arrived, for OpenSSL to read
    std::deque<std::string> app;         // what they carried, for receive
    State state = HANDSHAKING;
    TlsOutcome failure;                  // FAILED: why
    int ioError = 0;                     // the last socket error the BIO met
    bool accepted = false;               // a DTLSSocket has it (server)
    bool restarted = false;              // PEER_CLOSED: the peer began anew
#ifdef _WIN32
    Sch *sch = nullptr;                  // the client's DTLS by Schannel, instead of ssl
#endif
    DtlsConn() { memset(&peer, 0, sizeof(peer)); }
};

struct DtlsEndpoint
{
    sock_t fd = BAD_SOCKET;
    bool server = false;
    std::mutex mu;
    std::condition_variable cv;
    bool reading = false;                // a waiter is polling the socket
    bool closing = false;
    bool closeAfterRead = false;         // close was asked while one polled
    SSL_CTX *ctx = nullptr;
    std::map<std::string, DtlsConn *> conns;   // server: by peer
    std::deque<DtlsConn *> ready;              // server: past the cookie, not accepted
    DtlsConn *client = nullptr;                // client: its connection
    unsigned char secret[32];                  // server: for the cookies
    ~DtlsEndpoint();
};

// What a DTLSSocket or a DTLSServerSocket holds (CSELF).
struct DtlsHandle
{
    std::shared_ptr<DtlsEndpoint> ep;
    DtlsConn *conn = nullptr;            // nullptr for a DTLSServerSocket
};

static void freeConn(DtlsConn *c)
{
    if (c != nullptr)
    {
        if (c->ssl != nullptr)
        {
            SSL_free(c->ssl);
        }
#ifdef _WIN32
        schFree(c->sch);
#endif
        delete c;
    }
}

DtlsEndpoint::~DtlsEndpoint()
{
    // Accepted connections belong to their DTLSSocket (which keeps the
    // endpoint alive): what is left here was never accepted.
    std::vector<DtlsConn *> mine;
    for (auto &kv : conns)
    {
        if (!kv.second->accepted)
        {
            mine.push_back(kv.second);
        }
    }
    for (DtlsConn *c : ready)
    {
        bool listed = false;
        for (DtlsConn *m : mine)
        {
            listed = listed || m == c;
        }
        if (!listed && !c->accepted)
        {
            mine.push_back(c);
        }
    }
    for (DtlsConn *c : mine)
    {
        freeConn(c);
    }
    if (client != nullptr && !client->accepted)
    {
        freeConn(client);
    }
    if (ctx != nullptr)
    {
        SSL_CTX_free(ctx);
    }
    if (fd != BAD_SOCKET)
    {
        closesock(fd);
    }
}

// The datagram MTU OpenSSL fragments the handshake for: small enough for
// any path (as QUIC's 1200 bytes), IPv4 or IPv6.
static const long DTLS_MTU = 1200;
// A DTLS record carries at most this many bytes (SSL3_RT_MAX_PLAIN_LENGTH).
static const size_t DTLS_MAX_DATA = 16384;
// A server keeps at most this many handshakes in progress.
static const size_t DTLS_MAX_PENDING = 64;

/* ---- the BIO: a connection's datagrams --------------------------------------- */

static int dtlsBioWrite(BIO *b, const char *data, int len)
{
    DtlsConn *c = (DtlsConn *)BIO_get_data(b);
    BIO_clear_retry_flags(b);
    sock_t fd = c->ep->fd;
    if (fd == BAD_SOCKET)
    {
        return -1;
    }
    for (;;)
    {
        long n = c->ep->server
                 ? (long)sendto(fd, data, len, 0, (struct sockaddr *)&c->peer, c->peerLen)
                 : (long)send(fd, data, len, 0);
        if (n >= 0)
        {
            return len;
        }
        int e = lastError();
        if (interrupted(e))
        {
            continue;
        }
        if (wouldBlock(e))
        {
            return len;        // as if lost on the way: DTLS sends it again
        }
        c->ioError = e;
        return -1;
    }
}

static int dtlsBioRead(BIO *b, char *data, int len)
{
    DtlsConn *c = (DtlsConn *)BIO_get_data(b);
    BIO_clear_retry_flags(b);
    if (c->wire.empty())
    {
        BIO_set_retry_read(b);
        return -1;
    }
    std::string d = c->wire.front();
    c->wire.pop_front();
    int n = (int)d.size() < len ? (int)d.size() : len;
    memcpy(data, d.data(), (size_t)n);
    return n;
}

static long dtlsBioCtrl(BIO *b, int cmd, long num, void *ptr)
{
    DtlsConn *c = (DtlsConn *)BIO_get_data(b);
    switch (cmd)
    {
        case BIO_CTRL_FLUSH:
            return 1;
        case BIO_CTRL_DGRAM_QUERY_MTU:
        case BIO_CTRL_DGRAM_GET_FALLBACK_MTU:
            return DTLS_MTU;
        case BIO_CTRL_DGRAM_SET_MTU:
            return num;
        case BIO_CTRL_DGRAM_GET_MTU_OVERHEAD:
            return 0;                      // DTLS_MTU is what a datagram may carry
        case BIO_CTRL_DGRAM_MTU_EXCEEDED:
            return 0;
        case BIO_CTRL_DGRAM_GET_PEER:
            if (ptr != nullptr && c != nullptr)
            {
                BIO_ADDR *a = (BIO_ADDR *)ptr;
                if (c->peer.ss_family == AF_INET)
                {
                    struct sockaddr_in *s4 = (struct sockaddr_in *)&c->peer;
                    BIO_ADDR_rawmake(a, AF_INET, &s4->sin_addr, 4, s4->sin_port);
                }
                else
                {
                    struct sockaddr_in6 *s6 = (struct sockaddr_in6 *)&c->peer;
                    BIO_ADDR_rawmake(a, AF_INET6, &s6->sin6_addr, 16, s6->sin6_port);
                }
                return 1;
            }
            return 0;
        case BIO_CTRL_DGRAM_SET_PEER:
        case BIO_CTRL_DGRAM_SET_CONNECTED:
            return 1;
        default:
            return 0;
    }
}

static BIO_METHOD *dtlsBioMethod()
{
    static std::once_flag once;
    static BIO_METHOD *method = nullptr;
    std::call_once(once, []()
    {
        method = BIO_meth_new(BIO_get_new_index() | BIO_TYPE_SOURCE_SINK, "oosockets dtls");
        BIO_meth_set_write(method, dtlsBioWrite);
        BIO_meth_set_read(method, dtlsBioRead);
        BIO_meth_set_ctrl(method, dtlsBioCtrl);
        BIO_meth_set_create(method, bioCreate);
    });
    return method;
}

static DtlsConn *newConn(DtlsEndpoint *ep, const struct sockaddr_storage &peer, socklen_type peerLen)
{
    DtlsConn *c = new DtlsConn();
    c->ep = ep;
    memcpy(&c->peer, &peer, sizeof(peer));
    c->peerLen = peerLen;
    c->ssl = SSL_new(ep->ctx);
    BIO *bio = BIO_new(dtlsBioMethod());
    BIO_set_data(bio, c);
    SSL_set_bio(c->ssl, bio, bio);
    SSL_set_app_data(c->ssl, static_cast<PeerCheck *>(c));
    return c;
}

/* ---- cookies (server) -------------------------------------------------------- */

static std::string peerKey(const struct sockaddr *sa)
{
    if (sa->sa_family == AF_INET)
    {
        const struct sockaddr_in *s4 = (const struct sockaddr_in *)sa;
        return std::string("4", 1) + std::string((const char *)&s4->sin_addr, 4) +
               std::string((const char *)&s4->sin_port, 2);
    }
    const struct sockaddr_in6 *s6 = (const struct sockaddr_in6 *)sa;
    return std::string("6", 1) + std::string((const char *)&s6->sin6_addr, 16) +
           std::string((const char *)&s6->sin6_port, 2);
}

static int cookieMake(SSL *ssl, unsigned char *cookie, unsigned int *len)
{
    DtlsConn *c = static_cast<DtlsConn *>((PeerCheck *)SSL_get_app_data(ssl));
    unsigned char mac[EVP_MAX_MD_SIZE];
    unsigned int macLen = 0;
    if (HMAC(EVP_sha256(), c->ep->secret, sizeof(c->ep->secret), (const unsigned char *)c->key.data(),
             c->key.size(), mac, &macLen) == nullptr)
    {
        return 0;
    }
    if (macLen > 16)
    {
        macLen = 16;
    }
    memcpy(cookie, mac, macLen);
    *len = macLen;
    return 1;
}

static int cookieCheck(SSL *ssl, const unsigned char *cookie, unsigned int len)
{
    unsigned char want[EVP_MAX_MD_SIZE];
    unsigned int wantLen = 0;
    if (!cookieMake(ssl, want, &wantLen) || len != wantLen)
    {
        return 0;
    }
    return CRYPTO_memcmp(cookie, want, len) == 0 ? 1 : 0;
}

/* ---- what arrives ------------------------------------------------------------ */

// The outcome of an SSL call that failed, kept as the connection's failure.
static TlsOutcome dtlsOutcome(DtlsConn *c, int rc)
{
    TlsOutcome o;
    int e = SSL_get_error(c->ssl, rc);
    o.handshaking = !SSL_is_init_finished(c->ssl);
    o.socketError = c->ioError;
    o.sslError = ERR_peek_last_error();
    o.verifyResult = SSL_get_verify_result(c->ssl);
    if (e == SSL_ERROR_ZERO_RETURN)
    {
        o.status = TLS_EOF;
    }
    else if (e == SSL_ERROR_SYSCALL)
    {
        o.status = o.socketError != 0 ? TLS_SOCKET_ERROR : TLS_SSL_ERROR;
    }
    else
    {
        o.status = TLS_SSL_ERROR;
    }
    ERR_clear_error();
    return o;
}

// A server's connection leaves the table of peers (a new ClientHello from
// the same address and port then starts a new one).
static void unlistConn(DtlsEndpoint *ep, DtlsConn *c)
{
    auto it = ep->conns.find(c->key);
    if (it != ep->conns.end() && it->second == c)
    {
        ep->conns.erase(it);
    }
}

// A server's connection that nobody will ever see: out of the table and
// of accept's queue, and freed.
static void dropConn(DtlsEndpoint *ep, DtlsConn *c)
{
    unlistConn(ep, c);
    for (auto r = ep->ready.begin(); r != ep->ready.end(); ++r)
    {
        if (*r == c)
        {
            ep->ready.erase(r);
            break;
        }
    }
    freeConn(c);
}

// A connection that cannot go on. It keeps why, for its DTLSSocket's
// first receive or send: a server's client that fails its handshake
// before accept has returned it is still returned (Rony, 29/10/2026: the
// handshake on first use, as TLSServerSocket; the failure reaches the
// program there).
static void failConn(DtlsEndpoint *ep, DtlsConn *c, const TlsOutcome &o)
{
    if (ep->server)
    {
        unlistConn(ep, c);
    }
    c->state = DtlsConn::FAILED;
    c->failure = o;
}

#ifdef _WIN32

/* ---- the client by Schannel (Windows) ---------------------------------------- */
/* Measured in probes/schannel/: DTLS 1.2 with SCHANNEL_CRED (SCH_CREDENTIALS    */
/* refuses it); a flight larger than the MTU comes out a fragment at a time      */
/* (SEC_I_MESSAGE_FRAGMENT); called again with nothing, Schannel sends its last  */
/* flight again (the retransmission timer is ours); after the handshake the MTU  */
/* is raised so that a record takes the 16,384 bytes a datagram may carry.       */

static const int SCH_DTLS_FIRST_RESEND_MS = 1000;
static const int SCH_DTLS_MAX_RESEND_MS = 8000;
static const int SCH_DTLS_MAX_RESENDS = 6;
static const DWORD SCH_DTLS_MTU = 17000;

static unsigned long getN(const unsigned char *p, int n)
{
    unsigned long v = 0;
    for (int i = 0; i < n; i++)
    {
        v = (v << 8) | p[i];
    }
    return v;
}

// The server's Certificate message, gathered from the handshake records in
// clear (epoch 0) of the datagram d, fragment by fragment (DTLS 1.2: RFC
// 6347, 4.2.2); once whole, its certificates go to peerChain.
static void schDtlsGather(Sch *x, const std::string &d)
{
    const unsigned char *p = (const unsigned char *)d.data();
    size_t n = d.size();
    while (n >= 13 && x->peerChain.empty())
    {
        unsigned type = p[0];
        unsigned epoch = (unsigned)getN(p + 3, 2);
        size_t len = getN(p + 11, 2);
        if (13 + len > n)
        {
            return;
        }
        const unsigned char *h = p + 13;
        size_t left = len;
        while (type == 22 && epoch == 0 && left >= 12)
        {
            unsigned msgType = h[0];
            size_t total = getN(h + 1, 3);
            int seq = (int)getN(h + 4, 2);
            size_t off = getN(h + 6, 3);
            size_t flen = getN(h + 9, 3);
            if (12 + flen > left)
            {
                break;
            }
            if (msgType == 11 && total <= 1 << 20 && off + flen <= total)       // Certificate
            {
                if (x->certSeq != seq)
                {
                    x->certSeq = seq;
                    x->certMsg.assign(total, '\0');
                    x->certHave.assign(total, false);
                }
                if (total != x->certMsg.size())
                {
                    break;                      // not a fragment of the same message: dropped
                }
                memcpy(&x->certMsg[off], h + 12, flen);
                for (size_t i = off; i < off + flen; i++)
                {
                    x->certHave[i] = true;
                }
                bool whole = true;
                for (bool b : x->certHave)
                {
                    whole = whole && b;
                }
                if (whole && total >= 3)
                {
                    const unsigned char *c = (const unsigned char *)x->certMsg.data();
                    size_t listLen = getN(c, 3), at = 3;
                    std::vector<std::string> chain;
                    while (at + 3 <= 3 + listLen && at + 3 <= total)
                    {
                        size_t clen = getN(c + at, 3);
                        if (at + 3 + clen > total || at + 3 + clen > 3 + listLen)
                        {
                            break;
                        }
                        chain.push_back(std::string((const char *)c + at + 3, clen));
                        at += 3 + clen;
                    }
                    x->peerChain = chain;
                }
            }
            h += 12 + flen;
            left -= 12 + flen;
        }
        p += 13 + len;
        n -= 13 + len;
    }
}

// The highest sequence number of our records in epoch 0, in what goes out.
static void schDtlsSent(Sch *x, const std::string &d)
{
    const unsigned char *p = (const unsigned char *)d.data();
    size_t n = d.size();
    while (n >= 13)
    {
        size_t len = getN(p + 11, 2);
        if (getN(p + 3, 2) == 0)
        {
            unsigned long long seq = 0;
            for (int i = 5; i < 11; i++)
            {
                seq = (seq << 8) | p[i];
            }
            if (seq > x->sentSeq0)
            {
                x->sentSeq0 = seq;
            }
        }
        if (13 + len > n)
        {
            return;
        }
        p += 13 + len;
        n -= 13 + len;
    }
}

// A fatal alert in clear (epoch 0, before our keys change): what OpenSSL's
// client sends when it refuses the server's certificate.
static std::string schDtlsAlert(Sch *x, DWORD number)
{
    unsigned long long seq = x->sentSeq0 + 1;
    unsigned char r[15] = { 21, 0xfe, 0xfd, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2, 2, (unsigned char)number };
    for (int i = 10; i >= 5; i--)
    {
        r[i] = (unsigned char)(seq & 0xff);
        seq >>= 8;
    }
    return std::string((const char *)r, sizeof(r));
}

// The server's certificate, from its flight in clear, checked as for TLS.
static bool schDtlsCheck(DtlsConn *c, Sch *x)
{
    HCERTSTORE store = CertOpenStore(CERT_STORE_PROV_MEMORY, 0, 0, 0, nullptr);
    PCCERT_CONTEXT leaf = nullptr;
    for (size_t i = 0; i < x->peerChain.size(); i++)
    {
        PCCERT_CONTEXT one = nullptr;
        CertAddEncodedCertificateToStore(store, X509_ASN_ENCODING, (const BYTE *)x->peerChain[i].data(),
                                         (DWORD)x->peerChain[i].size(), CERT_STORE_ADD_ALWAYS, &one);
        if (i == 0)
        {
            leaf = one;
        }
        else if (one != nullptr)
        {
            CertFreeCertificateContext(one);
        }
    }
    bool ok;
    if (leaf == nullptr)
    {
        c->trust.set = true;
        c->trust.name = "SEC_E_CERT_UNKNOWN";
        c->trust.text = "the server sent no certificate";
        ok = false;
    }
    else
    {
        ok = schTrust(c, x, leaf);
        CertFreeCertificateContext(leaf);
    }
    CertCloseStore(store, 0);
    return ok;
}

static void schDtlsSend(DtlsEndpoint *ep, const std::string &d)
{
    if (!d.empty() && ep->fd != BAD_SOCKET)
    {
        send(ep->fd, d.data(), (int)d.size(), 0);   // connected; a lost one is sent again
    }
}

static void schDtlsFail(DtlsEndpoint *ep, DtlsConn *c, SECURITY_STATUS st)
{
    TlsOutcome o;
    o.status = TLS_SSL_ERROR;
    o.handshaking = c->state == DtlsConn::HANDSHAKING;
    o.schStatus = (long)st;
    failConn(ep, c, o);
}

// One step of the handshake: the datagram d (nullptr: the first step, or
// the last flight again), and whatever Schannel answers, fragment by
// fragment, each a datagram of its own.
static void schDtlsStep(DtlsEndpoint *ep, DtlsConn *c, std::string *d)
{
    Sch *x = c->sch;
    SEC_WCHAR *target = x->target.empty() ? nullptr : &x->target[0];
    SECURITY_STATUS st;
    std::string flight;
    if (d != nullptr)
    {
        schDtlsGather(x, *d);                   // before Schannel works on it in place
    }
    for (int fragments = 0; ; fragments++)
    {
        bool first = !x->haveCtx;
        SecBuffer inb[2] = { { d != nullptr ? (unsigned long)d->size() : 0, SECBUFFER_TOKEN,
                               d != nullptr && !d->empty() ? &(*d)[0] : nullptr },
                             { 0, SECBUFFER_EMPTY, nullptr } };
        SecBufferDesc ind = { SECBUFFER_VERSION, 2, inb };
        SecBuffer outb[2] = { { 0, SECBUFFER_TOKEN, nullptr }, { 0, SECBUFFER_ALERT, nullptr } };
        SecBufferDesc outd = { SECBUFFER_VERSION, 2, outb };
        ULONG attrs = 0;
        TimeStamp expiry;
        st = InitializeSecurityContextW(&x->cred->h, first ? nullptr : &x->ctx, target, SCH_DTLS_FLAGS, 0, 0,
                                        first ? nullptr : &ind, 0, &x->ctx, &outd, &attrs, &expiry);
        if (first && (st == SEC_I_CONTINUE_NEEDED || st == SEC_E_OK || st == SEC_I_MESSAGE_FRAGMENT))
        {
            x->haveCtx = true;
        }
        std::string tok;
        if (outb[0].pvBuffer != nullptr)
        {
            tok.assign((const char *)outb[0].pvBuffer, outb[0].cbBuffer);
            FreeContextBuffer(outb[0].pvBuffer);
        }
        if (outb[1].pvBuffer != nullptr)
        {
            FreeContextBuffer(outb[1].pvBuffer);
        }
        if (st != SEC_I_CONTINUE_NEEDED && st != SEC_E_OK && st != SEC_I_MESSAGE_FRAGMENT &&
            st != SEC_E_INCOMPLETE_MESSAGE)
        {
            schDtlsSend(ep, tok);               // an alert, if Schannel made one
            schDtlsFail(ep, c, st);
            return;
        }
        if (!x->checked && !tok.empty() && !x->peerChain.empty())
        {
            // Before our next flight: is the server's certificate good?
            x->checked = true;
            if (!schDtlsCheck(c, x))
            {
                schDtlsSend(ep, schDtlsAlert(x, alertFor(c->trust)));
                schDtlsFail(ep, c, SEC_E_CERT_UNKNOWN);
                return;
            }
        }
        if (!x->checked && st == SEC_E_OK)
        {
            // (not read from the flight: Schannel's, now that it is over)
            PCCERT_CONTEXT leaf = nullptr;
            if (QueryContextAttributesW(&x->ctx, SECPKG_ATTR_REMOTE_CERT_CONTEXT, &leaf) == SEC_E_OK
                && leaf != nullptr)
            {
                x->checked = true;
                bool ok = schTrust(c, x, leaf);
                CertFreeCertificateContext(leaf);
                if (!ok)
                {
                    schDtlsFail(ep, c, SEC_E_CERT_UNKNOWN);   // (no alert: as close_notify)
                    return;
                }
            }
        }
        schDtlsSent(x, tok);
        schDtlsSend(ep, tok);
        if (st != SEC_I_MESSAGE_FRAGMENT || fragments > 64)
        {
            break;
        }
        d = nullptr;                            // the next fragment
    }
    if (st == SEC_E_OK)
    {
        if (!x->checked)
        {
            c->trust.set = true;
            c->trust.name = "SEC_E_CERT_UNKNOWN";
            c->trust.text = "the server sent no certificate";
            schDtlsFail(ep, c, SEC_E_CERT_UNKNOWN);
            return;
        }
        if (!x->peerChain.empty())
        {
            // What was checked must be what Schannel used: fragments sent
            // twice with different bytes could make the two differ.
            PCCERT_CONTEXT used = nullptr;
            bool same = QueryContextAttributesW(&x->ctx, SECPKG_ATTR_REMOTE_CERT_CONTEXT, &used) == SEC_E_OK
                        && used != nullptr && used->cbCertEncoded == x->peerChain[0].size()
                        && memcmp(used->pbCertEncoded, x->peerChain[0].data(), used->cbCertEncoded) == 0;
            if (used != nullptr)
            {
                CertFreeCertificateContext(used);
            }
            if (same)
            {
                x->checkedDer = x->peerChain[0];
            }
            if (!same)
            {
                c->trust = TrustError();
                c->trust.set = true;
                c->trust.name = "SEC_E_CERT_UNKNOWN";
                c->trust.text = "the server's certificate is not the one that was checked";
                schDtlsFail(ep, c, SEC_E_CERT_UNKNOWN);
                return;
            }
        }
        DWORD mtu = SCH_DTLS_MTU;
        SetContextAttributesW(&x->ctx, SECPKG_ATTR_DTLS_MTU, &mtu, sizeof(mtu));
        x->done = true;
        c->state = DtlsConn::OPEN;
        return;
    }
    // waiting for the server: its answer, or the timer
    x->resendAt = Clock::now() + std::chrono::milliseconds(x->resendMs);
}

// Once connected, the records of the datagram d one by one: DecryptMessage
// takes only the first record of what it is given (the v9 review), and a
// peer may put several in one datagram (RFC 6347, 4.1.1). Records of data
// and alerts are decrypted each on its own; from a handshake record on
// (the server's last flight again), the rest goes as it is. A record cut
// short ends the datagram: the rest is dropped, as DTLS does.
static void schDtlsRecord(DtlsEndpoint *ep, DtlsConn *c, std::string d);

static void schDtlsRecords(DtlsEndpoint *ep, DtlsConn *c, const std::string &d)
{
    const unsigned char *p = (const unsigned char *)d.data();
    size_t at = 0;
    while (at < d.size() && c->state == DtlsConn::OPEN)
    {
        size_t len = at + 13 <= d.size() ? getN(p + at + 11, 2) : 0;
        if (at + 13 > d.size() || at + 13 + len > d.size())
        {
            if (at == 0)
            {
                schDtlsRecord(ep, c, d);       // not a record: as before (dropped)
            }
            return;
        }
        if (p[at] != 23 && p[at] != 21)        // not application data, not an alert
        {
            schDtlsRecord(ep, c, d.substr(at));
            return;
        }
        schDtlsRecord(ep, c, d.substr(at, 13 + len));
        at += 13 + len;
    }
}

// What arrived for the client, by Schannel: the handshake goes on, or the
// data is kept for receive. A datagram that does not decrypt is dropped,
// as DTLS does.
static void schDtlsDrive(DtlsEndpoint *ep, DtlsConn *c)
{
    Sch *x = c->sch;
    if (!x->haveCtx && c->state == DtlsConn::HANDSHAKING)
    {
        x->resendMs = SCH_DTLS_FIRST_RESEND_MS;
        schDtlsStep(ep, c, nullptr);            // the ClientHello
    }
    while (!c->wire.empty() && c->state <= DtlsConn::OPEN)
    {
        std::string d = c->wire.front();
        c->wire.pop_front();
        if (c->state == DtlsConn::HANDSHAKING)
        {
            x->resends = 0;
            x->resendMs = SCH_DTLS_FIRST_RESEND_MS;
            schDtlsStep(ep, c, &d);
            continue;
        }
        schDtlsRecords(ep, c, d);
    }
}

// One record once connected (or, from a handshake record on, the rest of
// the datagram).
static void schDtlsRecord(DtlsEndpoint *ep, DtlsConn *c, std::string d)
{
    Sch *x = c->sch;
    {
        bool handshake = !d.empty() && d[0] == 22;
        SecBuffer b[4] = { { (unsigned long)d.size(), SECBUFFER_DATA, d.empty() ? nullptr : &d[0] },
                           { 0, SECBUFFER_EMPTY, nullptr }, { 0, SECBUFFER_EMPTY, nullptr },
                           { 0, SECBUFFER_EMPTY, nullptr } };
        SecBufferDesc desc = { SECBUFFER_VERSION, 4, b };
        std::string copy = d;
        SECURITY_STATUS st = DecryptMessage(&x->ctx, &desc, 0, nullptr);
        if (st == SEC_E_OK)
        {
            for (int i = 0; i < 4; i++)
            {
                if (b[i].BufferType == SECBUFFER_DATA)
                {
                    c->app.push_back(std::string((const char *)b[i].pvBuffer, b[i].cbBuffer));
                    break;
                }
            }
        }
        else if (st == SEC_I_CONTEXT_EXPIRED)
        {
            c->state = DtlsConn::PEER_CLOSED;   // close_notify
        }
        else if (handshake)
        {
            // The server's last flight again: ours was lost. Schannel
            // answers it with ours again.
            std::string tok;
            SecBuffer inb[2] = { { (unsigned long)copy.size(), SECBUFFER_TOKEN, &copy[0] },
                                 { 0, SECBUFFER_EMPTY, nullptr } };
            SecBufferDesc ind = { SECBUFFER_VERSION, 2, inb };
            SecBuffer outb[2] = { { 0, SECBUFFER_TOKEN, nullptr }, { 0, SECBUFFER_ALERT, nullptr } };
            SecBufferDesc outd = { SECBUFFER_VERSION, 2, outb };
            ULONG attrs = 0;
            TimeStamp expiry;
            SECURITY_STATUS r = InitializeSecurityContextW(&x->cred->h, &x->ctx,
                                       x->target.empty() ? nullptr : &x->target[0],
                                       SCH_DTLS_FLAGS, 0, 0, &ind, 0, &x->ctx, &outd, &attrs, &expiry);
            if (outb[0].pvBuffer != nullptr)
            {
                tok.assign((const char *)outb[0].pvBuffer, outb[0].cbBuffer);
                FreeContextBuffer(outb[0].pvBuffer);
            }
            if (outb[1].pvBuffer != nullptr)
            {
                FreeContextBuffer(outb[1].pvBuffer);
            }
            if (r == SEC_E_OK && !schSameCertificate(x, x->checkedDer))
            {
                schDtlsFail(ep, c, SEC_E_CERT_UNKNOWN);  // another certificate: refused
                return;
            }
            schDtlsSend(ep, tok);
        }
    }
}

// The client's retransmission timer: the milliseconds until it fires, or
// -1; when it has, the last flight goes again (and after too many, the
// handshake fails: the peer does not answer).
static int schDtlsTimer(DtlsEndpoint *ep, DtlsConn *c)
{
    Sch *x = c->sch;
    if (c->state != DtlsConn::HANDSHAKING || !x->haveCtx)
    {
        return -1;
    }
    auto left = std::chrono::duration_cast<std::chrono::milliseconds>(x->resendAt - Clock::now()).count();
    if (left > 0)
    {
        return (int)left + 1;
    }
    if (++x->resends > SCH_DTLS_MAX_RESENDS)
    {
        TlsOutcome o;
        o.status = TLS_TIMEOUT;
        o.handshaking = true;
        failConn(ep, c, o);
        return -1;
    }
    x->resendMs = x->resendMs * 2 > SCH_DTLS_MAX_RESEND_MS ? SCH_DTLS_MAX_RESEND_MS : x->resendMs * 2;
    schDtlsStep(ep, c, nullptr);               // the last flight again
    return c->state == DtlsConn::HANDSHAKING ? x->resendMs : -1;
}

// The client's DTLS by Schannel: credentials, and the connection.
static SECURITY_STATUS schDtlsClient(DtlsConn *c, RexxMethodContext *context, RexxArrayObject trusted)
{
    Sch *x = new Sch();
    x->datagram = true;
    c->sch = x;
    if (!isAddress(c->host))
    {
        x->target = wide(c->host);
    }
    size_t count = context->ArrayItems(trusted);
    for (size_t i = 1; i <= count; i++)
    {
        RexxObjectPtr item = context->ArrayAt(trusted, i);
        if (item != NULLOBJECT)
        {
            RexxStringObject der = context->ObjectToString(item);
            x->trusted.push_back(std::string(context->StringData(der), context->StringLength(der)));
        }
    }
    return schCredentials(SECPKG_CRED_OUTBOUND,
                          SCH_USE_STRONG_CRYPTO | SCH_CRED_NO_DEFAULT_CREDS | SCH_CRED_MANUAL_CRED_VALIDATION,
                          SP_PROT_DTLS1_2_CLIENT, nullptr, x->cred, true);
}

#endif

// Lets OpenSSL read what has arrived for c: the handshake goes on, or the
// data is kept for receive.
static void driveConn(DtlsEndpoint *ep, DtlsConn *c)
{
#ifdef _WIN32
    if (c->sch != nullptr)
    {
        schDtlsDrive(ep, c);
        return;
    }
#endif
    if (c->state == DtlsConn::HANDSHAKING)
    {
        ERR_clear_error();
        c->ioError = 0;
        int rc = SSL_do_handshake(c->ssl);
        if (rc == 1)
        {
            c->state = DtlsConn::OPEN;
        }
        else
        {
            int e = SSL_get_error(c->ssl, rc);
            if (e != SSL_ERROR_WANT_READ && e != SSL_ERROR_WANT_WRITE)
            {
                failConn(ep, c, dtlsOutcome(c, rc));
                return;
            }
            ERR_clear_error();
        }
    }
    if (c->state != DtlsConn::OPEN)
    {
        return;
    }
    std::vector<char> buf(DTLS_MAX_DATA + 1024);
    for (;;)
    {
        size_t got = 0;
        ERR_clear_error();
        c->ioError = 0;
        int rc = SSL_read_ex(c->ssl, buf.data(), buf.size(), &got);
        if (rc == 1)
        {
            c->app.push_back(std::string(buf.data(), got));
            continue;
        }
        int e = SSL_get_error(c->ssl, rc);
        if (e == SSL_ERROR_WANT_READ || e == SSL_ERROR_WANT_WRITE)
        {
            ERR_clear_error();
            return;
        }
        if (e == SSL_ERROR_ZERO_RETURN)
        {
            ERR_clear_error();
            c->state = DtlsConn::PEER_CLOSED;
            return;
        }
        failConn(ep, c, dtlsOutcome(c, rc));
        return;
    }
}

// A ClientHello of epoch 0: a client beginning a connection.
static bool isClientHello(const char *d, size_t n)
{
    return n > 13 && (unsigned char)d[0] == 22 && d[3] == 0 && d[4] == 0 && d[13] == 1;
}

// A server's new client: its first datagram goes to DTLSv1_listen, which
// answers with a cookie, or (when the datagram carries the right cookie)
// accepts it. The connection, or nullptr.
static DtlsConn *listenFor(DtlsEndpoint *ep, const char *d, size_t n, const struct sockaddr_storage &from,
                           socklen_type fromLen, const std::string &key)
{
    if (!isClientHello(d, n))
    {
        return nullptr;
    }
    size_t pending = 0;
    for (auto &kv : ep->conns)
    {
        pending += kv.second->state == DtlsConn::HANDSHAKING ? 1 : 0;
    }
    if (pending >= DTLS_MAX_PENDING || ep->ready.size() >= DTLS_MAX_PENDING)
    {
        return nullptr;
    }
    DtlsConn *c = newConn(ep, from, fromLen);
    c->key = key;
    c->wire.push_back(std::string(d, n));
    BIO_ADDR *client = BIO_ADDR_new();
    ERR_clear_error();
    int rc = DTLSv1_listen(c->ssl, client);
    BIO_ADDR_free(client);
    ERR_clear_error();
    if (rc != 1)
    {
        freeConn(c);              // a HelloVerifyRequest went out, or it was not one
        return nullptr;
    }
    c->wire.clear();
    return c;
}

static void dispatch(DtlsEndpoint *ep, const char *d, size_t n, const struct sockaddr_storage &from,
                     socklen_type fromLen)
{
    if (!ep->server)
    {
        if (ep->client != nullptr && ep->client->state <= DtlsConn::OPEN)
        {
            ep->client->wire.push_back(std::string(d, n));
            driveConn(ep, ep->client);
        }
        return;
    }
    std::string key = peerKey((const struct sockaddr *)&from);
    auto it = ep->conns.find(key);
    if (it != ep->conns.end())
    {
        DtlsConn *c = it->second;
        if (c->state != DtlsConn::HANDSHAKING && isClientHello(d, n))
        {
            // The peer begins anew (it was restarted, say): once it has the
            // cookie, the old connection is over.
            DtlsConn *fresh = listenFor(ep, d, n, from, fromLen, key);
            if (fresh == nullptr)
            {
                return;
            }
            ep->conns.erase(it);
            if (c->accepted)
            {
                if (c->state <= DtlsConn::OPEN)
                {
                    c->state = DtlsConn::PEER_CLOSED;
                    c->restarted = true;
                }
            }
            else
            {
                dropConn(ep, c);         // superseded before anyone saw it
            }
            ep->conns[key] = fresh;
            ep->ready.push_back(fresh);
            driveConn(ep, fresh);
            return;
        }
        if (c->state <= DtlsConn::OPEN)
        {
            c->wire.push_back(std::string(d, n));
            driveConn(ep, c);
        }
        return;
    }
    DtlsConn *fresh = listenFor(ep, d, n, from, fromLen, key);
    if (fresh != nullptr)
    {
        ep->conns[key] = fresh;
        ep->ready.push_back(fresh);      // accept returns it now; the handshake goes on
        driveConn(ep, fresh);
    }
}

// Reads every datagram waiting (under the lock).
static void pump(DtlsEndpoint *ep)
{
    std::vector<char> buf(65536);
    for (int i = 0; i < 256 && ep->fd != BAD_SOCKET; i++)
    {
        struct sockaddr_storage from;
        socklen_type fromLen = sizeof(from);
        memset(&from, 0, sizeof(from));
        long n = (long)recvfrom(ep->fd, buf.data(), (int)buf.size(), 0, (struct sockaddr *)&from, &fromLen);
        if (n < 0)
        {
            int e = lastError();
            if (interrupted(e))
            {
                continue;
            }
            if (wouldBlock(e) || ep->server)
            {
                return;
            }
            // The client's socket is connected: "port unreachable" comes
            // back as this error.
#ifdef _WIN32
            if (e == WSAECONNRESET)
            {
                e = WSAECONNREFUSED;
            }
#endif
            DtlsConn *c = ep->client;
            if (c != nullptr && c->state <= DtlsConn::OPEN)
            {
                TlsOutcome o;
                o.status = TLS_SOCKET_ERROR;
                o.socketError = e;
                o.handshaking = c->state == DtlsConn::HANDSHAKING;
                failConn(ep, c, o);
            }
            return;
        }
        dispatch(ep, buf.data(), (size_t)n, from, fromLen);
    }
}

// DTLS's retransmission timers: each that has expired fires (sending its
// flight again). The milliseconds until the next one, or -1.
static int dtlsTimers(DtlsEndpoint *ep)
{
    std::vector<DtlsConn *> all;
    if (ep->server)
    {
        for (auto &kv : ep->conns)
        {
            all.push_back(kv.second);
        }
    }
    else if (ep->client != nullptr)
    {
        all.push_back(ep->client);
    }
    int next = -1;
    for (DtlsConn *c : all)
    {
        if (c->state > DtlsConn::OPEN)
        {
            continue;
        }
#ifdef _WIN32
        if (c->sch != nullptr)
        {
            int ms = schDtlsTimer(ep, c);
            if (ms >= 0 && (next < 0 || ms < next))
            {
                next = ms;
            }
            continue;
        }
#endif
        struct timeval tv;
        if (DTLSv1_get_timeout(c->ssl, &tv) != 1)
        {
            continue;
        }
        if (tv.tv_sec == 0 && tv.tv_usec == 0)
        {
            ERR_clear_error();
            c->ioError = 0;
            if (DTLSv1_handle_timeout(c->ssl) < 0)
            {
                TlsOutcome o;
                o.status = TLS_TIMEOUT;
                o.handshaking = c->state == DtlsConn::HANDSHAKING;
                ERR_clear_error();
                failConn(ep, c, o);
                continue;
            }
            ERR_clear_error();
            if (DTLSv1_get_timeout(c->ssl, &tv) != 1)
            {
                continue;
            }
        }
        long ms = (long)tv.tv_sec * 1000 + tv.tv_usec / 1000 + 1;
        if (next < 0 || ms < next)
        {
            next = (int)ms;
        }
    }
    return next;
}

static void closeEndpointFd(DtlsEndpoint *ep)
{
    if (ep->fd == BAD_SOCKET)
    {
        return;
    }
    if (ep->reading)
    {
        // The waiter polling it closes it when its poll ends (at most
        // SLICE_MS); shutdown may end that poll at once.
        ep->closeAfterRead = true;
#ifdef _WIN32
        shutdown(ep->fd, SD_BOTH);
#else
        shutdown(ep->fd, SHUT_RDWR);
#endif
        return;
    }
    closesock(ep->fd);
    ep->fd = BAD_SOCKET;
}

// Waits, under lk, until done() (checked under the lock), the deadline or
// SLICE_MS. 1 done; 0 the deadline came; 2 the slice ended; -1 closed.
template <class Done>
static int dtlsWait(DtlsEndpoint *ep, std::unique_lock<std::mutex> &lk, bool hasDeadline,
                    Clock::time_point deadline, Done done)
{
    Clock::time_point sliceEnd = Clock::now() + std::chrono::milliseconds(SLICE_MS);
    for (;;)
    {
        if (ep->closing || ep->fd == BAD_SOCKET)
        {
            return -1;
        }
        int timer = dtlsTimers(ep);
        if (done())
        {
            return 1;
        }
        Clock::time_point now = Clock::now();
        if (hasDeadline && now >= deadline)
        {
            return 0;
        }
        if (now >= sliceEnd)
        {
            return 2;
        }
        long ms = (long)std::chrono::duration_cast<std::chrono::milliseconds>(sliceEnd - now).count();
        if (hasDeadline)
        {
            long d = (long)std::chrono::duration_cast<std::chrono::milliseconds>(deadline - now).count();
            ms = d < ms ? d : ms;
        }
        if (timer >= 0 && timer < ms)
        {
            ms = timer;
        }
        if (ms < 1)
        {
            ms = 1;
        }
        if (!ep->reading)
        {
            ep->reading = true;
            sock_t fd = ep->fd;
            lk.unlock();
            struct pollfd p;
            p.fd = fd;
            p.events = POLLIN;
            p.revents = 0;
            int rc = pollsock(&p, 1, (int)ms);
            int e = rc < 0 ? lastError() : 0;
            lk.lock();
            ep->reading = false;
            if (ep->closeAfterRead)
            {
                ep->closeAfterRead = false;
                closesock(ep->fd);
                ep->fd = BAD_SOCKET;
            }
            if (rc > 0 && !ep->closing && ep->fd != BAD_SOCKET)
            {
                pump(ep);
            }
            ep->cv.notify_all();
            if (rc < 0 && interrupted(e))
            {
                return 2;            // a signal: let a HALT be seen
            }
        }
        else
        {
            ep->cv.wait_for(lk, std::chrono::milliseconds(ms));
        }
    }
}

/* ---- results ----------------------------------------------------------------- */

static int dtlsMinVersion(const char *v)
{
    if (strcmp(v, "1.3") == 0)
    {
#ifdef DTLS1_3_VERSION
        return DTLS1_3_VERSION;
#else
        return -1;
#endif
    }
    return DTLS1_2_VERSION;
}

static RexxArrayObject dtlsUnsupported(RexxMethodContext *context)
{
    return errorArray(context, "DTLS 1.3 is not supported (OpenSSL " OPENSSL_VERSION_STR ")", "", 0);
}

// After a connection has failed (or been closed by its peer, or by us).
static RexxArrayObject connResult(RexxMethodContext *context, DtlsConn *c)
{
    switch (c->state)
    {
        case DtlsConn::PEER_CLOSED:
            return errorArray(context, c->restarted ? "the peer began a new connection"
                                                    : "the peer closed the connection", "EOF", 0);
        case DtlsConn::CLOSED:
            return closedResult(context);
        default:
            break;
    }
    const TlsOutcome &o = c->failure;
    if (o.status == TLS_SOCKET_ERROR)
    {
        return errorResult(context, o.socketError);
    }
    if (o.status == TLS_TIMEOUT)
    {
        return errorArray(context, o.handshaking ? "handshake failed: the peer no longer answers"
                                                 : "the peer no longer answers", "ETIMEDOUT", 0);
    }
    return tlsIoResult(context, o);
}

static DtlsHandle *handleOf(void *cself)
{
    return (DtlsHandle *)cself;
}

// The client's handshake, for SLICE_MS at most: "OK", "AGAIN" and the
// seconds left, "TIMEOUT", or the failure.
static RexxArrayObject clientStep(RexxMethodContext *context, DtlsHandle *h, double timeout)
{
    DtlsEndpoint *ep = h->ep.get();
    DtlsConn *c = h->conn;
    bool hasDeadline = timeout >= 0;
    Clock::time_point deadline = deadlineFrom(hasDeadline ? timeout : 0);
    std::unique_lock<std::mutex> lk(ep->mu);
    int w = dtlsWait(ep, lk, hasDeadline, deadline, [&]() { return c->state != DtlsConn::HANDSHAKING; });
    if (w == 1)
    {
        // (the peer may have closed already, right after the handshake)
        if (c->state == DtlsConn::OPEN || c->state == DtlsConn::PEER_CLOSED)
        {
            return statusResult(context, "OK");
        }
        if (c->failure.status == TLS_TIMEOUT)
        {
            return statusResult(context, "TIMEOUT");
        }
        return handshakeFailure(context, c, c->failure);
    }
    if (w == 0)
    {
        return statusResult(context, "TIMEOUT");
    }
    if (w == 2)
    {
        return statusResult(context, "AGAIN", context->DoubleToObject(secondsLeft(hasDeadline, deadline)));
    }
    return closedResult(context);
}

/* ---- the client -------------------------------------------------------------- */

// nConnect(host, port, trusted, minVersion, timeout): a UDP socket
// connected to host and port, and the DTLS handshake. "OK"; "AGAIN" and the
// seconds left (nMore goes on); "TIMEOUT"; "SOCKET", text, name, number (no
// socket to the host: resolving, creating); or "ERROR", text, name, number
// (the handshake).
RexxMethod5(RexxArrayObject, dtls_connect, CSTRING, host, CSTRING, port, RexxArrayObject, trusted,
            CSTRING, minVersion, double, timeout)
{
#ifdef _WIN32
    bool bySchannel = dtlsClientBySchannel();
    if (bySchannel && strcmp(minVersion, "1.3") == 0)
    {
        return errorArray(context, "DTLS 1.3 is not supported (Schannel)", "", 0);
    }
#else
    const bool bySchannel = false;
#endif
    if (!bySchannel && !opensslHere())
    {
        return opensslMissing(context);
    }
    int minProto = bySchannel ? DTLS1_2_VERSION : dtlsMinVersion(minVersion);
    if (minProto < 0)
    {
        return dtlsUnsupported(context);
    }
    struct addrinfo hints;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_DGRAM;
    hints.ai_protocol = IPPROTO_UDP;
    struct addrinfo *list = nullptr;
    int rc = getaddrinfo(host, port, &hints, &list);
    if (rc != 0)
    {
        RexxArrayObject r = gaiErrorResult(context, rc);
        context->ArrayPut(r, context->String("SOCKET"), 1);
        return r;
    }
    // IPv4 first, for a name with both (as UDPSocket~send: UDP cannot try
    // the next address).
    struct addrinfo *pick = nullptr;
    for (struct addrinfo *ai = list; ai != nullptr && pick == nullptr; ai = ai->ai_next)
    {
        pick = ai->ai_family == AF_INET ? ai : nullptr;
    }
    if (pick == nullptr)
    {
        pick = list;
    }
    sock_t fd = socket(pick->ai_family, SOCK_DGRAM, IPPROTO_UDP);
    int err = fd == BAD_SOCKET ? lastError() : 0;
    if (fd != BAD_SOCKET)
    {
        prepareSocket(fd);
        if (connect(fd, pick->ai_addr, (socklen_type)pick->ai_addrlen) != 0)
        {
            err = lastError();
            closesock(fd);
            fd = BAD_SOCKET;
        }
    }
    struct sockaddr_storage peer;
    memset(&peer, 0, sizeof(peer));
    socklen_type peerLen = (socklen_type)pick->ai_addrlen;
    memcpy(&peer, pick->ai_addr, pick->ai_addrlen);
    freeaddrinfo(list);
    if (fd == BAD_SOCKET)
    {
        RexxArrayObject r = errorResult(context, err);
        context->ArrayPut(r, context->String("SOCKET"), 1);
        return r;
    }
    datagramBuffers(fd);
    connReset(fd, true);
    setBlocking(fd, false);

    DtlsHandle *h = new DtlsHandle();
    h->ep = std::make_shared<DtlsEndpoint>();
    DtlsEndpoint *ep = h->ep.get();
    ep->fd = fd;
#ifdef _WIN32
    if (bySchannel)
    {
        DtlsConn *c = new DtlsConn();
        c->ep = ep;
        memcpy(&c->peer, &peer, sizeof(peer));
        c->peerLen = peerLen;
        c->host = host;
        c->accepted = true;              // it belongs to its DTLSSocket
        SECURITY_STATUS st = schDtlsClient(c, context, trusted);
        if (st != SEC_E_OK)
        {
            freeConn(c);
            delete h;                    // and the endpoint, and its socket
            return secResult(context, st, "cannot start DTLS: ");
        }
        ep->client = c;
        h->conn = c;
        context->SetObjectVariable("CSELF", context->NewPointer(h));
        {
            std::lock_guard<std::mutex> guard(ep->mu);
            driveConn(ep, c);            // the ClientHello goes out
        }
        return clientStep(context, h, timeout);
    }
#endif
    ep->ctx = clientContext(context, DTLS_client_method(), minProto, trusted);
    SSL_CTX_set_options(ep->ctx, SSL_OP_NO_RENEGOTIATION);
    DtlsConn *c = newConn(ep, peer, peerLen);
    c->host = host;
    c->accepted = true;                  // it belongs to its DTLSSocket
    setPeerName(c->ssl, c->host);
    SSL_set_connect_state(c->ssl);
    ep->client = c;
    h->conn = c;
    context->SetObjectVariable("CSELF", context->NewPointer(h));
    {
        std::lock_guard<std::mutex> guard(ep->mu);
        driveConn(ep, c);                // the ClientHello goes out
    }
    return clientStep(context, h, timeout);
}

// nMore(timeout): goes on with the client's handshake.
RexxMethod2(RexxArrayObject, dtls_more, CSELF, cself, double, timeout)
{
    DtlsHandle *h = handleOf(cself);
    if (h == nullptr || h->conn == nullptr)
    {
        return closedResult(context);
    }
    return clientStep(context, h, timeout);
}

/* ---- the server -------------------------------------------------------------- */

// nListen(port, address, file, password, minVersion): a DTLS server on a
// UDP port. "OK"; "SOCKET", text, name, number; or "ERROR", text (the
// certificate).
RexxMethod5(RexxArrayObject, dtls_listen, CSTRING, port, CSTRING, address, CSTRING, file, CSTRING, password,
            CSTRING, minVersion)
{
    if (!opensslHere())
    {
        return opensslMissing(context);
    }
    int minProto = dtlsMinVersion(minVersion);
    if (minProto < 0)
    {
        return dtlsUnsupported(context);
    }
    std::string why;
    SSL_CTX *ctx = serverContext(file, password, DTLS_server_method(), minProto, why);
    if (ctx == nullptr)
    {
        return errorArray(context, "cannot use " + std::string(file) + ": " + why, "", 0);
    }
    SSL_CTX_set_options(ctx, SSL_OP_COOKIE_EXCHANGE | SSL_OP_NO_RENEGOTIATION);
    SSL_CTX_set_cookie_generate_cb(ctx, cookieMake);
    SSL_CTX_set_cookie_verify_cb(ctx, cookieCheck);
    sock_t fd;
    bool gai;
    int err = openDatagram(port, address, false, fd, gai);
    if (err != 0)
    {
        SSL_CTX_free(ctx);
        RexxArrayObject r = gai ? gaiErrorResult(context, err) : errorResult(context, err);
        context->ArrayPut(r, context->String("SOCKET"), 1);
        return r;
    }
    datagramBuffers(fd);
    connReset(fd, false);
    setBlocking(fd, false);
    DtlsHandle *h = new DtlsHandle();
    h->ep = std::make_shared<DtlsEndpoint>();
    h->ep->fd = fd;
    h->ep->server = true;
    h->ep->ctx = ctx;
    RAND_bytes(h->ep->secret, sizeof(h->ep->secret));
    context->SetObjectVariable("CSELF", context->NewPointer(h));
    return statusResult(context, "OK");
}

// nAccept(timeout): "OK" and a pointer for DTLSSocket~new (a client that
// has sent the cookie back: its handshake goes on, and ends, or fails, by
// its first receive or send); "TIMEOUT"; "AGAIN" and the seconds left; or
// an error.
RexxMethod2(RexxArrayObject, dtls_accept, CSELF, cself, double, timeout)
{
    DtlsHandle *h = handleOf(cself);
    if (h == nullptr || h->conn != nullptr)
    {
        return closedResult(context);
    }
    DtlsEndpoint *ep = h->ep.get();
    bool hasDeadline = timeout >= 0;
    Clock::time_point deadline = deadlineFrom(hasDeadline ? timeout : 0);
    std::unique_lock<std::mutex> lk(ep->mu);
    int w = dtlsWait(ep, lk, hasDeadline, deadline, [&]() { return !ep->ready.empty(); });
    if (w == 1)
    {
        DtlsConn *c = ep->ready.front();
        ep->ready.pop_front();
        c->accepted = true;
        DtlsHandle *mine = new DtlsHandle();
        mine->ep = h->ep;
        mine->conn = c;
        return statusResult(context, "OK", context->NewPointer(mine));
    }
    if (w == 0)
    {
        return statusResult(context, "TIMEOUT");
    }
    if (w == 2)
    {
        return statusResult(context, "AGAIN", context->DoubleToObject(secondsLeft(hasDeadline, deadline)));
    }
    return closedResult(context);
}

// DTLSSocket~new(pointer): an accepted connection.
RexxMethod1(RexxObjectPtr, dtls_adopt, POINTER, p)
{
    context->SetObjectVariable("CSELF", context->NewPointer(p));
    return NULLOBJECT;
}

/* ---- either side's connection ------------------------------------------------ */

// nSend(data, timeout): one datagram (one DTLS record). "OK"; while an
// accepted client's handshake goes on, "AGAIN" and the seconds left (it
// waits for it, timeout < 0: as long as it takes), or "TIMEOUT"; or an
// error.
RexxMethod3(RexxArrayObject, dtls_send, CSELF, cself, RexxStringObject, data, double, timeout)
{
    DtlsHandle *h = handleOf(cself);
    if (h == nullptr || h->conn == nullptr)
    {
        return closedResult(context);
    }
    DtlsEndpoint *ep = h->ep.get();
    DtlsConn *c = h->conn;
    size_t size = context->StringLength(data);
    if (size > DTLS_MAX_DATA)
    {
#ifdef _WIN32
        return errorResult(context, WSAEMSGSIZE);
#else
        return errorResult(context, EMSGSIZE);
#endif
    }
    std::unique_lock<std::mutex> lk(ep->mu);
    if (ep->closing || ep->fd == BAD_SOCKET)
    {
        return closedResult(context);
    }
    if (c->state == DtlsConn::HANDSHAKING)
    {
        bool hasDeadline = timeout >= 0;
        Clock::time_point deadline = deadlineFrom(hasDeadline ? timeout : 0);
        int w = dtlsWait(ep, lk, hasDeadline, deadline, [&]() { return c->state != DtlsConn::HANDSHAKING; });
        if (w == 0)
        {
            return statusResult(context, "TIMEOUT");
        }
        if (w == 2)
        {
            return statusResult(context, "AGAIN", context->DoubleToObject(secondsLeft(hasDeadline, deadline)));
        }
        if (w < 0)
        {
            return closedResult(context);
        }
    }
    if (c->state != DtlsConn::OPEN)
    {
        return connResult(context, c);
    }
#ifdef _WIN32
    if (c->sch != nullptr)
    {
        Sch *x = c->sch;
        SecPkgContext_StreamSizes sz;           // the same layout as the datagram sizes
        memset(&sz, 0, sizeof(sz));
        QueryContextAttributesW(&x->ctx, SECPKG_ATTR_DATAGRAM_SIZES, &sz);
        if (size > sz.cbMaximumMessage)
        {
            return errorResult(context, WSAEMSGSIZE);
        }
        std::string rec(sz.cbHeader + size + sz.cbTrailer, '\0');
        if (size > 0)
        {
            memcpy(&rec[sz.cbHeader], context->StringData(data), size);
        }
        SecBuffer b[4] = { { sz.cbHeader, SECBUFFER_STREAM_HEADER, &rec[0] },
                           { (unsigned long)size, SECBUFFER_DATA, &rec[sz.cbHeader] },
                           { sz.cbTrailer, SECBUFFER_STREAM_TRAILER, &rec[sz.cbHeader + size] },
                           { 0, SECBUFFER_EMPTY, nullptr } };
        SecBufferDesc d = { SECBUFFER_VERSION, 4, b };
        SECURITY_STATUS st = EncryptMessage(&x->ctx, 0, &d, 0);
        if (st != SEC_E_OK)
        {
            return secResult(context, st, "", "TLS");
        }
        int n = send(ep->fd, rec.data(), (int)(b[0].cbBuffer + b[1].cbBuffer + b[2].cbBuffer), 0);
        if (n < 0)
        {
            int e = lastError();
            return errorResult(context, e == WSAECONNRESET ? WSAECONNREFUSED : e);   // the connection goes on
        }
        return statusResult(context, "OK");
    }
#endif
    ERR_clear_error();
    c->ioError = 0;
    size_t sent = 0;
    int rc = SSL_write_ex(c->ssl, context->StringData(data), size, &sent);
    if (rc == 1)
    {
        return statusResult(context, "OK");
    }
    TlsOutcome o = dtlsOutcome(c, rc);
    if (o.status == TLS_SOCKET_ERROR)
    {
        return errorResult(context, o.socketError);     // the connection goes on
    }
    return tlsIoResult(context, o);
}

// nReceive(timeout): "OK", data, address, port; "TIMEOUT"; "AGAIN" and
// the seconds left; or an error ("EOF" as its name once the peer closed).
RexxMethod2(RexxArrayObject, dtls_receive, CSELF, cself, double, timeout)
{
    DtlsHandle *h = handleOf(cself);
    if (h == nullptr || h->conn == nullptr)
    {
        return closedResult(context);
    }
    DtlsEndpoint *ep = h->ep.get();
    DtlsConn *c = h->conn;
    bool hasDeadline = timeout >= 0;
    Clock::time_point deadline = deadlineFrom(hasDeadline ? timeout : 0);
    std::unique_lock<std::mutex> lk(ep->mu);
    if (c->state == DtlsConn::CLOSED)
    {
        return closedResult(context);
    }
    int w = dtlsWait(ep, lk, hasDeadline, deadline,
                     [&]() { return !c->app.empty() || c->state > DtlsConn::OPEN; });
    if (!c->app.empty())
    {
        std::string d = c->app.front();
        c->app.pop_front();
        std::string host;
        int port = 0;
        addressText((struct sockaddr *)&c->peer, host, port);
        RexxArrayObject r = context->NewArray(4);
        context->ArrayAppendString(r, "OK", 2);
        context->ArrayAppend(r, context->NewString(d.data(), d.size()));
        context->ArrayAppendString(r, host.c_str(), host.size());
        context->ArrayAppend(r, context->WholeNumber(port));
        return r;
    }
    if (w == 1)
    {
        return connResult(context, c);
    }
    if (w == 0)
    {
        return statusResult(context, "TIMEOUT");
    }
    if (w == 2)
    {
        return statusResult(context, "AGAIN", context->DoubleToObject(secondsLeft(hasDeadline, deadline)));
    }
    return closedResult(context);
}

// nInfo: "OK", protocol ("DTLSv1.2"), cipher.
RexxMethod1(RexxArrayObject, dtls_info, CSELF, cself)
{
    DtlsHandle *h = handleOf(cself);
    std::string protocol, cipher;
    if (h != nullptr && h->conn != nullptr)
    {
        std::lock_guard<std::mutex> guard(h->ep->mu);
#ifdef _WIN32
        if (h->conn->sch != nullptr)
        {
            schInfo(h->conn->sch, protocol, cipher);
        }
#endif
        if (h->conn->ssl != nullptr && SSL_is_init_finished(h->conn->ssl))
        {
            protocol = SSL_get_version(h->conn->ssl);
            const char *name = SSL_get_cipher_name(h->conn->ssl);
            cipher = name != nullptr ? name : "";
        }
    }
    RexxArrayObject r = context->NewArray(3);
    context->ArrayAppendString(r, "OK", 2);
    context->ArrayAppendString(r, protocol.c_str(), protocol.size());
    context->ArrayAppendString(r, cipher.c_str(), cipher.size());
    return r;
}

// nAddress(which): "L" ours, "R" the peer's: "OK", address, port.
RexxMethod2(RexxArrayObject, dtls_address, CSELF, cself, CSTRING, which)
{
    DtlsHandle *h = handleOf(cself);
    if (h == nullptr)
    {
        return closedResult(context);
    }
    std::lock_guard<std::mutex> guard(h->ep->mu);
    struct sockaddr_storage ss;
    memset(&ss, 0, sizeof(ss));
    if (which[0] == 'R')
    {
        if (h->conn == nullptr)
        {
            return closedResult(context);
        }
        memcpy(&ss, &h->conn->peer, sizeof(ss));
    }
    else
    {
        socklen_type len = sizeof(ss);
        if (h->ep->fd == BAD_SOCKET || getsockname(h->ep->fd, (struct sockaddr *)&ss, &len) != 0)
        {
            return closedResult(context);
        }
    }
    std::string host;
    int port = 0;
    addressText((struct sockaddr *)&ss, host, port);
    RexxArrayObject r = context->NewArray(3);
    context->ArrayAppendString(r, "OK", 2);
    context->ArrayAppendString(r, host.c_str(), host.size());
    context->ArrayAppend(r, context->WholeNumber(port));
    return r;
}

static void closeHandle(DtlsHandle *h)
{
    DtlsEndpoint *ep = h->ep.get();
    std::lock_guard<std::mutex> guard(ep->mu);
    DtlsConn *c = h->conn;
    if (c == nullptr)
    {
        // the server: every connection it has ends with it
        ep->closing = true;
        closeEndpointFd(ep);
    }
    else
    {
        if (c->state == DtlsConn::OPEN && ep->fd != BAD_SOCKET && !ep->closing)
        {
#ifdef _WIN32
            if (c->sch != nullptr)
            {
                // Schannel's DTLS client cannot make close_notify: after
                // ApplyControlToken, every way of asking for it sends the
                // last flight again (measured, 29/10/2026). Nothing goes.
            }
            else
#endif
            {
                ERR_clear_error();
                SSL_shutdown(c->ssl);    // close_notify
                ERR_clear_error();
            }
        }
        c->state = DtlsConn::CLOSED;
        if (ep->server)
        {
            auto it = ep->conns.find(c->key);
            if (it != ep->conns.end() && it->second == c)
            {
                ep->conns.erase(it);
            }
        }
        else
        {
            ep->closing = true;
            closeEndpointFd(ep);
        }
    }
    ep->cv.notify_all();
}

// nClose: a connection sends close_notify; a server stops. Twice is harmless.
RexxMethod1(RexxObjectPtr, dtls_close, CSELF, cself)
{
    (void)context;
    DtlsHandle *h = handleOf(cself);
    if (h != nullptr)
    {
        closeHandle(h);
    }
    return NULLOBJECT;
}

// uninit
RexxMethod1(RexxObjectPtr, dtls_free, CSELF, cself)
{
    DtlsHandle *h = handleOf(cself);
    if (h != nullptr)
    {
        closeHandle(h);
        if (h->conn != nullptr)
        {
            DtlsEndpoint *ep = h->ep.get();
            std::lock_guard<std::mutex> guard(ep->mu);
            if (ep->client == h->conn)
            {
                ep->client = nullptr;
            }
            freeConn(h->conn);
            h->conn = nullptr;
        }
        delete h;               // the endpoint goes with its last handle
        context->SetObjectVariable("CSELF", context->NewPointer(nullptr));
    }
    return NULLOBJECT;
}

/*----------------------------------------------------------------------------*/
/* The package                                                                */
/*----------------------------------------------------------------------------*/

static void RexxEntry oosocketsLoader(RexxThreadContext *)
{
#ifdef _WIN32
    WSADATA wsa;
    WSAStartup(MAKEWORD(2, 2), &wsa);
#endif
}

static RexxMethodEntry oosockets_methods[] =
{
    REXX_METHOD(socket_connect,  socket_connect),
    REXX_METHOD(socket_connect_more, socket_connect_more),
    REXX_METHOD(socket_tls_more, socket_tls_more),
    REXX_METHOD(socket_adopt,    socket_adopt),
    REXX_METHOD(socket_recv,     socket_recv),
    REXX_METHOD(socket_send,     socket_send),
    REXX_METHOD(socket_shutdown, socket_shutdown),
    REXX_METHOD(socket_nodelay,  socket_nodelay),
    REXX_METHOD(socket_resolve,  socket_resolve),
    REXX_METHOD(sock_close,      sock_close),
    REXX_METHOD(sock_free,       sock_free),
    REXX_METHOD(sock_address,    sock_address),
    REXX_METHOD(server_listen,   server_listen),
    REXX_METHOD(server_accept,   server_accept),
    REXX_METHOD(socket_starttls, socket_starttls),
    REXX_METHOD(socket_starttls_server, socket_starttls_server),
    REXX_METHOD(socket_tlsinfo,  socket_tlsinfo),
    REXX_METHOD(server_tls,      server_tls),
    REXX_METHOD(tls_check_identity, tls_check_identity),
    REXX_METHOD(tls_load_certificates, tls_load_certificates),
    REXX_METHOD(udp_open,        udp_open),
    REXX_METHOD(udp_connect,     udp_connect),
    REXX_METHOD(udp_send,        udp_send),
    REXX_METHOD(udp_receive,     udp_receive),
    REXX_METHOD(udp_broadcast,   udp_broadcast),
    REXX_METHOD(mcast_group,     mcast_group),
    REXX_METHOD(mcast_option,    mcast_option),
    REXX_METHOD(dtls_connect,    dtls_connect),
    REXX_METHOD(dtls_more,       dtls_more),
    REXX_METHOD(dtls_listen,     dtls_listen),
    REXX_METHOD(dtls_accept,     dtls_accept),
    REXX_METHOD(dtls_adopt,      dtls_adopt),
    REXX_METHOD(dtls_send,       dtls_send),
    REXX_METHOD(dtls_receive,    dtls_receive),
    REXX_METHOD(dtls_info,       dtls_info),
    REXX_METHOD(dtls_address,    dtls_address),
    REXX_METHOD(dtls_close,      dtls_close),
    REXX_METHOD(dtls_free,       dtls_free),
    REXX_LAST_METHOD()
};

#ifndef OOSOCKETS_VERSION
  #define OOSOCKETS_VERSION "0.0.0"        // CMakeLists.txt's project version
#endif

static RexxPackageEntry oosockets_package_entry =
{
    STANDARD_PACKAGE_HEADER
    REXX_INTERPRETER_5_0_0,
    "oosockets",
    OOSOCKETS_VERSION,
    oosocketsLoader,
    nullptr,
    nullptr,
    oosockets_methods
};

OOREXX_GET_PACKAGE(oosockets);
