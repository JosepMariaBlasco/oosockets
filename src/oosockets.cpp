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
 * receives bytes, with optional timeouts, on IPv4 and IPv6, on Linux,
 * macOS and Windows. Everything a Rexx programmer sees (streams, lines,
 * NOTREADY, SYNTAX 48.900 and its message) is done in sockets.cls.
 *
 * Results that can fail come back as an array whose first item is a
 * status word:
 *   "OK"       [, value]
 *   "EOF"                       (recv: the peer closed its side)
 *   "TIMEOUT"
 *   "ERROR", text, name, number (text in English, the same on the three
 *                                systems for the common errors; name as
 *                                POSIX's, e.g. "ECONNREFUSED"; number the
 *                                system's own)
 *
 * The OS handle lives in a heap Sock, reached through CSELF.
 */

#include <string>
#include <vector>
#include <cstring>
#include <cstdio>
#include <cerrno>
#include <chrono>
#include <mutex>

#ifdef _WIN32
  #ifndef WIN32_LEAN_AND_MEAN
    #define WIN32_LEAN_AND_MEAN
  #endif
  #include <winsock2.h>
  #include <ws2tcpip.h>
  #include <windows.h>
  #include <wincrypt.h>                    // before OpenSSL, which undoes its X509_NAME
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

#ifdef __APPLE__
  #include <Security/Security.h>
#endif


// Why a certificate was refused: our text, the system's name and number.
struct TrustError
{
    bool set = false;
    std::string text;
    std::string name;
    long long code = 0;
};

struct Sock
{
    sock_t fd;
    // TLS, once started: the connection's own context and SSL. OpenSSL
    // does not allow two threads in one SSL at once, and a socket may be
    // read in one activity and written in another; so every SSL call is
    // made under mu, and mu is never held while waiting for the network.
    SSL_CTX *ctx = nullptr;
    SSL *ssl = nullptr;
    std::mutex mu;
    int ioError = 0;             // the last socket error the BIO met
    std::string host;            // the name verified (client)
    TrustError trust;            // why the system refused the certificate
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
    }
#endif
    return {"", nullptr};
}

static RexxArrayObject errorResult(RexxMethodContext *context, int code)
{
    ErrInfo e = errInfo(code);
    std::string text;
    if (e.text != nullptr)
    {
        text = e.text;
    }
    else
    {
#ifdef _WIN32
        char buf[512] = "";
        FormatMessageA(FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
                       nullptr, (DWORD)code, 0, buf, sizeof(buf), nullptr);
        text = buf;
        while (!text.empty() && (text.back() == '\n' || text.back() == '\r' || text.back() == '.'))
        {
            text.pop_back();
        }
#else
        text = strerror(code);
#endif
        if (!text.empty())
        {
            text[0] = (char)tolower((unsigned char)text[0]);
        }
    }
    RexxArrayObject r = context->NewArray(4);
    context->ArrayAppendString(r, "ERROR", 5);
    context->ArrayAppendString(r, text.c_str(), text.size());
    context->ArrayAppendString(r, e.name, strlen(e.name));
    context->ArrayAppend(r, context->WholeNumber(code));
    return r;
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
    RexxArrayObject r = context->NewArray(4);
    context->ArrayAppendString(r, "ERROR", 5);
    context->ArrayAppendString(r, text.c_str(), text.size());
    context->ArrayAppendString(r, name, strlen(name));
    context->ArrayAppend(r, context->WholeNumber(code));
    return r;
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

static void closeSock(Sock *s)
{
    if (s == nullptr)
    {
        return;
    }
    std::lock_guard<std::mutex> guard(s->mu);
    if (s->fd != BAD_SOCKET)
    {
        // TLS: tell the peer (close_notify), if the socket takes it now.
        if (s->ssl != nullptr)
        {
            ERR_clear_error();
            SSL_shutdown(s->ssl);
            ERR_clear_error();
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
/* OpenSSL does the TLS on the three systems (linked statically on macOS and  */
/* Windows). Who decides whether the server's certificate is good:            */
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
enum TlsStatus { TLS_OK, TLS_EOF, TLS_TIMEOUT, TLS_CLOSED, TLS_SOCKET_ERROR, TLS_SSL_ERROR };

struct TlsOutcome
{
    TlsStatus status = TLS_OK;
    int socketError = 0;          // TLS_SOCKET_ERROR
    unsigned long sslError = 0;   // TLS_SSL_ERROR: ERR_get_error()'s
    long verifyResult = X509_V_OK;
    bool handshaking = false;     // the handshake had not finished
};

// Runs call(ssl) until it succeeds, retrying when OpenSSL wants to read or
// write, waiting outside the lock (until the deadline, if there is one).
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
            int w = waitFor(fd, sslErr == SSL_ERROR_WANT_READ ? POLLIN : POLLOUT, hasDeadline, deadline, &err);
            if (w == 0)
            {
                out.status = TLS_TIMEOUT;
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

static RexxArrayObject errorArray(RexxMethodContext *context, const std::string &text,
                                  const std::string &name, long long code)
{
    RexxArrayObject r = context->NewArray(4);
    context->ArrayAppendString(r, "ERROR", 5);
    context->ArrayAppendString(r, text.c_str(), text.size());
    context->ArrayAppendString(r, name.c_str(), name.size());
    context->ArrayAppend(r, context->Int64ToObject(code));
    return r;
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

static TrustError opensslTrustError(long v);

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
            // "ERROR:TLS handshake failed: tlsv1 alert unknown ca" as the
            // description (the handshake of an accepted socket happens on
            // its first read or write).
            if (o.handshaking && o.verifyResult != X509_V_OK && o.verifyResult != X509_V_ERR_APPLICATION_VERIFICATION)
            {
                return errorArray(context, opensslTrustError(o.verifyResult).text, "TLS",
                                  (long long)o.verifyResult);
            }
            return errorArray(context, (o.handshaking ? "handshake failed: " : "") + sslReason(o.sslError),
                              "TLS", (long long)ERR_GET_REASON(o.sslError));
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
                    CFStringRef desc = err != nullptr ? CFErrorCopyDescription(err) : nullptr;
                    why.text = cfString(desc);
                    if (desc != nullptr)
                    {
                        CFRelease(desc);
                    }
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
    char buf[512] = "";
    FormatMessageA(FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS, nullptr, code,
                   MAKELANGID(LANG_ENGLISH, SUBLANG_ENGLISH_US), buf, sizeof(buf), nullptr);
    why.name = "HRESULT";
    why.text = buf;
    while (!why.text.empty() && (why.text.back() == '\n' || why.text.back() == '\r' || why.text.back() == '.'))
    {
        why.text.pop_back();
    }
    if (!why.text.empty())
    {
        why.text[0] = (char)tolower((unsigned char)why.text[0]);
    }
    else
    {
        why.text = CERT_UNTRUSTED;
    }
}

// Windows decides: the chain it builds (with the server's certificates as
// extra ones), and its SSL policy for the host name.
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
    if (!CertGetCertificateChain(nullptr, leaf, nullptr, extra, &para, 0, nullptr, &ctx))
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
        else
        {
            ok = true;
        }
        CertFreeCertificateChain(ctx);
    }
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
    Sock *s = (Sock *)SSL_get_app_data(ssl);
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
            ERR_clear_error();
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

// TLSOptions~nLoad(file, password): "OK" and the certificates in the file,
// each as DER bytes; or an error ("ERROR", text, "", 0).
RexxMethod2(RexxArrayObject, tls_load_certificates, CSTRING, file, OPTIONAL_CSTRING, password)
{
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
static RexxArrayObject handshakeFailure(RexxMethodContext *context, Sock *s, const TlsOutcome &o)
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
        return errorArray(context, s->trust.text, s->trust.name, s->trust.code);
    }
    if (o.verifyResult != X509_V_OK)
    {
        TrustError t = opensslTrustError(o.verifyResult);
        return errorArray(context, t.text, t.name, t.code);
    }
    return errorArray(context, "handshake failed: " + sslReason(o.sslError), "SSL_ERROR_SSL",
                      (long long)ERR_GET_REASON(o.sslError));
}

static int minVersionOf(const char *v)
{
    return strcmp(v, "1.3") == 0 ? TLS1_3_VERSION : TLS1_2_VERSION;
}

// Puts the Sock in TLS: a new SSL over our BIO; the socket non-blocking.
static void attachSsl(Sock *s, SSL_CTX *ctx)
{
    std::lock_guard<std::mutex> guard(s->mu);
    s->ctx = ctx;
    s->ssl = SSL_new(ctx);
    BIO *bio = BIO_new(sockBioMethod());
    BIO_set_data(bio, s);
    SSL_set_bio(s->ssl, bio, bio);
    SSL_set_app_data(s->ssl, s);
    setBlocking(s->fd, false);
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
    if (s->ssl != nullptr)
    {
        return errorArray(context, "TLS has already started on this connection", "", 0);
    }
    SSL_CTX *ctx = SSL_CTX_new(TLS_client_method());
    SSL_CTX_set_min_proto_version(ctx, minVersionOf(minVersion));
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

    s->host = host;
    s->trust = TrustError();
    attachSsl(s, ctx);
    {
        std::lock_guard<std::mutex> guard(s->mu);
        std::string h = s->host;
        if (isAddress(h))
        {
            X509_VERIFY_PARAM_set1_ip_asc(SSL_get0_param(s->ssl), h.substr(0, h.find('%')).c_str());
        }
        else
        {
            SSL_set_tlsext_host_name(s->ssl, h.c_str());   // SNI
            SSL_set1_host(s->ssl, h.c_str());
        }
    }
    bool hasDeadline = timeout >= 0;
    TlsOutcome o = tlsRun(s, hasDeadline, deadlineFrom(hasDeadline ? timeout : 0),
                          [](SSL *ssl) { return SSL_connect(ssl); });
    if (o.status == TLS_OK)
    {
        return statusResult(context, "OK");
    }
    return handshakeFailure(context, s, o);
}

// A server's TLS context, with the certificate and key in file (PKCS#12
// with its password, or PEM with both); nullptr and why if it cannot be.
static SSL_CTX *serverContext(const char *file, const char *password, const char *minVersion, std::string &why)
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
    SSL_CTX *ctx = SSL_CTX_new(TLS_server_method());
    SSL_CTX_set_min_proto_version(ctx, minVersionOf(minVersion));
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
// certificate and its key; else "ERROR", why.
RexxMethod2(RexxArrayObject, tls_check_identity, CSTRING, file, CSTRING, password)
{
    std::string why;
    SSL_CTX *ctx = serverContext(file, password, "1.2", why);
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
    if (s->ssl != nullptr)
    {
        return errorArray(context, "TLS has already started on this connection", "", 0);
    }
    std::string why;
    SSL_CTX *ctx = serverContext(file, password, minVersion, why);
    if (ctx == nullptr)
    {
        return errorArray(context, "cannot use " + std::string(file) + ": " + why, "", 0);
    }
    s->trust = TrustError();
    attachSsl(s, ctx);
    bool hasDeadline = timeout >= 0;
    TlsOutcome o = tlsRun(s, hasDeadline, deadlineFrom(hasDeadline ? timeout : 0),
                          [](SSL *ssl) { return SSL_accept(ssl); });
    if (o.status == TLS_OK)
    {
        return statusResult(context, "OK");
    }
    return handshakeFailure(context, s, o);
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
    SSL_CTX *ctx = serverContext(file, password, minVersion, why);
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
        on = s->ssl != nullptr;
        if (on && SSL_is_init_finished(s->ssl))
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

static bool isTls(Sock *s)
{
    std::lock_guard<std::mutex> guard(s->mu);
    return s->ssl != nullptr;
}

static RexxArrayObject tlsRecv(RexxMethodContext *context, Sock *s, size_t max, double timeout)
{
    std::vector<char> buf(max);
    size_t got = 0;
    bool hasDeadline = timeout >= 0;
    TlsOutcome o = tlsRun(s, hasDeadline, deadlineFrom(hasDeadline ? timeout : 0),
                          [&](SSL *ssl) { return SSL_read_ex(ssl, buf.data(), max, &got); });
    if (o.status == TLS_OK)
    {
        return statusResult(context, "OK", context->NewString(buf.data(), got));
    }
    return tlsIoResult(context, o);
}

static RexxArrayObject tlsSend(RexxMethodContext *context, Sock *s, const char *p, size_t left, double timeout)
{
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

// nConnect(host, port, timeout): timeout < 0 means none (the system's).
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

    bool hasDeadline = timeout >= 0;
    Clock::time_point deadline = deadlineFrom(hasDeadline ? timeout : 0);
    int lastErr = 0;
    bool timedOut = false;

    for (struct addrinfo *ai = list; ai != nullptr; ai = ai->ai_next)
    {
        sock_t fd = socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol);
        if (fd == BAD_SOCKET)
        {
            lastErr = lastError();
            continue;
        }
        prepareSocket(fd);
        setBlocking(fd, false);
        int err = 0;
        if (connect(fd, ai->ai_addr, (socklen_type)ai->ai_addrlen) != 0)
        {
            err = lastError();
            if (inProgress(err))
            {
                int w = waitFor(fd, POLLOUT, hasDeadline, deadline, &err);
                if (w == 0)
                {
                    timedOut = true;
                    closesock(fd);
                    break;          // the deadline is for the whole connect
                }
                if (w > 0)
                {
                    int soerr = 0;
                    socklen_type len = sizeof(soerr);
                    getsockopt(fd, SOL_SOCKET, SO_ERROR, (char *)&soerr, &len);
                    err = soerr;
                }
            }
        }
        if (err == 0)
        {
            setBlocking(fd, true);
            freeaddrinfo(list);
            setCself(context, new Sock(fd));
            return statusResult(context, "OK");
        }
        lastErr = err;
        closesock(fd);
    }
    freeaddrinfo(list);
    if (timedOut)
    {
        return statusResult(context, "TIMEOUT");
    }
    return errorResult(context, lastErr);
}

// nAdopt(pointer): a socket that ServerSocket~accept made.
RexxMethod1(RexxObjectPtr, socket_adopt, POINTER, p)
{
    setCself(context, (Sock *)p);
    return NULLOBJECT;
}

// nRecv(max, timeout): up to max bytes, waiting at most timeout seconds
// (< 0: as long as it takes; 0: only what is already there).
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
    if (timeout >= 0)
    {
        int err = 0;
        int w = waitFor(s->fd, POLLIN, true, deadlineFrom(timeout), &err);
        if (w == 0)
        {
            return statusResult(context, "TIMEOUT");
        }
        if (w < 0)
        {
            return errorResult(context, err);
        }
    }
    std::vector<char> buf(max);
    for (;;)
    {
        long n = (long)recv(s->fd, buf.data(), (int)max, 0);
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
        return errorResult(context, e);
    }
}

// nSend(data, timeout): all of data, or an error / timeout. The result
// has, after the status, how many bytes went out.
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
        if (hasDeadline)
        {
            int err = 0;
            int w = waitFor(s->fd, POLLOUT, true, deadline, &err);
            if (w == 0)
            {
                return statusResult(context, "TIMEOUT", context->StringSize(sent));
            }
            if (w < 0)
            {
                return errorResult(context, err);
            }
        }
        int chunk = left > 0x40000000 ? 0x40000000 : (int)left;
        long n = (long)send(s->fd, p + sent, chunk, SEND_FLAGS);
        if (n < 0)
        {
            int e = lastError();
            if (interrupted(e))
            {
                continue;
            }
            return errorResult(context, e);
        }
        sent += (size_t)n;
        left -= (size_t)n;
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
        ERR_clear_error();
        SSL_shutdown(s->ssl);
        ERR_clear_error();
    }
#ifdef _WIN32
    int rc = shutdown(s->fd, SD_SEND);
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
// "TIMEOUT", or an error.
RexxMethod2(RexxArrayObject, server_accept, CSELF, cself, double, timeout)
{
    Sock *s = (Sock *)cself;
    if (s == nullptr || s->fd == BAD_SOCKET)
    {
        return closedResult(context);
    }
    if (timeout >= 0)
    {
        int err = 0;
        int w = waitFor(s->fd, POLLIN, true, deadlineFrom(timeout), &err);
        if (w == 0)
        {
            return statusResult(context, "TIMEOUT");
        }
        if (w < 0)
        {
            return errorResult(context, err);
        }
    }
    for (;;)
    {
        sock_t fd = accept(s->fd, nullptr, nullptr);
        if (fd != BAD_SOCKET)
        {
            prepareSocket(fd);
            setBlocking(fd, true);
            Sock *c = new Sock(fd);
            SSL_CTX *ctx;
            {
                std::lock_guard<std::mutex> guard(s->mu);
                ctx = s->ctx;
                if (ctx != nullptr)
                {
                    SSL_CTX_up_ref(ctx);
                }
            }
            if (ctx != nullptr)
            {
                // TLSServerSocket: the handshake happens on the first read
                // or write, in whatever activity serves this client.
                attachSsl(c, ctx);
                SSL_set_accept_state(c->ssl);
            }
            return statusResult(context, "OK", context->NewPointer(c));
        }
        int e = lastError();
        if (interrupted(e))
        {
            continue;
        }
        return errorResult(context, e);
    }
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
    REXX_LAST_METHOD()
};

static RexxPackageEntry oosockets_package_entry =
{
    STANDARD_PACKAGE_HEADER
    REXX_INTERPRETER_5_0_0,
    "oosockets",
    "0.1.0",
    oosocketsLoader,
    nullptr,
    nullptr,
    oosockets_methods
};

OOREXX_GET_PACKAGE(oosockets);
