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

#include "oorexxapi.h"

#include <string>
#include <vector>
#include <cstring>
#include <cstdio>
#include <cerrno>
#include <chrono>

#ifdef _WIN32
  #ifndef WIN32_LEAN_AND_MEAN
    #define WIN32_LEAN_AND_MEAN
  #endif
  #include <winsock2.h>
  #include <ws2tcpip.h>
  #include <windows.h>
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


struct Sock
{
    sock_t fd;
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
    if (s != nullptr && s->fd != BAD_SOCKET)
    {
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

// nShutdown: no more output (the peer reads end of stream).
RexxMethod1(RexxArrayObject, socket_shutdown, CSELF, cself)
{
    Sock *s = (Sock *)cself;
    if (s == nullptr || s->fd == BAD_SOCKET)
    {
        return closedResult(context);
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
            return statusResult(context, "OK", context->NewPointer(new Sock(fd)));
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
    REXX_METHOD(socket_resolve,  socket_resolve),
    REXX_METHOD(sock_close,      sock_close),
    REXX_METHOD(sock_free,       sock_free),
    REXX_METHOD(sock_address,    sock_address),
    REXX_METHOD(server_listen,   server_listen),
    REXX_METHOD(server_accept,   server_accept),
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
