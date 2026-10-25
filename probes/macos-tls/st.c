/* Secure Transport over a socket we connected ourselves (what startTLS
   needs). Usage: st host [port] [noverify] */
#include "common.h"
#include <Security/Security.h>
#include <Security/SecureTransport.h>

static OSStatus rd(SSLConnectionRef c, void *data, size_t *len)
{
    int fd = *(const int *)c; size_t want = *len; size_t got = 0;
    while (got < want) {
        ssize_t n = recv(fd, (char *)data + got, want - got, 0);
        if (n > 0) { got += n; continue; }
        *len = got;
        if (n == 0) return got ? noErr : errSSLClosedGraceful;
        return errSSLClosedAbort;
    }
    *len = got; return noErr;
}
static OSStatus wr(SSLConnectionRef c, const void *data, size_t *len)
{
    int fd = *(const int *)c; size_t want = *len; size_t put = 0;
    while (put < want) {
        ssize_t n = send(fd, (const char *)data + put, want - put, 0);
        if (n <= 0) { *len = put; return errSSLClosedAbort; }
        put += n;
    }
    *len = put; return noErr;
}
static const char *ver(SSLProtocol p)
{
    switch (p) { case kTLSProtocol1: return "TLS 1.0"; case kTLSProtocol11: return "TLS 1.1";
                 case kTLSProtocol12: return "TLS 1.2"; case kTLSProtocol13: return "TLS 1.3";
                 default: return "?"; }
}
int main(int argc, char **argv)
{
    const char *host = argv[1], *port = argc > 2 ? argv[2] : "443";
    int noverify = argc > 3;
    printf("Secure Transport -> %s:%s%s\n", host, port, noverify ? " (no verify, version only)" : "");
    int fd = tcp_connect(host, port); if (fd < 0) return 1;
    SSLContextRef ctx = SSLCreateContext(NULL, kSSLClientSide, kSSLStreamType);
    SSLSetIOFuncs(ctx, rd, wr);
    SSLSetConnection(ctx, &fd);
    SSLSetPeerDomainName(ctx, host, strlen(host));
    OSStatus s13 = SSLSetProtocolVersionMax(ctx, kTLSProtocol13);
    printf("  SSLSetProtocolVersionMax(TLS 1.3): %d\n", (int)s13);
    if (noverify) SSLSetSessionOption(ctx, kSSLSessionOptionBreakOnServerAuth, true);
    OSStatus st;
    do { st = SSLHandshake(ctx); } while (st == errSSLWouldBlock || (noverify && st == errSSLPeerAuthCompleted));
    if (st != noErr) {
        CFStringRef msg = SecCopyErrorMessageString(st, NULL);
        char buf[256] = ""; if (msg) CFStringGetCString(msg, buf, sizeof buf, kCFStringEncodingUTF8);
        printf("  RESULT: handshake failed, OSStatus %d (%s)\n", (int)st, buf);
        return 0;
    }
    SSLProtocol p; SSLGetNegotiatedProtocolVersion(ctx, &p);
    char req[256]; snprintf(req, sizeof req, "GET / HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n", host);
    size_t done; SSLWrite(ctx, req, strlen(req), &done);
    char line[128] = ""; size_t got = 0; SSLRead(ctx, line, sizeof line - 1, &got); line[got] = 0;
    char *nl = strpbrk(line, "\r\n"); if (nl) *nl = 0;
    printf("  RESULT: OK, %s, first line: %s\n", ver(p), line);
    SSLClose(ctx); CFRelease(ctx); close(fd);
    return 0;
}
