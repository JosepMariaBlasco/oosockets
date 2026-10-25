/* OpenSSL (Homebrew's) over our own socket, three ways to decide trust:
     anchors : OpenSSL verifies, against the keychain's anchor certificates
               (SecTrustCopyAnchorCertificates) loaded into its X509_STORE
     certpem : OpenSSL verifies, against /etc/ssl/cert.pem
     sectrust: OpenSSL only does the handshake; macOS decides
               (SecTrustEvaluateWithError on the peer's chain, SSL policy
               with the host name)
   Usage: ossl mode host [port] */
#include "common.h"
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/x509v3.h>
#include <Security/Security.h>

static int load_anchors(X509_STORE *store)
{
    CFArrayRef anchors = NULL;
    if (SecTrustCopyAnchorCertificates(&anchors) != errSecSuccess) return -1;
    int n = 0;
    for (CFIndex i = 0; i < CFArrayGetCount(anchors); i++) {
        CFDataRef der = SecCertificateCopyData((SecCertificateRef)CFArrayGetValueAtIndex(anchors, i));
        const unsigned char *p = CFDataGetBytePtr(der);
        X509 *x = d2i_X509(NULL, &p, CFDataGetLength(der));
        if (x) { if (X509_STORE_add_cert(store, x)) n++; X509_free(x); }
        CFRelease(der);
    }
    CFRelease(anchors);
    return n;
}

static void sectrust(SSL *ssl, const char *host)
{
    STACK_OF(X509) *chain = SSL_get_peer_cert_chain(ssl);
    CFMutableArrayRef certs = CFArrayCreateMutable(NULL, 0, &kCFTypeArrayCallBacks);
    for (int i = 0; i < sk_X509_num(chain); i++) {
        unsigned char *der = NULL; int len = i2d_X509(sk_X509_value(chain, i), &der);
        CFDataRef d = CFDataCreate(NULL, der, len); OPENSSL_free(der);
        SecCertificateRef c = SecCertificateCreateWithData(NULL, d); CFRelease(d);
        if (c) { CFArrayAppendValue(certs, c); CFRelease(c); }
    }
    CFStringRef h = CFStringCreateWithCString(NULL, host, kCFStringEncodingUTF8);
    SecPolicyRef pol = SecPolicyCreateSSL(true, h);
    SecTrustRef trust = NULL;
    SecTrustCreateWithCertificates(certs, pol, &trust);
    CFErrorRef err = NULL;
    bool ok = SecTrustEvaluateWithError(trust, &err);
    if (ok) printf("  macOS trust: OK\n");
    else {
        char buf[512] = "";
        CFStringRef desc = err ? CFErrorCopyDescription(err) : NULL;
        if (desc) { CFStringGetCString(desc, buf, sizeof buf, kCFStringEncodingUTF8); CFRelease(desc); }
        printf("  macOS trust: REFUSED, code %ld: %s\n", err ? (long)CFErrorGetCode(err) : 0L, buf);
    }
    if (err) CFRelease(err);
    CFRelease(trust); CFRelease(pol); CFRelease(h); CFRelease(certs);
}

int main(int argc, char **argv)
{
    const char *mode = argv[1], *host = argv[2], *port = argc > 3 ? argv[3] : "443";
    printf("OpenSSL %s (%s) -> %s:%s\n", mode, OpenSSL_version(OPENSSL_VERSION), host, port);
    SSL_CTX *ctx = SSL_CTX_new(TLS_client_method());
    SSL_CTX_set_min_proto_version(ctx, TLS1_2_VERSION);
    if (!strcmp(mode, "anchors")) {
        int n = load_anchors(SSL_CTX_get_cert_store(ctx));
        printf("  anchors from the keychain: %d\n", n);
        SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, NULL);
    } else if (!strcmp(mode, "certpem")) {
        printf("  load /etc/ssl/cert.pem: %d\n", SSL_CTX_load_verify_locations(ctx, "/etc/ssl/cert.pem", NULL));
        SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, NULL);
    } else {
        SSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, NULL);
    }
    int fd = tcp_connect(host, port); if (fd < 0) return 1;
    SSL *ssl = SSL_new(ctx);
    SSL_set_fd(ssl, fd);
    SSL_set_tlsext_host_name(ssl, host);
    if (strcmp(mode, "sectrust")) SSL_set1_host(ssl, host);
    if (SSL_connect(ssl) != 1) {
        long vr = SSL_get_verify_result(ssl);
        printf("  RESULT: handshake failed: %s (verify: %s)\n",
               ERR_reason_error_string(ERR_peek_last_error()), X509_verify_cert_error_string(vr));
        return 0;
    }
    if (!strcmp(mode, "sectrust")) sectrust(ssl, host);
    char req[256]; snprintf(req, sizeof req, "HEAD / HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n", host);
    SSL_write(ssl, req, strlen(req));
    char line[128] = ""; int got = SSL_read(ssl, line, sizeof line - 1); if (got > 0) line[got] = 0;
    char *nl = strpbrk(line, "\r\n"); if (nl) *nl = 0;
    printf("  RESULT: OK, %s, first line: %s\n", SSL_get_version(ssl), line);
    SSL_shutdown(ssl); SSL_free(ssl); SSL_CTX_free(ctx); close(fd);
    return 0;
}
