/* TLS on Windows: OpenSSL (vcpkg's, linked statically) over our own
   socket, and the ways to decide whether the certificate is good.

     wintrust     : OpenSSL only does the handshake; Windows decides
                    (CertGetCertificateChain + CertVerifyCertificateChainPolicy,
                    CERT_CHAIN_POLICY_SSL with the host name), no revocation
     wintrust-rev : the same, with revocation checked (chain, not root)
     winstore     : OpenSSL verifies, against the certificates in Windows'
                    ROOT store loaded into its X509_STORE
     pin          : OpenSSL verifies, against one certificate (PEM, 4th arg)
     wintrust-pin : Windows decides, with one certificate as the only root
                    (a chain engine with hExclusiveRoot)

   Usage: probe mode host [port [pem]]                                  */

#define WIN32_LEAN_AND_MEAN
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <wincrypt.h>
#include <stdio.h>
#include <string.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/x509v3.h>
#include <openssl/pem.h>

static SOCKET tcp_connect(const char *host, const char *port)
{
    struct addrinfo hints, *list, *ai;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    int rc = getaddrinfo(host, port, &hints, &list);
    if (rc != 0) { printf("  getaddrinfo: %d\n", rc); return INVALID_SOCKET; }
    SOCKET fd = INVALID_SOCKET;
    for (ai = list; ai; ai = ai->ai_next) {
        fd = socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol);
        if (fd == INVALID_SOCKET) continue;
        if (connect(fd, ai->ai_addr, (int)ai->ai_addrlen) == 0) break;
        closesocket(fd); fd = INVALID_SOCKET;
    }
    freeaddrinfo(list);
    if (fd == INVALID_SOCKET) printf("  connect failed: %d\n", WSAGetLastError());
    return fd;
}

static void print_error(const char *who, DWORD code)
{
    char buf[512] = "";
    FormatMessageA(FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS, NULL, code,
                   MAKELANGID(LANG_ENGLISH, SUBLANG_ENGLISH_US), buf, sizeof buf, NULL);
    char *nl = strpbrk(buf, "\r\n"); if (nl) *nl = 0;
    printf("  %s: REFUSED, 0x%08lX: %s\n", who, (unsigned long)code, buf);
}

static PCCERT_CONTEXT to_windows(X509 *x)
{
    unsigned char *der = NULL;
    int len = i2d_X509(x, &der);
    PCCERT_CONTEXT c = CertCreateCertificateContext(X509_ASN_ENCODING, der, len);
    OPENSSL_free(der);
    return c;
}

/* Windows decides, on the chain the server sent. */
static void wintrust(SSL *ssl, const char *host, int revocation, const char *pin)
{
    STACK_OF(X509) *chain = SSL_get_peer_cert_chain(ssl);
    if (!chain || sk_X509_num(chain) == 0) { printf("  no peer chain\n"); return; }
    PCCERT_CONTEXT leaf = to_windows(sk_X509_value(chain, 0));
    HCERTSTORE extra = CertOpenStore(CERT_STORE_PROV_MEMORY, 0, 0, 0, NULL);
    for (int i = 1; i < sk_X509_num(chain); i++) {
        PCCERT_CONTEXT c = to_windows(sk_X509_value(chain, i));
        CertAddCertificateContextToStore(extra, c, CERT_STORE_ADD_ALWAYS, NULL);
        CertFreeCertificateContext(c);
    }

    HCERTCHAINENGINE engine = NULL;               /* NULL: the system's */
    HCERTSTORE roots = NULL;
    if (pin) {
        FILE *f = fopen(pin, "r"); X509 *x = PEM_read_X509(f, NULL, NULL, NULL); fclose(f);
        PCCERT_CONTEXT c = to_windows(x); X509_free(x);
        roots = CertOpenStore(CERT_STORE_PROV_MEMORY, 0, 0, 0, NULL);
        CertAddCertificateContextToStore(roots, c, CERT_STORE_ADD_ALWAYS, NULL);
        CertFreeCertificateContext(c);
        CERT_CHAIN_ENGINE_CONFIG cfg;
        memset(&cfg, 0, sizeof cfg);
        cfg.cbSize = sizeof cfg;
        cfg.hExclusiveRoot = roots;
        if (!CertCreateCertificateChainEngine(&cfg, &engine)) {
            print_error("chain engine", GetLastError());
            return;
        }
        printf("  only root: %s\n", pin);
    }

    char *usage[] = { szOID_PKIX_KP_SERVER_AUTH };
    CERT_CHAIN_PARA para;
    memset(&para, 0, sizeof para);
    para.cbSize = sizeof para;
    para.RequestedUsage.dwType = USAGE_MATCH_TYPE_AND;
    para.RequestedUsage.Usage.cUsageIdentifier = 1;
    para.RequestedUsage.Usage.rgpszUsageIdentifier = usage;
    DWORD flags = revocation ? CERT_CHAIN_REVOCATION_CHECK_CHAIN_EXCLUDE_ROOT : 0;
    PCCERT_CHAIN_CONTEXT ctx = NULL;
    if (!CertGetCertificateChain(engine, leaf, NULL, extra, &para, flags, NULL, &ctx)) {
        print_error("CertGetCertificateChain", GetLastError());
        return;
    }
    printf("  chain trust status: error 0x%08lX, info 0x%08lX\n",
           (unsigned long)ctx->TrustStatus.dwErrorStatus, (unsigned long)ctx->TrustStatus.dwInfoStatus);

    wchar_t whost[256];
    MultiByteToWideChar(CP_UTF8, 0, host, -1, whost, 256);
    SSL_EXTRA_CERT_CHAIN_POLICY_PARA ssl_para;
    memset(&ssl_para, 0, sizeof ssl_para);
    ssl_para.cbSize = sizeof ssl_para;
    ssl_para.dwAuthType = AUTHTYPE_SERVER;
    ssl_para.pwszServerName = whost;
    CERT_CHAIN_POLICY_PARA pol;
    memset(&pol, 0, sizeof pol);
    pol.cbSize = sizeof pol;
    pol.pvExtraPolicyPara = &ssl_para;
    CERT_CHAIN_POLICY_STATUS st;
    memset(&st, 0, sizeof st);
    st.cbSize = sizeof st;
    if (!CertVerifyCertificateChainPolicy(CERT_CHAIN_POLICY_SSL, ctx, &pol, &st))
        print_error("CertVerifyCertificateChainPolicy", GetLastError());
    else if (st.dwError == 0)
        printf("  Windows trust: OK\n");
    else
        print_error("Windows trust", st.dwError);

    CertFreeCertificateChain(ctx);
    if (engine) CertFreeCertificateChainEngine(engine);
    if (roots) CertCloseStore(roots, 0);
    CertCloseStore(extra, 0);
    CertFreeCertificateContext(leaf);
}

/* The certificates of Windows' ROOT store (local machine and user), into
   OpenSSL's store. */
static int load_root_store(X509_STORE *store)
{
    HCERTSTORE h = CertOpenSystemStoreA(0, "ROOT");
    if (!h) return -1;
    int n = 0;
    PCCERT_CONTEXT c = NULL;
    while ((c = CertEnumCertificatesInStore(h, c)) != NULL) {
        const unsigned char *p = c->pbCertEncoded;
        X509 *x = d2i_X509(NULL, &p, c->cbCertEncoded);
        if (x) { if (X509_STORE_add_cert(store, x)) n++; X509_free(x); }
    }
    CertCloseStore(h, 0);
    return n;
}

int main(int argc, char **argv)
{
    if (argc < 3) { printf("usage: probe mode host [port [pem]]\n"); return 2; }
    const char *mode = argv[1], *host = argv[2], *port = argc > 3 ? argv[3] : "443";
    const char *pem = argc > 4 ? argv[4] : NULL;
    WSADATA wsa; WSAStartup(MAKEWORD(2, 2), &wsa);
    printf("OpenSSL %s (%s) -> %s:%s\n", mode, OpenSSL_version(OPENSSL_VERSION), host, port);

    SSL_CTX *sctx = SSL_CTX_new(TLS_client_method());
    SSL_CTX_set_min_proto_version(sctx, TLS1_2_VERSION);
    int windows = !strncmp(mode, "wintrust", 8);
    if (!strcmp(mode, "winstore")) {
        printf("  certificates from Windows' ROOT store: %d\n", load_root_store(SSL_CTX_get_cert_store(sctx)));
        SSL_CTX_set_verify(sctx, SSL_VERIFY_PEER, NULL);
    } else if (!strcmp(mode, "pin")) {
        printf("  load %s: %d\n", pem, SSL_CTX_load_verify_locations(sctx, pem, NULL));
        SSL_CTX_set_verify(sctx, SSL_VERIFY_PEER, NULL);
    } else {
        SSL_CTX_set_verify(sctx, SSL_VERIFY_NONE, NULL);
    }

    SOCKET fd = tcp_connect(host, port);
    if (fd == INVALID_SOCKET) return 1;
    SSL *ssl = SSL_new(sctx);
    SSL_set_fd(ssl, (int)fd);
    SSL_set_tlsext_host_name(ssl, host);
    if (!windows) SSL_set1_host(ssl, host);
    if (SSL_connect(ssl) != 1) {
        long vr = SSL_get_verify_result(ssl);
        printf("  RESULT: handshake failed: %s (verify: %s)\n",
               ERR_reason_error_string(ERR_peek_last_error()), X509_verify_cert_error_string(vr));
        return 0;
    }
    if (windows)
        wintrust(ssl, host, !strcmp(mode, "wintrust-rev"), !strcmp(mode, "wintrust-pin") ? pem : NULL);
    char req[256];
    snprintf(req, sizeof req, "GET / HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n", host);
    SSL_write(ssl, req, (int)strlen(req));
    char line[128] = "";
    int got = SSL_read(ssl, line, sizeof line - 1);
    if (got > 0) line[got] = 0;
    char *nl = strpbrk(line, "\r\n"); if (nl) *nl = 0;
    printf("  RESULT: handshake OK, %s, first line: %s\n", SSL_get_version(ssl), line);
    SSL_shutdown(ssl); SSL_free(ssl); SSL_CTX_free(sctx); closesocket(fd);
    return 0;
}
