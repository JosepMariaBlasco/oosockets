/* Schannel, Windows' own TLS, measured for what ooSockets needs (Rony,
   27/10/2026: use the system's TLS, so that the system's updates fix it).

     client  host port [min]       TLS client over our own connected socket;
                                   Schannel verifies the server (the system's
                                   roots, the host name). min: 12 (default)
                                   or 13, the oldest version accepted. Sends
                                   a HEAD request and prints the first line.
     pin     host port cert.pem    the same, but the server's certificate is
                                   checked against cert.pem alone (manual
                                   validation, then a chain engine with
                                   hExclusiveRoot, as probes/windows-tls).
     server  port keystore pw mode TLS server, one client: mode p12 (keystore
                                   is a PKCS#12 file, imported with
                                   PKCS12_NO_PERSIST_KEY), p12-persist (the
                                   same, keys persisted: the default), or pem
                                   (keystore is "cert.pem;key.pem", pw unused).
                                   Echoes one line, upper-cased.
     starttls-server port p12 pw   reads "STARTTLS" in clear, answers "220 go",
                                   then TLS (server side) on the same socket.
     starttls-client host port pem the other side, then one line over TLS.
     dtls    host port cert.pem    DTLS 1.2 client (UDP), checked as pin;
                                   sends "hello", prints what comes back.
     dtls-server port p12 pw       DTLS 1.2 server, one client: echoes one
                                   datagram upper-cased.

   Everything prints what happened, with Schannel's status and its text. */

#define WIN32_LEAN_AND_MEAN
#define SECURITY_WIN32
#define SCHANNEL_USE_BLACKLISTS          /* SCH_CREDENTIALS, TLS_PARAMETERS */
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <wincrypt.h>
#include <subauth.h>                       /* UNICODE_STRING, for schannel.h */
#include <schannel.h>
#include <security.h>
#include <sspi.h>
#include <ncrypt.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>

#ifndef SEC_I_MESSAGE_FRAGMENT
#define SEC_I_MESSAGE_FRAGMENT ((HRESULT)0x00090364L)
#endif

static void say_status(const char *who, SECURITY_STATUS st)
{
    char buf[512] = "";
    FormatMessageA(FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS, NULL, (DWORD)st,
                   MAKELANGID(LANG_ENGLISH, SUBLANG_ENGLISH_US), buf, sizeof buf, NULL);
    char *nl = strpbrk(buf, "\r\n"); if (nl) *nl = 0;
    printf("  %s: 0x%08lX %s\n", who, (unsigned long)st, buf);
}

/* ------------------------------------------------------------------ */
/* sockets                                                             */

static SOCKET connect_to(const char *host, const char *port, int type)
{
    struct addrinfo hints, *list, *ai;
    memset(&hints, 0, sizeof hints);
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = type;
    int rc = getaddrinfo(host, port, &hints, &list);
    if (rc) { printf("  getaddrinfo: %d\n", rc); return INVALID_SOCKET; }
    SOCKET fd = INVALID_SOCKET;
    for (ai = list; ai; ai = ai->ai_next) {
        if (type == SOCK_DGRAM && ai->ai_family != AF_INET) continue;   /* 127.0.0.1 */
        fd = socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol);
        if (fd == INVALID_SOCKET) continue;
        if (connect(fd, ai->ai_addr, (int)ai->ai_addrlen) == 0) break;
        closesocket(fd); fd = INVALID_SOCKET;
    }
    freeaddrinfo(list);
    if (fd == INVALID_SOCKET) printf("  connect failed: %d\n", WSAGetLastError());
    return fd;
}

static SOCKET listen_on(int port, int type)
{
    SOCKET fd = socket(AF_INET, type, 0);
    struct sockaddr_in a;
    memset(&a, 0, sizeof a);
    a.sin_family = AF_INET; a.sin_port = htons((u_short)port);
    a.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    BOOL on = TRUE;
    setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, (char *)&on, sizeof on);
    if (bind(fd, (struct sockaddr *)&a, sizeof a) != 0) { printf("  bind: %d\n", WSAGetLastError()); return INVALID_SOCKET; }
    if (type == SOCK_STREAM) listen(fd, 5);
    return fd;
}

/* recv with a timeout in ms; -2 on timeout */
static int recv_wait(SOCKET fd, char *buf, int len, int ms)
{
    fd_set r; FD_ZERO(&r); FD_SET(fd, &r);
    struct timeval tv = { ms / 1000, (ms % 1000) * 1000 };
    int n = select(0, &r, NULL, NULL, &tv);
    if (n == 0) return -2;
    if (n < 0) return -1;
    return recv(fd, buf, len, 0);
}

static int send_all(SOCKET fd, const char *p, int len)
{
    while (len > 0) {
        int n = send(fd, p, len, 0);
        if (n <= 0) return -1;
        p += n; len -= n;
    }
    return 0;
}

/* ------------------------------------------------------------------ */
/* credentials                                                         */

#define ALL_TLS  (SP_PROT_TLS1_0 | SP_PROT_TLS1_1 | SP_PROT_TLS1_2 | SP_PROT_TLS1_3 | \
                  SP_PROT_DTLS1_0 | SP_PROT_DTLS1_2 | SP_PROT_SSL3 | SP_PROT_SSL2)

/* How the credentials are described (the CRED environment variable):
     sch    SCH_CREDENTIALS, the protocols not wanted disabled (default)
     sch0   SCH_CREDENTIALS, nothing disabled: the system's defaults
     legacy SCHANNEL_CRED (deprecated), grbitEnabledProtocols            */
static const char *cred_style(void)
{
    const char *s = getenv("CRED");
    return s && *s ? s : "sch";
}

/* enabled: the SP_PROT_* bits to allow (both sides' bits are fine). */
static int acquire(CredHandle *cred, ULONG dir, DWORD enabled, PCCERT_CONTEXT cert, int manual)
{
    SCH_CREDENTIALS sc;
    TLS_PARAMETERS tp;
    TimeStamp exp;
    if (!strcmp(cred_style(), "legacy")) {
        SCHANNEL_CRED lc;
        memset(&lc, 0, sizeof lc);
        lc.dwVersion = SCHANNEL_CRED_VERSION;
        lc.dwFlags = SCH_USE_STRONG_CRYPTO;
        if (dir == SECPKG_CRED_OUTBOUND)
            lc.dwFlags |= SCH_CRED_NO_DEFAULT_CREDS |
                          (manual ? SCH_CRED_MANUAL_CRED_VALIDATION : SCH_CRED_AUTO_CRED_VALIDATION);
        if (cert) { lc.cCreds = 1; lc.paCred = &cert; }
        lc.grbitEnabledProtocols = enabled & (dir == SECPKG_CRED_OUTBOUND
            ? (SP_PROT_TLS1_2_CLIENT | SP_PROT_TLS1_3_CLIENT | SP_PROT_DTLS1_2_CLIENT)
            : (SP_PROT_TLS1_2_SERVER | SP_PROT_TLS1_3_SERVER | SP_PROT_DTLS1_2_SERVER));
        SECURITY_STATUS st = AcquireCredentialsHandleW(NULL, (LPWSTR)UNISP_NAME_W, dir, NULL, &lc,
                                                       NULL, NULL, cred, &exp);
        if (st != SEC_E_OK) { say_status("AcquireCredentialsHandle (legacy)", st); return 0; }
        return 1;
    }
    memset(&sc, 0, sizeof sc); memset(&tp, 0, sizeof tp);
    sc.dwVersion = SCH_CREDENTIALS_VERSION;
    sc.dwFlags = SCH_USE_STRONG_CRYPTO;
    if (dir == SECPKG_CRED_OUTBOUND) {
        sc.dwFlags |= SCH_CRED_NO_DEFAULT_CREDS;
        sc.dwFlags |= manual ? SCH_CRED_MANUAL_CRED_VALIDATION : SCH_CRED_AUTO_CRED_VALIDATION;
    }
    if (cert) { sc.cCreds = 1; sc.paCred = &cert; }
    tp.grbitDisabledProtocols = strcmp(cred_style(), "sch0") ? (ALL_TLS & ~enabled) : 0;
    sc.cTlsParameters = 1; sc.pTlsParameters = &tp;
    SECURITY_STATUS st = AcquireCredentialsHandleW(NULL, (LPWSTR)UNISP_NAME_W, dir, NULL, &sc,
                                                   NULL, NULL, cred, &exp);
    if (st != SEC_E_OK) { say_status("AcquireCredentialsHandle", st); return 0; }
    return 1;
}

/* Which property holds the private key, if any (does not open the key). */
static const char *key_where(PCCERT_CONTEXT c)
{
    DWORD n = 0;
    if (CertGetCertificateContextProperty(c, CERT_NCRYPT_KEY_HANDLE_PROP_ID, NULL, &n)) return "NCRYPT_KEY_HANDLE";
    n = 0;
    if (CertGetCertificateContextProperty(c, CERT_KEY_CONTEXT_PROP_ID, NULL, &n)) return "KEY_CONTEXT";
    n = 0;
    if (CertGetCertificateContextProperty(c, CERT_KEY_PROV_INFO_PROP_ID, NULL, &n)) return "KEY_PROV_INFO";
    return NULL;
}

static char *read_file(const char *name, DWORD *len)
{
    FILE *f = fopen(name, "rb");
    if (!f) { printf("  cannot open %s\n", name); return NULL; }
    fseek(f, 0, SEEK_END); long n = ftell(f); fseek(f, 0, SEEK_SET);
    char *p = malloc(n + 1); fread(p, 1, n, f); p[n] = 0; fclose(f);
    *len = (DWORD)n;
    return p;
}

/* keymode: nopersist   PKCS12_NO_PERSIST_KEY
            nopersist-cng   the same, with PKCS12_ALWAYS_CNG_KSP
            persist     the key saved in the user's profile (the default)
            delete      as persist, the key deleted once the credentials
                        are acquired (see delete_key)                    */
static PCCERT_CONTEXT import_pfx(CRYPT_DATA_BLOB *blob, const char *pw, const char *keymode)
{
    wchar_t wpw[256]; MultiByteToWideChar(CP_UTF8, 0, pw, -1, wpw, 256);
    DWORD flags = CRYPT_USER_KEYSET;
    if (!strcmp(keymode, "nopersist")) flags |= PKCS12_NO_PERSIST_KEY;
    else if (!strcmp(keymode, "nopersist-cng")) flags |= PKCS12_NO_PERSIST_KEY | PKCS12_ALWAYS_CNG_KSP;
    else flags |= PKCS12_ALWAYS_CNG_KSP;
    HCERTSTORE store = PFXImportCertStore(blob, wpw, flags);
    if (!store) { say_status("PFXImportCertStore", (SECURITY_STATUS)HRESULT_FROM_WIN32(GetLastError())); return NULL; }
    PCCERT_CONTEXT c = NULL, found = NULL;
    while ((c = CertEnumCertificatesInStore(store, c)) != NULL) {
        const char *w = key_where(c);
        if (w) { printf("  key (%s): %s\n", keymode, w); found = CertDuplicateCertificateContext(c); break; }
    }
    if (c) CertFreeCertificateContext(c);
    if (!found) printf("  no certificate with a private key (%s)\n", keymode);
    return found;
}

static PCCERT_CONTEXT load_p12(const char *file, const char *pw, const char *keymode)
{
    DWORD len; char *data = read_file(file, &len);
    if (!data) return NULL;
    CRYPT_DATA_BLOB blob = { len, (BYTE *)data };
    PCCERT_CONTEXT c = import_pfx(&blob, pw, keymode);
    free(data);
    return c;
}

/* The persisted key of c deleted (keymode "delete"), after
   AcquireCredentialsHandle: does Schannel still use it? */
static void delete_key(PCCERT_CONTEXT c)
{
    HCRYPTPROV_OR_NCRYPT_KEY_HANDLE k = 0; DWORD spec = 0; BOOL free_it = FALSE;
    if (!CryptAcquireCertificatePrivateKey(c, CRYPT_ACQUIRE_SILENT_FLAG | CRYPT_ACQUIRE_ONLY_NCRYPT_KEY_FLAG,
                                           NULL, &k, &spec, &free_it)) {
        printf("  delete_key: CryptAcquireCertificatePrivateKey %lu\n", GetLastError()); return;
    }
    SECURITY_STATUS st = NCryptDeleteKey(k, 0);
    printf("  persisted key deleted: 0x%08lX\n", (unsigned long)st);
}

static BYTE *pem_der(const char *file, DWORD *der_len)
{
    DWORD len; char *pem = read_file(file, &len);
    if (!pem) return NULL;
    *der_len = 0;
    CryptStringToBinaryA(pem, len, CRYPT_STRING_BASE64HEADER, NULL, der_len, NULL, NULL);
    BYTE *der = malloc(*der_len ? *der_len : 1);
    if (!CryptStringToBinaryA(pem, len, CRYPT_STRING_BASE64HEADER, der, der_len, NULL, NULL)) {
        printf("  PEM %s: %lu\n", file, GetLastError()); return NULL;
    }
    free(pem);
    return der;
}

/* PEM: the certificate and its PKCS#8 private key. pfx = 0: the key
   imported into CNG as an ephemeral key and attached to the certificate;
   pfx = 1: that, exported as a PKCS#12 in memory and imported again as
   keymode says (Schannel may refuse an ephemeral key). */
static PCCERT_CONTEXT load_pem(const char *certfile, const char *keyfile, int pfx, const char *keymode)
{
    DWORD der_len, klen;
    BYTE *der = pem_der(certfile, &der_len);
    BYTE *kder = pem_der(keyfile, &klen);
    if (!der || !kder) return NULL;
    HCERTSTORE mem = CertOpenStore(CERT_STORE_PROV_MEMORY, 0, 0, 0, NULL);
    PCCERT_CONTEXT c = NULL;
    if (!CertAddEncodedCertificateToStore(mem, X509_ASN_ENCODING, der, der_len, CERT_STORE_ADD_ALWAYS, &c)) {
        printf("  CertAddEncodedCertificateToStore: %lu\n", GetLastError()); return NULL;
    }
    NCRYPT_PROV_HANDLE prov; NCRYPT_KEY_HANDLE key;
    SECURITY_STATUS st = NCryptOpenStorageProvider(&prov, MS_KEY_STORAGE_PROVIDER, 0);
    if (st) { say_status("NCryptOpenStorageProvider", st); return NULL; }
    st = NCryptImportKey(prov, 0, NCRYPT_PKCS8_PRIVATE_KEY_BLOB, NULL, &key, kder, klen,
                         NCRYPT_SILENT_FLAG | NCRYPT_DO_NOT_FINALIZE_FLAG);
    if (st) { say_status("NCryptImportKey (PKCS#8)", st); return NULL; }
    DWORD policy = NCRYPT_ALLOW_EXPORT_FLAG | NCRYPT_ALLOW_PLAINTEXT_EXPORT_FLAG;
    NCryptSetProperty(key, NCRYPT_EXPORT_POLICY_PROPERTY, (PBYTE)&policy, sizeof policy, NCRYPT_PERSIST_FLAG);
    st = NCryptFinalizeKey(key, NCRYPT_SILENT_FLAG);
    if (st) { say_status("NCryptFinalizeKey", st); return NULL; }
    if (!CertSetCertificateContextProperty(c, CERT_NCRYPT_KEY_HANDLE_PROP_ID, 0, &key)) {
        printf("  CertSetCertificateContextProperty: %lu\n", GetLastError()); return NULL;
    }
    free(der); free(kder);
    (void)keymode;
    if (!pfx) { printf("  PEM loaded, ephemeral CNG key\n"); return c; }
    printf("  (unreachable)\n");
    return NULL;
}

/* ------------------------------------------------------------------ */
/* after the handshake                                                 */

static void show_connection(CtxtHandle *ctx)
{
    SecPkgContext_ConnectionInfo ci;
    SecPkgContext_CipherInfo cip;
    const char *proto = "?";
    if (QueryContextAttributesW(ctx, SECPKG_ATTR_CONNECTION_INFO, &ci) == SEC_E_OK) {
        DWORD p = ci.dwProtocol;
        if (p & SP_PROT_TLS1_3) proto = "TLS 1.3";
        else if (p & SP_PROT_TLS1_2) proto = "TLS 1.2";
        else if (p & SP_PROT_DTLS1_2) proto = "DTLS 1.2";
        else if (p & SP_PROT_DTLS1_0) proto = "DTLS 1.0";
        else if (p & (SP_PROT_TLS1_1 | SP_PROT_TLS1_0)) proto = "TLS 1.0/1.1";
    }
    memset(&cip, 0, sizeof cip);
    if (QueryContextAttributesW(ctx, SECPKG_ATTR_CIPHER_INFO, &cip) == SEC_E_OK)
        printf("  connected: %s, %ls\n", proto, cip.szCipherSuite);
    else
        printf("  connected: %s\n", proto);
}

/* The certificate the server sent, checked against pin.pem only (a chain
   engine whose only root is the pinned certificate) and the host name. */
static int check_pin(CtxtHandle *ctx, const char *host, const char *pinfile)
{
    PCCERT_CONTEXT leaf = NULL;
    SECURITY_STATUS st = QueryContextAttributesW(ctx, SECPKG_ATTR_REMOTE_CERT_CONTEXT, &leaf);
    if (st != SEC_E_OK) { say_status("SECPKG_ATTR_REMOTE_CERT_CONTEXT", st); return 0; }
    DWORD len, der_len = 0; char *pem = read_file(pinfile, &len);
    CryptStringToBinaryA(pem, len, CRYPT_STRING_BASE64HEADER, NULL, &der_len, NULL, NULL);
    BYTE *der = malloc(der_len);
    CryptStringToBinaryA(pem, len, CRYPT_STRING_BASE64HEADER, der, &der_len, NULL, NULL);
    HCERTSTORE roots = CertOpenStore(CERT_STORE_PROV_MEMORY, 0, 0, 0, NULL);
    CertAddEncodedCertificateToStore(roots, X509_ASN_ENCODING, der, der_len, CERT_STORE_ADD_ALWAYS, NULL);

    CERT_CHAIN_ENGINE_CONFIG ec; memset(&ec, 0, sizeof ec);
    ec.cbSize = sizeof ec;
    ec.hExclusiveRoot = roots;
    HCERTCHAINENGINE engine;
    if (!CertCreateCertificateChainEngine(&ec, &engine)) { printf("  chain engine: %lu\n", GetLastError()); return 0; }
    CERT_CHAIN_PARA cp; memset(&cp, 0, sizeof cp); cp.cbSize = sizeof cp;
    PCCERT_CHAIN_CONTEXT chain;
    if (!CertGetCertificateChain(engine, leaf, NULL, leaf->hCertStore, &cp, 0, NULL, &chain)) {
        printf("  CertGetCertificateChain: %lu\n", GetLastError()); return 0;
    }
    wchar_t whost[256]; MultiByteToWideChar(CP_UTF8, 0, host, -1, whost, 256);
    SSL_EXTRA_CERT_CHAIN_POLICY_PARA sp; memset(&sp, 0, sizeof sp);
    sp.cbSize = sizeof sp; sp.dwAuthType = AUTHTYPE_SERVER; sp.pwszServerName = whost;
    CERT_CHAIN_POLICY_PARA pp; memset(&pp, 0, sizeof pp); pp.cbSize = sizeof pp; pp.pvExtraPolicyPara = &sp;
    CERT_CHAIN_POLICY_STATUS ps; memset(&ps, 0, sizeof ps); ps.cbSize = sizeof ps;
    CertVerifyCertificateChainPolicy(CERT_CHAIN_POLICY_SSL, chain, &pp, &ps);
    if (ps.dwError) { say_status("pinned certificate REFUSED", (SECURITY_STATUS)ps.dwError); return 0; }
    printf("  pinned certificate accepted\n");
    return 1;
}

/* ------------------------------------------------------------------ */
/* TLS over a stream socket                                            */

typedef struct {
    SOCKET fd;
    CtxtHandle ctx;
    int server;
    SecPkgContext_StreamSizes sizes;
    char in[65536]; int inlen;          /* received, not yet decrypted */
} tls;

/* resume: a post-handshake message (TLS 1.3) is in t->in, for the
   existing context. */
static SECURITY_STATUS handshake(tls *t, CredHandle *cred, const wchar_t *target, int resume)
{
    int first = !resume;
    DWORD flags = t->server
        ? (ASC_REQ_SEQUENCE_DETECT | ASC_REQ_REPLAY_DETECT | ASC_REQ_CONFIDENTIALITY |
           ASC_REQ_EXTENDED_ERROR | ASC_REQ_ALLOCATE_MEMORY | ASC_REQ_STREAM)
        : (ISC_REQ_SEQUENCE_DETECT | ISC_REQ_REPLAY_DETECT | ISC_REQ_CONFIDENTIALITY |
           ISC_REQ_EXTENDED_ERROR | ISC_REQ_ALLOCATE_MEMORY | ISC_REQ_STREAM |
           ISC_REQ_USE_SUPPLIED_CREDS);
    SECURITY_STATUS st = SEC_I_CONTINUE_NEEDED;
    for (;;) {
        if (!(first && !t->server)) {            /* the client's first call has no input */
            if (t->inlen == 0 || st == SEC_E_INCOMPLETE_MESSAGE) {
                if (resume) printf("    post-handshake: waiting for more (status 0x%08lX)\n", (unsigned long)st);
                int n = recv_wait(t->fd, t->in + t->inlen, sizeof t->in - t->inlen, 10000);
                if (n <= 0) { printf("  handshake: recv %d (%d)\n", n, WSAGetLastError()); return SEC_E_INTERNAL_ERROR; }
                t->inlen += n;
            }
        }
        SecBuffer inb[2] = { { (ULONG)t->inlen, SECBUFFER_TOKEN, t->in }, { 0, SECBUFFER_EMPTY, NULL } };
        SecBufferDesc ind = { SECBUFFER_VERSION, 2, inb };
        SecBuffer outb[2] = { { 0, SECBUFFER_TOKEN, NULL }, { 0, SECBUFFER_ALERT, NULL } };
        SecBufferDesc outd = { SECBUFFER_VERSION, 2, outb };
        ULONG attrs; TimeStamp exp;
        if (t->server)
            st = AcceptSecurityContext(cred, first ? NULL : &t->ctx, &ind, flags, 0,
                                       &t->ctx, &outd, &attrs, &exp);
        else
            st = InitializeSecurityContextW(cred, first ? NULL : &t->ctx, (SEC_WCHAR *)target, flags, 0, 0,
                                            first ? NULL : &ind, 0, &t->ctx, &outd, &attrs, &exp);
        first = 0;
        if (outb[0].cbBuffer && outb[0].pvBuffer) {
            send_all(t->fd, outb[0].pvBuffer, outb[0].cbBuffer);
        }
        if (outb[0].pvBuffer) FreeContextBuffer(outb[0].pvBuffer);
        if (outb[1].pvBuffer) FreeContextBuffer(outb[1].pvBuffer);
        if (st == SEC_E_INCOMPLETE_MESSAGE) continue;
        /* what was not used stays for the next call (or for the data) */
        if (inb[1].BufferType == SECBUFFER_EXTRA && inb[1].cbBuffer) {
            memmove(t->in, t->in + (t->inlen - inb[1].cbBuffer), inb[1].cbBuffer);
            t->inlen = inb[1].cbBuffer;
        } else if (st != SEC_E_INCOMPLETE_MESSAGE) t->inlen = 0;
        if (st == SEC_E_OK) {
            QueryContextAttributesW(&t->ctx, SECPKG_ATTR_STREAM_SIZES, &t->sizes);
            return st;
        }
        if (st == SEC_I_INCOMPLETE_CREDENTIALS) { printf("  the server asks for a client certificate\n"); continue; }
        if (st != SEC_I_CONTINUE_NEEDED) return st;
    }
}

static int tls_send(tls *t, const char *data, int len)
{
    char *buf = malloc(t->sizes.cbHeader + len + t->sizes.cbTrailer);
    memcpy(buf + t->sizes.cbHeader, data, len);
    SecBuffer b[4] = { { t->sizes.cbHeader, SECBUFFER_STREAM_HEADER, buf },
                       { (ULONG)len, SECBUFFER_DATA, buf + t->sizes.cbHeader },
                       { t->sizes.cbTrailer, SECBUFFER_STREAM_TRAILER, buf + t->sizes.cbHeader + len },
                       { 0, SECBUFFER_EMPTY, NULL } };
    SecBufferDesc d = { SECBUFFER_VERSION, 4, b };
    SECURITY_STATUS st = EncryptMessage(&t->ctx, 0, &d, 0);
    if (st != SEC_E_OK) { say_status("EncryptMessage", st); free(buf); return -1; }
    int rc = send_all(t->fd, buf, b[0].cbBuffer + b[1].cbBuffer + b[2].cbBuffer);
    free(buf);
    return rc;
}

/* One piece of plaintext into out; 0 at the end (close_notify or EOF). */
static int tls_recv(tls *t, char *out, int outlen, CredHandle *cred, const wchar_t *target)
{
    for (;;) {
        if (t->inlen > 0) {
            SecBuffer b[4] = { { (ULONG)t->inlen, SECBUFFER_DATA, t->in }, { 0, SECBUFFER_EMPTY, NULL },
                               { 0, SECBUFFER_EMPTY, NULL }, { 0, SECBUFFER_EMPTY, NULL } };
            SecBufferDesc d = { SECBUFFER_VERSION, 4, b };
            SECURITY_STATUS st = DecryptMessage(&t->ctx, &d, 0, NULL);
            if (st == SEC_E_OK || st == SEC_I_RENEGOTIATE || st == SEC_I_CONTEXT_EXPIRED) {
                int got = 0; char *extra = NULL; int extralen = 0;
                for (int i = 0; i < 4; i++) {
                    if (b[i].BufferType == SECBUFFER_DATA && b[i].cbBuffer) {
                        got = (int)b[i].cbBuffer < outlen ? (int)b[i].cbBuffer : outlen;
                        memcpy(out, b[i].pvBuffer, got);
                    }
                    if (b[i].BufferType == SECBUFFER_EXTRA) { extra = b[i].pvBuffer; extralen = b[i].cbBuffer; }
                }
                if (extra) { memmove(t->in, extra, extralen); t->inlen = extralen; } else t->inlen = 0;
                if (st == SEC_I_CONTEXT_EXPIRED) { printf("  peer sent close_notify\n"); return 0; }
                if (st == SEC_I_RENEGOTIATE) {
                    /* TLS 1.3: a post-handshake message (a session ticket, a
                       key update): back to the handshake function with it. */
                    printf("  DecryptMessage: SEC_I_RENEGOTIATE (post-handshake message), %d bytes left\n", t->inlen);
                    SECURITY_STATUS h = handshake(t, cred, target, 1);
                    printf("  post-handshake message processed: 0x%08lX, %d bytes left\n", (unsigned long)h, t->inlen);
                    if (h != SEC_E_OK) { say_status("post-handshake", h); return -1; }
                }
                if (got) return got;
                continue;
            }
            if (st != SEC_E_INCOMPLETE_MESSAGE) { say_status("DecryptMessage", st); return -1; }
        }
        int n = recv_wait(t->fd, t->in + t->inlen, sizeof t->in - t->inlen, 10000);
        if (n == 0) { printf("  connection closed without close_notify\n"); return 0; }
        if (n < 0) { printf("  recv %d (%d)\n", n, WSAGetLastError()); return -1; }
        t->inlen += n;
    }
}

static void tls_close(tls *t, CredHandle *cred)
{
    DWORD type = SCHANNEL_SHUTDOWN;
    SecBuffer b = { sizeof type, SECBUFFER_TOKEN, &type };
    SecBufferDesc d = { SECBUFFER_VERSION, 1, &b };
    ApplyControlToken(&t->ctx, &d);
    SecBuffer ob = { 0, SECBUFFER_TOKEN, NULL };
    SecBufferDesc od = { SECBUFFER_VERSION, 1, &ob };
    ULONG attrs; TimeStamp exp;
    SECURITY_STATUS st = t->server
        ? AcceptSecurityContext(cred, &t->ctx, NULL, ASC_REQ_ALLOCATE_MEMORY | ASC_REQ_STREAM, 0, NULL, &od, &attrs, &exp)
        : InitializeSecurityContextW(cred, &t->ctx, NULL, ISC_REQ_ALLOCATE_MEMORY | ISC_REQ_STREAM, 0, 0, NULL, 0, NULL, &od, &attrs, &exp);
    if (ob.pvBuffer) {
        send_all(t->fd, ob.pvBuffer, ob.cbBuffer);
        printf("  close_notify sent (%lu bytes, 0x%08lX)\n", (unsigned long)ob.cbBuffer, (unsigned long)st);
        FreeContextBuffer(ob.pvBuffer);
    }
    DeleteSecurityContext(&t->ctx);
    closesocket(t->fd);
}

/* ------------------------------------------------------------------ */
/* modes                                                               */

static int do_client(const char *host, const char *port, int min13, const char *pin)
{
    CredHandle cred;
    DWORD en = SP_PROT_TLS1_3_CLIENT | (min13 ? 0 : SP_PROT_TLS1_2_CLIENT);
    if (!acquire(&cred, SECPKG_CRED_OUTBOUND, en, NULL, pin != NULL)) return 1;
    tls t; memset(&t, 0, sizeof t);
    t.fd = connect_to(host, port, SOCK_STREAM);
    if (t.fd == INVALID_SOCKET) return 1;
    wchar_t whost[256]; MultiByteToWideChar(CP_UTF8, 0, host, -1, whost, 256);
    SECURITY_STATUS st = handshake(&t, &cred, whost, 0);
    if (st != SEC_E_OK) { say_status("handshake REFUSED", st); return 1; }
    show_connection(&t.ctx);
    if (pin && !check_pin(&t.ctx, host, pin)) return 1;
    char req[512];
    snprintf(req, sizeof req, "HEAD / HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n", host);
    if (pin) snprintf(req, sizeof req, "hello over schannel\n");
    tls_send(&t, req, (int)strlen(req));
    char buf[4096]; int n = tls_recv(&t, buf, sizeof buf - 1, &cred, whost);
    if (n > 0) { buf[n] = 0; char *nl = strpbrk(buf, "\r\n"); if (nl) *nl = 0; printf("  received: %s\n", buf); }
    tls_close(&t, &cred);
    return 0;
}

/* PEM, the key imported into CNG as a named, persisted key, which the
   certificate points to (CERT_KEY_PROV_INFO_PROP_ID); "delete" removes it
   once the credentials are acquired. */
static PCCERT_CONTEXT load_pem_named(const char *certfile, const char *keyfile)
{
    DWORD der_len, klen;
    BYTE *der = pem_der(certfile, &der_len);
    BYTE *kder = pem_der(keyfile, &klen);
    if (!der || !kder) return NULL;
    PCCERT_CONTEXT c = CertCreateCertificateContext(X509_ASN_ENCODING, der, der_len);
    if (!c) { printf("  CertCreateCertificateContext: %lu\n", GetLastError()); return NULL; }
    wchar_t name[64];
    swprintf(name, 64, L"oosockets-probe-%lu", (unsigned long)GetCurrentProcessId());
    NCryptBuffer nb = { (ULONG)((wcslen(name) + 1) * sizeof(wchar_t)), NCRYPTBUFFER_PKCS_KEY_NAME, name };
    NCryptBufferDesc nbd = { NCRYPTBUFFER_VERSION, 1, &nb };
    NCRYPT_PROV_HANDLE prov; NCRYPT_KEY_HANDLE key;
    SECURITY_STATUS st = NCryptOpenStorageProvider(&prov, MS_KEY_STORAGE_PROVIDER, 0);
    if (st) { say_status("NCryptOpenStorageProvider", st); return NULL; }
    st = NCryptImportKey(prov, 0, NCRYPT_PKCS8_PRIVATE_KEY_BLOB, &nbd, &key, kder, klen,
                         NCRYPT_SILENT_FLAG | NCRYPT_OVERWRITE_KEY_FLAG);
    if (st) { say_status("NCryptImportKey (named)", st); return NULL; }
    NCryptFreeObject(key);
    CRYPT_KEY_PROV_INFO kpi; memset(&kpi, 0, sizeof kpi);
    kpi.pwszContainerName = name;
    kpi.pwszProvName = (LPWSTR)MS_KEY_STORAGE_PROVIDER;
    if (!CertSetCertificateContextProperty(c, CERT_KEY_PROV_INFO_PROP_ID, 0, &kpi)) {
        printf("  CertSetCertificateContextProperty: %lu\n", GetLastError()); return NULL;
    }
    printf("  PEM loaded, named CNG key %ls\n", name);
    return c;
}

/* keystore: a PKCS#12 file, or "cert.pem;key.pem". keymode: see
   import_pfx; for PEM also "ephemeral" (the CNG key as it is). */
static PCCERT_CONTEXT server_cert(const char *keystore, const char *pw, const char *keymode)
{
    if (strchr(keystore, ';')) {
        char c[512]; strncpy(c, keystore, sizeof c - 1); c[sizeof c - 1] = 0;
        char *k = strchr(c, ';'); *k++ = 0;
        if (!strcmp(keymode, "ephemeral")) return load_pem(c, k, 0, keymode);
        return load_pem_named(c, k);
    }
    return load_p12(keystore, pw, keymode);
}

/* Server credentials for cert; with keymode "delete", the persisted key
   is deleted right after. */
static int server_cred(CredHandle *cred, DWORD protocols, PCCERT_CONTEXT cert, const char *keymode)
{
    if (!acquire(cred, SECPKG_CRED_INBOUND, protocols, cert, 0)) return 0;
    if (!strcmp(keymode, "delete")) delete_key(cert);
    return 1;
}

/* one client: a line in, the line upper-cased out */
static int serve_one(tls *t, CredHandle *cred)
{
    SECURITY_STATUS st = handshake(t, cred, NULL, 0);
    if (st != SEC_E_OK) { say_status("server handshake FAILED", st); closesocket(t->fd); return 1; }
    show_connection(&t->ctx);
    char buf[4096]; int n = tls_recv(t, buf, sizeof buf - 1, cred, NULL);
    if (n > 0) {
        buf[n] = 0; printf("  server received: %s", buf);
        for (int i = 0; i < n; i++) buf[i] = (char)toupper((unsigned char)buf[i]);
        tls_send(t, buf, n);
    }
    tls_close(t, cred);
    return 0;
}

static int do_server(int port, const char *keystore, const char *pw, const char *mode, int clients)
{
    PCCERT_CONTEXT cert = server_cert(keystore, pw, mode);
    if (!cert) return 1;
    CredHandle cred;
    if (!server_cred(&cred, SP_PROT_TLS1_2_SERVER | SP_PROT_TLS1_3_SERVER, cert, mode)) return 1;
    SOCKET l = listen_on(port, SOCK_STREAM);
    printf("  server (%s) listening on %d\n", mode, port); fflush(stdout);
    for (int i = 0; i < clients; i++) {
        tls t; memset(&t, 0, sizeof t); t.server = 1;
        t.fd = accept(l, NULL, NULL);
        serve_one(&t, &cred);
        fflush(stdout);
    }
    return 0;
}

static int do_starttls_server(int port, const char *p12, const char *pw, const char *keymode)
{
    PCCERT_CONTEXT cert = load_p12(p12, pw, keymode);
    if (!cert) return 1;
    CredHandle cred;
    if (!server_cred(&cred, SP_PROT_TLS1_2_SERVER | SP_PROT_TLS1_3_SERVER, cert, keymode)) return 1;
    SOCKET l = listen_on(port, SOCK_STREAM);
    tls t; memset(&t, 0, sizeof t); t.server = 1;
    t.fd = accept(l, NULL, NULL);
    char line[64]; int n = recv_wait(t.fd, line, 10, 10000);   /* "STARTTLS\r\n" */
    if (n != 10) { printf("  starttls-server: got %d bytes\n", n); return 1; }
    printf("  starttls-server: got STARTTLS in clear\n");
    send_all(t.fd, "220 go\r\n", 8);
    return serve_one(&t, &cred);
}

static int do_starttls_client(const char *host, const char *port, const char *pin)
{
    CredHandle cred;
    if (!acquire(&cred, SECPKG_CRED_OUTBOUND, SP_PROT_TLS1_2_CLIENT | SP_PROT_TLS1_3_CLIENT, NULL, 1)) return 1;
    tls t; memset(&t, 0, sizeof t);
    t.fd = connect_to(host, port, SOCK_STREAM);
    if (t.fd == INVALID_SOCKET) return 1;
    send_all(t.fd, "STARTTLS\r\n", 10);
    char line[16]; int n = recv_wait(t.fd, line, 8, 10000);
    printf("  starttls-client: %d bytes in clear: %.6s\n", n, n > 0 ? line : "");
    wchar_t whost[256]; MultiByteToWideChar(CP_UTF8, 0, host, -1, whost, 256);
    SECURITY_STATUS st = handshake(&t, &cred, whost, 0);
    if (st != SEC_E_OK) { say_status("handshake REFUSED", st); return 1; }
    show_connection(&t.ctx);
    if (!check_pin(&t.ctx, host, pin)) return 1;
    tls_send(&t, "after starttls\n", 15);
    char buf[256]; n = tls_recv(&t, buf, sizeof buf - 1, &cred, whost);
    if (n > 0) { buf[n] = 0; printf("  received: %s", buf); }
    tls_close(&t, &cred);
    return 0;
}

/* ------------------------------------------------------------------ */
/* DTLS                                                                */

static const char *status_name(SECURITY_STATUS st)
{
    switch (st) {
    case SEC_E_OK: return "SEC_E_OK";
    case SEC_I_CONTINUE_NEEDED: return "SEC_I_CONTINUE_NEEDED";
    case SEC_I_MESSAGE_FRAGMENT: return "SEC_I_MESSAGE_FRAGMENT";
    case SEC_E_INCOMPLETE_MESSAGE: return "SEC_E_INCOMPLETE_MESSAGE";
    case SEC_E_INVALID_PARAMETER: return "SEC_E_INVALID_PARAMETER";
    case SEC_E_INVALID_TOKEN: return "SEC_E_INVALID_TOKEN";
    default: return "";
    }
}

/* One step of a DTLS handshake. in/inlen: a datagram, or NULL. addr: the
   client's address, for the server (SECBUFFER_EXTRA, the cookie's). Sends
   whatever comes out, fragment by fragment, each as one datagram. */
static SECURITY_STATUS dtls_step(int server, CredHandle *cred, CtxtHandle *ctx, int *first,
                                 const wchar_t *target, SOCKET fd, char *in, int inlen,
                                 struct sockaddr *addr, int addrlen, int addr_mode)
{
    DWORD flags = server
        ? (ASC_REQ_SEQUENCE_DETECT | ASC_REQ_REPLAY_DETECT | ASC_REQ_CONFIDENTIALITY |
           ASC_REQ_EXTENDED_ERROR | ASC_REQ_ALLOCATE_MEMORY | ASC_REQ_DATAGRAM)
        : (ISC_REQ_SEQUENCE_DETECT | ISC_REQ_REPLAY_DETECT | ISC_REQ_CONFIDENTIALITY |
           ISC_REQ_EXTENDED_ERROR | ISC_REQ_ALLOCATE_MEMORY | ISC_REQ_DATAGRAM |
           ISC_REQ_USE_SUPPLIED_CREDS);
    SECURITY_STATUS st;
    int fragments = 0;
    do {
        SecBuffer inb[2] = { { (ULONG)inlen, SECBUFFER_TOKEN, in }, { 0, SECBUFFER_EMPTY, NULL } };
        if (server && addr_mode == 1) { inb[1].BufferType = SECBUFFER_EXTRA; inb[1].cbBuffer = addrlen; inb[1].pvBuffer = addr; }
        SecBufferDesc ind = { SECBUFFER_VERSION, 2, inb };
        SecBuffer outb[2] = { { 0, SECBUFFER_TOKEN, NULL }, { 0, SECBUFFER_ALERT, NULL } };
        SecBufferDesc outd = { SECBUFFER_VERSION, 2, outb };
        ULONG attrs; TimeStamp exp;
        if (server)
            st = AcceptSecurityContext(cred, *first ? NULL : ctx, &ind, flags, 0, ctx, &outd, &attrs, &exp);
        else
            st = InitializeSecurityContextW(cred, *first ? NULL : ctx, (SEC_WCHAR *)target, flags, 0, 0,
                                            (*first && !in) ? NULL : &ind, 0, ctx, &outd, &attrs, &exp);
        if (st == SEC_E_OK || st == SEC_I_CONTINUE_NEEDED || st == SEC_I_MESSAGE_FRAGMENT) *first = 0;
        printf("    %s step (in %d bytes): 0x%08lX %s, out %lu bytes\n", server ? "server" : "client", inlen,
               (unsigned long)st, status_name(st), (unsigned long)outb[0].cbBuffer);
        if (outb[0].cbBuffer && outb[0].pvBuffer) {
            int n = server ? sendto(fd, outb[0].pvBuffer, outb[0].cbBuffer, 0, addr, addrlen)
                           : send(fd, outb[0].pvBuffer, outb[0].cbBuffer, 0);
            if (n < 0) printf("    send: %d\n", WSAGetLastError());
        }
        if (outb[0].pvBuffer) FreeContextBuffer(outb[0].pvBuffer);
        if (outb[1].pvBuffer) FreeContextBuffer(outb[1].pvBuffer);
        in = NULL; inlen = 0;                    /* the next fragment: no input */
    } while (st == SEC_I_MESSAGE_FRAGMENT && ++fragments < 20);
    return st;
}

static int dtls_send(CtxtHandle *ctx, SOCKET fd, const char *data, int len)
{
    SecPkgContext_StreamSizes sz;
    SECURITY_STATUS st = QueryContextAttributesW(ctx, SECPKG_ATTR_DATAGRAM_SIZES, &sz);
    if (st) { say_status("SECPKG_ATTR_DATAGRAM_SIZES", st); return -1; }
    char *buf = malloc(sz.cbHeader + len + sz.cbTrailer);
    memcpy(buf + sz.cbHeader, data, len);
    SecBuffer b[4] = { { sz.cbHeader, SECBUFFER_STREAM_HEADER, buf },
                       { (ULONG)len, SECBUFFER_DATA, buf + sz.cbHeader },
                       { sz.cbTrailer, SECBUFFER_STREAM_TRAILER, buf + sz.cbHeader + len },
                       { 0, SECBUFFER_EMPTY, NULL } };
    SecBufferDesc d = { SECBUFFER_VERSION, 4, b };
    st = EncryptMessage(ctx, 0, &d, 0);
    if (st) { say_status("EncryptMessage (DTLS)", st); return -1; }
    int n = send(fd, buf, b[0].cbBuffer + b[1].cbBuffer + b[2].cbBuffer, 0);
    printf("  DTLS record sent: %d bytes for %d of data (max message %lu)\n", n, len, (unsigned long)sz.cbMaximumMessage);
    free(buf);
    return n;
}

static int dtls_recv(CtxtHandle *ctx, SOCKET fd, char *out, int outlen)
{
    for (int tries = 0; tries < 5; tries++) {
        char in[65536];
        int n = recv_wait(fd, in, sizeof in, 8000);
        if (n == -2) { printf("  DTLS receive: timed out\n"); return -1; }
        if (n < 0) { printf("  DTLS receive: %d\n", WSAGetLastError()); return -1; }
        SecBuffer b[4] = { { (ULONG)n, SECBUFFER_DATA, in }, { 0, SECBUFFER_EMPTY, NULL },
                           { 0, SECBUFFER_EMPTY, NULL }, { 0, SECBUFFER_EMPTY, NULL } };
        SecBufferDesc d = { SECBUFFER_VERSION, 4, b };
        SECURITY_STATUS st = DecryptMessage(ctx, &d, 0, NULL);
        if (st == SEC_I_CONTEXT_EXPIRED) { printf("  DTLS: peer sent close_notify\n"); return 0; }
        if (st != SEC_E_OK) { say_status("DecryptMessage (DTLS)", st); continue; }
        for (int i = 0; i < 4; i++)
            if (b[i].BufferType == SECBUFFER_DATA) {
                int got = (int)b[i].cbBuffer < outlen ? (int)b[i].cbBuffer : outlen;
                memcpy(out, b[i].pvBuffer, got);
                return got;
            }
    }
    return -1;
}

static int do_dtls_client(const char *host, const char *port, const char *pin)
{
    CredHandle cred;
    if (!acquire(&cred, SECPKG_CRED_OUTBOUND, SP_PROT_DTLS1_2_CLIENT, NULL, 1)) return 1;
    SOCKET fd = connect_to(host, port, SOCK_DGRAM);
    if (fd == INVALID_SOCKET) return 1;
    wchar_t whost[256]; MultiByteToWideChar(CP_UTF8, 0, host, -1, whost, 256);
    CtxtHandle ctx; int first = 1;
    SECURITY_STATUS st = dtls_step(0, &cred, &ctx, &first, whost, fd, NULL, 0, NULL, 0, 0);
    int timeouts = 0;
    while (st == SEC_I_CONTINUE_NEEDED) {
        char in[65536];
        int n = recv_wait(fd, in, sizeof in, 2000);
        if (n == -2) {
            /* Lost? Ask Schannel again with no input: does it send the flight again? */
            if (++timeouts > 3) { printf("  DTLS client: no answer\n"); return 1; }
            printf("  DTLS client: timeout %d, calling again with no input\n", timeouts);
            st = dtls_step(0, &cred, &ctx, &first, whost, fd, NULL, 0, NULL, 0, 0);
            continue;
        }
        if (n < 0) { printf("  DTLS client: recv %d\n", WSAGetLastError()); return 1; }
        st = dtls_step(0, &cred, &ctx, &first, whost, fd, in, n, NULL, 0, 0);
    }
    if (st != SEC_E_OK) { say_status("DTLS handshake REFUSED", st); return 1; }
    show_connection(&ctx);
    if (getenv("DTLS_MTU")) {
        DWORD mtu = (DWORD)atoi(getenv("DTLS_MTU"));
        SECURITY_STATUS m = SetContextAttributesW(&ctx, SECPKG_ATTR_DTLS_MTU, &mtu, sizeof mtu);
        printf("  SECPKG_ATTR_DTLS_MTU = %lu: 0x%08lX\n", (unsigned long)mtu, (unsigned long)m);
    }
    if (pin && !check_pin(&ctx, host, pin)) return 1;
    dtls_send(&ctx, fd, "hello\n", 6);
    char buf[2048]; int n = dtls_recv(&ctx, fd, buf, sizeof buf - 1);
    if (n > 0) { buf[n] = 0; printf("  DTLS received: %s", buf); }
    /* how large a datagram can EncryptMessage take? */
    char *big = malloc(20000); memset(big, 'x', 20000);
    dtls_send(&ctx, fd, big, 1000);
    dtls_send(&ctx, fd, big, 1200);
    dtls_send(&ctx, fd, big, 16000);
    dtls_send(&ctx, fd, big, 16384);
    return 0;
}

/* addr_mode 0: no address given to AcceptSecurityContext; 1: the client's
   address as SECBUFFER_EXTRA (what the few public uses of Schannel's DTLS
   server suggest; undocumented). */
static int do_dtls_server(int port, const char *p12, const char *pw, int addr_mode, const char *keymode)
{
    PCCERT_CONTEXT cert = load_p12(p12, pw, keymode);
    if (!cert) return 1;
    CredHandle cred;
    if (!server_cred(&cred, SP_PROT_DTLS1_2_SERVER, cert, keymode)) return 1;
    SOCKET fd = listen_on(port, SOCK_DGRAM);
    printf("  DTLS server on %d (client address: %s)\n", port, addr_mode ? "SECBUFFER_EXTRA" : "none");
    fflush(stdout);
    CtxtHandle ctx; int first = 1;
    struct sockaddr_storage from; int fromlen;
    SECURITY_STATUS st = SEC_I_CONTINUE_NEEDED;
    int steps = 0;
    while (st == SEC_I_CONTINUE_NEEDED && steps++ < 30) {
        char in[65536];
        fromlen = sizeof from;
        fd_set r; FD_ZERO(&r); FD_SET(fd, &r);
        struct timeval tv = { 15, 0 };
        if (select(0, &r, NULL, NULL, &tv) <= 0) { printf("  DTLS server: nothing in 15 s\n"); return 1; }
        int n = recvfrom(fd, in, sizeof in, 0, (struct sockaddr *)&from, &fromlen);
        if (n < 0) { printf("  DTLS server: recvfrom %d\n", WSAGetLastError()); return 1; }
        st = dtls_step(1, &cred, &ctx, &first, NULL, fd, in, n, (struct sockaddr *)&from, fromlen, addr_mode);
    }
    if (st != SEC_E_OK) { say_status("DTLS server handshake FAILED", st); return 1; }
    show_connection(&ctx);
    connect(fd, (struct sockaddr *)&from, fromlen);
    char buf[2048]; int n = dtls_recv(&ctx, fd, buf, sizeof buf - 1);
    if (n > 0) {
        buf[n] = 0; printf("  DTLS server received: %s", buf);
        for (int i = 0; i < n; i++) buf[i] = (char)toupper((unsigned char)buf[i]);
        dtls_send(&ctx, fd, buf, n);
    }
    Sleep(1000);
    return 0;
}

int main(int argc, char **argv)
{
    WSADATA w; WSAStartup(MAKEWORD(2, 2), &w);
    setvbuf(stdout, NULL, _IONBF, 0);
    if (argc < 3) { printf("usage: see probe.c\n"); return 2; }
    const char *m = argv[1];
    if (!strcmp(m, "client")) return do_client(argv[2], argc > 3 ? argv[3] : "443", argc > 4 && !strcmp(argv[4], "13"), NULL);
    if (!strcmp(m, "pin") && argc > 4) return do_client(argv[2], argv[3], 0, argv[4]);
    if (!strcmp(m, "server") && argc > 5) return do_server(atoi(argv[2]), argv[3], argv[4], argv[5], argc > 6 ? atoi(argv[6]) : 1);
    if (!strcmp(m, "starttls-server") && argc > 5) return do_starttls_server(atoi(argv[2]), argv[3], argv[4], argv[5]);
    if (!strcmp(m, "starttls-client") && argc > 4) return do_starttls_client(argv[2], argv[3], argv[4]);
    if (!strcmp(m, "dtls") && argc > 4) return do_dtls_client(argv[2], argv[3], argv[4]);
    if (!strcmp(m, "dtls-server") && argc > 6) return do_dtls_server(atoi(argv[2]), argv[3], argv[4], atoi(argv[5]), argv[6]);
    printf("unknown mode or missing arguments\n");
    return 2;
}
