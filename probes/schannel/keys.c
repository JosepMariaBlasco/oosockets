/* What Windows does with the private keys of a PKCS#12 file, measured for
   ooSockets' Schannel server (the v10 review's open points):

     keys orphan   file.p12 pw     a persisted import (as the server does
                                   now): which keys appear in the user's key
                                   store, and which are left once the keys of
                                   the certificates are deleted.
     keys reuse    file.p12 pw name
                                   a persisted key called name exists first;
                                   then the file is imported persisted (with
                                   PKCS12_ALLOW_OVERWRITE_KEY if OVERWRITE is
                                   set): is name still the same key?
     keys export   file.p12 pw     imported NOT persisted, exportable: can
                                   the key be exported (PKCS#8, plain or
                                   encrypted; CNG's own blob), imported again
                                   as a named persisted key, and Schannel's
                                   server credentials made with it?
     keys list     prefix          the keys whose name starts with prefix;
                                   deletes them if DELETE is set.

   Everything prints what happened. */

#define WIN32_LEAN_AND_MEAN
#define SECURITY_WIN32
#include <windows.h>
#include <wincrypt.h>
#include <ncrypt.h>
#include <subauth.h>
#include <schannel.h>
#include <security.h>
#include <sspi.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <wchar.h>

#ifndef PKCS12_ALWAYS_CNG_KSP
#define PKCS12_ALWAYS_CNG_KSP 0x00000200
#endif
#ifndef PKCS12_ALLOW_OVERWRITE_KEY
#define PKCS12_ALLOW_OVERWRITE_KEY 0x00004000
#endif
#ifndef PKCS12_NO_PERSIST_KEY
#define PKCS12_NO_PERSIST_KEY 0x00008000
#endif

static void say(const char *what, SECURITY_STATUS st)
{
    char text[512] = "";
    FormatMessageA(FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS, NULL, (DWORD)st, 0, text,
                   sizeof text, NULL);
    for (char *p = text; *p; p++) if (*p == '\r' || *p == '\n') *p = ' ';
    printf("  %s: 0x%08lX %s\n", what, (unsigned long)st, text);
}

static char *read_file(const char *name, DWORD *len)
{
    FILE *f = fopen(name, "rb");
    if (!f) { printf("  cannot open %s\n", name); exit(1); }
    fseek(f, 0, SEEK_END); long n = ftell(f); fseek(f, 0, SEEK_SET);
    char *b = malloc(n); fread(b, 1, n, f); fclose(f);
    *len = (DWORD)n;
    return b;
}

/* The names of the user's keys in the Microsoft Software KSP. */
#define MAXK 4096
static int list_keys(wchar_t names[][128], int max)
{
    NCRYPT_PROV_HANDLE prov = 0;
    if (NCryptOpenStorageProvider(&prov, MS_KEY_STORAGE_PROVIDER, 0) != ERROR_SUCCESS) return -1;
    NCryptKeyName *k = NULL; PVOID state = NULL; int n = 0;
    while (NCryptEnumKeys(prov, NULL, &k, &state, NCRYPT_SILENT_FLAG) == ERROR_SUCCESS) {
        if (n < max) { wcsncpy(names[n], k->pszName, 127); names[n][127] = 0; n++; }
        NCryptFreeBuffer(k);
    }
    if (state) NCryptFreeBuffer(state);
    NCryptFreeObject(prov);
    return n;
}

static wchar_t before[MAXK][128], after[MAXK][128];

static void show_new(int nb, int na, const char *what)
{
    int shown = 0;
    for (int i = 0; i < na; i++) {
        int old = 0;
        for (int j = 0; j < nb && !old; j++) old = !wcscmp(after[i], before[j]);
        if (!old) { printf("  %s: %ls\n", what, after[i]); shown++; }
    }
    if (!shown) printf("  %s: none\n", what);
}

static void cert_name(PCCERT_CONTEXT c, char *out, int n)
{
    CertGetNameStringA(c, CERT_NAME_SIMPLE_DISPLAY_TYPE, 0, NULL, out, n);
}

/* Each certificate of the store, with the container of its key. */
static void show_certs(HCERTSTORE st)
{
    PCCERT_CONTEXT x = NULL; int i = 0;
    while ((x = CertEnumCertificatesInStore(st, x)) != NULL) {
        char nm[256]; cert_name(x, nm, sizeof nm);
        DWORD n = 0;
        if (CertGetCertificateContextProperty(x, CERT_KEY_PROV_INFO_PROP_ID, NULL, &n)) {
            CRYPT_KEY_PROV_INFO *pi = malloc(n);
            CertGetCertificateContextProperty(x, CERT_KEY_PROV_INFO_PROP_ID, pi, &n);
            printf("  certificate %d (%s): key container %ls, provider %ls\n", i, nm, pi->pwszContainerName,
                   pi->pwszProvName ? pi->pwszProvName : L"-");
            free(pi);
        } else if (CertGetCertificateContextProperty(x, CERT_NCRYPT_KEY_HANDLE_PROP_ID, NULL, &n)) {
            printf("  certificate %d (%s): an NCrypt key handle (not persisted)\n", i, nm);
        } else {
            printf("  certificate %d (%s): no key\n", i, nm);
        }
        i++;
    }
    if (!i) printf("  no certificate in the store\n");
}

static HCERTSTORE import(const char *file, const char *pw, DWORD flags)
{
    DWORD len; char *data = read_file(file, &len);
    CRYPT_DATA_BLOB blob = { len, (BYTE *)data };
    wchar_t wpw[256]; MultiByteToWideChar(CP_UTF8, 0, pw, -1, wpw, 256);
    HCERTSTORE st = PFXImportCertStore(&blob, wpw, flags);
    if (!st && !*pw) st = PFXImportCertStore(&blob, NULL, flags);
    if (!st) say("PFXImportCertStore", (SECURITY_STATUS)HRESULT_FROM_WIN32(GetLastError()));
    return st;
}

static void delete_cert_keys(HCERTSTORE st)
{
    PCCERT_CONTEXT x = NULL;
    while ((x = CertEnumCertificatesInStore(st, x)) != NULL) {
        HCRYPTPROV_OR_NCRYPT_KEY_HANDLE k = 0; DWORD spec = 0; BOOL free_it = FALSE; DWORD n = 0;
        if (CertGetCertificateContextProperty(x, CERT_KEY_PROV_INFO_PROP_ID, NULL, &n) &&
            CryptAcquireCertificatePrivateKey(x, CRYPT_ACQUIRE_SILENT_FLAG | CRYPT_ACQUIRE_ONLY_NCRYPT_KEY_FLAG,
                                              NULL, &k, &spec, &free_it)) {
            SECURITY_STATUS s = NCryptDeleteKey((NCRYPT_KEY_HANDLE)k, 0);
            printf("  deleted a certificate's key: 0x%08lX\n", (unsigned long)s);
        }
    }
}

static int do_orphan(const char *file, const char *pw)
{
    int nb = list_keys(before, MAXK);
    printf("  keys before: %d\n", nb);
    HCERTSTORE st = import(file, pw, CRYPT_USER_KEYSET | PKCS12_ALWAYS_CNG_KSP);
    if (!st) return 1;
    show_certs(st);
    int na = list_keys(after, MAXK);
    printf("  keys after the import: %d\n", na);
    show_new(nb, na, "new key");
    delete_cert_keys(st);
    CertCloseStore(st, 0);
    na = list_keys(after, MAXK);
    printf("  keys after deleting the certificates' keys: %d\n", na);
    show_new(nb, na, "left behind");
    /* clean up what the probe left, so that runs do not add up */
    for (int i = 0; i < na; i++) {
        int old = 0;
        for (int j = 0; j < nb && !old; j++) old = !wcscmp(after[i], before[j]);
        if (!old) {
            NCRYPT_PROV_HANDLE p = 0; NCRYPT_KEY_HANDLE k = 0;
            NCryptOpenStorageProvider(&p, MS_KEY_STORAGE_PROVIDER, 0);
            if (NCryptOpenKey(p, &k, after[i], 0, NCRYPT_SILENT_FLAG) == ERROR_SUCCESS) NCryptDeleteKey(k, 0);
            NCryptFreeObject(p);
        }
    }
    return 0;
}

static int public_blob(NCRYPT_KEY_HANDLE k, BYTE *out, DWORD max, DWORD *n)
{
    return NCryptExportKey(k, 0, BCRYPT_PUBLIC_KEY_BLOB, NULL, out, max, n, 0) == ERROR_SUCCESS;
}

static int do_reuse(const char *file, const char *pw, const char *name)
{
    wchar_t wname[128]; MultiByteToWideChar(CP_UTF8, 0, name, -1, wname, 128);
    NCRYPT_PROV_HANDLE prov = 0; NCRYPT_KEY_HANDLE k = 0;
    NCryptOpenStorageProvider(&prov, MS_KEY_STORAGE_PROVIDER, 0);
    if (NCryptOpenKey(prov, &k, wname, 0, NCRYPT_SILENT_FLAG) == ERROR_SUCCESS) { NCryptDeleteKey(k, 0); k = 0; }
    SECURITY_STATUS s = NCryptCreatePersistedKey(prov, &k, BCRYPT_RSA_ALGORITHM, wname, 0, 0);
    if (s == ERROR_SUCCESS) s = NCryptFinalizeKey(k, 0);
    if (s != ERROR_SUCCESS) { say("creating the existing key", s); return 1; }
    BYTE pub1[2048], pub2[2048]; DWORD n1 = 0, n2 = 0;
    public_blob(k, pub1, sizeof pub1, &n1);
    NCryptFreeObject(k); k = 0;
    printf("  key %s created (%lu bytes of public key)\n", name, (unsigned long)n1);
    DWORD flags = CRYPT_USER_KEYSET | PKCS12_ALWAYS_CNG_KSP | (getenv("OVERWRITE") ? PKCS12_ALLOW_OVERWRITE_KEY : 0);
    printf("  import flags 0x%08lX\n", (unsigned long)flags);
    HCERTSTORE st = import(file, pw, flags);
    if (st) show_certs(st);
    s = NCryptOpenKey(prov, &k, wname, 0, NCRYPT_SILENT_FLAG);
    if (s != ERROR_SUCCESS) say("the existing key, after the import", s);
    else {
        public_blob(k, pub2, sizeof pub2, &n2);
        printf("  the existing key, after the import: %s\n",
               n1 == n2 && !memcmp(pub1, pub2, n1) ? "UNCHANGED" : "REPLACED (another public key)");
    }
    if (st) {
        /* would deleting the certificates' keys (as ooSockets does) delete it? */
        delete_cert_keys(st);
        CertCloseStore(st, 0);
        if (k) { NCryptFreeObject(k); k = 0; }
        s = NCryptOpenKey(prov, &k, wname, 0, NCRYPT_SILENT_FLAG);
        printf("  the existing key, after deleting the certificates' keys: %s\n",
               s == ERROR_SUCCESS ? "still there" : "GONE");
    }
    if (k) NCryptDeleteKey(k, 0);
    NCryptFreeObject(prov);
    return 0;
}

static NCRYPT_KEY_HANDLE cert_key(PCCERT_CONTEXT x)
{
    HCRYPTPROV_OR_NCRYPT_KEY_HANDLE k = 0; DWORD spec = 0; BOOL free_it = FALSE;
    if (!CryptAcquireCertificatePrivateKey(x, CRYPT_ACQUIRE_SILENT_FLAG | CRYPT_ACQUIRE_ONLY_NCRYPT_KEY_FLAG |
                                           CRYPT_ACQUIRE_CACHE_FLAG, NULL, &k, &spec, &free_it)) {
        say("CryptAcquireCertificatePrivateKey", (SECURITY_STATUS)HRESULT_FROM_WIN32(GetLastError()));
        return 0;
    }
    return (NCRYPT_KEY_HANDLE)k;
}

static int server_credentials(PCCERT_CONTEXT cert)
{
    SCHANNEL_CRED sc; memset(&sc, 0, sizeof sc);
    sc.dwVersion = SCHANNEL_CRED_VERSION;
    sc.cCreds = 1; sc.paCred = &cert;
    sc.grbitEnabledProtocols = SP_PROT_TLS1_2_SERVER;
    CredHandle h; TimeStamp ts;
    SECURITY_STATUS s = AcquireCredentialsHandleW(NULL, (SEC_WCHAR *)UNISP_NAME_W, SECPKG_CRED_INBOUND, NULL, &sc,
                                                  NULL, NULL, &h, &ts);
    say("AcquireCredentialsHandle (server)", s);
    if (s == SEC_E_OK) FreeCredentialsHandle(&h);
    return s == SEC_E_OK;
}

static int do_export(const char *file, const char *pw)
{
    int nb = list_keys(before, MAXK);
    HCERTSTORE st = import(file, pw, PKCS12_NO_PERSIST_KEY | PKCS12_ALWAYS_CNG_KSP | CRYPT_EXPORTABLE);
    if (!st) return 1;
    show_certs(st);
    int na = list_keys(after, MAXK);
    show_new(nb, na, "key persisted by a NO_PERSIST import");
    PCCERT_CONTEXT x = NULL, cert = NULL;
    while ((x = CertEnumCertificatesInStore(st, x)) != NULL) {
        DWORD n = 0;
        if (CertGetCertificateContextProperty(x, CERT_NCRYPT_KEY_HANDLE_PROP_ID, NULL, &n) ||
            CertGetCertificateContextProperty(x, CERT_KEY_PROV_INFO_PROP_ID, NULL, &n)) {
            cert = CertDuplicateCertificateContext(x);
        }
    }
    if (!cert) { printf("  no certificate with a key\n"); return 1; }
    NCRYPT_KEY_HANDLE k = cert_key(cert);
    if (!k) return 1;
    DWORD policy = 0, n = 0;
    SECURITY_STATUS s = NCryptGetProperty(k, NCRYPT_EXPORT_POLICY_PROPERTY, (PBYTE)&policy, sizeof policy, &n, 0);
    printf("  export policy: 0x%08lX (status 0x%08lX; 1 allow export, 2 allow plaintext export)\n",
           (unsigned long)policy, (unsigned long)s);
    wchar_t alg[64] = L""; n = 0;
    NCryptGetProperty(k, NCRYPT_ALGORITHM_PROPERTY, (PBYTE)alg, sizeof alg, &n, 0);
    printf("  algorithm: %ls\n", alg);

    /* 1. PKCS#8, plain */
    static BYTE blob[16384]; DWORD bn = 0;
    s = NCryptExportKey(k, 0, NCRYPT_PKCS8_PRIVATE_KEY_BLOB, NULL, blob, sizeof blob, &bn, 0);
    say("export PKCS#8, plain", s);
    int have_plain = s == ERROR_SUCCESS;
    /* 2. CNG's own private blob */
    static BYTE blob2[16384]; DWORD bn2 = 0;
    LPCWSTR own = !wcscmp(alg, L"RSA") ? BCRYPT_RSAFULLPRIVATE_BLOB : BCRYPT_ECCPRIVATE_BLOB;
    s = NCryptExportKey(k, 0, own, NULL, blob2, sizeof blob2, &bn2, 0);
    printf("  (CNG's blob: %ls)\n", own);
    say("export CNG's private blob", s);
    /* 3. PKCS#8, encrypted with a password (PKCS#12's 3DES) */
    static BYTE blob3[16384]; DWORD bn3 = 0;
    wchar_t secret[] = L"oosockets-probe";
    BYTE salt[8] = { 1, 2, 3, 4, 5, 6, 7, 8 };
    BYTE pbe[sizeof(CRYPT_PKCS12_PBE_PARAMS) + 8];
    CRYPT_PKCS12_PBE_PARAMS *pp = (CRYPT_PKCS12_PBE_PARAMS *)pbe;
    pp->iIterations = 2048; pp->cbSalt = 8;
    memcpy(pbe + sizeof(CRYPT_PKCS12_PBE_PARAMS), salt, 8);
    char oid[] = szOID_PKCS_12_pbeWithSHA1And3KeyTripleDES;
    NCryptBuffer eb[3] = {
        { (ULONG)((wcslen(secret) + 1) * sizeof(wchar_t)), NCRYPTBUFFER_PKCS_SECRET, secret },
        { (ULONG)sizeof oid, NCRYPTBUFFER_PKCS_ALG_OID, oid },
        { (ULONG)sizeof pbe, NCRYPTBUFFER_PKCS_ALG_PARAM, pbe } };
    NCryptBufferDesc ed = { NCRYPTBUFFER_VERSION, 3, eb };
    s = NCryptExportKey(k, 0, NCRYPT_PKCS8_PRIVATE_KEY_BLOB, &ed, blob3, sizeof blob3, &bn3, 0);
    say("export PKCS#8, encrypted", s);
    int have_enc = s == ERROR_SUCCESS;

    /* the exported key, imported again persisted under our own name */
    if (have_plain || have_enc) {
        NCRYPT_PROV_HANDLE prov = 0; NCRYPT_KEY_HANDLE nk = 0;
        NCryptOpenStorageProvider(&prov, MS_KEY_STORAGE_PROVIDER, 0);
        wchar_t name[] = L"oosockets-probe-export";
        NCryptBuffer ib[2] = { { (ULONG)sizeof name, NCRYPTBUFFER_PKCS_KEY_NAME, name },
                               { (ULONG)((wcslen(secret) + 1) * sizeof(wchar_t)), NCRYPTBUFFER_PKCS_SECRET, secret } };
        NCryptBufferDesc id = { NCRYPTBUFFER_VERSION, have_plain ? 1 : 2, ib };
        s = NCryptImportKey(prov, 0, NCRYPT_PKCS8_PRIVATE_KEY_BLOB, &id, &nk, have_plain ? blob : blob3,
                            have_plain ? bn : bn3, NCRYPT_DO_NOT_FINALIZE_FLAG);
        if (s == ERROR_SUCCESS) s = NCryptFinalizeKey(nk, 0);
        printf("  (imported from the %s export)\n", have_plain ? "plain" : "encrypted");
        say("import as a named persisted key", s);
        if (s == ERROR_SUCCESS) {
            PCCERT_CONTEXT c2 = CertCreateCertificateContext(X509_ASN_ENCODING, cert->pbCertEncoded,
                                                             cert->cbCertEncoded);
            CRYPT_KEY_PROV_INFO info; memset(&info, 0, sizeof info);
            info.pwszContainerName = name; info.pwszProvName = (LPWSTR)MS_KEY_STORAGE_PROVIDER;
            CertSetCertificateContextProperty(c2, CERT_KEY_PROV_INFO_PROP_ID, 0, &info);
            printf("  server credentials with the key imported again:\n");
            server_credentials(c2);
            NCryptDeleteKey(nk, 0);
            CertFreeCertificateContext(c2);
        }
        if (have_enc && have_plain) {
            /* and the encrypted one too, to know it works */
            ib[0].pvBuffer = name; id.cBuffers = 2; nk = 0;
            s = NCryptImportKey(prov, 0, NCRYPT_PKCS8_PRIVATE_KEY_BLOB, &id, &nk, blob3, bn3,
                                NCRYPT_DO_NOT_FINALIZE_FLAG);
            if (s == ERROR_SUCCESS) s = NCryptFinalizeKey(nk, 0);
            say("import of the encrypted export as a named persisted key", s);
            if (nk) NCryptDeleteKey(nk, 0);
        }
        NCryptFreeObject(prov);
    }
    printf("  server credentials with the NO_PERSIST import itself (known: 0x8009030E):\n");
    server_credentials(cert);
    CertFreeCertificateContext(cert);
    CertCloseStore(st, 0);
    na = list_keys(after, MAXK);
    show_new(nb, na, "left behind");
    return 0;
}

static int do_list(const char *prefix)
{
    int n = list_keys(after, MAXK);
    wchar_t wp[128]; MultiByteToWideChar(CP_UTF8, 0, prefix, -1, wp, 128);
    printf("  %d keys in all\n", n);
    for (int i = 0; i < n; i++) {
        if (wcsncmp(after[i], wp, wcslen(wp))) continue;
        printf("  %ls", after[i]);
        if (getenv("DELETE")) {
            NCRYPT_PROV_HANDLE p = 0; NCRYPT_KEY_HANDLE k = 0;
            NCryptOpenStorageProvider(&p, MS_KEY_STORAGE_PROVIDER, 0);
            SECURITY_STATUS s = NCryptOpenKey(p, &k, after[i], 0, NCRYPT_SILENT_FLAG);
            if (s == ERROR_SUCCESS) s = NCryptDeleteKey(k, 0);
            printf(" (deleted: 0x%08lX)", (unsigned long)s);
            NCryptFreeObject(p);
        }
        printf("\n");
    }
    return 0;
}

int main(int argc, char **argv)
{
    setvbuf(stdout, NULL, _IONBF, 0);
    if (argc >= 4 && !strcmp(argv[1], "orphan")) return do_orphan(argv[2], argv[3]);
    if (argc >= 5 && !strcmp(argv[1], "reuse")) return do_reuse(argv[2], argv[3], argv[4]);
    if (argc >= 4 && !strcmp(argv[1], "export")) return do_export(argv[2], argv[3]);
    if (argc >= 3 && !strcmp(argv[1], "list")) return do_list(argv[2]);
    printf("usage: keys orphan|reuse|export|list ...\n");
    return 2;
}
