/* The probe's library, built as liboosockets would be: weakly linked to
   @rpath/libssl.3.dylib and @rpath/libcrypto.3.dylib, with Homebrew's and
   MacPorts' directories as its rpaths. Loading it must not need OpenSSL;
   probe_tls() says whether OpenSSL was found, where, and that it works. */
#include <dlfcn.h>
#include <stdio.h>
#include <string.h>
#include <openssl/ssl.h>
#include <openssl/crypto.h>
#include <openssl/opensslv.h>

int probe_plain(char *out, int len)
{
    snprintf(out, len, "plain code runs (built against %s)", OPENSSL_VERSION_TEXT);
    return 1;
}

int probe_tls(char *out, int len)
{
    /* weak symbols: NULL when the library was not found. Through a
       volatile, so that the compiler cannot take a function's address
       for non-null (the headers do not declare them weak). */
    void *volatile a = (void *)&OpenSSL_version_num;
    void *volatile b = (void *)&SSL_CTX_new;
    if (a == NULL || b == NULL) {
        snprintf(out, len, "OpenSSL NOT FOUND (weak symbols are NULL)");
        return 0;
    }
    unsigned long v = OpenSSL_version_num();
    Dl_info ssl, crypto;
    memset(&ssl, 0, sizeof ssl); memset(&crypto, 0, sizeof crypto);
    dladdr((void *)&SSL_CTX_new, &ssl);
    dladdr((void *)&OpenSSL_version_num, &crypto);
    SSL_CTX *ctx = SSL_CTX_new(TLS_client_method());
    int ok = ctx != NULL;
    if (ctx) SSL_CTX_free(ctx);
    snprintf(out, len, "found %s (0x%lx); libssl %s; libcrypto %s; SSL_CTX_new %s",
             OpenSSL_version(OPENSSL_VERSION), v, ssl.dli_fname ? ssl.dli_fname : "?",
             crypto.dli_fname ? crypto.dli_fname : "?", ok ? "works" : "FAILED");
    return ok;
}
