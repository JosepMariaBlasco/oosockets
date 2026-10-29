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
 * ossl.h: OpenSSL loaded when TLS is first used (Linux and macOS).
 *
 * The library does not link OpenSSL: the first way into TLS or DTLS loads
 * libssl with dlopen, and takes every function it calls from it (and from
 * the libcrypto libssl itself depends on, so that the two always belong
 * together). Without OpenSSL 3 the library still loads and the plain
 * sockets work. Where it comes from:
 *
 *   OOSOCKETS_OPENSSL set: libssl in that directory, and nowhere else
 *                          (Rony, 29/10/2026: an optional environment
 *                          variable, "to keep the flexibility")
 *   Linux:  libssl.so.3, as the system finds it
 *   macOS:  the OpenSSL 3 of Homebrew (Apple Silicon, Intel) or MacPorts
 *
 * Include it after OpenSSL's headers: from here on, each name in
 * OSSL_FUNCTIONS is a call through the table (OpenSSL's own macros, such
 * as SSL_CTX_set_mode, expand to those names and go through it too).
 * Windows links OpenSSL as before (to be replaced by Schannel).
 */

#ifndef OOSOCKETS_OSSL_H
#define OOSOCKETS_OSSL_H

#ifndef _WIN32
#define OOSOCKETS_DYNAMIC_OPENSSL 1

// Every OpenSSL function the library calls. A name missing here is an
// undefined symbol in the library (`nm -u`): the CI checks there is none.
#define OSSL_FUNCTIONS(X) \
    X(BIO_ADDR_free) X(BIO_ADDR_new) X(BIO_ADDR_rawmake) X(BIO_clear_flags) \
    X(BIO_free) X(BIO_get_data) X(BIO_get_new_index) X(BIO_meth_new) \
    X(BIO_meth_set_create) X(BIO_meth_set_ctrl) X(BIO_meth_set_read) \
    X(BIO_meth_set_write) X(BIO_new) X(BIO_new_mem_buf) X(BIO_set_data) \
    X(BIO_set_flags) X(BIO_set_init) X(BIO_test_flags) \
    X(CRYPTO_free) X(CRYPTO_memcmp) \
    X(DTLS_client_method) X(DTLS_server_method) X(DTLSv1_listen) \
    X(ERR_clear_error) X(ERR_error_string_n) X(ERR_get_error) \
    X(ERR_peek_last_error) X(ERR_reason_error_string) \
    X(EVP_PKEY_free) X(EVP_sha256) X(HMAC) \
    X(OPENSSL_sk_free) X(OPENSSL_sk_num) X(OPENSSL_sk_shift) X(OPENSSL_sk_value) \
    X(OpenSSL_version_num) \
    X(PEM_read_bio_PrivateKey) X(PEM_read_bio_X509) X(PKCS12_free) X(PKCS12_parse) \
    X(RAND_bytes) \
    X(SSL_CIPHER_get_name) X(SSL_CTX_check_private_key) X(SSL_CTX_ctrl) \
    X(SSL_CTX_free) X(SSL_CTX_get_cert_store) X(SSL_CTX_new) \
    X(SSL_CTX_set_cert_verify_callback) X(SSL_CTX_set_cookie_generate_cb) \
    X(SSL_CTX_set_cookie_verify_cb) X(SSL_CTX_set_default_verify_paths) \
    X(SSL_CTX_set_num_tickets) X(SSL_CTX_set_options) X(SSL_CTX_set_verify) \
    X(SSL_CTX_up_ref) X(SSL_CTX_use_PrivateKey) X(SSL_CTX_use_certificate) \
    X(SSL_ctrl) X(SSL_do_handshake) X(SSL_free) X(SSL_get0_param) \
    X(SSL_get_current_cipher) X(SSL_get_error) X(SSL_get_ex_data) \
    X(SSL_get_ex_data_X509_STORE_CTX_idx) X(SSL_get_verify_result) \
    X(SSL_get_version) X(SSL_is_init_finished) X(SSL_new) X(SSL_read_ex) \
    X(SSL_set1_host) X(SSL_set_accept_state) X(SSL_set_bio) \
    X(SSL_set_connect_state) X(SSL_set_ex_data) X(SSL_shutdown) X(SSL_write_ex) \
    X(TLS_client_method) X(TLS_server_method) \
    X(X509_STORE_CTX_get0_cert) X(X509_STORE_CTX_get0_untrusted) \
    X(X509_STORE_CTX_get_ex_data) X(X509_STORE_CTX_set_error) \
    X(X509_STORE_add_cert) X(X509_STORE_set_flags) \
    X(X509_VERIFY_PARAM_set1_ip_asc) X(X509_cmp) X(X509_free) \
    X(X509_verify_cert_error_string) X(d2i_PKCS12) X(d2i_X509) X(i2d_X509)

struct OsslTable
{
#define OSSL_FIELD(f) decltype(&::f) f;
    OSSL_FUNCTIONS(OSSL_FIELD)
#undef OSSL_FIELD
};

static OsslTable ossl;

#include <dlfcn.h>
#include <cstdlib>
#include <mutex>
#include <string>
#include <vector>

// Loads OpenSSL once, the first time any thread asks; true if it is there.
// Otherwise false, and why says what to do (the same text every time).
static bool osslLoad(std::string &why)
{
    static std::once_flag once;
    static bool loaded = false;
    static std::string reason;
    std::call_once(once, []
    {
        const char *env = getenv("OOSOCKETS_OPENSSL");
#ifdef __APPLE__
        const char *name = "libssl.3.dylib";
        std::vector<std::string> where = {
            "/opt/homebrew/opt/openssl@3/lib",      // Homebrew, Apple Silicon
            "/usr/local/opt/openssl@3/lib",         // Homebrew, Intel (and Rosetta)
            "/opt/local/lib/openssl-3",             // MacPorts' openssl3
            "/opt/local/libexec/openssl3/lib"};
        reason = "OpenSSL 3 not found; install it with \"brew install openssl@3\""
                 " or \"sudo port install openssl3\"";
#else
        const char *name = "libssl.so.3";
        std::vector<std::string> where = {""};     // where the system finds it
        reason = "OpenSSL 3 not found; install it with the system's package manager";
#endif
        bool own = env != nullptr && *env != '\0';
        if (own)
        {
            where = {env};
            reason = std::string("OpenSSL 3 not found in ") + env + " (OOSOCKETS_OPENSSL)";
        }
        void *h = nullptr;
        for (const std::string &dir : where)
        {
            std::string path = dir.empty() ? name : dir + "/" + name;
            h = dlopen(path.c_str(), RTLD_NOW | RTLD_LOCAL);
            if (h != nullptr)
            {
                break;
            }
        }
        if (h == nullptr)
        {
            return;
        }
        // libssl's handle finds libcrypto's functions too: the libcrypto
        // that this libssl was built with.
        std::string missing;
#define OSSL_LOAD(f) \
        ossl.f = (decltype(ossl.f))dlsym(h, #f); \
        if (ossl.f == nullptr && missing.empty()) missing = #f;
        OSSL_FUNCTIONS(OSSL_LOAD)
#undef OSSL_LOAD
        if (!missing.empty() || ossl.OpenSSL_version_num() < 0x30000000UL)
        {
            // An OpenSSL, but not a 3.x (or not a whole one).
            if (own)
            {
                reason = std::string("the OpenSSL in ") + env + " (OOSOCKETS_OPENSSL) is not OpenSSL 3";
            }
            ossl = OsslTable();
            dlclose(h);
            return;
        }
        loaded = true;                              // h stays open for good
    });
    if (!loaded)
    {
        why = reason;
    }
    return loaded;
}

// From here on, the names are the table's.
#define BIO_ADDR_free (ossl.BIO_ADDR_free)
#define BIO_ADDR_new (ossl.BIO_ADDR_new)
#define BIO_ADDR_rawmake (ossl.BIO_ADDR_rawmake)
#define BIO_clear_flags (ossl.BIO_clear_flags)
#define BIO_free (ossl.BIO_free)
#define BIO_get_data (ossl.BIO_get_data)
#define BIO_get_new_index (ossl.BIO_get_new_index)
#define BIO_meth_new (ossl.BIO_meth_new)
#define BIO_meth_set_create (ossl.BIO_meth_set_create)
#define BIO_meth_set_ctrl (ossl.BIO_meth_set_ctrl)
#define BIO_meth_set_read (ossl.BIO_meth_set_read)
#define BIO_meth_set_write (ossl.BIO_meth_set_write)
#define BIO_new (ossl.BIO_new)
#define BIO_new_mem_buf (ossl.BIO_new_mem_buf)
#define BIO_set_data (ossl.BIO_set_data)
#define BIO_set_flags (ossl.BIO_set_flags)
#define BIO_set_init (ossl.BIO_set_init)
#define BIO_test_flags (ossl.BIO_test_flags)
#define CRYPTO_free (ossl.CRYPTO_free)
#define CRYPTO_memcmp (ossl.CRYPTO_memcmp)
#define DTLS_client_method (ossl.DTLS_client_method)
#define DTLS_server_method (ossl.DTLS_server_method)
#define DTLSv1_listen (ossl.DTLSv1_listen)
#define ERR_clear_error (ossl.ERR_clear_error)
#define ERR_error_string_n (ossl.ERR_error_string_n)
#define ERR_get_error (ossl.ERR_get_error)
#define ERR_peek_last_error (ossl.ERR_peek_last_error)
#define ERR_reason_error_string (ossl.ERR_reason_error_string)
#define EVP_PKEY_free (ossl.EVP_PKEY_free)
#define EVP_sha256 (ossl.EVP_sha256)
#define HMAC (ossl.HMAC)
#define OPENSSL_sk_free (ossl.OPENSSL_sk_free)
#define OPENSSL_sk_num (ossl.OPENSSL_sk_num)
#define OPENSSL_sk_shift (ossl.OPENSSL_sk_shift)
#define OPENSSL_sk_value (ossl.OPENSSL_sk_value)
#define OpenSSL_version_num (ossl.OpenSSL_version_num)
#define PEM_read_bio_PrivateKey (ossl.PEM_read_bio_PrivateKey)
#define PEM_read_bio_X509 (ossl.PEM_read_bio_X509)
#define PKCS12_free (ossl.PKCS12_free)
#define PKCS12_parse (ossl.PKCS12_parse)
#define RAND_bytes (ossl.RAND_bytes)
#define SSL_CIPHER_get_name (ossl.SSL_CIPHER_get_name)
#define SSL_CTX_check_private_key (ossl.SSL_CTX_check_private_key)
#define SSL_CTX_ctrl (ossl.SSL_CTX_ctrl)
#define SSL_CTX_free (ossl.SSL_CTX_free)
#define SSL_CTX_get_cert_store (ossl.SSL_CTX_get_cert_store)
#define SSL_CTX_new (ossl.SSL_CTX_new)
#define SSL_CTX_set_cert_verify_callback (ossl.SSL_CTX_set_cert_verify_callback)
#define SSL_CTX_set_cookie_generate_cb (ossl.SSL_CTX_set_cookie_generate_cb)
#define SSL_CTX_set_cookie_verify_cb (ossl.SSL_CTX_set_cookie_verify_cb)
#define SSL_CTX_set_default_verify_paths (ossl.SSL_CTX_set_default_verify_paths)
#define SSL_CTX_set_num_tickets (ossl.SSL_CTX_set_num_tickets)
#define SSL_CTX_set_options (ossl.SSL_CTX_set_options)
#define SSL_CTX_set_verify (ossl.SSL_CTX_set_verify)
#define SSL_CTX_up_ref (ossl.SSL_CTX_up_ref)
#define SSL_CTX_use_PrivateKey (ossl.SSL_CTX_use_PrivateKey)
#define SSL_CTX_use_certificate (ossl.SSL_CTX_use_certificate)
#define SSL_ctrl (ossl.SSL_ctrl)
#define SSL_do_handshake (ossl.SSL_do_handshake)
#define SSL_free (ossl.SSL_free)
#define SSL_get0_param (ossl.SSL_get0_param)
#define SSL_get_current_cipher (ossl.SSL_get_current_cipher)
#define SSL_get_error (ossl.SSL_get_error)
#define SSL_get_ex_data (ossl.SSL_get_ex_data)
#define SSL_get_ex_data_X509_STORE_CTX_idx (ossl.SSL_get_ex_data_X509_STORE_CTX_idx)
#define SSL_get_verify_result (ossl.SSL_get_verify_result)
#define SSL_get_version (ossl.SSL_get_version)
#define SSL_is_init_finished (ossl.SSL_is_init_finished)
#define SSL_new (ossl.SSL_new)
#define SSL_read_ex (ossl.SSL_read_ex)
#define SSL_set1_host (ossl.SSL_set1_host)
#define SSL_set_accept_state (ossl.SSL_set_accept_state)
#define SSL_set_bio (ossl.SSL_set_bio)
#define SSL_set_connect_state (ossl.SSL_set_connect_state)
#define SSL_set_ex_data (ossl.SSL_set_ex_data)
#define SSL_shutdown (ossl.SSL_shutdown)
#define SSL_write_ex (ossl.SSL_write_ex)
#define TLS_client_method (ossl.TLS_client_method)
#define TLS_server_method (ossl.TLS_server_method)
#define X509_STORE_CTX_get0_cert (ossl.X509_STORE_CTX_get0_cert)
#define X509_STORE_CTX_get0_untrusted (ossl.X509_STORE_CTX_get0_untrusted)
#define X509_STORE_CTX_get_ex_data (ossl.X509_STORE_CTX_get_ex_data)
#define X509_STORE_CTX_set_error (ossl.X509_STORE_CTX_set_error)
#define X509_STORE_add_cert (ossl.X509_STORE_add_cert)
#define X509_STORE_set_flags (ossl.X509_STORE_set_flags)
#define X509_VERIFY_PARAM_set1_ip_asc (ossl.X509_VERIFY_PARAM_set1_ip_asc)
#define X509_cmp (ossl.X509_cmp)
#define X509_free (ossl.X509_free)
#define X509_verify_cert_error_string (ossl.X509_verify_cert_error_string)
#define d2i_PKCS12 (ossl.d2i_PKCS12)
#define d2i_X509 (ossl.d2i_X509)
#define i2d_X509 (ossl.i2d_X509)

#endif // !_WIN32
#endif // OOSOCKETS_OSSL_H
