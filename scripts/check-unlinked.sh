#!/usr/bin/env bash
# Linux and macOS: the library must not link OpenSSL. It loads it the first
# time TLS is used (src/ossl.h), so it may neither depend on libssl or
# libcrypto nor leave an OpenSSL function undefined (one missing from
# ossl.h's OSSL_FUNCTIONS would be: the library would then fail to load, or
# need OpenSSL to load at all).
#   scripts/check-unlinked.sh <the library>
set -euo pipefail
lib="$1"
ossl='^(SSL|X509|EVP|PEM|PKCS12|BIO|ERR|OPENSSL|OpenSSL|DTLS|TLS|d2i|i2d|RAND|CRYPTO|HMAC|ASN1|OSSL)'
case "$(uname -s)" in
  Darwin)
    deps="$(otool -L "$lib")"
    und="$(nm -u "$lib" | sed -n 's/^_//p' | grep -E "$ossl" || true)" ;;
  *)
    deps="$(ldd "$lib")"
    # on Linux every undefined symbol but OpenSSL's has a version (GLIBC_...)
    und="$(nm -D -u "$lib" | awk '$1 == "U" {print $2}' | grep -v '@' || true)" ;;
esac
echo "$deps"
rc=0
if echo "$deps" | grep -E 'libssl|libcrypto'; then
  echo "the library links OpenSSL" >&2; rc=1
fi
if [ -n "$und" ]; then
  echo "undefined, not in ossl.h's OSSL_FUNCTIONS:" >&2; echo "$und" | sort -u >&2; rc=1
fi
[ $rc = 0 ] && echo "OpenSSL: not linked, nothing of it undefined"
exit $rc
