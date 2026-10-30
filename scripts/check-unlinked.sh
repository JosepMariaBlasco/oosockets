#!/usr/bin/env bash
# The library must not link OpenSSL. It loads it the first time it is
# needed (src/ossl.h), so it may neither depend on libssl or libcrypto nor
# leave an OpenSSL function undefined (one missing from ossl.h's
# OSSL_FUNCTIONS would be: the library would then fail to load, or need
# OpenSSL to load at all). On Windows such a function does not link: only
# the DLLs it depends on are looked at (dumpbin, from Visual Studio).
# Linux and macOS: nor may it carry a path of the machine that built it
# (an absolute rpath; on Linux, any RUNPATH).
#   scripts/check-unlinked.sh <the library>
set -euo pipefail
lib="$1"
ossl='^(SSL|X509|EVP|PEM|PKCS12|BIO|ERR|OPENSSL|OpenSSL|DTLS|TLS|d2i|i2d|RAND|CRYPTO|HMAC|ASN1|OSSL)'
case "$(uname -s)" in
  MINGW*|MSYS*|CYGWIN*)
    vswhere="/c/Program Files (x86)/Microsoft Visual Studio/Installer/vswhere.exe"
    vs="$(cygpath -u "$("$vswhere" -latest -property installationPath | tr -d '\r')")"
    dumpbin="$(ls "$vs"/VC/Tools/MSVC/*/bin/Hostx64/x64/dumpbin.exe | head -1)"
    deps="$("$dumpbin" //nologo //dependents "$lib" | grep -i '\.dll')"
    und=""; rpaths=""; bad="" ;;
  Darwin)
    deps="$(otool -L "$lib")"
    und="$(nm -u "$lib" | sed -n 's/^_//p' | grep -E "$ossl" || true)"
    rpaths="$(otool -l "$lib" | awk '$1 == "cmd" {c = $2} c == "LC_RPATH" && $1 == "path" {print $2}' | sort -u)"
    bad="$(echo "$rpaths" | grep -v -E '^(@|$)' || true)" ;;
  *)
    deps="$(ldd "$lib")"
    # on Linux every undefined symbol but OpenSSL's has a version (GLIBC_...)
    und="$(nm -D -u "$lib" | awk '$1 == "U" {print $2}' | grep -v '@' || true)"
    rpaths="$(readelf -d "$lib" | grep -E 'RPATH|RUNPATH' || true)"
    bad="$rpaths" ;;
esac
echo "$deps"
rc=0
if echo "$deps" | grep -i -E 'libssl|libcrypto'; then
  echo "the library links OpenSSL" >&2; rc=1
fi
if [ -n "$und" ]; then
  echo "undefined, not in ossl.h's OSSL_FUNCTIONS:" >&2; echo "$und" | sort -u >&2; rc=1
fi
[ -n "$rpaths" ] && echo "rpaths:" $rpaths
if [ -n "$bad" ]; then
  echo "a path of the machine that built it (rpath):" >&2; echo "$bad" >&2; rc=1
fi
[ $rc = 0 ] && echo "OpenSSL: not linked, nothing of it undefined; no rpath of the build machine"
exit $rc
