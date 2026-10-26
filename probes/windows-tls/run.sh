#!/usr/bin/env bash
# Builds and runs the Windows TLS probe (on a GitHub Windows runner, Git
# Bash). OpenSSL from vcpkg, linked statically, as ooSockets would ship it.
set -uo pipefail
cd "$(dirname "$0")"
cmd //c ver; echo "vcpkg: $VCPKG_INSTALLATION_ROOT"

echo "== OpenSSL (vcpkg, x64-windows-static)"
"$VCPKG_INSTALLATION_ROOT/vcpkg" install openssl:x64-windows-static > vcpkg.log 2>&1 \
  || { tail -30 vcpkg.log; exit 1; }
grep -m1 -i "openssl:x64-windows-static" vcpkg.log

echo "== build"
cmake -S . -B pb -DCMAKE_TOOLCHAIN_FILE="$VCPKG_INSTALLATION_ROOT/scripts/buildsystems/vcpkg.cmake" \
      -DVCPKG_TARGET_TRIPLET=x64-windows-static > cmake.log 2>&1 || { cat cmake.log; exit 1; }
cmake --build pb --config Release > build.log 2>&1 || { cat build.log; exit 1; }
grep -i -E "warning|error" build.log | head -10
P=pb/Release/probe.exe
echo "probe.exe imports (no OpenSSL DLL expected):"
dumpbin=$(ls "/c/Program Files/Microsoft Visual Studio/2022/Enterprise/VC/Tools/MSVC/"*/bin/Hostx64/x64/dumpbin.exe 2>/dev/null | head -1)
[ -n "$dumpbin" ] && "$dumpbin" //dependents "$P" | grep -i "\.dll"

lim() { timeout 30 "$@" || echo "  (exit $?)"; }

hosts="example.com github.com letsencrypt.org www.google.com expired.badssl.com wrong.host.badssl.com self-signed.badssl.com untrusted-root.badssl.com revoked.badssl.com"
for h in $hosts; do
  echo; echo "######## $h"
  for m in wintrust wintrust-rev winstore; do lim $P $m "$h"; done
done

echo; echo "######## local servers, TLS 1.3 only, five kinds of certificate, trusted explicitly"
O=openssl                     # Git for Windows' own
$O version | head -1
# keytool: the runner's default JDK (JAVA_HOME may not be set).
KT="$(command -v keytool || true)"
for j in "${JAVA_HOME:-}" "${JAVA_HOME_21_X64:-}" "${JAVA_HOME_17_X64:-}"; do
  [ -z "$KT" ] && [ -n "$j" ] && [ -x "$j/bin/keytool.exe" ] && KT="$j/bin/keytool.exe"
done
echo "keytool: $KT"; java -version 2>&1 | head -1
export MSYS_NO_PATHCONV=1     # keep -subj /CN=... as it is
$O req -x509 -newkey rsa:2048 -nodes -keyout k1.pem -out c1.pem -days 30 -subj /CN=localhost \
   -addext subjectAltName=DNS:localhost 2>/dev/null
$O req -x509 -newkey rsa:2048 -nodes -keyout k2.pem -out c2.pem -days 30 -subj /CN=localhost \
   -addext subjectAltName=DNS:localhost -addext extendedKeyUsage=serverAuth \
   -addext basicConstraints=critical,CA:FALSE 2>/dev/null
kt() { "$KT" -genkeypair -alias mysrv -keyalg RSA -dname "CN=localhost" -ext "SAN=dns:localhost,ip:127.0.0.1,ip:::1" \
         -validity "$2" -keystore ks$1.p12 -storepass 123456 "${@:3}" 2>&1 | grep -v -i "generating" 
       $O pkcs12 -in ks$1.p12 -passin pass:123456 -nodes -nocerts -out k$1.pem 2>/dev/null
       $O pkcs12 -in ks$1.p12 -passin pass:123456 -nokeys -clcerts -out c$1.pem 2>/dev/null; }
kt 3 30                       # the line sent to Rony on 25/10 (validity shortened)
kt 4 30 -ext EKU=serverAuth
kt 5 3650 -ext EKU=serverAuth # as 4, ten years
for n in 1 2 3 4 5; do
  echo; echo "---- certificate $n:"; $O x509 -in c$n.pem -noout -ext basicConstraints,extendedKeyUsage 2>/dev/null | tr '\n' ' '; echo
  $O x509 -in c$n.pem -noout -dates | tr '\n' ' '; echo
  $O s_server -accept 944$n -tls1_3 -cert c$n.pem -key k$n.pem -www -quiet -naccept 2 > /dev/null 2>&1 &
  sleep 2
  lim $P pin localhost 944$n c$n.pem
  lim $P wintrust-pin localhost 944$n c$n.pem
done
kill $(jobs -p) 2>/dev/null; true
