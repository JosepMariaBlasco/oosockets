#!/usr/bin/env bash
# Builds and runs the Schannel probe (a GitHub Windows runner, Git Bash).
# The other end of the local tests is Git for Windows' own OpenSSL
# (s_server, s_client).
set -uo pipefail
cd "$(dirname "$0")"
cmd //c ver
powershell -NoProfile -Command "(Get-CimInstance Win32_OperatingSystem).Caption + ' ' + (Get-CimInstance Win32_OperatingSystem).BuildNumber"

echo "== build"
cmake -S . -B pb > cmake.log 2>&1 || { cat cmake.log; exit 1; }
cmake --build pb --config Release > build.log 2>&1 || { cat build.log; exit 1; }
grep -i -E "warning|error" build.log | head -10
P=pb/Release/probe.exe

lim() { timeout "${T:-30}" "$@" || echo "  (exit $?)"; }

echo; echo "######## clients, Schannel verifying (the system's roots, the host name)"
for h in example.com github.com letsencrypt.org www.google.com expired.badssl.com \
         wrong.host.badssl.com self-signed.badssl.com untrusted-root.badssl.com revoked.badssl.com; do
  echo "---- $h"; lim $P client $h 443
done
echo "---- minVersion 1.3: example.com, then tls-v1-2.badssl.com:1012 (TLS 1.2 only)"
lim $P client example.com 443 13
lim $P client tls-v1-2.badssl.com 1012 13
echo "---- the same TLS 1.2-only server, 1.2 allowed"
lim $P client tls-v1-2.badssl.com 1012

echo; echo "######## certificates"
O=openssl
$O version | head -1
KT=""
for j in "${JAVA_HOME_21_X64:-}" "${JAVA_HOME_17_X64:-}" "${JAVA_HOME:-}"; do
  [ -z "$KT" ] && [ -n "$j" ] && [ -x "$j/bin/keytool.exe" ] && KT="$j/bin/keytool.exe"
done
echo "keytool: $KT"
export MSYS_NO_PATHCONV=1
$O req -x509 -newkey rsa:2048 -nodes -keyout k1.pem -out c1.pem -days 30 -subj /CN=localhost \
   -addext subjectAltName=DNS:localhost 2>/dev/null
$O req -x509 -newkey rsa:2048 -nodes -keyout k2.pem -out c2.pem -days 30 -subj /CN=localhost \
   -addext subjectAltName=DNS:localhost -addext extendedKeyUsage=serverAuth \
   -addext basicConstraints=critical,CA:FALSE 2>/dev/null
"$KT" -genkeypair -alias mysrv -keyalg RSA -dname "CN=localhost" -ext "SAN=dns:localhost,ip:127.0.0.1,ip:::1" \
      -ext EKU=serverAuth -validity 825 -keystore ks4.p12 -storepass 123456 2>&1 | grep -v -i generating
$O pkcs12 -in ks4.p12 -passin pass:123456 -nokeys -clcerts -out c4.pem 2>/dev/null
$O pkcs12 -in ks4.p12 -passin pass:123456 -nodes -nocerts -out k4.pem 2>/dev/null
# an OpenSSL-made PKCS#12 (AES, as OpenSSL 3 makes them), for comparison
$O pkcs12 -export -in c2.pem -inkey k2.pem -out ks2.p12 -passout pass:secret 2>/dev/null
# PKCS#8 key ("PRIVATE KEY"): what NCryptImportKey takes
$O pkcs8 -topk8 -nocrypt -in k2.pem -out k2p8.pem 2>/dev/null; head -1 k2p8.pem

echo; echo "######## explicit trust (pin): against s_server, TLS 1.3 and TLS 1.2"
$O s_server -accept 9441 -tls1_3 -cert c4.pem -key k4.pem -quiet -naccept 1 > /dev/null 2>&1 &
sleep 2; echo "---- TLS 1.3, pinned c4 (the keytool certificate)"; lim $P pin localhost 9441 c4.pem
$O s_server -accept 9442 -tls1_2 -cert c4.pem -key k4.pem -quiet -naccept 1 > /dev/null 2>&1 &
sleep 2; echo "---- TLS 1.2, pinned c4"; lim $P pin localhost 9442 c4.pem
$O s_server -accept 9443 -tls1_3 -cert c4.pem -key k4.pem -quiet -naccept 1 > /dev/null 2>&1 &
sleep 2; echo "---- TLS 1.3, pinned c1 (not the server's: must be refused)"; lim $P pin localhost 9443 c1.pem
$O s_server -accept 9444 -tls1_3 -cert c1.pem -key k1.pem -quiet -naccept 1 > /dev/null 2>&1 &
sleep 2; echo "---- TLS 1.3, certificate 1 (openssl req defaults: CA:TRUE, no EKU), pinned"; lim $P pin localhost 9444 c1.pem

echo; echo "######## server: Schannel, s_client as the client"
srv() {   # port keystore pw mode
  lim $P server "$1" "$2" "$3" "$4" 3 &
  sleep 3
  for v in -tls1_3 -tls1_2; do
    echo "  s_client $v:"
    echo "hello from s_client $v" | T=10 lim $O s_client -connect localhost:$1 $v -CAfile c4.pem -verify_return_error \
         -verify_hostname localhost -quiet 2>&1 | sed 's/^/    /' | head -5
  done
  echo "  s_client trusting another certificate (must fail; what does the server see?):"
  echo "x" | T=10 lim $O s_client -connect localhost:$1 -CAfile c1.pem -verify_return_error -quiet 2>&1 | sed 's/^/    /' | head -3
  wait
}
echo "---- keytool PKCS#12, PKCS12_NO_PERSIST_KEY"; srv 9501 ks4.p12 123456 p12
echo "---- keytool PKCS#12, keys persisted (the default)"; srv 9502 ks4.p12 123456 p12-persist
echo "---- PEM certificate and key (k4 is PKCS#8 from openssl pkcs12 -nodes)"; srv 9503 "c4.pem;k4.pem" "" pem
echo "---- OpenSSL 3 PKCS#12 (ks2.p12, certificate 2: s_client trusting c4 must fail the first two)"
lim $P server 9504 ks2.p12 secret p12 1 &
sleep 3
echo "x" | T=10 lim $O s_client -connect localhost:9504 -CAfile c2.pem -verify_return_error -verify_hostname localhost -quiet 2>&1 | sed 's/^/    /' | head -3
wait
echo "---- persisted keys left behind?"
ls "$APPDATA/Microsoft/Crypto/Keys" 2>/dev/null | wc -l
ls "$APPDATA/Microsoft/Crypto/RSA/"* 2>/dev/null | wc -l

echo; echo "######## STARTTLS: both ends Schannel, on sockets already in use"
lim $P starttls-server 9601 ks4.p12 123456 &
sleep 2; lim $P starttls-client localhost 9601 c4.pem; wait

echo; echo "######## DTLS 1.2 client: Schannel against s_server -dtls1_2"
for opt in "" "-listen"; do
  echo "---- s_server $opt (-listen: cookie exchange, DTLSv1_listen)"
  (sleep 1; ) ; $O s_server -dtls1_2 $opt -accept 127.0.0.1:9701 -cert c4.pem -key k4.pem -rev -naccept 1 > ss.log 2>&1 &
  sleep 2; lim $P dtls localhost 9701 c4.pem
  sleep 1; kill %% 2>/dev/null; echo "  s_server said:"; sed 's/^/    /' ss.log | head -8
done

echo; echo "######## DTLS 1.2 server: Schannel, s_client -dtls1_2 as the client"
for mode in 1 0; do
  echo "---- client address to AcceptSecurityContext: $([ $mode = 1 ] && echo SECBUFFER_EXTRA || echo none)"
  lim $P dtls-server 9801 ks4.p12 123456 $mode &
  sleep 2
  echo "hello over dtls" | T=15 lim $O s_client -dtls1_2 -connect 127.0.0.1:9801 -CAfile c4.pem -verify_return_error \
       -verify_hostname localhost -quiet 2>&1 | sed 's/^/    /' | head -6
  wait
done
kill $(jobs -p) 2>/dev/null; true
