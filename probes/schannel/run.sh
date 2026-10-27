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
# ONLY: the sections to run, by name ("all", the default, runs every one)
on() { [[ " ${ONLY:-all} " == *" all "* || " ${ONLY:-all} " == *" $1 "* ]]; }

if on clients; then
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
fi
if on flaky; then
echo; echo "######## expired and self-signed, five times each (one run closed instead of refusing)"
for i in 1 2 3 4 5; do for h in expired.badssl.com self-signed.badssl.com; do echo "---- $h ($i)"; lim $P client $h 443; done; done
fi

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

if on pin; then
echo; echo "######## explicit trust (pin): against s_server, TLS 1.3 and TLS 1.2"
$O s_server -accept 9441 -tls1_3 -cert c4.pem -key k4.pem -quiet -naccept 1 > /dev/null 2>&1 &
sleep 2; echo "---- TLS 1.3, pinned c4 (the keytool certificate)"; lim $P pin localhost 9441 c4.pem
$O s_server -accept 9442 -tls1_2 -cert c4.pem -key k4.pem -quiet -naccept 1 > /dev/null 2>&1 &
sleep 2; echo "---- TLS 1.2, pinned c4"; lim $P pin localhost 9442 c4.pem
$O s_server -accept 9443 -tls1_3 -cert c4.pem -key k4.pem -quiet -naccept 1 > /dev/null 2>&1 &
sleep 2; echo "---- TLS 1.3, pinned c1 (not the server's: must be refused)"; lim $P pin localhost 9443 c1.pem
$O s_server -accept 9444 -tls1_3 -cert c1.pem -key k1.pem -quiet -naccept 1 > /dev/null 2>&1 &
sleep 2; echo "---- TLS 1.3, certificate 1 (openssl req defaults: CA:TRUE, no EKU), pinned"; lim $P pin localhost 9444 c1.pem
fi

keys() { find "$APPDATA/Microsoft/Crypto" -type f 2>/dev/null | wc -l; }

echo; echo "######## server: Schannel, s_client as the client"
srv() {   # port keystore pw keymode
  echo "  key files in the profile before: $(keys)"
  lim $P server "$1" "$2" "$3" "$4" 3 &
  sleep 3
  for v in -tls1_3 -tls1_2; do
    echo "  s_client $v:"
    echo "hello from s_client $v" | T=10 lim $O s_client -connect localhost:$1 $v -CAfile "${CA:-c4.pem}" -verify_return_error \
         -verify_hostname localhost -quiet 2>&1 | grep -v -E "^Connecting|SSL_get_servername|^depth|^verify return" | sed 's/^/    /' | head -4
  done
  echo "  s_client trusting another certificate (must fail; what does the server see?):"
  echo "x" | T=10 lim $O s_client -connect localhost:$1 -CAfile c1.pem -verify_return_error -quiet 2>&1 | grep -i error | sed 's/^/    /' | head -2
  wait
  echo "  key files in the profile after: $(keys)"
}
if on server; then
n=9500
for km in nopersist nopersist-cng persist delete; do
  n=$((n+1)); echo "---- keytool PKCS#12, $km"; srv $n ks4.p12 123456 $km
done
for km in ephemeral nopersist-cng delete; do
  n=$((n+1)); echo "---- PEM certificate and PKCS#8 key, $km"; CA=c2.pem srv $n "c2.pem;k2p8.pem" "" $km
done
n=$((n+1)); echo "---- OpenSSL 3 PKCS#12 (AES), delete"; CA=c2.pem srv $n ks2.p12 secret delete
fi
if on pem; then
n=9550
for km in persist delete; do
  n=$((n+1)); echo "---- PEM certificate and PKCS#8 key, a named CNG key, $km"; CA=c2.pem srv $n "c2.pem;k2p8.pem" "" $km
done
fi

if on starttls; then
echo; echo "######## STARTTLS: both ends Schannel, on sockets already in use"
lim $P starttls-server 9601 ks4.p12 123456 persist &
sleep 2; lim $P starttls-client localhost 9601 c4.pem; wait
fi

if on dtlsc; then
echo; echo "######## DTLS 1.2 client: Schannel against s_server -dtls1_2"
n=9700
for cs in sch sch0 legacy; do
  for opt in "" "-listen"; do
    n=$((n+1)); echo "---- credentials $cs, s_server $opt"
    (sleep 5; echo "REPLY FROM S_SERVER") | $O s_server -dtls1_2 $opt -accept 127.0.0.1:$n -cert c4.pem -key k4.pem -naccept 1 > ss.log 2>&1 &
    sleep 2; CRED=$cs lim $P dtls localhost $n c4.pem
    sleep 1; kill %% 2>/dev/null; echo "  s_server said:"; grep -v -E "^ACCEPT|^-----|^Shared|^Supported|^Signature|^Peer" ss.log | sed 's/^/    /' | head -6
  done
done
fi
if on mtu; then
echo; echo "######## DTLS client (legacy credentials): the largest datagram, with SECPKG_ATTR_DTLS_MTU"
n=9750
for mtu in "" 1400 17000 65000; do
  n=$((n+1)); echo "---- DTLS_MTU=${mtu:-(not set)}"
  (sleep 5; echo "REPLY FROM S_SERVER") | $O s_server -dtls1_2 -accept 127.0.0.1:$n -cert c4.pem -key k4.pem -naccept 1 > ss.log 2>&1 &
  sleep 2; CRED=legacy DTLS_MTU=$mtu lim $P dtls localhost $n c4.pem 2>&1 | grep -v "step (in"
  sleep 1; kill %% 2>/dev/null; echo "  s_server said:"; grep -E "x{20}|DONE|error" ss.log | cut -c1-60 | sed 's/^/    /' | head -6
done
fi

if on dtlss; then
echo; echo "######## DTLS 1.2 server: Schannel, s_client -dtls1_2 as the client"
n=9800
for cs in ${DTLSS_CRED:-sch sch0 legacy}; do
  for mode in 1 0; do
    n=$((n+1)); echo "---- credentials $cs, client address: $([ $mode = 1 ] && echo SECBUFFER_EXTRA || echo none)"
    CRED=$cs lim $P dtls-server $n ks4.p12 123456 $mode persist &
    sleep 2
    (echo "hello over dtls"; sleep 4) | T=15 lim $O s_client -dtls1_2 -connect 127.0.0.1:$n -CAfile c4.pem -verify_return_error \
         -verify_hostname localhost -quiet 2>&1 | grep -v -E "^Connecting|SSL_get_servername|^depth|^verify return" | sed 's/^/    /' | head -4
    wait
  done
done
fi
echo; echo "key files in the profile at the end: $(keys)"
kill $(jobs -p) 2>/dev/null; true
