#!/usr/bin/env bash
# Builds and runs the macOS TLS probes (on a GitHub macOS runner).
set -uo pipefail
cd "$(dirname "$0")"
sw_vers; uname -m
OSSL="$(brew --prefix openssl@3 2>/dev/null || true)"
if [ ! -d "$OSSL/include/openssl" ]; then brew install openssl@3 >/dev/null; OSSL="$(brew --prefix openssl@3)"; fi
echo "Homebrew OpenSSL: $OSSL"; ls -la /etc/ssl/cert.pem

echo "== build (deprecation warnings counted)"
clang -Wall -o st st.c -framework Security -framework CoreFoundation 2> st.warn; echo "st.c: $(grep -c 'deprecated' st.warn) deprecation warnings"; grep -m3 'deprecated' st.warn
clang -Wall -o nw nw.c -framework Network -framework Security 2> nw.warn; echo "nw.c: $(grep -c 'deprecated' nw.warn) deprecation warnings"; cat nw.warn | head -20
clang -Wall -o ossl ossl.c -I"$OSSL/include" -L"$OSSL/lib" -lssl -lcrypto -framework Security -framework CoreFoundation 2> ossl.warn; echo "ossl.c: $(grep -c 'deprecated' ossl.warn) deprecation warnings"; grep -E 'error|deprecated' ossl.warn | head -5

echo "== Network.framework: any call that takes a file descriptor or socket?"
NWH="$(xcrun --show-sdk-path)/System/Library/Frameworks/Network.framework/Headers"
grep -n -i -E '\b(int|fd|socket)\b.*(file_descriptor|_fd\b|socket\b)|from_fd|with_fd|file_descriptor' "$NWH"/*.h | head -10 || true
echo "(end of matches)"

# Every probe gets 30 s at most (macOS has no timeout(1)).
lim() { perl -e 'alarm 30; exec @ARGV' "$@" || echo "  (exit $?)"; }

hosts="example.com expired.badssl.com wrong.host.badssl.com self-signed.badssl.com untrusted-root.badssl.com revoked.badssl.com"
for h in $hosts; do
  echo; echo "######## $h"
  lim ./st "$h"
  lim ./nw "$h"
  for m in anchors certpem sectrust sectrust-rev; do lim ./ossl $m "$h"; done
done

echo; echo "######## local servers, TLS 1.3 only, four kinds of certificate, trusted explicitly"
O="$OSSL/bin/openssl"
# 1: openssl req -x509, its defaults (CA:TRUE, no extended key usage)
$O req -x509 -newkey rsa:2048 -nodes -keyout k1.pem -out c1.pem -days 30 -subj /CN=localhost \
   -addext subjectAltName=DNS:localhost 2>/dev/null
# 2: the same with extendedKeyUsage=serverAuth and CA:FALSE
$O req -x509 -newkey rsa:2048 -nodes -keyout k2.pem -out c2.pem -days 30 -subj /CN=localhost \
   -addext subjectAltName=DNS:localhost -addext extendedKeyUsage=serverAuth \
   -addext basicConstraints=critical,CA:FALSE 2>/dev/null
# 3: keytool, the line sent to Rony on 25/10 (validity shortened)
# 4: the same plus -ext EKU=serverAuth
kt() { keytool -genkeypair -alias mysrv -keyalg RSA -dname "CN=localhost" -ext "SAN=dns:localhost,ip:127.0.0.1,ip:::1" \
         -validity "$2" -keystore ks$1.p12 -storepass 123456 "${@:3}" 2>/dev/null
       $O pkcs12 -in ks$1.p12 -passin pass:123456 -nodes -nocerts -out k$1.pem 2>/dev/null
       $O pkcs12 -in ks$1.p12 -passin pass:123456 -nokeys -clcerts -out c$1.pem 2>/dev/null; }
kt 3 30
kt 4 30 -ext EKU=serverAuth
# 5: as 4, with the ten years of the line sent to Rony (Apple limits validity)
kt 5 3650 -ext EKU=serverAuth
for n in 1 2 3 4 5; do
  echo; echo "---- certificate $n:"; $O x509 -in c$n.pem -noout -ext basicConstraints,extendedKeyUsage,keyUsage 2>/dev/null | tr '\n' ' '; echo
  $O x509 -in c$n.pem -noout -dates | tr '\n' ' '; echo
  $O s_server -accept 944$n -tls1_3 -cert c$n.pem -key k$n.pem -www -quiet -naccept 6 > /dev/null 2>&1 &
  sleep 1
  lim ./ossl pin localhost 944$n c$n.pem
  lim ./ossl sectrust-pin localhost 944$n c$n.pem
done
echo; echo "---- the longest validity macOS accepts (keytool, serverAuth, trusted explicitly)"
for d in 397 398 399 824 825 826; do
  kt v$d $d -ext EKU=serverAuth
  $O s_server -accept 9450 -tls1_3 -cert cv$d.pem -key kv$d.pem -www -quiet -naccept 1 > /dev/null 2>&1 &
  sleep 1
  printf "%s days: " $d; lim ./ossl sectrust-pin localhost 9450 cv$d.pem | grep 'macOS trust'
done
echo; echo "---- Secure Transport and Network.framework against the TLS 1.3-only server"
lim ./st localhost 9442 noverify
lim ./nw localhost 9442
kill %% 2>/dev/null; true
