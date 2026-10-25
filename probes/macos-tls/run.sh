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
clang -Wall -o nw nw.c -framework Network 2> nw.warn; echo "nw.c: $(grep -c 'deprecated' nw.warn) deprecation warnings"; cat nw.warn | grep -E 'error|warning' | head -5
clang -Wall -o ossl ossl.c -I"$OSSL/include" -L"$OSSL/lib" -lssl -lcrypto -framework Security -framework CoreFoundation 2> ossl.warn; echo "ossl.c: $(grep -c 'deprecated' ossl.warn) deprecation warnings"; grep -E 'error|deprecated' ossl.warn | head -5

echo "== Network.framework: any call that takes a file descriptor or socket?"
NWH="$(xcrun --show-sdk-path)/System/Library/Frameworks/Network.framework/Headers"
grep -n -i -E '\b(int|fd|socket)\b.*(file_descriptor|_fd\b|socket\b)|from_fd|with_fd|file_descriptor' "$NWH"/*.h | head -10 || true
echo "(end of matches)"

hosts="example.com expired.badssl.com wrong.host.badssl.com self-signed.badssl.com untrusted-root.badssl.com"
for h in $hosts; do
  echo; echo "######## $h"
  ./st "$h"
  ./nw "$h"
  for m in anchors certpem sectrust; do ./ossl $m "$h"; done
done

echo; echo "######## local server, TLS 1.3 only (Homebrew openssl s_server)"
"$OSSL/bin/openssl" req -x509 -newkey rsa:2048 -nodes -keyout k.pem -out c.pem -days 2 -subj /CN=localhost -addext subjectAltName=DNS:localhost 2>/dev/null
"$OSSL/bin/openssl" s_server -accept 9443 -tls1_3 -cert c.pem -key k.pem -www -quiet > /dev/null 2>&1 &
srv=$!; sleep 1
./st localhost 9443 noverify
./ossl sectrust localhost 9443
kill $srv
