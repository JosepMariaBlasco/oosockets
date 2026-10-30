#!/usr/bin/env bash
# Makes the certificates the TLS tests use, in tests/certs/. They are in
# git (keys included: they protect nothing); run this only to remake them.
# Needs OpenSSL 3 and Java's keytool.
#
#   ca.pem            a test certificate authority (the one the tests trust)
#   server.pem        localhost, 127.0.0.1, ::1; signed by the CA; with its
#                     key (PEM), and the same as server.p12 (password "test")
#   expired.pem       as server.pem, but expired in 2020
#   wronghost.pem     for other.example only; signed by the CA
#   selfsigned.pem    localhost, self-signed (not by the CA)
#   keytool.p12       localhost, made with keytool as the line given to Rony
#                     (plus serverAuth), password 123456
#   mismatch.pem      server.pem's certificate with wronghost.pem's key
#   ec.pem            localhost, self-signed, an EC P-256 key in SEC1 ("EC
#                     PRIVATE KEY")
#   pkcs1.pem         localhost, self-signed, an RSA key in PKCS#1 ("RSA
#                     PRIVATE KEY")
#   encrypted.pem     pkcs1.pem's certificate, its key as encrypted PKCS#8
#                     (password "test"; PBES2, AES-256, OpenSSL 3's default)
# (The last three: the key formats Windows reads by itself.)
#   ec.p12            ec.pem as PKCS#12 (password "test"): an EC key through
#                     Windows' PKCS#12 import
set -euo pipefail
cd "$(dirname "$0")/../tests"
rm -rf certs; mkdir certs; cd certs
w=$(mktemp -d); trap 'rm -rf "$w"' EXIT
days=36500                                        # a hundred years

openssl req -x509 -newkey rsa:2048 -nodes -keyout "$w/ca.key" -out ca.pem -days $days \
  -subj "/CN=ooSockets test CA" -addext basicConstraints=critical,CA:TRUE \
  -addext keyUsage=critical,keyCertSign,cRLSign 2>/dev/null

# leaf name san [startdate enddate]
leaf() {
  openssl req -newkey rsa:2048 -nodes -keyout "$w/$1.key" -out "$w/$1.csr" -subj "/CN=$2" 2>/dev/null
  cat > "$w/$1.ext" <<EOF
basicConstraints=critical,CA:FALSE
keyUsage=critical,digitalSignature,keyEncipherment
extendedKeyUsage=serverAuth
subjectAltName=$3
EOF
  if [ $# -gt 3 ]; then
    # openssl ca: the only way to give past dates with OpenSSL 3.0
    mkdir -p "$w/db"; : > "$w/db/index"; echo 01 > "$w/db/serial"
    cat > "$w/ca.cnf" <<EOF
[ca]
default_ca = test
[test]
database = $w/db/index
serial = $w/db/serial
new_certs_dir = $w/db
default_md = sha256
policy = any
copy_extensions = none
[any]
commonName = supplied
EOF
    openssl ca -batch -config "$w/ca.cnf" -cert ca.pem -keyfile "$w/ca.key" -in "$w/$1.csr" \
      -out "$w/$1.crt" -startdate "$4" -enddate "$5" -extfile "$w/$1.ext" -notext 2>/dev/null
  else
    openssl x509 -req -in "$w/$1.csr" -CA ca.pem -CAkey "$w/ca.key" -CAcreateserial \
      -out "$w/$1.crt" -days $days -extfile "$w/$1.ext" 2>/dev/null
  fi
  cat "$w/$1.crt" "$w/$1.key" > "$1.pem"
}

leaf server localhost "DNS:localhost,IP:127.0.0.1,IP:::1"
leaf expired localhost "DNS:localhost,IP:127.0.0.1,IP:::1" 20190101000000Z 20200101000000Z
leaf wronghost other.example "DNS:other.example"
openssl pkcs12 -export -in "$w/server.crt" -inkey "$w/server.key" -certfile ca.pem \
  -out server.p12 -passout pass:test

openssl req -x509 -newkey rsa:2048 -nodes -keyout "$w/self.key" -out "$w/self.crt" -days $days \
  -subj "/CN=localhost" -addext subjectAltName=DNS:localhost,IP:127.0.0.1,IP:::1 2>/dev/null
cat "$w/self.crt" "$w/self.key" > selfsigned.pem

keytool -genkeypair -alias mysrv -keyalg RSA -dname "CN=localhost" \
  -ext "SAN=dns:localhost,ip:127.0.0.1,ip:::1" -ext EKU=serverAuth -validity $days \
  -keystore keytool.p12 -storepass 123456 2>/dev/null

{ openssl x509 -in server.pem; openssl pkey -in wronghost.pem; } > mismatch.pem

# self name: a self-signed certificate for localhost, with its key in self.key
self() {
  openssl req -x509 "${@:2}" -nodes -keyout "$w/$1.key" -out "$w/$1.crt" -days $days \
    -subj "/CN=localhost" -addext subjectAltName=DNS:localhost,IP:127.0.0.1,IP:::1 2>/dev/null
}
self ec -newkey ec -pkeyopt ec_paramgen_curve:P-256
{ cat "$w/ec.crt"; openssl ec -in "$w/ec.key" 2>/dev/null; } > ec.pem
openssl pkcs12 -export -in ec.pem -out ec.p12 -passout pass:test
self rsa -newkey rsa:2048
{ cat "$w/rsa.crt"; openssl rsa -in "$w/rsa.key" -traditional 2>/dev/null; } > pkcs1.pem
{ cat "$w/rsa.crt"; openssl pkcs8 -topk8 -in "$w/rsa.key" -v2 aes-256-cbc -passout pass:test; } > encrypted.pem

rm -f ca.srl
ls -l
