# TLS on macOS: what the options do

Measured 25/10/2026 on GitHub's `macos-15` (arm64) and `macos-15-intel`
runners, macOS 15.7.9 (24G830), Xcode 16.4's SDK, Homebrew's OpenSSL 3.6.3
(Intel) and 3.6.4 (arm64). The two machines gave the same results. The
probes are the C files here; `run.sh` builds and runs them; the workflow
is `.github/workflows/macos-tls-probe.yml`.

The question: how should `TLSSocket` do TLS on macOS, given that it runs
over a socket we opened ourselves (which `Socket~startTLS`, for SMTP and
IMAP's STARTTLS, needs)?

## The options

| | Secure Transport | Network.framework | OpenSSL |
|---|---|---|---|
| Part of macOS | yes, **deprecated since 10.15** (38 deprecation warnings in `st.c`) | yes, current | no: it would have to be shipped (e.g. linked statically) |
| Runs over our socket | yes (`SSLSetIOFuncs`) | **no**: it makes its own connection (`nw_connection`); its headers have no call that takes a file descriptor | yes (`SSL_set_fd`) |
| TLS 1.3 | **no**: `SSLSetProtocolVersionMax(kTLSProtocol13)` gives -9830, and a TLS 1.3-only server fails with -9836 "bad protocol version" | yes | yes |
| example.com | TLS 1.2 | TLS 1.3 | TLS 1.3 |
| Refuses expired, wrong host, self-signed, untrusted root | yes, all four -9807 "invalid certificate chain" | yes, -9814 (expired) or -9808 (the other three), numbers only | yes, with the reason (see below) |

## Who decides trust, with OpenSSL

OpenSSL does the handshake in all three ways; what changes is who says
whether the certificate is good.

| | anchors | certpem | sectrust (macOS decides) |
|---|---|---|---|
| How | the keychain's 153 anchors (`SecTrustCopyAnchorCertificates`) loaded into OpenSSL's `X509_STORE`; OpenSSL verifies, `SSL_set1_host` | `/etc/ssl/cert.pem` (Apple ships it for LibreSSL) | after the handshake, `SecTrustEvaluateWithError` on the peer's chain with `SecPolicyCreateSSL(true, host)`; not deprecated |
| expired | "certificate has expired" | the same | "certificate is expired" (-67818) |
| wrong host | "hostname mismatch" | the same | "certificate name does not match input" (-67602) |
| self-signed | "self-signed certificate" | the same | "certificate is not trusted" (-67843) |
| untrusted root | "self-signed certificate in certificate chain" | the same | "…Untrusted Root Certificate Authority certificate is not trusted" (-67843) |

With macOS deciding, the system's own policy applies: user-added and
MDM-installed roots, distrusted roots, Apple's rules for TLS certificates.

## Trusting one certificate explicitly (`TLSOptions~trust`)

A local TLS 1.3-only server (`openssl s_server`), its certificate given as
the one to trust: OpenSSL with only that certificate in its store (`pin`),
or macOS with it as the only anchor (`SecTrustSetAnchorCertificates` +
`SecTrustSetAnchorCertificatesOnly`, `sectrust-pin`).

| Certificate | OpenSSL decides | macOS decides |
|---|---|---|
| 1. `openssl req -x509`, its defaults (CA:TRUE, no extended key usage) | OK | **refused**, -67609 "not permitted for this usage" |
| 2. the same with `extendedKeyUsage=serverAuth`, CA:FALSE | OK | OK |
| 3. `keytool -genkeypair ... -ext SAN=...` (the line sent to Rony), 30 days | OK | **refused**, -67609 |
| 4. the same plus `-ext EKU=serverAuth`, 30 days | OK | OK |
| 5. as 4, 3650 days | OK | **refused**, -67901 "not standards compliant" |

The longest validity macOS accepts for such a certificate (keytool,
`serverAuth`): **825 days** OK, 826 refused (397, 398, 399, 824 OK).

So a certificate that works everywhere, with either side deciding:

    keytool -genkeypair -alias mysrv -keyalg RSA -dname "CN=localhost"
            -ext "SAN=dns:localhost,ip:127.0.0.1,ip:::1" -ext EKU=serverAuth
            -validity 825 -keystore mySrvKeystore.p12 -storepass 123456

## Decision (26/10/2026)

OpenSSL, linked statically, does the TLS on macOS. Trust:

- ordinarily, **macOS decides** (`SecTrustEvaluateWithError` with
  `SecPolicyCreateSSL(true, host)`), so the system's policy applies;
- when the program **trusts a certificate explicitly**, **OpenSSL
  decides**, with that certificate as its only anchor and the host name
  checked (`SSL_set1_host`). Apple's `serverAuth` and 825-day rules are
  policy for public certificate authorities; they protect nothing when
  the program names the one certificate it trusts, and without them the
  same keytool certificate works on every system (rows 1–5 above: all OK
  with OpenSSL).
