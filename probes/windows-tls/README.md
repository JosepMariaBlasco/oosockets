# TLS on Windows: OpenSSL with Windows deciding trust

Measured 26/10/2026 on GitHub's `windows-2022` runner (Windows Server
2022, 10.0.20348.5761, image 20261021.618), OpenSSL 3.6.5 from vcpkg
(`openssl:x64-windows-static`), linked statically. The probe is
`probe.c`; `run.sh` builds and runs it; the workflow is
`.github/workflows/windows-tls-probe.yml`.

The question: on macOS it was decided (26/10/2026,
`probes/macos-tls/README.md`) that OpenSSL does the TLS and the system
decides trust, OpenSSL deciding only for an explicitly trusted
certificate. Does the same work on Windows, so that ooSockets has one TLS
code path instead of OpenSSL plus SChannel?

## Linked statically

`probe.exe` imports `WS2_32`, `CRYPT32`, `USER32`, `ADVAPI32`, `KERNEL32`
only: no OpenSSL DLL to ship.

## Over our socket, against the Internet

`wintrust`: OpenSSL does the handshake (`SSL_set_fd` on our socket) and
does not verify; Windows decides, on the chain the server sent
(`CertGetCertificateChain`, the intermediates in a memory store, usage
`serverAuth`; then `CertVerifyCertificateChainPolicy`,
`CERT_CHAIN_POLICY_SSL`, `AUTHTYPE_SERVER`, the host name).
`wintrust-rev`: the same, with revocation checked
(`CERT_CHAIN_REVOCATION_CHECK_CHAIN_EXCLUDE_ROOT`). `winstore`: OpenSSL
verifies, against the 572 certificates of Windows' `ROOT` store loaded
into its `X509_STORE`.

| | wintrust | wintrust-rev | winstore |
|---|---|---|---|
| example.com, github.com, letsencrypt.org, www.google.com | OK (TLS 1.3) | OK | OK |
| expired | 0x800B0101 "not within its validity period" | the same | "certificate has expired" |
| wrong host | 0x800B010F "the certificate's CN name does not match the passed value" | the same | "hostname mismatch" |
| self-signed | 0x800B0109 "terminated in a root certificate which is not trusted" | the same | "self-signed certificate" |
| untrusted root | 0x800B0109, the same | the same | "self-signed certificate in certificate chain" |
| revoked (revoked.badssl.com) | **OK** | 0x80092010 "the certificate is revoked" | **OK** |

The messages come from `FormatMessage`, in English when asked
(`LANG_ENGLISH`); on a machine in another language they may come in that
language.

Revocation is checked only when asked for. With it, Windows refused the
revoked certificate and accepted the good ones (the check went to the
network: CRL or OCSP). OpenSSL checks nothing by default.

Why `winstore` is not the way even though it worked here: the runner has
572 roots in its store, but Windows fetches roots it lacks from Windows
Update when building a chain (Microsoft's "automatic root certificates
update"), so a machine's store can be much smaller and still validate.
Building the chain with Windows (`wintrust`) gets that; loading the store
into OpenSSL does not. (From Microsoft's documentation; not measured
here.)

## Trusting one certificate explicitly

A local TLS 1.3-only server (`openssl s_server`, Git for Windows' OpenSSL
3.5.9), its certificate given as the one to trust: OpenSSL with only that
certificate in its store (`pin`, what was decided for macOS), and, for
comparison, Windows with it as the only root (`wintrust-pin`: a chain
engine with `hExclusiveRoot`). The same five certificates as on macOS,
keytool from JDK 21.0.12:

| Certificate | OpenSSL decides | Windows decides |
|---|---|---|
| 1. `openssl req -x509`, its defaults (CA:TRUE, no extended key usage) | OK | OK |
| 2. the same with `extendedKeyUsage=serverAuth`, CA:FALSE | OK | OK |
| 3. `keytool -genkeypair ... -ext SAN=...` (the line sent to Rony), 30 days | OK | OK |
| 4. the same plus `-ext EKU=serverAuth`, 30 days | OK | OK |
| 5. as 4, 3650 days | OK | OK |

Windows has none of macOS's extra rules for an explicitly trusted
certificate (no `serverAuth` required, no 825-day limit).

## In short

OpenSSL over our socket with Windows deciding trust works on Windows as
on macOS: TLS 1.3, every bad certificate refused with a reason, and
nothing to ship but our own library. Explicit trust with OpenSSL gives
the same answers as on macOS (and Windows itself would agree). SChannel
was not measured.
