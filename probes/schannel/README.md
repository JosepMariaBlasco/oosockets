# Schannel: Windows' own TLS, for ooSockets

Rony asked (27/10/2026) that ooSockets not link OpenSSL statically, so
that security fixes come with the system's updates. On Windows that means
Schannel, which Windows Update keeps current. `probe.c` measures whether
Schannel does what ooSockets' TLS and DTLS do; `run.sh` builds and runs it
against Git for Windows' OpenSSL (3.5.9: `s_server`, `s_client`) and
public test servers; the workflow is `.github/workflows/schannel-probe.yml`.

Measured 27/10/2026 on GitHub's `windows-2022` (Windows Server 2022,
10.0.20348.5761) and `windows-2025` (Windows Server 2025, 10.0.26100.33650)
runners, runs 40503282126, 40503930468, 40508206456, 40508608036. The two
systems gave the same results everywhere.

## TLS client: works

Over our own connected socket (`InitializeSecurityContext`, `ISC_REQ_STREAM`),
with `SCH_CREDENTIALS` (the protocols not wanted disabled):

| Server | Result |
|---|---|
| example.com, github.com, letsencrypt.org, www.google.com | TLS 1.3, a HEAD request answered |
| expired.badssl.com | `0x80090328` The received certificate has expired. |
| wrong.host.badssl.com | `0x80090322` The target principal name is incorrect. |
| self-signed.badssl.com, untrusted-root.badssl.com | `0x80090325` The certificate chain was issued by an authority that is not trusted. |
| revoked.badssl.com | accepted (revocation is not checked unless asked, as with OpenSSL) |
| tls-v1-2.badssl.com:1012 (TLS 1.2 only), TLS 1.3 required | `0x80090326` The message received was unexpected or badly formatted. (a generic text) |
| the same, TLS 1.2 allowed | TLS 1.2 |

Schannel verifies with Windows' roots and the host name by itself
(`SCH_CRED_AUTO_CRED_VALIDATION`). In one run, expired and self-signed
badssl.com closed the connection before Schannel refused (`recv` 0); ten
more tries in the next run refused with the texts above.

TLS 1.3 servers send messages after the handshake (session tickets):
`DecryptMessage` returns `SEC_I_RENEGOTIATE`, and the data it returns as
`SECBUFFER_EXTRA` goes to `InitializeSecurityContext` on the same context;
then decrypting goes on (round 1 of the probe got this wrong).

**Explicit trust** (`SCH_CRED_MANUAL_CRED_VALIDATION`, then the server's
certificate checked with a chain engine whose only root is the trusted
certificate, `hExclusiveRoot`, and the host name): the keytool certificate
and OpenSSL's `req -x509` defaults accepted over TLS 1.3 and 1.2; another
certificate refused (`0x800B0109`, root not trusted).

## TLS server: works, with a key that has to touch the disk

`AcceptSecurityContext` over our own accepted socket, against `s_client`
over TLS 1.3 and 1.2, with keytool's PKCS#12, OpenSSL 3's PKCS#12 (AES) and
a PEM certificate with its PKCS#8 key. A client that refuses the
certificate shows on the server as `0x80090326` (unexpected or badly
formatted message).

The private key is the problem:

| How the key is given to Schannel | Result |
|---|---|
| `PFXImportCertStore` with `PKCS12_NO_PERSIST_KEY` (with or without `PKCS12_ALWAYS_CNG_KSP`) | `AcquireCredentialsHandle`: `0x8009030E` No credentials are available in the security package |
| a PEM key imported into CNG as an ephemeral key | the same `0x8009030E` |
| `PFXImportCertStore`, key persisted (the default) | works; leaves a key file in the user's profile (`%APPDATA%\Microsoft\Crypto`) each time |
| PEM key imported into CNG as a named, persisted key | works; leaves a key file too |
| either, the key deleted (`NCryptDeleteKey`) right after `AcquireCredentialsHandle` | **works**, and leaves nothing (counted) |

So a Schannel server needs its key persisted at least while the
credentials are made; deleting it right after works. A program killed in
between would leave a key file behind.

## STARTTLS: works

Both ends Schannel, on sockets that first exchanged a line in clear:
TLS 1.3, data both ways, `close_notify`.

## DTLS 1.2 client: works, with the older credentials structure

Against `s_server -dtls1_2` (with and without `-listen`, its cookie
exchange):

- `SCH_CREDENTIALS` (what Microsoft recommends now), with the other
  protocols disabled: `AcquireCredentialsHandle` fails, `0x80090331` (no
  common algorithm). With nothing disabled, the handshake starts and then
  fails (`0x80090318`).
- `SCHANNEL_CRED` (deprecated) with `grbitEnabledProtocols =
  SP_PROT_DTLS1_2_CLIENT`: **works**. Lost flights: calling
  `InitializeSecurityContext` again with no input sends the last flight
  again. Larger flights come out as `SEC_I_MESSAGE_FRAGMENT`, one datagram
  each.
- The largest message `EncryptMessage` takes is the MTU: 1096 bytes by
  default; with `SECPKG_ATTR_DTLS_MTU` set (17000, 65000), the 16,384
  bytes ooSockets allows.

## DTLS 1.2 server: not achieved

Microsoft does not document Schannel's DTLS server. With `SCHANNEL_CRED`:

| Variant | Result |
|---|---|
| the ClientHello alone | `0x8009035D` invalid parameter |
| the client's address as a second input buffer (`SECBUFFER_EXTRA`), as the few public uses suggest | the HelloVerifyRequest (cookie) goes out; the ClientHello with the cookie then fails, `0x80090320` (incomplete credentials) |
| the same, with a new context after the cookie | the same `0x80090320` |
| the address with the first ClientHello only | `0x8009035D` |

With `SCH_CREDENTIALS`, `0x80090331` at once. The same certificate and key
work for the TLS server.

## In short

Schannel can do the TLS client, the TLS server (deleting its key once the
credentials are made), STARTTLS and the DTLS client (with the deprecated
credentials structure and the MTU set). The DTLS server was not made to
work: it is undocumented, and the obvious ways fail after the cookie.
