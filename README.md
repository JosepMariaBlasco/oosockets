# ooSockets

Object oriented TCP/IP sockets for [ooRexx](https://www.oorexx.org/):
IPv4 and IPv6, sockets that are Rexx streams, and TLS with the operating
system deciding which certificates to trust.

> **Status: prototype.** The TCP classes and the TLS client work and are
> tested on Linux, macOS and Windows; the TLS server and UDP are not
> written yet. Names and behaviour may still change until 1.0.

```rexx
s = .Socket~new("localhost", 8888)        -- IPv6 or IPv4, whichever answers
s~lineOut("Hello, this is from your ooRexx-client!")
say "CLIENT: data received from server:" s~lineIn
s~close
::requires "sockets.cls"
```

```rexx
srv = .ServerSocket~new(8888)             -- every address, IPv6 and IPv4
client = srv~accept                       -- waits; returns a .Socket
say "SERVER: data received from client:" client~lineIn
client~lineOut("Hello from the ooRexx-server!")
client~close; srv~close
::requires "sockets.cls"
```

- A `Socket` is an `InputOutputStream`: `lineIn`, `lineOut`, `charIn`,
  `charOut`, `lines`, `chars`, `say`, `state`, `description`, and it can be
  the destination of `.output`. `lineIn` takes lines ending in LF or CRLF;
  `lineOut` writes CRLF (the network protocols' line end), or what
  `lineEnd` says.
- Strings are bytes, and so is the network: nothing is converted.
- Failing to connect or to listen is a SYNTAX condition, **48.900**:
  `Socket error: connection refused (localhost, port 8888)`; the system's
  error name and number follow in `condition("A")`. Once connected, the
  end of the connection, a timeout or an error is **NOTREADY**, as for
  any stream.
- Timeouts, in seconds, none by default: `.Socket~new(host, port,
  connectTimeout)`, `readTimeout`, `writeTimeout`, and the
  `ServerSocket`'s `acceptTimeout` (an expired `accept` returns `.nil`).
- Writes go out when written. A program that writes many small pieces
  can ask for them to be kept and sent together, `s~bufferOutput = .true`
  (64 KiB, or a number of bytes): what is kept goes out when the buffer
  fills, on `flush`, `close` and `shutdownOutput`, and before any read
  that has to wait, so a request is never left in the buffer while its
  reply is awaited. (A read already waiting in *another* activity does
  not send it: there, call `flush`.) 100,000 `lineOut`s of 50 bytes over
  loopback: about 3 s unbuffered, 0.3 s buffered (Linux). `noDelay =
  .true` turns off the system's joining of small segments (TCP_NODELAY).
- Each blocking call waits in its own activity without stopping the
  others: a server can serve every client in an activity of its own, and
  one activity can read while another writes on the same socket.
- `rxsock`, `socket.cls` and `streamsocket.cls` are untouched. A program
  that requires both `socket.cls` (or `smtp.cls`, which requires it) and
  `sockets.cls` should require `sockets.cls` first, or refer to the classes
  through a namespace (`::requires "sockets.cls" namespace oo`, then
  `oo:Socket`).

## TLS

```rexx
s = .TLSSocket~new("www.example.com", 443)  -- the certificate is verified
s~lineOut("HEAD / HTTP/1.1")
s~lineOut("Host: www.example.com")
s~lineOut("Connection: close")
s~lineOut("")
say s~lineIn                                -- HTTP/1.1 200 OK
s~close
::requires "sockets.cls"
```

- A `TLSSocket` is a `Socket`: the same methods, the same NOTREADY.
  `.TLSSocket~new(host, port [, options [, connectTimeout]])`;
  `connectTimeout` covers the connection and the TLS handshake together.
- **The certificate is always verified**, and there is no way to turn
  that off. The operating system decides whether it is good: its trusted
  roots, its rules (macOS: `SecTrustEvaluateWithError`; Windows:
  `CertVerifyCertificateChainPolicy`; Linux: OpenSSL with the system's
  certificate store). A certificate that does not verify is a SYNTAX
  condition, 48.900: `TLS error: certificate has expired
  (expired.badssl.com, port 443)`. The common reasons read the same on
  the three systems (*certificate has expired*, *certificate does not
  match the host name*, *certificate is not trusted*); the system's own
  name and number follow in `condition("A")`.
- **A server with its own certificate** (a test server, a classroom
  one): trust that certificate explicitly. Then only the certificates
  trusted so count, the system's roots do not, and OpenSSL checks them
  (with the host name) the same way on every system:

  ```rexx
  opts = .TLSOptions~new~trust("mySrvKeystore.p12", "123456")
  s = .TLSSocket~new("localhost", 9999, opts)
  ```

  `trust` takes PEM, DER, or a PKCS#12 keystore with its password, as
  Java's `keytool` makes them (`keytool -genkeypair -alias mysrv -keyalg
  RSA -dname "CN=localhost" -ext "SAN=dns:localhost,ip:127.0.0.1,ip:::1"
  -keystore mySrvKeystore.p12 -storepass 123456`). `minVersion`: `"1.2"`
  (the default) or `"1.3"`.
- **STARTTLS**: `s~startTLS([host [, options]])` turns a plain `Socket`
  into a TLS one in place, for the protocols that start in clear (SMTP,
  IMAP, FTP). Bytes that arrived in clear before the handshake are
  refused (they would be taken as if they had come over TLS).
- `secure` (`.true` once TLS has started), `protocol` (`"TLSv1.3"`),
  `cipher`.
- A peer that closes the connection without TLS's own closing message
  (`close_notify`), as many HTTP servers do, is taken as the end of the
  stream.
- **Revocation is not checked** (as in Java and .NET, by default). macOS
  checks it on its own, as best it can, and may refuse a revoked
  certificate; Linux and Windows do not.
- Underneath, OpenSSL does the TLS on the three systems: the system's on
  Linux, and on macOS and Windows linked statically into the library
  (neither system ships it), so there is nothing else to install.

## Building

Needs CMake, a C++11 compiler, an installed ooRexx 5.x (the family of
projects this belongs to uses trunk r13297, see `scripts/oorexx-version.sh`)
and OpenSSL 3: on Linux the system's development package (`libssl-dev`);
on macOS Homebrew's `openssl@3`; on Windows vcpkg's
`openssl:x64-windows-static-md` (`.github/workflows/ci.yml` has the
details).

```sh
cmake -S . -B build -DOOREXX_HOME=/usr/local     # where include/oorexxapi.h is
#   macOS:   -DOPENSSL_ROOT_DIR=$(brew --prefix openssl@3)
#   Windows: -DCMAKE_TOOLCHAIN_FILE=<vcpkg>/scripts/buildsystems/vcpkg.cmake
#            -DVCPKG_TARGET_TRIPLET=x64-windows-static-md
cmake --build build --config Release
```

`build/` (on Windows, `build/Release/`) then holds the native library
(`liboosockets.so`, `liboosockets.dylib` or `oosockets.dll`) and
`sockets.cls`. A program needs that directory on `REXX_PATH` and on the
library path (`LD_LIBRARY_PATH`, `DYLD_LIBRARY_PATH`, `PATH`).

## Tests

```sh
scripts/test.sh            # fetches ooRexxUnit the first time
```

The tests use ooRexxUnit, ooRexx's own test framework, from ooRexx's test
suite at the revision in `scripts/oorexx-version.sh`. The TLS tests use
the certificates in `tests/certs/` (made by `scripts/make-test-certs.sh`);
those that need real servers (badssl.com) run only with
`OOSOCKETS_ONLINE=1`, as the CI does.

## Licence

[Common Public License 1.0](LICENSE), the licence of ooRexx, so that the
classes can become part of ooRexx.
