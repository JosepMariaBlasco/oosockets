# ooSockets

Object oriented TCP/IP sockets for [ooRexx](https://www.oorexx.org/):
IPv4 and IPv6, sockets that are Rexx streams, TLS with the operating
system deciding which certificates to trust, and UDP, with multicast and
DTLS (TLS over UDP).

> **Status: beta**, as ooRexx 5.3.0 is; 1.0 comes with ooRexx 5.3.0.
> The TCP classes, the TLS client, the TLS server, UDP, multicast and DTLS
> work and are tested on Linux, macOS and Windows. Needs ooRexx 5.3.0 beta (trunk
> r13329 or later), not 5.2.0: see `INSTALL.txt`. Names and behaviour may
> still change until 1.0.

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
  `Socket error: connection refused (localhost, port 8888)`. The TLS
  classes say `TLS error:`, also when what failed was the socket
  underneath (`TLS error: connection refused (localhost, port 4433)`),
  and add the system's own reason when it says more than ours (`TLS
  error: certificate is not trusted: self-signed certificate (localhost,
  port 4433)`). `condition("A")` holds the message, the system's name for
  the error (`ECONNREFUSED`), its number, its own text (`Connection
  refused`), and where it failed: `SOCKET` or `TLS`. Once connected, the
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
- **Ctrl-C (HALT) stops a wait**: a `lineIn`, `accept`, `receive`, a
  write to a peer that does not read, a connection or a TLS handshake
  that hangs. The HALT is raised at the program's own line, where `signal
  on halt` catches it (measured: about 5 ms on Linux after SIGINT or
  SIGTERM; 0.05 s on Windows after a console Ctrl-C). A
  socket whose read was halted goes on working, and nothing that arrives
  later is lost; a write may have sent part of its data; after a halted
  TLS handshake, close the socket. An idle wait costs nothing measurable
  (it wakes 10 times a second: 0.2 % of a CPU on Linux). The time spent
  looking up a host name cannot be halted.
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
  trusted so count, the system's roots do not; OpenSSL checks them (with
  the host name), or on Windows Windows itself, with those as its only
  anchors:

  ```rexx
  opts = .TLSOptions~new~trust("mySrvKeystore.p12", "123456")
  s = .TLSSocket~new("localhost", 9999, opts)
  ```

  `trust` takes PEM, DER, or a PKCS#12 keystore with its password, as
  Java's `keytool` makes them (see below). `minVersion`: `"1.2"` (the
  default) or `"1.3"`.
- **STARTTLS**: `s~startTLS([host [, options]])` turns a plain `Socket`
  into a TLS one in place, for the protocols that start in clear (SMTP,
  IMAP, FTP). Bytes that arrived in clear before the handshake are
  refused (they would be taken as if they had come over TLS).
- `secure` (`.true` once TLS has started), `protocol` (`"TLSv1.3"`),
  `cipher` (both `""` until the handshake has been made). Cipher names
  are the TLS library's: for TLS 1.2, OpenSSL's `ECDHE-RSA-AES256-GCM-SHA384`
  is Windows' `TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384`; TLS 1.3's are the
  same on both (`TLS_AES_256_GCM_SHA384`).
- A peer that closes the connection without TLS's own closing message
  (`close_notify`), as many HTTP servers do, is taken as the end of the
  stream.
- **Revocation is not checked** (as in Java and .NET, by default). macOS
  checks it on its own, as best it can, and may refuse a revoked
  certificate; Linux and Windows do not.
- Underneath, OpenSSL does the TLS, kept up to date by the system: on
  Linux, the system's; on macOS, the OpenSSL 3 of **Homebrew** (`brew
  install openssl@3`) or **MacPorts** (`sudo port install openssl3`),
  since macOS has none that fits and ooSockets ships none. The library
  loads OpenSSL the first time TLS is used: without it the plain sockets
  work, and TLS raises `TLS error: OpenSSL 3 not found; install it with
  ...`. To use another OpenSSL 3, name its directory (the one with
  `libssl`) in the environment variable **`OOSOCKETS_OPENSSL`**; ooSockets
  then uses that one and no other.
- **On Windows**, TLS is Windows' own, **Schannel**, kept up to date by
  Windows Update: `TLSSocket`, `TLSServerSocket`, `startTLS`,
  `startTLSServer` and the DTLS client, `DTLSSocket`. Only the DTLS server
  (`DTLSServerSocket`) uses OpenSSL, since Schannel's cannot be made to
  work (`probes/schannel/`). The Windows zip has OpenSSL 3's DLLs
  (`libssl-3-x64.dll`, `libcrypto-3-x64.dll`), loaded only when the DTLS
  server (or `OOSOCKETS_TLS`, below) needs them: keep them next to
  `oosockets.dll`. Without them everything else works, certificate files
  included (Windows reads them itself), and the DTLS server raises `TLS
  error: OpenSSL 3 not found; ...`. `OOSOCKETS_OPENSSL` names another
  OpenSSL 3's directory, as elsewhere. To use OpenSSL for everything, set
  the environment variable **`OOSOCKETS_TLS`** to `openssl` (Windows still
  decides trust). One difference: Schannel's
  DTLS client cannot send DTLS's closing message (`close_notify`), so a
  server is not told when a Windows `DTLSSocket` closes.

### A TLS server

```rexx
opts = .TLSOptions~new~certificate("mySrvKeystore.p12", "123456")
srv = .TLSServerSocket~new(9999, opts)
do forever
  .Session~new(srv~accept)~start("serve")   -- each client in its own activity
end
::class Session
::method init
  expose s; use strict arg s
::method serve
  expose s
  s~readTimeout = 30
  signal on notready                        -- the client went away, or failed TLS
  do forever
    line = s~lineIn
    if line = "bye" then leave
    s~lineOut("You said:" line)
  end
notready:
  s~close
::requires "sockets.cls"
```

- `.TLSServerSocket~new(port, options [, address [, backlog]])`, as
  `ServerSocket`; `options` must have the server's certificate and key:
  `certificate(file [, password])`, a PKCS#12 keystore (as keytool makes
  them) or PEM with both. A file that cannot be used (no key, the wrong
  password, a key that is not the certificate's) is a SYNTAX condition,
  48.900, at `certificate`.
- `accept` returns a `TLSSocket` at once. **Its TLS handshake happens on
  its first read or write**, in the activity that serves it (as Java's
  `SSLServerSocket` does). So a client that fails the handshake — a
  browser that does not trust a self-signed certificate, a port scanner,
  `telnet` — does not stop the server: that socket gets NOTREADY, its
  `description` says why (`ERROR:TLS handshake failed: tlsv1 alert
  unknown ca`), and the usual `signal on notready` closes it. A client
  that connects and says nothing waits only in its own activity, for
  `readTimeout` at most.
- **STARTTLS, the server's side**: `s~startTLSServer(options)` on an
  accepted plain `Socket`, after the protocol's own command (SMTP's
  `STARTTLS`): the handshake is made then, and failing it is a SYNTAX
  condition, 48.900, as for `startTLS`.
- Client certificates (mutual TLS) are not supported yet.

### A certificate for a test server, with Java's keytool

Rules for certificates keep tightening, so this says what worked and
when. **On 26/10/2026** this line, with keytool from OpenJDK 21.0.12,

```sh
keytool -genkeypair -alias mysrv -keyalg RSA -dname "CN=localhost" \
        -ext "SAN=dns:localhost,ip:127.0.0.1,ip:::1" -ext EKU=serverAuth \
        -validity 825 -keystore mySrvKeystore.p12 -storepass 123456
```

made a keystore (PKCS#12, RSA 3072, SHA-384) that ooSockets accepted as
the server's certificate and, trusted explicitly (`.TLSOptions~new~trust(
"mySrvKeystore.p12", "123456")`), on the client, for `localhost` and
`127.0.0.1` (Ubuntu 24.04, OpenSSL 3.0.13). The tests do the same on
Linux, macOS 15 and Windows Server 2022 with a keystore made the same way
(`tests/certs/keytool.p12`, longer-lived). Java's own `SSLSocket`
samples worked with such a keystore as `keyStore` and as `trustStore`
(25/10/2026, without `EKU` and `-validity`). What each part is for:

- `SAN=...`: the names the certificate is good for. Clients check the
  host name only against these (not against `CN`), so without them no
  verifying client accepts it.
- `EKU=serverAuth` and at most 825 days: ooSockets does not need them
  (a certificate trusted explicitly is checked by OpenSSL, which does not
  ask for them), but macOS's own clients refuse a certificate without
  them even when told to trust it (measured, `probes/macos-tls/`).
- `.p12`: keytool has made PKCS#12 by default since Java 9. An old JKS
  keystore can be converted: `keytool -importkeystore -srckeystore
  old.jks -destkeystore new.p12 -deststoretype pkcs12`. Its certificate
  may still be refused (expired, RSA 1024, SHA-1, no SAN).

## UDP

A `UDPSocket` is not a stream: each `send` is one datagram, which
arrives whole or not at all, and `receive` returns the next one with who
sent it.

```rexx
s = .UDPSocket~new(5000)                  -- every address, IPv6 and IPv4
loop
  d = s~receive                           -- waits; returns a .Datagram
  say "From" d~address":"d~port":" d~data
  s~send(d~data~upper, d~address, d~port) -- the answer, to its sender
end
::requires "sockets.cls"
```

```rexx
c = .UDPSocket~new                        -- a port the system chooses
c~receiveTimeout = 2
c~send("hello", "localhost", 5000)
d = c~receive
if d == .nil then say "No answer in 2 seconds"
             else say d                   -- HELLO (a Datagram's string is its data)
::requires "sockets.cls"
```

- `.UDPSocket~new([port [, address]])`: without a port (or with 0),
  one the system chooses (`localPort`); without an address, every
  address, IPv6 and IPv4 (IPv4 senders read as `127.0.0.1`, not
  `::ffff:127.0.0.1`).
- `send(data, host, port)`: one datagram. The host, a name or an
  address, is resolved on every send; a name with IPv4 and IPv6 addresses
  (`localhost`) is sent to over IPv4 when the socket can (as Java does by
  default: UDP cannot try the next address, as TCP does, when nobody
  answers). Up to 65,507 bytes over IPv4 (65,527 over IPv6); more is an
  error, `message too long`. Nothing says whether a datagram arrived.
- `receive` returns a `Datagram` (`data`, `address`, `port`); a datagram
  is never truncated. With a `receiveTimeout` (seconds, `.nil` by
  default) that expires, `receive` returns `.nil`.
- `connect(host, port)`: from then on `send(data)` goes there and only
  its datagrams are received (`remoteAddress`, `remotePort`). A datagram
  sent to a port where nobody listens can then make the next `receive`
  fail with `connection refused`; without `connect`, nothing is said, on
  the three systems (Windows would say it, and ooSockets asks it not to).
- `broadcast = .true` allows sending to broadcast addresses.
- Every error is a SYNTAX condition, **48.900**: `Socket error: unknown
  host (no-such-host.invalid, port 5000)`. There is no NOTREADY: there
  is no stream, and no connection to lose.
- `close` from another activity ends a `receive` waiting there (48.900,
  `the UDP socket is closed`).

### Multicast

A `MulticastSocket` is a `UDPSocket` that joins groups: what anyone sends
to a group reaches every member. Its port may be shared: several programs
on one machine can be members on the same port.

```rexx
m = .MulticastSocket~new(5000)
m~joinGroup("239.1.2.3")                  -- IPv4; "ff15::1234" for IPv6
loop
  d = m~receive                           -- what anyone sent to the group
  say d~address":" d~data
end
::requires "sockets.cls"
```

```rexx
s = .MulticastSocket~new
s~send("hello, everybody", "239.1.2.3", 5000)
::requires "sockets.cls"
```

- `joinGroup(group [, interface])`, `leaveGroup(group [, interface])`:
  group is an IPv4 address from 224.0.0.0 to 239.255.255.255 (239.x.x.x
  for a group of one's own) or an IPv6 one starting with `ff`; interface
  is the network interface to receive on, by name (`eth0`, `en0`), index
  or one of its addresses (`192.168.1.10`; `127.0.0.1` is the loopback);
  without it, the system chooses.
- `timeToLive` (1, the default, keeps the datagrams in the local network),
  `loopback` (`.true`, the default: members on the sender's machine get
  them too; on Windows it is the receiving socket's setting that counts),
  `networkInterface` (the interface the datagrams to a group leave from;
  `""`, the system's choice).
- A member gets the datagrams of the groups it joined, and those sent to
  its port alone; a datagram sent to a shared port alone (not to a group)
  reaches only one of the sockets on it.
- One socket, without an address, takes IPv4 and IPv6 groups, on the three
  systems (macOS cannot send to an IPv4 group from such a socket: there,
  ooSockets sends through a second socket, IPv4, on the same port).

### DTLS

A `DTLSSocket` is TLS over UDP: datagrams, encrypted, between two ends that
have made a handshake, as a `TLSSocket` does over TCP. A `DTLSServerSocket`
serves any number of clients on one UDP port.

```rexx
opts = .TLSOptions~new~certificate("server.p12", "secret")
srv = .DTLSServerSocket~new(4433, opts)
loop
  c = srv~accept                          -- a client; the handshake ends on first use
  d = c~receive
  c~send(d~data~upper)
  c~close                                 -- tells the client (close_notify)
end
::requires "sockets.cls"
```

```rexx
s = .DTLSSocket~new("localhost", 4433, .TLSOptions~new~trust("server.p12", "secret"), 10)
s~send("hello")
say s~receive                             -- HELLO
s~close
::requires "sockets.cls"
```

- `.DTLSSocket~new(host, port [, options [, connectTimeout]])`: the
  handshake, with the server's certificate checked as for `TLSSocket` (the
  system decides, unless `options` trust certificates explicitly).
  `connectTimeout`, in seconds, bounds it: DTLS sends its messages again
  when they are lost, so without one a server that never answers makes
  `new` wait about a minute.
- `send(data)`: one datagram, up to 16,384 bytes. `receive` returns a
  `Datagram` (`.nil` when `receiveTimeout` expires). Datagrams may be lost
  or arrive in another order, as with UDP; DTLS protects them, it does not
  deliver them.
- `.DTLSServerSocket~new(port, options [, address])`: `options` with the
  server's certificate. Each new client is first sent a cookie to send
  back, so that a forged address costs the server nothing; `accept`
  returns it then (`.nil` after `acceptTimeout`), and **its handshake ends
  on its first `receive` or `send`**, in the activity that serves it, as
  with `TLSServerSocket`. A client that fails the handshake makes that
  `receive` or `send` raise a SYNTAX condition, 48.900 (`TLS error:
  handshake failed: tlsv1 alert unknown ca (127.0.0.1, port 50123)`), and
  the server goes on. The server answers handshakes while something waits
  on it: `accept`, or a `receive` or `send` on one of its clients.
- `protocol` (`DTLSv1.2`), `cipher`; DTLS 1.2 (OpenSSL has no DTLS 1.3 yet).
- Every error is a SYNTAX condition, 48.900: `TLS error: certificate has
  expired (localhost, port 4433)`; once the peer has closed, `receive`
  raises `TLS error: the peer closed the connection (localhost, port
  4433)`.

## Building

Needs CMake, a C++11 compiler, an installed ooRexx 5.x (the family of
projects this belongs to uses trunk r13329, see `scripts/oorexx-version.sh`)
and OpenSSL 3: on Linux the system's development package (`libssl-dev`);
on macOS Homebrew's `openssl@3`; on Windows vcpkg's `openssl:x64-windows`
(on all three, only its headers: the library does not link OpenSSL, it
loads it when it is first needed, `src/ossl.h`; `.github/workflows/ci.yml`
has the details).

```sh
cmake -S . -B build -DOOREXX_HOME=/usr/local     # where include/oorexxapi.h is
#   macOS:   -DOPENSSL_ROOT_DIR=$(brew --prefix openssl@3)
#   Windows: -DCMAKE_TOOLCHAIN_FILE=<vcpkg>/scripts/buildsystems/vcpkg.cmake
#            -DVCPKG_TARGET_TRIPLET=x64-windows
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

## Reference

`doc/` holds the reference of every class, method and attribute: a
chapter for ooRexx's *Rexx Extensions Library Reference*, in the style of
that book, with its syntax diagrams (`doc/README.md` says how to build
it).

## Licence

[Common Public License 1.0](LICENSE), the licence of ooRexx, so that the
classes can become part of ooRexx.
