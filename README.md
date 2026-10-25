# ooSockets

Object oriented TCP/IP sockets for [ooRexx](https://www.oorexx.org/):
IPv4 and IPv6, sockets that are Rexx streams, and (to come) TLS through
the operating system.

> **Status: prototype.** The plain TCP classes work and are tested on
> Linux, macOS and Windows; TLS and UDP are not written yet. Names and
> behaviour may still change until 1.0.

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
- Each blocking call waits in its own activity without stopping the
  others: a server can serve every client in an activity of its own, and
  one activity can read while another writes on the same socket.
- `rxsock`, `socket.cls` and `streamsocket.cls` are untouched. A program
  that requires both `socket.cls` (or `smtp.cls`, which requires it) and
  `sockets.cls` should require `sockets.cls` first, or refer to the classes
  through a namespace (`::requires "sockets.cls" namespace oo`, then
  `oo:Socket`).

## Building

Needs CMake, a C++11 compiler and an installed ooRexx 5.x (the family of
projects this belongs to uses trunk r13297, see `scripts/oorexx-version.sh`).

```sh
cmake -S . -B build -DOOREXX_HOME=/usr/local     # where include/oorexxapi.h is
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
suite at the revision in `scripts/oorexx-version.sh`.

## Licence

[Common Public License 1.0](LICENSE), the licence of ooRexx, so that the
classes can become part of ooRexx.
