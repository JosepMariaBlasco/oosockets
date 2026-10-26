/* The other end, for the tests: a ServerSocket on 127.0.0.1 (or ::1) and
   a free port, whose behaviours run in another activity:
     peer = .Peer~new
     msg = peer~start("echo")      -- the peer accepts and echoes lines
     s = .Socket~new("127.0.0.1", peer~port)
     ...
     msg~result                    -- waits for the peer; its result      */

::requires "sockets.cls"

::class Peer public

::method init unguarded
  expose srv
  use strict arg address = "127.0.0.1"
  srv = .ServerSocket~new(0, address)

::method port unguarded
  expose srv
  return srv~localPort

::method server unguarded
  expose srv
  return srv

::method close unguarded
  expose srv
  srv~close

-- Echoes lines until "bye" or the end; returns the lines it got.
::method echo unguarded
  expose srv
  c = srv~accept
  got = .array~new
  signal on notready
  loop
    line = c~lineIn
    got~append(line)
    if line == "bye" then leave
    c~lineOut(line)
  end
notready:
  c~close
  return got

-- Sends the bytes as they are, then closes.
::method send unguarded
  expose srv
  use strict arg bytes
  c = srv~accept
  c~charOut(bytes)
  c~close
  return 0

-- Reads everything until the client closes or shuts down its output;
-- then sends back, if asked, and closes. Returns what it read.
::method collect unguarded
  expose srv
  use strict arg reply = .nil
  c = srv~accept
  data = .mutableBuffer~new
  signal on notready
  loop
    data~append(c~read)
  end
notready:
  if reply \== .nil then c~charOut(reply)
  c~close
  return data~string

-- Accepts, waits for the given seconds without sending, then sends a
-- line and waits for the client to close.
::method silentThenLine unguarded
  expose srv
  use strict arg seconds, line
  c = srv~accept
  call sysSleep seconds
  c~lineOut(line)
  signal on notready
  c~lineIn
notready:
  c~close
  return 0

-- Reads lines until none arrives for the given seconds (or the client
-- closes); returns them, as an array, and closes.
::method linesWithin unguarded
  expose srv
  use strict arg seconds
  c = srv~accept
  c~readTimeout = seconds
  got = .array~new
  signal on notready
  loop
    got~append(c~lineIn)
  end
notready:
  c~close
  return got

-- Accepts and closes at once.
::method acceptAndClose unguarded
  expose srv
  c = srv~accept
  c~close
  return 0

/* ---- TLS: the server's side (Socket~startTLSServer) ---------------------- */

-- Accepts, makes the TLS handshake with the certificate in file (in
-- tests/certs/), and echoes lines until "bye" or the end. Returns the lines
-- it got; or, if the handshake fails, the message.
::method tlsEcho unguarded
  expose srv
  use strict arg file = "server.pem", password = "test"
  c = srv~accept
  c~readTimeout = 10
  signal on syntax
  c~startTLSServer(serverOptions(file, password))
  got = .array~new
  signal on notready
  loop
    line = c~lineIn
    got~append(line)
    if line == "bye" then leave
    c~lineOut(line)
  end
notready:
  c~close
  return got
syntax:
  c~close
  return condition("o")~message

-- Accepts, makes the TLS handshake, sends the bytes and closes.
::method tlsSend unguarded
  expose srv
  use strict arg bytes, file = "server.pem", password = "test"
  c = srv~accept
  c~readTimeout = 10
  c~startTLSServer(serverOptions(file, password))
  c~charOut(bytes)
  c~close
  return 0

-- Accepts, makes the TLS handshake, reads everything until the client
-- shuts down its output, then sends back how many bytes it read, and
-- closes. Returns what it read.
::method tlsCollect unguarded
  expose srv
  c = srv~accept
  c~readTimeout = 20
  c~startTLSServer(serverOptions("server.pem"))
  data = .mutableBuffer~new
  signal on notready
  loop
    data~append(c~read)
  end
notready:
  c~lineOut(data~length)
  c~close
  return data~string

-- A server that speaks in clear and then starts TLS when asked, as SMTP:
-- "220 ready"; waits for "STARTTLS"; "220 go ahead"; the handshake; then
-- echoes one line, and closes.
::method startTLSEcho unguarded
  expose srv
  c = srv~accept
  c~readTimeout = 10
  c~lineOut("220 ready")
  if c~lineIn \== "STARTTLS" then do
    c~close
    return "no STARTTLS"
  end
  c~lineOut("220 go ahead")
  c~startTLSServer(serverOptions("server.pem"))
  c~lineOut(c~lineIn)
  c~close
  return 0

-- Sends two lines in one write (as an attacker injecting a command after
-- the server's reply would), then waits for the client to go away.
::method twoLinesAtOnce unguarded
  expose srv
  c = srv~accept
  c~readTimeout = 10
  c~charOut("220 ready" || "0d0a"x || "INJECTED" || "0d0a"x)
  signal on notready
  c~read
notready:
  c~close
  return 0


-- TLSOptions with a certificate from tests/certs/.
::routine serverOptions public
  use strict arg file, password = "test"
  return .TLSOptions~new~certificate(certFile(file), password)

-- The full path of a file in tests/certs/.
::routine certFile public
  use strict arg name
  return filespec("location", .context~package~name) || "certs" || .file~separator || name
