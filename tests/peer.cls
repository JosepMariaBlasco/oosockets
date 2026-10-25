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
