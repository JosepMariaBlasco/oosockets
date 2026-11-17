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
  loop
    line = c~lineIn
    got~append(line)
    if line == "bye" then leave
    c~lineOut(line)
  catch notready
  finally
    c~close
  end
  return got

-- Sends the bytes as they are, then closes.
::method send unguarded
  expose srv
  use strict arg bytes
  c = srv~accept
  do
    c~charOut(bytes)
  finally
    c~close
  end
  return 0

-- Reads everything until the client closes or shuts down its output;
-- then sends back, if asked, and closes. Returns what it read.
::method collect unguarded
  expose srv
  use strict arg reply = .nil
  c = srv~accept
  data = .mutableBuffer~new
  do
    loop
      data~append(c~read)
    catch notready
    end
    if reply \== .nil then c~charOut(reply)
  finally
    c~close
  end
  return data~string

-- Accepts, waits for the given seconds without sending, then sends a
-- line and waits for the client to close.
::method silentThenLine unguarded
  expose srv
  use strict arg seconds, line
  c = srv~accept
  do
    call sysSleep seconds
    c~lineOut(line)
    do
      c~lineIn
    catch notready
    end
  finally
    c~close
  end
  return 0

-- Reads lines until none arrives for the given seconds (or the client
-- closes); returns them, as an array, and closes.
::method linesWithin unguarded
  expose srv
  use strict arg seconds
  c = srv~accept
  got = .array~new
  do
    c~readTimeout = seconds
    loop
      got~append(c~lineIn)
    catch notready
    end
  finally
    c~close
  end
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
  do
    c~readTimeout = 10
    do
      c~startTLSServer(serverOptions(file, password))
    catch e = syntax
      return e~message
    end
    got = .array~new
    loop
      line = c~lineIn
      got~append(line)
      if line == "bye" then leave
      c~lineOut(line)
    catch notready
    end
    return got
  finally
    c~close
  end

-- Accepts, makes the TLS handshake, sends the bytes and closes.
::method tlsSend unguarded
  expose srv
  use strict arg bytes, file = "server.pem", password = "test"
  c = srv~accept
  do
    c~readTimeout = 10
    c~startTLSServer(serverOptions(file, password))
    c~charOut(bytes)
  finally
    c~close
  end
  return 0

-- Accepts, makes the TLS handshake, reads everything until the client
-- shuts down its output, then sends back how many bytes it read, and
-- closes. Returns what it read.
::method tlsCollect unguarded
  expose srv
  c = srv~accept
  data = .mutableBuffer~new
  do
    c~readTimeout = 20
    c~startTLSServer(serverOptions("server.pem"))
    loop
      data~append(c~read)
    catch notready
    end
    c~lineOut(data~length)
  finally
    c~close
  end
  return data~string

-- A server that speaks in clear and then starts TLS when asked, as SMTP:
-- "220 ready"; waits for "STARTTLS"; "220 go ahead"; the handshake; then
-- echoes one line, and closes.
::method startTLSEcho unguarded
  expose srv
  c = srv~accept
  do
    c~readTimeout = 10
    c~lineOut("220 ready")
    if c~lineIn \== "STARTTLS" then return "no STARTTLS"
    c~lineOut("220 go ahead")
    c~startTLSServer(serverOptions("server.pem"))
    c~lineOut(c~lineIn)
  finally
    c~close
  end
  return 0

-- Sends two lines in one write (as an attacker injecting a command after
-- the server's reply would), then waits for the client to go away.
::method twoLinesAtOnce unguarded
  expose srv
  c = srv~accept
  do
    c~readTimeout = 10
    c~charOut("220 ready" || "0d0a"x || "INJECTED" || "0d0a"x)
    do
      c~read
    catch notready
    end
  finally
    c~close
  end
  return 0


-- TLSOptions with a certificate from tests/certs/.
::routine serverOptions public
  use strict arg file, password = "test"
  return .TLSOptions~new~certificate(certFile(file), password)

-- The full path of a file in tests/certs/.
::routine certFile public
  use strict arg name
  return filespec("location", .context~package~name) || "certs" || .file~separator || name
