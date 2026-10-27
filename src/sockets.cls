/*----------------------------------------------------------------------------*/
/*                                                                            */
/* Copyright (c) 2026 Rexx Language Association. All rights reserved.         */
/*                                                                            */
/* This program and the accompanying materials are made available under       */
/* the terms of the Common Public License v1.0 which accompanies this         */
/* distribution. A copy is also available at the following address:           */
/* https://www.oorexx.org/license.html                                        */
/*                                                                            */
/* Redistribution and use in source and binary forms, with or                 */
/* without modification, are permitted provided that the following            */
/* conditions are met:                                                        */
/*                                                                            */
/* Redistributions of source code must retain the above copyright             */
/* notice, this list of conditions and the following disclaimer.              */
/* Redistributions in binary form must reproduce the above copyright          */
/* notice, this list of conditions and the following disclaimer in            */
/* the documentation and/or other materials provided with the distribution.   */
/*                                                                            */
/* Neither the name of Rexx Language Association nor the names                */
/* of its contributors may be used to endorse or promote products             */
/* derived from this software without specific prior written permission.      */
/*                                                                            */
/* THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS        */
/* "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT          */
/* LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS          */
/* FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT   */
/* OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,      */
/* SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED   */
/* TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA,        */
/* OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY     */
/* OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING    */
/* NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS         */
/* SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.               */
/*                                                                            */
/*----------------------------------------------------------------------------*/

/* sockets.cls: TCP and UDP sockets for ooRexx, IPv4 and IPv6, with TLS.

   s = .Socket~new("localhost", 8888)      -- connects: IPv6 or IPv4
   s~lineOut("Hello")                      -- a socket is a Rexx stream
   say s~lineIn
   s~close

   srv = .ServerSocket~new(8888)           -- every address, IPv6 and IPv4
   client = srv~accept                     -- waits; returns a .Socket

   Failing to connect (or to listen) is a SYNTAX condition, 48.900:
     "Socket error: connection refused (localhost, port 8888)".
   Once connected, the end of the connection, a timeout or an error is
   NOTREADY, as for any stream.

   Writes go out when written, unless s~bufferOutput = .true; then they
   are kept until the buffer fills, flush, close, or a read that has to
   wait (so a request is never left in the buffer while its reply is
   awaited).

   s = .TLSSocket~new("www.example.com", 443)   -- certificate verified
   srv = .TLSServerSocket~new(9999, .TLSOptions~new~certificate("srv.p12", "pw"))

   u = .UDPSocket~new                      -- UDP: datagrams, not a stream
   u~send("ping", "localhost", 5000)
   d = u~receive                           -- a .Datagram: data, address, port

   Strings are bytes, and so is the network: nothing is converted.      */

::requires "oosockets" LIBRARY

/* HALT (Ctrl-C). The methods that wait for the network trap HALT and pass
   it on to their caller ("halted: raise propagate"), so that it reaches
   the program at the line that called them, and its own SIGNAL ON HALT
   catches it: without that, a HALT raised inside a method of this package
   would end the program from there, past the program's own trap.      */


/*============================================================================*/
/* Socket: a connected TCP socket, either end                                 */
/*============================================================================*/

::class Socket public subclass InputOutputStream inherit SocketOutput

/* ---- the native layer (oosockets.cpp) ---------------------------------- */
::method nConnect  private external "LIBRARY oosockets socket_connect"
::method nConnectMore private external "LIBRARY oosockets socket_connect_more"
::method nTLSMore  private external "LIBRARY oosockets socket_tls_more"
::method nAdopt    private external "LIBRARY oosockets socket_adopt"
::method nRecv     private external "LIBRARY oosockets socket_recv"
::method nSend     private unguarded external "LIBRARY oosockets socket_send"
::method nShutdown private unguarded external "LIBRARY oosockets socket_shutdown"
::method nNoDelay  private unguarded external "LIBRARY oosockets socket_nodelay"
::method nClose    private unguarded external "LIBRARY oosockets sock_close"
::method nFree     private external "LIBRARY oosockets sock_free"
::method nAddress  private unguarded external "LIBRARY oosockets sock_address"
::method nResolve  class private external "LIBRARY oosockets socket_resolve"
::method nStartTLS private external "LIBRARY oosockets socket_starttls"
::method nStartTLSServer private external "LIBRARY oosockets socket_starttls_server"
::method nTLSInfo  private unguarded external "LIBRARY oosockets socket_tlsinfo"

/* ---- class methods ------------------------------------------------------ */

/** The addresses of a host, as strings, IPv6 and IPv4. A name that does
    not resolve is a SYNTAX condition, 48.900. */
::method resolve class
  use strict arg host
  r = self~nResolve(host~string)
  if r[1] == "OK" then return r[2]
  raise syntax 48.900 array("Socket error:" r[2] "("host")", r[3], r[4])

/* ---- making one --------------------------------------------------------- */

/** new(host, port [, connectTimeout]): connects. port is a number, or a
    service name ("http"). connectTimeout in seconds (fractions allowed);
    without it, the system's. */
::method init
  expose buffer atEnd closed st desc name lineEnd readTimeout writeTimeout peerHost peerPort tls
  signal on halt name halted          -- to the caller: see "halted" below
  self~init:super
  buffer = ""; atEnd = .false; closed = .false
  st = "READY"; desc = "READY:"
  lineEnd = "0d0a"x
  readTimeout = .nil; writeTimeout = .nil
  tls = .false

  if arg() == 1, arg(1)~isA(.Pointer) then do  -- from ServerSocket~accept
    self~nAdopt(arg(1))
    tls = self~nTLSInfo[4] == 1                -- from TLSServerSocket~accept
    peerHost = self~remoteAddress; peerPort = self~remotePort
    name = hostAndPort(peerHost, peerPort)
    return
  end

  use strict arg host, port, connectTimeout = .nil
  host = host~string; port = port~string
  if host == "" then raise syntax 88.900 array("Socket~new: the host must not be empty")
  if port~dataType("W") then do
    if port < 0 | port > 65535 then
      raise syntax 88.900 array("Socket~new: the port must be between 0 and 65535; found" port)
    port = port + 0
  end
  else if port == "" then raise syntax 88.900 array("Socket~new: the port must not be empty")
  timeout = checkTimeout(connectTimeout, "Socket~new", "connectTimeout")
  if timeout == .nil then timeout = -1

  name = hostAndPort(host, port)
  peerHost = host; peerPort = port
  r = self~nConnect(host, port, timeout)
  loop while r[1] == "AGAIN"                 -- see "HALT" in oosockets.cpp
    r = self~nConnectMore(r[2])
  end
  select
    when r[1] == "OK" then nop
    when r[1] == "TIMEOUT" then
      raise syntax 48.900 array("Socket error: timed out (" || host || ", port" port")", "ETIMEDOUT", 0)
    otherwise
      raise syntax 48.900 array("Socket error:" r[2] "(" || host || ", port" port")", r[3], r[4])
  end
  return
halted:
  raise propagate

::method uninit
  self~nFree

/* ---- input -------------------------------------------------------------- */

/** One line. A line ends with LF; a CR before it is removed. Waits until
    a whole line arrives. At the end of the connection, a last line
    without LF is returned; after it, NOTREADY. */
::method lineIn
  expose buffer atEnd closed st desc name readTimeout
  signal on halt name halted
  use strict arg line = .nil, count = 1
  if line \== .nil then
    raise syntax 93.900 array("Socket~lineIn: a socket has no line positions")
  if count \== 1 then do
    if count == 0 then return ""
    raise syntax 93.900 array("Socket~lineIn: count must be 0 or 1; found" count)
  end
  loop
    p = buffer~pos("0a"x)
    if p > 0 then do
      line = buffer~left(p - 1); buffer = buffer~substr(p + 1)
      if line~right(1) == "0d"x then line = line~left(line~length - 1)
      self~ready
      return line
    end
    if atEnd | closed then do
      if buffer \== "" then do
        line = buffer; buffer = ""
        if line~right(1) == "0d"x then line = line~left(line~length - 1)
        self~ready
        return line
      end
      self~endOfStream
      raise notready description(name) additional(self) return ""
    end
    r = self~fill(readTimeout)               -- "EOF": round again, to the end
    if r == "TIMEOUT" | r == "ERROR" then
      raise notready description(name) additional(self) return ""
  end
  return
halted:
  raise propagate

/** charIn(, n): exactly n bytes (default 1), waiting for them; fewer only
    at the end of the connection, and then NOTREADY. */
::method charIn
  expose buffer atEnd closed name readTimeout
  signal on halt name halted
  use strict arg start = .nil, length = 1
  if start \== .nil then
    raise syntax 93.900 array("Socket~charIn: a socket has no character positions")
  if \length~dataType("W") | length < 0 then
    raise syntax 93.900 array("Socket~charIn: length must be a non-negative whole number; found" length)
  if length == 0 then return ""
  loop while buffer~length < length
    if atEnd | closed then do
      data = buffer; buffer = ""
      self~endOfStream
      raise notready description(name) additional(self) return (data)
    end
    r = self~fill(readTimeout)               -- "EOF": round again, to the end
    if r == "TIMEOUT" | r == "ERROR" then
      raise notready description(name) additional(self) return ""
  end
  data = buffer~left(length); buffer = buffer~substr(length + 1)
  self~ready
  return data
halted:
  raise propagate

/** read([max]): whatever has arrived, up to max bytes (default 65536),
    waiting only if nothing has. At the end of the connection, NOTREADY
    and "". */
::method read
  expose buffer atEnd closed name readTimeout
  signal on halt name halted
  use strict arg max = 65536
  if \max~dataType("W") | max < 1 then
    raise syntax 93.900 array("Socket~read: max must be a positive whole number; found" max)
  if buffer == "", \(atEnd | closed) then do
    r = self~fill(readTimeout)               -- "EOF": round again, to the end
    if r == "TIMEOUT" | r == "ERROR" then
      raise notready description(name) additional(self) return ""
  end
  if buffer == "" then do
    self~endOfStream
    raise notready description(name) additional(self) return ""
  end
  data = buffer~left(min(max, buffer~length)); buffer = buffer~substr(data~length + 1)
  self~ready
  return data
halted:
  raise propagate

/** chars: the bytes that have arrived; 1 if none have yet but the
    connection is open (more may come); 0 at its end. Never waits. */
::method chars
  expose buffer atEnd closed st
  if buffer == "", \(atEnd | closed), st \== "ERROR" then self~fill(0)
  if buffer \== "" then return buffer~length
  if atEnd | closed | st == "ERROR" then return 0
  return 1

/** lines: 1 while the connection can still deliver a line, 0 at its end.
    Never waits. */
::method lines
  expose buffer atEnd closed st
  use strict arg option = "N"
  if buffer == "", \(atEnd | closed), st \== "ERROR" then self~fill(0)
  if buffer \== "" then return 1
  if atEnd | closed | st == "ERROR" then return 0
  return 1

/* ---- output ------------------------------------------------------------- */

/** lineOut(text): the text and a line end (CRLF unless lineEnd says
    otherwise). 0 when written; 1 and NOTREADY when not. */
::method lineOut unguarded
  expose lineEnd name
  signal on halt name halted
  use strict arg text = .nil
  if text == .nil then return 0
  if self~put(text~string || lineEnd) then return 0
  raise notready description(name) additional(self) return (1)
halted:
  raise propagate

/** charOut(text): the bytes. 0 when written; else the number of bytes
    not written, and NOTREADY. */
::method charOut unguarded
  expose name
  signal on halt name halted
  use strict arg text = .nil, start = .nil
  if start \== .nil then
    raise syntax 93.900 array("Socket~charOut: a socket has no character positions")
  if text == .nil then return 0
  text = text~string
  if self~put(text) then return 0
  raise notready description(name) additional(self) return (text~length)
halted:
  raise propagate

/** say(text): as lineOut, so that a socket can be .output's destination. */
::method say unguarded
  expose lineEnd name
  signal on halt name halted
  use strict arg text = ""
  if self~put(text~string || lineEnd) then return 0
  raise notready description(name) additional(self) return (1)
halted:
  raise propagate

/** flush: sends what bufferOutput has kept. "READY:" when sent (or when
    nothing was kept); else NOTREADY, and the description. */
::method flush unguarded
  expose desc name
  signal on halt name halted
  if self~sendKept then return "READY:"
  raise notready description(name) additional(self) return (desc)
halted:
  raise propagate

/* ---- the connection ----------------------------------------------------- */

/** close: sends what bufferOutput has kept, then closes the connection.
    "READY:"; if what was kept could not be sent, NOTREADY and that
    description (the socket is closed all the same). Closing twice is
    harmless. */
::method close unguarded
  expose closed st desc name
  signal on halt name halted
  sent = .true
  if \closed then sent = self~sendKept
  failure = desc
  self~nClose
  closed = .true
  st = "UNKNOWN"; desc = "UNKNOWN:"
  if sent then return "READY:"
  raise notready description(name) additional(self) return (failure)
halted:
  raise propagate

/** shutdownOutput: tells the peer nothing more is coming (it reads the
    end of the stream); this end can still read. */
::method shutdownOutput unguarded
  expose name
  signal on halt name halted
  if \self~sendKept then
    raise notready description(name) additional(self) return (1)
  r = self~nShutdown
  if r[1] == "OK" then return 0
  self~failed(r)
  raise notready description(name) additional(self) return (1)
halted:
  raise propagate

::method state unguarded
  expose st
  return st

/** As for streams: "READY:", "NOTREADY:EOF", "NOTREADY:TIMEOUT",
    "ERROR:ECONNRESET connection reset by peer", "UNKNOWN:" once closed. */
::method description unguarded
  expose desc
  return desc

::method remoteAddress unguarded
  r = self~nAddress("R")
  if r[1] == "OK" then return r[2]
  return ""

::method remotePort unguarded
  r = self~nAddress("R")
  if r[1] == "OK" then return r[3]
  return 0

::method localAddress unguarded
  r = self~nAddress("L")
  if r[1] == "OK" then return r[2]
  return ""

::method localPort unguarded
  r = self~nAddress("L")
  if r[1] == "OK" then return r[3]
  return 0

/** The line end lineOut writes: "0d0a"x (CRLF) unless set. */
::attribute lineEnd get unguarded
::attribute lineEnd set unguarded
  expose lineEnd
  use strict arg value
  lineEnd = value~string

/** Seconds a read may wait (fractions allowed); .nil, the default: as
    long as it takes. An expired timeout is NOTREADY ("NOTREADY:TIMEOUT");
    the socket stays usable. */
::attribute readTimeout get unguarded
::attribute readTimeout set unguarded
  expose readTimeout
  use strict arg value
  readTimeout = checkTimeout(value, "Socket~readTimeout=", "value")

/** Seconds a write may wait; .nil, the default: as long as it takes. */
::attribute writeTimeout get unguarded
::attribute writeTimeout set unguarded
  expose writeTimeout
  use strict arg value
  writeTimeout = checkTimeout(value, "Socket~writeTimeout=", "value")

/** .true when writes are kept in a buffer, .false (the default) when each
    goes out when written. Set to .true (a 65536-byte buffer), to a
    number of bytes, or to .false (which sends what was kept). 1 and 0
    are .true and .false. */
::attribute bufferOutput get unguarded
  return self~keepSize > 0
::attribute bufferOutput set unguarded
  expose name
  signal on halt name halted
  use strict arg value
  select
    when value == .true then size = 65536
    when value == .false then size = 0
    when value~dataType("W"), value > 0 then size = value + 0
    otherwise
      raise syntax 88.900 array("Socket~bufferOutput=: the value must be .true, .false or a positive whole number of bytes; found" value)
  end
  if \self~sendKept then
    raise notready description(name) additional(self)
  self~keepSize = size
  return
halted:
  raise propagate

/** .true when small writes go out at once (TCP_NODELAY), .false (the
    system's default) when the system may wait briefly to join them
    (Nagle's algorithm). */
::attribute noDelay get unguarded
  r = self~nNoDelay(-1)
  if r[1] == "OK" then return r[2] == 1
  return .false
::attribute noDelay set unguarded
  expose name
  use strict arg value
  if value \== .true & value \== .false then
    raise syntax 88.900 array("Socket~noDelay=: the value must be .true or .false; found" value)
  r = self~nNoDelay(value)
  if r[1] \== "OK" then do
    self~failed(r)
    raise notready description(name) additional(self)
  end

/* ---- TLS ---------------------------------------------------------------- */

/** startTLS([host [, options]]): TLS on this connection from now on (what
    SMTP, IMAP or FTP do after STARTTLS). host is the name the server's
    certificate must have; without it, the host this socket was made with.
    options: a TLSOptions. The handshake waits at most readTimeout. Not
    making it is a SYNTAX condition, 48.900, and the socket is closed. */
::method startTLS
  expose peerHost readTimeout
  signal on halt name halted
  use strict arg host = .nil, options = .nil
  if host == .nil then host = peerHost
  self~handshake(host~string, options, readTimeout, "Socket~startTLS")
  return self
halted:
  raise propagate

/** .true once TLS has started (TLSSocket, or startTLS). */
::method secure unguarded
  expose tls
  return tls

/** The TLS protocol in use ("TLSv1.3", "TLSv1.2"); "" without TLS. */
::method protocol unguarded
  return self~nTLSInfo[2]

/** The TLS cipher suite in use ("TLS_AES_256_GCM_SHA384"); "" without TLS. */
::method cipher unguarded
  return self~nTLSInfo[3]

/** startTLSServer(options): the server's side of TLS on this connection,
    from now on (an SMTP server after STARTTLS). options: a TLSOptions with
    the server's certificate. The handshake is made now, waiting at most
    readTimeout; not making it is a SYNTAX condition, 48.900, and the
    socket is closed. */
::method startTLSServer
  expose tls closed st desc peerHost peerPort readTimeout
  signal on halt name halted
  use strict arg options
  identity = serverIdentity(options, "Socket~startTLSServer")
  where = "(" || peerHost || ", port" peerPort")"
  self~beforeHandshake(where)
  timeout = readTimeout
  if timeout == .nil then timeout = -1
  r = self~nStartTLSServer(identity[1], identity[2], options~minVersion, timeout)
  loop while r[1] == "AGAIN"
    r = self~nTLSMore(r[2])
  end
  if r[1] == "OK" then do
    tls = .true
    return self
  end
  self~nClose; closed = .true; st = "UNKNOWN"; desc = "UNKNOWN:"
  if r[1] == "TIMEOUT" then
    raise syntax 48.900 array("TLS error: timed out" where, "ETIMEDOUT", 0)
  raise syntax 48.900 array("TLS error:" r[2] where, r[3], r[4])
halted:
  raise propagate

/** host:port, as given or as accepted ("[::1]:8888" for IPv6). */
::method string unguarded
  expose name
  return name

/* ---- private ------------------------------------------------------------ */

-- The client's side of the TLS handshake. timeout: .nil, as long as it
-- takes. On failure the socket is closed and a SYNTAX condition raised.
::method handshake private
  expose closed st desc peerPort tls
  signal on halt name halted
  use arg host, options, timeout, who
  if options \== .nil, \options~isA(.TLSOptions) then
    raise syntax 88.900 array(who": options must be a TLSOptions; found" options)
  where = "(" || host || ", port" peerPort")"
  self~beforeHandshake(where)
  trusted = .array~new; minVersion = "1.2"
  if options \== .nil then do
    trusted = options~trusted
    minVersion = options~minVersion
  end
  if timeout == .nil then timeout = -1
  r = self~nStartTLS(host, trusted, minVersion, timeout)
  loop while r[1] == "AGAIN"
    r = self~nTLSMore(r[2])
  end
  if r[1] == "OK" then do
    tls = .true
    return
  end
  self~nClose; closed = .true; st = "UNKNOWN"; desc = "UNKNOWN:"
  if r[1] == "TIMEOUT" then
    raise syntax 48.900 array("TLS error: timed out" where, "ETIMEDOUT", 0)
  raise syntax 48.900 array("TLS error:" r[2] where, r[3], r[4])
halted:
  raise propagate

-- What must hold before either side's handshake.
::method beforeHandshake private
  expose buffer closed st desc tls
  signal on halt name halted
  use arg where
  if tls then
    raise syntax 48.900 array("TLS error: TLS has already started on this connection" where, "", 0)
  if closed then
    raise syntax 48.900 array("TLS error: the socket is closed" where, "EBADF", 0)
  if \self~sendKept then
    raise syntax 48.900 array("TLS error: what was kept to send could not be sent" where, "", 0)
  if buffer \== "" then do
    -- Bytes that came before the handshake, in clear, would be taken as
    -- if they had come over TLS (the STARTTLS injection attacks).
    self~nClose; closed = .true; st = "UNKNOWN"; desc = "UNKNOWN:"
    raise syntax 48.900 array("TLS error: data arrived before the TLS handshake" where, "", 0)
  end
  return
halted:
  raise propagate

-- Reads what arrives into the buffer. "OK", "EOF", "TIMEOUT" or "ERROR";
-- the state is set for the last three (but not for a poll, timeout 0).
::method fill private
  expose buffer atEnd closed st desc
  signal on halt name halted
  use arg timeout
  if closed then do
    st = "NOTREADY"; desc = "NOTREADY:closed"
    return "ERROR"
  end
  if timeout == .nil then timeout = -1
  -- About to wait: what was kept goes out first (it may be the request
  -- whose reply this read is waiting for).
  if timeout \= 0, self~keptLength > 0 then
    if \self~sendKept then do
      if st == "NOTREADY", desc == "NOTREADY:TIMEOUT" then return "TIMEOUT"
      return "ERROR"
    end
  r = self~nRecv(65536, timeout)
  loop while r[1] == "AGAIN"                 -- see "HALT" in oosockets.cpp
    r = self~nRecv(65536, r[2])
  end
  select
    when r[1] == "OK" then do
      buffer = buffer || r[2]
      return "OK"
    end
    when r[1] == "EOF" then do
      atEnd = .true
      return "EOF"
    end
    when r[1] == "TIMEOUT" then do
      if timeout \= 0 then do
        st = "NOTREADY"; desc = "NOTREADY:TIMEOUT"
      end
      return "TIMEOUT"
    end
    otherwise
      self~failed(r)
      return "ERROR"
  end
  return
halted:
  raise propagate

-- Writes all of data (or keeps it, see bufferOutput). .true when written
-- or kept; else the state says why.
::method put private unguarded
  expose closed st desc writeTimeout
  signal on halt name halted
  use arg data
  if closed then do
    st = "NOTREADY"; desc = "NOTREADY:closed"
    return .false
  end
  timeout = writeTimeout
  if timeout == .nil then timeout = -1
  return self~sent(self~keep(data, timeout))
halted:
  raise propagate

-- Sends what was kept. .true when sent (or nothing was kept); else the
-- state says why.
::method sendKept private unguarded
  expose closed st desc writeTimeout
  signal on halt name halted
  if self~keptLength == 0 then return .true
  if closed then do
    st = "NOTREADY"; desc = "NOTREADY:closed"
    return .false
  end
  timeout = writeTimeout
  if timeout == .nil then timeout = -1
  return self~sent(self~sendAllKept(timeout))
halted:
  raise propagate

-- The state after a send's result.
::method sent private unguarded
  expose st desc
  use arg r
  if r[1] == "OK" then do
    self~ready
    return .true
  end
  if r[1] == "TIMEOUT" then do
    st = "NOTREADY"; desc = "NOTREADY:TIMEOUT"
    return .false
  end
  self~failed(r)
  return .false

::method ready private unguarded
  expose st desc
  st = "READY"; desc = "READY:"

::method endOfStream private unguarded
  expose st desc
  st = "NOTREADY"; desc = "NOTREADY:EOF"

::method failed private unguarded
  expose st desc
  use arg r
  st = "ERROR"; desc = ("ERROR:" || r[3] r[2])~strip


/*============================================================================*/
/* SocketOutput: Socket's write buffer                                        */
/*============================================================================*/

/* A mixin so that its guarded methods take a lock of their own (a scope's
   lock), not Socket's: an activity blocked reading holds Socket's, and
   another must still be able to write. Under this lock, data is kept and
   sent in order, whichever activity sends it. Results are nSend's.    */

::class SocketOutput mixinclass Object

-- keep(data, timeout): sends data at once if nothing is kept and no
-- buffer is set; else adds it to what is kept, and sends all of it when
-- the buffer is full.
::method keep private
  expose kept keepSize
  signal on halt name halted
  use arg data, timeout
  if var("kept") == 0 then kept = .mutableBuffer~new
  if var("keepSize") == 0 then keepSize = 0
  if keepSize == 0, kept~length == 0 then return self~sendAll(data, timeout)
  kept~append(data)
  if kept~length < keepSize then return .array~of("OK", 0)
  return self~sendAllKept(timeout)
halted:
  raise propagate

-- Sends all that is kept. On a timeout, what did not go out stays kept;
-- on an error, it is dropped (the connection is broken).
::method sendAllKept private
  expose kept
  signal on halt name halted
  use arg timeout
  if var("kept") == 0 then kept = .mutableBuffer~new
  if kept~length == 0 then return .array~of("OK", 0)
  r = self~nSend(kept~string, timeout)
  loop while r[1] == "AGAIN"               -- see "HALT" in oosockets.cpp
    kept = .mutableBuffer~new(kept~substr(r[2] + 1))   -- what went out is not kept
    r = self~nSend(kept~string, r[3])
  end
  select
    when r[1] == "OK" then kept~setBufferSize(0)
    when r[1] == "TIMEOUT" then kept = .mutableBuffer~new(kept~substr(r[2] + 1))
    otherwise kept~setBufferSize(0)
  end
  return r
halted:
  raise propagate

-- nSend, going on after each "AGAIN" (see "HALT" in oosockets.cpp); the
-- count of bytes sent in the result is the whole call's.
::method sendAll private
  signal on halt name halted
  use arg data, timeout
  total = 0
  r = self~nSend(data, timeout)
  loop while r[1] == "AGAIN"
    total += r[2]
    data = data~substr(r[2] + 1)
    r = self~nSend(data, r[3])
  end
  if r~items > 1, r[2]~dataType("W") then r[2] = r[2] + total
  return r
halted:
  raise propagate

-- Bytes kept, without waiting for the lock.
::method keptLength private unguarded
  expose kept
  if var("kept") == 0 then return 0
  return kept~length

::attribute keepSize get private unguarded
  expose keepSize
  if var("keepSize") == 0 then return 0
  return keepSize
::attribute keepSize set private
  expose keepSize
  use arg keepSize


/*============================================================================*/
/* TLSSocket: a Socket over TLS                                               */
/*============================================================================*/

/* new(host, port [, options [, connectTimeout]]): connects, and makes the
   TLS handshake. The server's certificate must be good for host: the
   system decides (its trusted roots, its rules), unless options trust
   certificates explicitly; then only those count. There is no way to turn
   verification off. Not making the connection is a SYNTAX condition,
   48.900: "TLS error: certificate has expired (expired.badssl.com, port
   443)". connectTimeout, in seconds, covers the connection and the
   handshake together.

   Once connected, a TLSSocket is a Socket: the same methods, the same
   NOTREADY. A peer that closes without TLS's own close (close_notify) is
   taken as the end of the stream, as most HTTP servers do it.          */

::class TLSSocket public subclass Socket

::method init
  signal on halt name halted
  if arg() == 1, arg(1)~isA(.Pointer) then do  -- from TLSServerSocket~accept
    self~init:super(arg(1))
    return
  end
  use strict arg host, port, options = .nil, connectTimeout = .nil
  if options \== .nil, \options~isA(.TLSOptions) then
    raise syntax 88.900 array("TLSSocket~new: options must be a TLSOptions; found" options)
  timeout = checkTimeout(connectTimeout, "TLSSocket~new", "connectTimeout")
  started = .DateTime~new
  self~init:super(host, port, timeout)
  if timeout \== .nil then
    timeout = max(0, timeout - (.DateTime~new - started)~totalSeconds)
  self~handshake(host~string, options, timeout, "TLSSocket~new")
  return
halted:
  raise propagate


/*============================================================================*/
/* TLSOptions: optional settings for TLS                                      */
/*============================================================================*/

/*   opts = .TLSOptions~new~trust("mySrv.pem")
     s = .TLSSocket~new("localhost", 9999, opts)

   Nothing in it turns verification off.                                */

::class TLSOptions public

::method nLoad private external "LIBRARY oosockets tls_load_certificates"
::method nCheckIdentity private external "LIBRARY oosockets tls_check_identity"

::method init
  expose trusted minVersion
  trusted = .array~new
  minVersion = "1.2"

/** trust(file [, password]): trusts the certificates in file (PEM, DER, or
    a PKCS#12 keystore with its password, as Java's keytool makes them),
    and from then on only the certificates trusted so: the system's roots
    no longer count. May be called more than once. Returns the TLSOptions.
    A file that cannot be used is a SYNTAX condition, 48.900. */
::method trust
  expose trusted
  use strict arg file, password = ""
  r = self~nLoad(file~string, password~string)
  if r[1] \== "OK" then
    raise syntax 48.900 array("TLS error: cannot use" file~string":" r[2], r[3], r[4])
  trusted~appendAll(r[2])
  return self

/** certificate(file [, password]): this end's certificate and its private
    key, in file: a PKCS#12 keystore with its password (as keytool makes
    them), or PEM with both. What a TLSServerSocket presents to its
    clients. Returns the TLSOptions. A file that cannot be used is a
    SYNTAX condition, 48.900. */
::method certificate
  expose identity
  use strict arg file, password = ""
  file = file~string; password = password~string
  r = self~nCheckIdentity(file, password)
  if r[1] \== "OK" then
    raise syntax 48.900 array("TLS error: cannot use" file":" r[2], r[3], r[4])
  identity = .array~of(file, password)
  return self

/** The certificate's file and password, as an array, or .nil if none was
    given (for TLSServerSocket and startTLSServer). */
::method identity
  expose identity
  if var("identity") == 0 then return .nil
  return identity~copy

/** The certificates trusted, as an array of DER strings (a copy). */
::method trusted
  expose trusted
  return trusted~copy

/** The oldest TLS version accepted: "1.2" (the default) or "1.3". */
::attribute minVersion get
::attribute minVersion set
  expose minVersion
  use strict arg value
  value = value~string
  if value \== "1.2", value \== "1.3" then
    raise syntax 88.900 array("TLSOptions~minVersion=: the value must be ""1.2"" or ""1.3""; found" value)
  minVersion = value


/*============================================================================*/
/* ServerSocket: a listening TCP socket                                       */
/*============================================================================*/

::class ServerSocket public

::method nListen private external "LIBRARY oosockets server_listen"
::method nAccept private external "LIBRARY oosockets server_accept"
::method nClose  private unguarded external "LIBRARY oosockets sock_close"
::method nFree   private external "LIBRARY oosockets sock_free"
::method nAddress private unguarded external "LIBRARY oosockets sock_address"

/** new(port [, address [, backlog]]): listens. port 0 asks the system for
    a free one (see localPort). Without an address, on every address,
    IPv6 and IPv4. */
::method init
  expose port closed acceptTimeout
  use strict arg port, address = "", backlog = 0
  port = port~string; address = address~string
  if \port~dataType("W") then
    raise syntax 88.900 array("ServerSocket~new: the port must be a whole number; found" port)
  if port < 0 | port > 65535 then
    raise syntax 88.900 array("ServerSocket~new: the port must be between 0 and 65535; found" port)
  if \backlog~dataType("W") | backlog < 0 then
    raise syntax 88.900 array("ServerSocket~new: the backlog must be a non-negative whole number; found" backlog)
  port = port + 0
  closed = .false; acceptTimeout = .nil
  r = self~nListen(port, address, backlog)
  if r[1] \== "OK" then do
    where = "port" port
    if address \== "" then where = address || "," where
    raise syntax 48.900 array("Socket error:" r[2] "(" || where || ")", r[3], r[4])
  end
  if port == 0 then port = self~localPort

::method uninit
  self~nFree

/** accept: waits for a client and returns its .Socket. With an
    acceptTimeout that expires, returns .nil. */
::method accept
  expose port closed acceptTimeout
  signal on halt name halted
  if closed then
    raise syntax 48.900 array("Socket error: the server socket is closed (port" port")", "EBADF", 0)
  timeout = acceptTimeout
  if timeout == .nil then timeout = -1
  r = self~nAccept(timeout)
  loop while r[1] == "AGAIN"                 -- see "HALT" in oosockets.cpp
    r = self~nAccept(r[2])
  end
  select
    when r[1] == "OK" then return self~accepted(r[2])
    when r[1] == "TIMEOUT" then return .nil
    otherwise
      raise syntax 48.900 array("Socket error:" r[2] "(accepting on port" port")", r[3], r[4])
  end
  return
halted:
  raise propagate

::method close unguarded
  expose closed
  self~nClose
  closed = .true
  return "READY:"

-- The Socket for an accepted connection.
::method accepted private
  use arg pointer
  return .Socket~new(pointer)

::method localAddress unguarded
  r = self~nAddress("L")
  if r[1] == "OK" then return r[2]
  return ""

::method localPort unguarded
  r = self~nAddress("L")
  if r[1] == "OK" then return r[3]
  return 0

/** Seconds accept may wait; .nil, the default: as long as it takes. */
::attribute acceptTimeout get unguarded
::attribute acceptTimeout set unguarded
  expose acceptTimeout
  use strict arg value
  acceptTimeout = checkTimeout(value, "ServerSocket~acceptTimeout=", "value")

::method string unguarded
  expose port
  return "a ServerSocket on port" port


/*============================================================================*/
/* TLSServerSocket: a listening socket whose connections are TLS              */
/*============================================================================*/

/* new(port, options [, address [, backlog]]): listens, as ServerSocket.
   options: a TLSOptions with the server's certificate (certificate(file
   [, password])). accept returns a TLSSocket at once; its TLS handshake
   happens on its first read or write, in the activity that serves it, so
   a client that fails the handshake (a browser that does not trust the
   certificate, a port scanner) or never makes it does not stop the
   server: that socket gets NOTREADY, its description says why ("ERROR:TLS
   handshake failed: tlsv1 alert unknown ca"), and the handshake waits at
   most readTimeout (or writeTimeout, if it starts with a write).      */

::class TLSServerSocket public subclass ServerSocket

::method nTLS private external "LIBRARY oosockets server_tls"

::method init
  use strict arg port, options, address = "", backlog = 0
  identity = serverIdentity(options, "TLSServerSocket~new")
  self~init:super(port, address, backlog)
  r = self~nTLS(identity[1], identity[2], options~minVersion)
  if r[1] \== "OK" then do
    self~close
    raise syntax 48.900 array("TLS error:" r[2], r[3], r[4])
  end

::method accepted private
  use arg pointer
  return .TLSSocket~new(pointer)

::method string unguarded
  return "a TLSServerSocket on port" self~localPort


/*============================================================================*/
/* UDPSocket: a UDP socket                                                    */
/*============================================================================*/

/* Not a stream: each send is one datagram, which arrives whole or not at
   all, and receive returns the next one with who sent it.

   s = .UDPSocket~new(5000)                 -- every address, IPv6 and IPv4
   d = s~receive                            -- waits; a .Datagram
   s~send(d~data~upper, d~address, d~port)  -- an answer to its sender

   Every error is a SYNTAX condition, 48.900:
     "Socket error: message too long (localhost, port 5000)".          */

::class UDPSocket public

::method nOpen      private external "LIBRARY oosockets udp_open"
::method nConnect   private external "LIBRARY oosockets udp_connect"
::method nSend      private unguarded external "LIBRARY oosockets udp_send"
::method nReceive   private unguarded external "LIBRARY oosockets udp_receive"
::method nBroadcast private unguarded external "LIBRARY oosockets udp_broadcast"
::method nClose     private unguarded external "LIBRARY oosockets sock_close"
::method nFree      private external "LIBRARY oosockets sock_free"
::method nAddress   private unguarded external "LIBRARY oosockets sock_address"

/** new([port [, address]]): a UDP socket on port (without it, or 0, one
    the system chooses: see localPort). Without an address, on every
    address, IPv6 and IPv4. */
::method init
  expose port closed peer receiveTimeout
  use strict arg port = 0, address = ""
  port = port~string; address = address~string
  if \port~dataType("W") then
    raise syntax 88.900 array("UDPSocket~new: the port must be a whole number; found" port)
  if port < 0 | port > 65535 then
    raise syntax 88.900 array("UDPSocket~new: the port must be between 0 and 65535; found" port)
  port = port + 0
  closed = .false; peer = .nil; receiveTimeout = .nil
  r = self~nOpen(port, address)
  if r[1] \== "OK" then do
    where = "port" port
    if address \== "" then where = address || "," where
    raise syntax 48.900 array("Socket error:" r[2] "(" || where || ")", r[3], r[4])
  end
  if port == 0 then port = self~localPort

::method uninit
  self~nFree

/** send(data, host, port): data as one datagram to host (a name or an
    address) and port. On a connected socket, send(data). */
::method send unguarded
  expose peer
  if peer == .nil then do
    use strict arg data, host, port
    host = host~string
    if host == "" then
      raise syntax 88.900 array("UDPSocket~send: the host must not be empty")
    port = checkPort(port, "UDPSocket~send")
  end
  else do
    if arg() > 1 then
      raise syntax 88.900 array("UDPSocket~send: the socket is connected to" hostAndPort(peer[1], peer[2]) || "; send takes only the data")
    use strict arg data
    host = ""; port = ""
  end
  self~checkOpen
  r = self~nSend(data~string, host, port)
  if r[1] == "OK" then return
  self~raiseError(r, host, port)

/** receive: waits for the next datagram and returns it as a .Datagram.
    With a receiveTimeout that expires, returns .nil. */
::method receive unguarded
  expose receiveTimeout
  signal on halt name halted
  self~checkOpen
  timeout = receiveTimeout
  if timeout == .nil then timeout = -1
  r = self~nReceive(timeout)
  loop while r[1] == "AGAIN"                 -- see "HALT" in oosockets.cpp
    r = self~nReceive(r[2])
  end
  select
    when r[1] == "OK" then return .Datagram~new(r[2], r[3], r[4])
    when r[1] == "TIMEOUT" then return .nil
    otherwise self~raiseError(r, "", "")
  end
  return
halted:
  raise propagate

/** connect(host, port): from now on send(data) goes there, and only its
    datagrams are received. A datagram to a port where nobody listens can
    then make the next receive (or send) fail with "connection refused". */
::method connect
  expose peer
  use strict arg host, port
  host = host~string
  if host == "" then
    raise syntax 88.900 array("UDPSocket~connect: the host must not be empty")
  port = checkPort(port, "UDPSocket~connect")
  self~checkOpen
  r = self~nConnect(host, port)
  if r[1] \== "OK" then self~raiseError(r, host, port)
  peer = .array~of(host, port)

/** .true once connect has been made. */
::method connected unguarded
  expose peer
  return peer \== .nil

::method close unguarded
  expose closed
  closed = .true                -- first: a receive it wakes must see it
  self~nClose

/** Seconds receive may wait; .nil, the default: as long as it takes. */
::attribute receiveTimeout get unguarded
::attribute receiveTimeout set unguarded
  expose receiveTimeout
  use strict arg value
  receiveTimeout = checkTimeout(value, "UDPSocket~receiveTimeout=", "value")

/** .true when datagrams may be sent to broadcast addresses
    (255.255.255.255, or a network's own); .false, the default. */
::attribute broadcast get unguarded
  r = self~nBroadcast(-1)
  if r[1] == "OK" then return r[2] == 1
  return .false
::attribute broadcast set unguarded
  use strict arg value
  if value \== .true & value \== .false then
    raise syntax 88.900 array("UDPSocket~broadcast=: the value must be .true or .false; found" value)
  self~checkOpen
  r = self~nBroadcast(value)
  if r[1] \== "OK" then self~raiseError(r, "", "")

::method localAddress unguarded
  r = self~nAddress("L")
  if r[1] == "OK" then return r[2]
  return ""

::method localPort unguarded
  r = self~nAddress("L")
  if r[1] == "OK" then return r[3]
  return 0

/** The connected peer's address and port ("" and 0 if not connected). */
::method remoteAddress unguarded
  r = self~nAddress("R")
  if r[1] == "OK" then return r[2]
  return ""

::method remotePort unguarded
  r = self~nAddress("R")
  if r[1] == "OK" then return r[3]
  return 0

::method string unguarded
  expose port
  return "a UDPSocket on port" port

::method checkOpen private unguarded
  expose closed port
  if closed then
    raise syntax 48.900 array("Socket error: the UDP socket is closed (port" port")", "EBADF", 0)

-- 48.900 for a failure; where is host and port, the connected peer's, or
-- this socket's own port.
::method raiseError private unguarded
  expose closed port peer
  use arg r, host, port2
  if closed then
    raise syntax 48.900 array("Socket error: the UDP socket is closed (port" port")", "EBADF", 0)
  select
    when host \== "" then where = host || ", port" port2
    when peer \== .nil then where = peer[1] || ", port" peer[2]
    otherwise where = "port" port
  end
  raise syntax 48.900 array("Socket error:" r[2] "(" || where || ")", r[3], r[4])


/*============================================================================*/
/* Datagram: what UDPSocket~receive returns                                   */
/*============================================================================*/

::class Datagram public

/** new(data, address, port) */
::method init
  expose data address port
  use strict arg data, address, port

/** The bytes received. */
::attribute data get
/** Who sent them: an address (IPv4 as "127.0.0.1", IPv6 as "::1") and a port. */
::attribute address get
::attribute port get

/** The data, so that say d shows it. */
::method string
  expose data
  return data

::method makeString
  expose data
  return data


/*============================================================================*/
/* Helpers                                                                    */
/*============================================================================*/

-- The certificate file and password of options, a TLSOptions that must
-- have one.
::routine serverIdentity
  use arg options, who
  if \options~isA(.TLSOptions) then
    raise syntax 88.900 array(who": options must be a TLSOptions; found" options)
  identity = options~identity
  if identity == .nil then
    raise syntax 88.900 array(who": options must have the server's certificate (TLSOptions~certificate)")
  return identity

-- A port: a whole number 0..65535, or a service name ("domain").
::routine checkPort
  use arg port, who
  port = port~string
  if port == "" then raise syntax 88.900 array(who": the port must not be empty")
  if \port~dataType("W") then return port
  if port < 0 | port > 65535 then
    raise syntax 88.900 array(who": the port must be between 0 and 65535; found" port)
  return port + 0

-- .nil, or a non-negative number of seconds.
::routine checkTimeout
  use arg value, who, what
  if value == .nil then return .nil
  if \value~dataType("N") then
    raise syntax 88.900 array(who": the" what "must be .nil or a number of seconds; found" value)
  if value < 0 then
    raise syntax 88.900 array(who": the" what "must not be negative; found" value)
  return value

-- "host:port", "[::1]:port" for IPv6.
::routine hostAndPort
  use arg host, port
  if host~pos(":") > 0 then return "[" || host || "]:" || port
  return host":"port
