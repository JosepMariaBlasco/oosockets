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

/* sockets.cls: TCP sockets for ooRexx, IPv4 and IPv6.

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

   Strings are bytes, and so is the network: nothing is converted.      */

::requires "oosockets" LIBRARY


/*============================================================================*/
/* Socket: a connected TCP socket, either end                                 */
/*============================================================================*/

::class Socket public subclass InputOutputStream

/* ---- the native layer (oosockets.cpp) ---------------------------------- */
::method nConnect  private external "LIBRARY oosockets socket_connect"
::method nAdopt    private external "LIBRARY oosockets socket_adopt"
::method nRecv     private external "LIBRARY oosockets socket_recv"
::method nSend     private unguarded external "LIBRARY oosockets socket_send"
::method nShutdown private unguarded external "LIBRARY oosockets socket_shutdown"
::method nClose    private unguarded external "LIBRARY oosockets sock_close"
::method nFree     private external "LIBRARY oosockets sock_free"
::method nAddress  private unguarded external "LIBRARY oosockets sock_address"
::method nResolve  class private external "LIBRARY oosockets socket_resolve"

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
  expose buffer atEnd closed st desc name lineEnd readTimeout writeTimeout
  self~init:super
  buffer = ""; atEnd = .false; closed = .false
  st = "READY"; desc = "READY:"
  lineEnd = "0d0a"x
  readTimeout = .nil; writeTimeout = .nil

  if arg() == 1, arg(1)~isA(.Pointer) then do  -- from ServerSocket~accept
    self~nAdopt(arg(1))
    name = hostAndPort(self~remoteAddress, self~remotePort)
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
  r = self~nConnect(host, port, timeout)
  select
    when r[1] == "OK" then nop
    when r[1] == "TIMEOUT" then
      raise syntax 48.900 array("Socket error: timed out (" || host || ", port" port")", "ETIMEDOUT", 0)
    otherwise
      raise syntax 48.900 array("Socket error:" r[2] "(" || host || ", port" port")", r[3], r[4])
  end

::method uninit
  self~nFree

/* ---- input -------------------------------------------------------------- */

/** One line. A line ends with LF; a CR before it is removed. Waits until
    a whole line arrives. At the end of the connection, a last line
    without LF is returned; after it, NOTREADY. */
::method lineIn
  expose buffer atEnd closed st desc name readTimeout
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

/** charIn(, n): exactly n bytes (default 1), waiting for them; fewer only
    at the end of the connection, and then NOTREADY. */
::method charIn
  expose buffer atEnd closed name readTimeout
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

/** read([max]): whatever has arrived, up to max bytes (default 65536),
    waiting only if nothing has. At the end of the connection, NOTREADY
    and "". */
::method read
  expose buffer atEnd closed name readTimeout
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
  use strict arg text = .nil
  if text == .nil then return 0
  if self~put(text~string || lineEnd) then return 0
  raise notready description(name) additional(self) return (1)

/** charOut(text): the bytes. 0 when written; else the number of bytes
    not written, and NOTREADY. */
::method charOut unguarded
  expose name
  use strict arg text = .nil, start = .nil
  if start \== .nil then
    raise syntax 93.900 array("Socket~charOut: a socket has no character positions")
  if text == .nil then return 0
  text = text~string
  if self~put(text) then return 0
  raise notready description(name) additional(self) return (text~length)

/** say(text): as lineOut, so that a socket can be .output's destination. */
::method say unguarded
  expose lineEnd name
  use strict arg text = ""
  if self~put(text~string || lineEnd) then return 0
  raise notready description(name) additional(self) return (1)

/** flush: writes are not buffered; nothing to do. */
::method flush unguarded
  return "READY:"

/* ---- the connection ----------------------------------------------------- */

/** close: closes the connection. Closing twice is harmless. */
::method close unguarded
  expose closed st desc
  self~nClose
  closed = .true
  st = "UNKNOWN"; desc = "UNKNOWN:"
  return "READY:"

/** shutdownOutput: tells the peer nothing more is coming (it reads the
    end of the stream); this end can still read. */
::method shutdownOutput unguarded
  expose name
  r = self~nShutdown
  if r[1] == "OK" then return 0
  self~failed(r)
  raise notready description(name) additional(self) return (1)

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

/** host:port, as given or as accepted ("[::1]:8888" for IPv6). */
::method string unguarded
  expose name
  return name

/* ---- private ------------------------------------------------------------ */

-- Reads what arrives into the buffer. "OK", "EOF", "TIMEOUT" or "ERROR";
-- the state is set for the last three (but not for a poll, timeout 0).
::method fill private
  expose buffer atEnd closed st desc
  use arg timeout
  if closed then do
    st = "NOTREADY"; desc = "NOTREADY:closed"
    return "ERROR"
  end
  if timeout == .nil then timeout = -1
  r = self~nRecv(65536, timeout)
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

-- Writes all of data. .true when written; else the state says why.
::method put private unguarded
  expose closed st desc writeTimeout
  use arg data
  if closed then do
    st = "NOTREADY"; desc = "NOTREADY:closed"
    return .false
  end
  timeout = writeTimeout
  if timeout == .nil then timeout = -1
  r = self~nSend(data, timeout)
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
  if closed then
    raise syntax 48.900 array("Socket error: the server socket is closed (port" port")", "EBADF", 0)
  timeout = acceptTimeout
  if timeout == .nil then timeout = -1
  r = self~nAccept(timeout)
  select
    when r[1] == "OK" then return .Socket~new(r[2])
    when r[1] == "TIMEOUT" then return .nil
    otherwise
      raise syntax 48.900 array("Socket error:" r[2] "(accepting on port" port")", r[3], r[4])
  end

::method close unguarded
  expose closed
  self~nClose
  closed = .true
  return "READY:"

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
/* Helpers                                                                    */
/*============================================================================*/

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
