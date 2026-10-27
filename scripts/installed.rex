/* Checks an installed ooSockets (as INSTALL.txt says), with nothing on
   REXX_PATH or the library path: TCP, UDP, multicast, TLS and DTLS over
   loopback.
   rexx installed.rex <tests/certs directory>                         */
  use arg certs
  sep = .file~separator
  if certs~right(1) \== sep then certs = certs || sep
  -- TCP
  srv = .ServerSocket~new(0, "127.0.0.1")
  c = .Socket~new("127.0.0.1", srv~localPort)
  p = srv~accept
  c~lineOut("tcp")
  call check p~lineIn == "tcp", "TCP"
  c~close; p~close; srv~close
  -- UDP
  u = .UDPSocket~new(0, "127.0.0.1"); v = .UDPSocket~new
  u~receiveTimeout = 5
  v~send("udp", "127.0.0.1", u~localPort)
  call check u~receive~data == "udp", "UDP"
  u~close; v~close
  -- multicast
  m1 = .MulticastSocket~new; m1~receiveTimeout = 5
  m1~joinGroup("239.255.42.200", "127.0.0.1")
  m2 = .MulticastSocket~new; m2~networkInterface = "127.0.0.1"
  m2~send("multicast", "239.255.42.200", m1~localPort)
  call check m1~receive~data == "multicast", "multicast"
  m1~close; m2~close
  -- TLS
  tsrv = .TLSServerSocket~new(0, .TLSOptions~new~certificate(certs"server.p12", "test"), "127.0.0.1")
  m = .Server~new~start("serve", tsrv)
  t = .TLSSocket~new("localhost", tsrv~localPort, .TLSOptions~new~trust(certs"ca.pem"))
  t~readTimeout = 5
  t~lineOut("tls")
  call check t~lineIn == "TLS", "TLS (" || t~protocol || ")"
  t~close; m~result; tsrv~close
  -- DTLS
  dsrv = .DTLSServerSocket~new(0, .TLSOptions~new~certificate(certs"server.p12", "test"), "127.0.0.1")
  m = .Server~new~start("serveDatagram", dsrv)
  d = .DTLSSocket~new("localhost", dsrv~localPort, .TLSOptions~new~trust(certs"ca.pem"), 10)
  d~receiveTimeout = 5
  d~send("dtls")
  call check d~receive~data == "DTLS", "DTLS (" || d~protocol || ")"
  d~close; m~result; dsrv~close
  say "installed ooSockets works:" .context~package~findClass("Socket")~package~name
  exit 0

check: procedure
  use arg ok, what
  if ok then say "ok:" what
  else do; say "FAILED:" what; exit 1; end
  return

::requires "sockets.cls"

::class Server
::method serve
  use arg srv
  c = srv~accept
  c~readTimeout = 5
  c~lineOut(c~lineIn~upper)
  c~close
::method serveDatagram
  use arg srv
  c = srv~accept
  c~receiveTimeout = 5
  c~send(c~receive~data~upper)
  c~close
