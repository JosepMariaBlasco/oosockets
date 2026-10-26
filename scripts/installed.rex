/* Checks an installed ooSockets (as INSTALL.txt says), with nothing on
   REXX_PATH or the library path: TCP, UDP and TLS over loopback.
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
  u = .DatagramSocket~new(0, "127.0.0.1"); v = .DatagramSocket~new
  u~receiveTimeout = 5
  v~send("udp", "127.0.0.1", u~localPort)
  call check u~receive~data == "udp", "UDP"
  u~close; v~close
  -- TLS
  tsrv = .TLSServerSocket~new(0, .TLSOptions~new~certificate(certs"server.p12", "test"), "127.0.0.1")
  m = .Server~new~start("serve", tsrv)
  t = .TLSSocket~new("localhost", tsrv~localPort, .TLSOptions~new~trust(certs"ca.pem"))
  t~readTimeout = 5
  t~lineOut("tls")
  call check t~lineIn == "TLS", "TLS (" || t~protocol || ")"
  t~close; m~result; tsrv~close
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
