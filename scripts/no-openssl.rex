#!/usr/bin/env rexx
/* With no OpenSSL 3 to be found (the CI hides Homebrew's on macOS, or
   points OOSOCKETS_OPENSSL at a directory without one): every way into
   OpenSSL's TLS and DTLS must raise SYNTAX 48.900 saying what to do, and
   nothing else may break (the plain sockets' tests run after this). Needs
   sockets.cls and its library on REXX_PATH and the library path.
     rexx no-openssl.rex <tests/certs> [windows]
   The text expected: with OOSOCKETS_OPENSSL set, that OpenSSL 3 is not
   in its directory; else what each system says when it finds none by
   itself. windows: Windows, where Schannel does TLS without OpenSSL, and
   reads the certificate files: only the DTLS server, and everything with
   OOSOCKETS_TLS=openssl, need OpenSSL.                                   */

  parse arg certs mode
  sep = .file~separator
  if certs~right(1) \== sep then certs = certs || sep
  windows = mode~strip~lower == "windows"
  dir = value("OOSOCKETS_OPENSSL", , "ENVIRONMENT")
  parse source os .
  if dir \== "" then
    want = "OpenSSL 3 not found in" dir "(OOSOCKETS_OPENSSL)"
  else if os~upper~pos("DARWIN") > 0 | os~upper~pos("MAC") > 0 then
    want = "OpenSSL 3 not found; install it with ""brew install openssl@3"" or ""sudo port install openssl3"""
  else if os~upper~pos("WINDOWS") > 0 then
    want = "OpenSSL 3 not found; put libssl-3-x64.dll and libcrypto-3-x64.dll next to oosockets.dll"
  else
    want = "OpenSSL 3 not found; install it with the system's package manager"
  say "expected:" want
  failures = 0
  srv = .ServerSocket~new(0, "127.0.0.1")
  port = srv~localPort
  if windows then do
    call works "TLSOptions~trust", 'x = .TLSOptions~new~trust("'certs'ca.pem")'
    call works "TLSOptions~trust (PKCS#12)", 'x = .TLSOptions~new~trust("'certs'server.p12", "test")'
    call works "TLSOptions~certificate", 'x = .TLSOptions~new~certificate("'certs'server.p12", "test")'
    call works "TLSOptions~certificate (PEM)", 'x = .TLSOptions~new~certificate("'certs'server.pem")'
    opts = .TLSOptions~new~certificate(certs"server.pem")
    call try "DTLSServerSocket~new", 'x = .DTLSServerSocket~new(0, opts, "127.0.0.1")'
    call value "OOSOCKETS_TLS", "openssl", "ENVIRONMENT"
  end
  call try "TLSSocket~new", 'x = .TLSSocket~new("127.0.0.1",' port', , 5)'
  if \windows then
    call try "TLSOptions~trust", 'x = .TLSOptions~new~trust("'certs'ca.pem")'
  call try "TLSOptions~certificate", 'x = .TLSOptions~new~certificate("'certs'server.p12", "test")'
  call try "DTLSSocket~new", 'x = .DTLSSocket~new("127.0.0.1",' port', , 5)'
  s = .Socket~new("127.0.0.1", port)            -- a plain one still connects
  c = srv~accept
  call try "Socket~startTLS", 's~startTLS'
  c~close; srv~close
  if windows then
    call value "OOSOCKETS_TLS", "", "ENVIRONMENT"
  say "plain sockets connected; failures:" failures
  exit failures > 0

works: procedure expose failures opts
  use arg what, code
  signal on syntax name broke
  interpret code
  say "ok:" what "works"
  return
broke:
  say "FAILED:" what":" condition("O")~code condition("A")[1]; failures += 1
  return

try: procedure expose want failures s opts
  use arg what, code
  signal on syntax
  interpret code
  say "FAILED:" what "did not raise a condition"; failures += 1
  return
syntax:
  a = condition("A")
  if condition("O")~code == 48.900, a[1]~pos(want) > 0, a[1]~startsWith("TLS error: ") then
    say "ok:" what":" a[1]
  else do
    say "FAILED:" what":" condition("O")~code a[1]; failures += 1
  end
  return

::requires "sockets.cls"
