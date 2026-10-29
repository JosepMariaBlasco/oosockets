#!/usr/bin/env rexx
/* macOS, with no OpenSSL 3 to be found (the CI hides Homebrew's): every way
   into TLS and DTLS must raise SYNTAX 48.900 saying what to install, and
   nothing else may break (the plain sockets' tests run after this). Needs
   sockets.cls and its library on REXX_PATH and DYLD_LIBRARY_PATH.       */

  want = "OpenSSL 3 not found; install it with ""brew install openssl@3"" or ""sudo port install openssl3"""
  failures = 0
  srv = .ServerSocket~new(0, "127.0.0.1")
  port = srv~localPort
  certs = arg(1)                               -- tests/certs/
  call try "TLSSocket~new", 'x = .TLSSocket~new("127.0.0.1",' port', , 5)'
  call try "TLSOptions~trust", 'x = .TLSOptions~new~trust("'certs'ca.pem")'
  call try "TLSOptions~certificate", 'x = .TLSOptions~new~certificate("'certs'server.p12", "test")'
  call try "DTLSSocket~new", 'x = .DTLSSocket~new("127.0.0.1",' port', , 5)'
  s = .Socket~new("127.0.0.1", port)            -- a plain one still connects
  c = srv~accept
  call try "Socket~startTLS", 's~startTLS'
  c~close; srv~close
  say "plain sockets connected; failures:" failures
  exit failures > 0

try: procedure expose want failures s
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
