# The keys ooSockets persists for Schannel's servers (Windows), checked
# around a test run:
#   windows-keys.ps1 plant   two keys named as ooSockets names them: one of a
#                            process that has ended (the sweep must delete
#                            it), one of a process that is running (pid 4,
#                            the System process: it must stay); and the
#                            number of the user's keys, saved
#   windows-keys.ps1 check   the first gone, the second there (then deleted),
#                            and no other key left behind by the tests
param([string]$what)
$ErrorActionPreference = 'Stop'
$dead = 'oosockets-4294967292-' + ('a' * 32)
$live = 'oosockets-4-' + ('b' * 32)
$keys = Join-Path $env:APPDATA 'Microsoft\Crypto\Keys'
$state = Join-Path $env:RUNNER_TEMP 'windows-keys.txt'
function count { if (Test-Path $keys) { (Get-ChildItem $keys -File).Count } else { 0 } }
function exists($n) { [System.Security.Cryptography.CngKey]::Exists($n) }
if ($what -eq 'plant') {
  foreach ($n in $dead, $live) {
    if (-not (exists $n)) {
      $k = [System.Security.Cryptography.CngKey]::Create([System.Security.Cryptography.CngAlgorithm]::Rsa, $n)
      $k.Dispose()
    }
  }
  Set-Content $state (count)
  "planted $dead and $live; $(count) keys"
  exit 0
}
$before = [int](Get-Content $state)
$rc = 0
if (exists $dead) { "FAILED: $dead (a process that has ended) is still there"; $rc = 1 }
else { "$dead (a process that has ended): deleted" }
if (exists $live) { "$live (a running process): kept" }
else { "FAILED: $live (a running process) was deleted"; $rc = 1 }
$after = count
"keys: $before before the tests (with the two planted), $after after"
$expected = $before - $(if (exists $dead) { 0 } else { 1 })
if ($after -ne $expected) { "FAILED: the tests left $($after - $expected) key(s) behind"; $rc = 1 }
if (exists $live) { [System.Security.Cryptography.CngKey]::Open($live).Delete() }
exit $rc
