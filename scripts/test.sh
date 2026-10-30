#!/usr/bin/env bash
# Runs the tests against the build in build/ (or $1); only the test groups
# named after it, if any (scripts/test.sh build DTLSSocket).
set -euo pipefail
root="$(cd "$(dirname "$0")/.." && pwd)"
build="${1:-$root/build}"
[ -f "$root/tests/framework/ooTest.frm" ] || "$root/scripts/get-oorexxunit.sh"
# Windows (Git Bash): rexx needs ';' and native paths.
if command -v cygpath >/dev/null 2>&1; then
  b="$(cygpath -w "$build")"; t="$(cygpath -w "$root/tests")"; f="$(cygpath -w "$root/tests/framework")"
  export REXX_PATH="$b;$t;$f"
  export PATH="$build:$PATH"
else
  export REXX_PATH="$build:$root/tests:$root/tests/framework"
  export LD_LIBRARY_PATH="$build${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}"
  export DYLD_LIBRARY_PATH="$build${DYLD_LIBRARY_PATH:+:$DYLD_LIBRARY_PATH}"
fi
cd "$root/tests"
rexx run.rex "${@:2}"
