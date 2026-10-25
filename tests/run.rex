#!/usr/bin/env rexx
/* Runs every *.testGroup in this directory with ooRexxUnit and exits 1 if
   any test fails or errs. Needs: tests/framework (scripts/get-oorexxunit.sh),
   and the built library and sockets.cls on REXX_PATH and on the library
   path (scripts/test.sh sets both). */

  parse source . . me
  dir = filespec("location", me)
  .local~bRunTestsLocally = .true          -- each group runs and prints itself

  groups = .array~new
  call sysFileTree dir"*.testGroup", "found.", "FO"
  do i = 1 to found.0
    groups~append(found.i)
  end
  groups~sort

  failed = 0; errors = 0; tests = 0
  do g over groups
    say
    say "=====" filespec("name", g)
    call (g)
    r = result
    tests += r~runCount; failed += r~failureCount; errors += r~errorCount
  end

  say
  say "===== Total:" groups~items "groups," tests "tests," failed "failures," errors "errors"
  if failed + errors > 0 then exit 1
  exit 0
