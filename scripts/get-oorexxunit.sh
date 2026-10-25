#!/usr/bin/env bash
# Fetches ooRexxUnit (ooRexx's test framework) at the pinned revision of
# ooRexx's test suite into tests/framework/ (not in git).
set -euo pipefail
here="$(cd "$(dirname "$0")" && pwd)"
. "$here/oorexx-version.sh"
dest="$here/../tests/framework"
base="https://svn.code.sf.net/p/oorexx/code-0/!svn/bc/$OOREXX_TEST_REV/test/trunk"
mkdir -p "$dest"
for f in ooTest.frm framework/OOREXXUNIT.CLS; do
  curl -fsSL --retry 3 -o "$dest/$(basename "$f")" "$base/$f"
done
echo "$OOREXX_TEST_REV" > "$dest/REVISION"
echo "ooRexxUnit from test/trunk r$OOREXX_TEST_REV in $dest"
