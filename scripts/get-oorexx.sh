#!/usr/bin/env bash
# Gets an ooRexx to build and test against.
#   scripts/get-oorexx.sh <version> <build> <dest>
#   version: "trunk": main/trunk at the revision in scripts/oorexx-version.sh,
#            checked out from SourceForge's SVN and built here (needs svn,
#            cmake and a C++ compiler; Linux, also ncurses' headers;
#            Windows, the MSVC environment, as from vcvars64.bat);
#            "latest": the newest 5.3.0 beta portable build SourceForge has
#            for this platform (builds appear there as trunk moves, platform
#            by platform), or trunk if that build is older than our
#            revision; or "5.2.0"
#   build:   SourceForge's platform name, e.g. ubuntu2204.x86_64,
#            macos.arm64.x86_64, windows.x86_64 (for trunk, only a name)
# Prints the ooRexx home directory (with bin/, lib/, include/), and nothing
# else on stdout.
set -euo pipefail
here="$(cd "$(dirname "$0")" && pwd)"
version="$1"; build="$2"; dest="$3"
. "$here/oorexx-version.sh"

# trunk: checked out (not exported, so that the build knows its revision
# and "rexx -v" says it), built, installed in the portable builds' layout.
from_svn() {
  local rev="$OOREXX_REV" src="$dest/src-r$OOREXX_REV" bld="$dest/build-r$OOREXX_REV"
  local home="$dest/oorexx-5.3.0-$OOREXX_REV.$build-svn"
  if [ -x "$home/bin/rexx" ] || [ -f "$home/bin/rexx.exe" ]; then echo "$home"; return; fi
  mkdir -p "$dest"
  echo "ooRexx: main/trunk r$rev from SourceForge's SVN, built for $build" >&2
  for i in 1 2 3; do
    svn checkout -q -r "$rev" "https://svn.code.sf.net/p/oorexx/code-0/main/trunk" "$src" >&2 && break
    echo "svn checkout failed ($i), retrying" >&2; svn cleanup "$src" >&2 2>/dev/null || true; sleep 10
  done
  [ -f "$src/CMakeLists.txt" ] || { echo "no ooRexx source from SVN" >&2; exit 1; }
  local extra=() prefix="$home"
  case "$(uname -s)" in
    Darwin) extra=(-DBUILD_OSX_UNIVERSAL_BINARIES=ON) ;;
    MINGW*|MSYS*|CYGWIN*) extra=(-G "NMake Makefiles"); prefix="$dest/install-r$rev" ;;
  esac
  cmake -S "$src" -B "$bld" -DCMAKE_BUILD_TYPE=Release -DCMAKE_INSTALL_PREFIX="$prefix" "${extra[@]}" > "$dest/cmake-r$rev.log" 2>&1 \
    || { tail -40 "$dest/cmake-r$rev.log" >&2; exit 1; }
  cmake --build "$bld" --config Release --parallel 4 > "$dest/build-r$rev.log" 2>&1 \
    || { grep -i -m20 -B2 -A5 'error' "$dest/build-r$rev.log" >&2; tail -20 "$dest/build-r$rev.log" >&2; exit 1; }
  cmake --install "$bld" --config Release > "$dest/install-r$rev.log" 2>&1 \
    || { tail -40 "$dest/install-r$rev.log" >&2; exit 1; }
  case "$(uname -s)" in
    MINGW*|MSYS*|CYGWIN*)
      # Windows installs everything at the root and the headers and import
      # libraries in api/; the portable builds have bin/, lib/, include/.
      mkdir -p "$home/bin" "$home/lib" "$home/include"
      find "$prefix" -maxdepth 1 -type f -exec cp {} "$home/bin/" \;
      cp "$prefix"/api/*.lib "$home/lib/"
      cp "$prefix"/api/*.h "$home/include/" ;;
  esac
  rm -rf "$bld"
  echo "$home"
}

case "$version" in
  trunk) from_svn; exit 0 ;;
  latest)
    rev="$(curl -fsSL --retry 3 "https://sourceforge.net/projects/oorexx/files/oorexx/5.3.0beta/portable/" \
           | grep -o "oorexx-5\.3\.0-[0-9]*\.$build-portable-release\.zip" \
           | sed 's/^oorexx-5\.3\.0-\([0-9]*\)\..*/\1/' | sort -n | tail -1)" || rev=""
    if [ -z "$rev" ] || [ "$rev" -lt "$OOREXX_REV" ]; then
      echo "ooRexx 5.3.0 beta: the newest build for $build is r${rev:-none}, older than r$OOREXX_REV: trunk instead" >&2
      from_svn; exit 0
    fi
    echo "ooRexx 5.3.0 beta, the newest build for $build: r$rev" >&2
    name="oorexx-5.3.0-$rev.$build-portable-release"
    url="https://downloads.sourceforge.net/project/oorexx/oorexx/5.3.0beta/portable/$name.zip" ;;
  5.2.0)
    name="oorexx-5.2.0-13156.$build-portable-release"
    url="https://downloads.sourceforge.net/project/oorexx/oorexx/5.2.0/portable/$name.zip" ;;
  *) echo "unknown ooRexx version: $version" >&2; exit 1 ;;
esac
mkdir -p "$dest"
zip="$dest/$name.zip"
# SourceForge's mirrors cut a transfer now and then: try again.
for i in 1 2 3 4 5; do
  curl -fsSL --retry 3 -o "$zip" "$url" && break
  echo "download failed ($i), retrying" >&2; sleep 5
done
if command -v 7z > /dev/null 2>&1; then
  7z x -y -o"$dest" "$zip" > /dev/null
else
  unzip -qo "$zip" -d "$dest"
fi
rm -f "$zip"
echo "$dest/$name"
