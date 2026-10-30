#!/usr/bin/env bash
# Makes a release zip: the native library, sockets.cls, README, LICENSE
# and INSTALL.txt, in a directory oosockets-<version>-<platform>/. On
# Windows also OpenSSL's DLLs and their licence, if they are next to the
# library (the release puts them there: Rony, 29/10/2026, separate DLLs).
#   scripts/package.sh <directory with the built library> <platform> <outdir>
set -euo pipefail
root="$(cd "$(dirname "$0")/.." && pwd)"
libdir="$1"; platform="$2"; out="$3"
version="$(sed -n 's/^project(oosockets VERSION \([0-9.]*\).*/\1/p' "$root/CMakeLists.txt")"
name="oosockets-$version-$platform"
stage="$(mktemp -d)/$name"
mkdir -p "$stage" "$out"
found=0
for f in liboosockets.so liboosockets.dylib oosockets.dll; do
  if [ -f "$libdir/$f" ]; then cp "$libdir/$f" "$stage/"; found=1; fi
done
[ "$found" = 1 ] || { echo "no library in $libdir" >&2; exit 1; }
for f in "$libdir"/libssl-3*.dll "$libdir"/libcrypto-3*.dll "$libdir"/OpenSSL-LICENSE.txt; do
  if [ -f "$f" ]; then cp "$f" "$stage/"; fi
done
cp "$root/src/sockets.cls" "$root/README.md" "$root/LICENSE" "$root/INSTALL.txt" "$stage/"
out="$(cd "$out" && pwd)"
rm -f "$out/$name.zip"
cd "$(dirname "$stage")"
if command -v 7z > /dev/null 2>&1 && ! command -v zip > /dev/null 2>&1; then
  7z a -tzip "$out/$name.zip" "$name" > /dev/null
else
  zip -qr "$out/$name.zip" "$name"
fi
echo "$out/$name.zip"
