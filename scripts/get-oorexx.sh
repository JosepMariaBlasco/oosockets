#!/usr/bin/env bash
# Fetches a portable ooRexx from SourceForge and unpacks it.
#   scripts/get-oorexx.sh <version> <build> <dest>
#   version: "trunk" (the family's revision, scripts/oorexx-version.sh) or "5.2.0"
#   build:   SourceForge's platform name, e.g. ubuntu2204.x86_64,
#            macos.arm64.x86_64, windows.x86_64
# Prints the ooRexx home directory (with bin/, lib/, include/).
set -euo pipefail
here="$(cd "$(dirname "$0")" && pwd)"
version="$1"; build="$2"; dest="$3"
case "$version" in
  trunk)
    . "$here/oorexx-version.sh"
    name="oorexx-5.3.0-$OOREXX_REV.$build-portable-release"
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
