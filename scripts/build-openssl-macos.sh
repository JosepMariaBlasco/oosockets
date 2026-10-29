#!/usr/bin/env bash
# Builds OpenSSL for macOS, arm64 and x86_64 joined in one universal file
# each (lipo), for macOS 11 (arm64) and 10.14 (x86_64).
#   scripts/build-openssl-macos.sh <version> <dest> [static|shared]
# shared (what the release uses): libssl.3.dylib and libcrypto.3.dylib,
# named @rpath/..., only to link liboosockets against (weakly): ooSockets
# ships no OpenSSL, the machine's comes from Homebrew or MacPorts (Rony,
# 29/10/2026). Build against the oldest OpenSSL 3 (3.0) so that every 3.x
# has the functions it calls. static: the static libraries (as before).
set -euo pipefail
version="$1"; dest="$2"; kind="${3:-static}"
work="$(mktemp -d)"
cd "$work"
base="https://github.com/openssl/openssl/releases/download/openssl-$version"
curl -fsSL --retry 3 -o openssl.tar.gz "$base/openssl-$version.tar.gz"
curl -fsSL --retry 3 -o openssl.sha256 "$base/openssl-$version.tar.gz.sha256"
expected="$(awk '{print $1}' openssl.sha256)"
actual="$(shasum -a 256 openssl.tar.gz | awk '{print $1}')"
if [ "$expected" != "$actual" ]; then
  echo "SHA-256 mismatch: expected $expected, got $actual" >&2
  exit 1
fi
for arch in arm64 x86_64; do
  if [ "$arch" = arm64 ]; then min=11.0; else min=10.14; fi
  mkdir "src-$arch"
  tar -xzf openssl.tar.gz -C "src-$arch" --strip-components 1
  (
    cd "src-$arch"
    if [ "$kind" = shared ]; then what=shared; else what=no-shared; fi
    ./Configure "darwin64-$arch-cc" "$what" no-tests \
      "-mmacosx-version-min=$min" --prefix="$work/out-$arch" --libdir=lib > configure.log
    make -j"$(sysctl -n hw.ncpu)" build_libs > make.log
    make install_dev > install.log
  )
done
mkdir -p "$dest/lib"
rm -rf "$dest/include"
cp -R "out-arm64/include" "$dest/include"
if [ "$kind" = shared ]; then
  for lib in libssl libcrypto; do
    lipo -create "out-arm64/lib/$lib.3.dylib" "out-x86_64/lib/$lib.3.dylib" -output "$dest/lib/$lib.3.dylib"
    ln -sf "$lib.3.dylib" "$dest/lib/$lib.dylib"
  done
  install_name_tool -id @rpath/libcrypto.3.dylib "$dest/lib/libcrypto.3.dylib"
  install_name_tool -id @rpath/libssl.3.dylib "$dest/lib/libssl.3.dylib"
  old=$(otool -L "$dest/lib/libssl.3.dylib" | awk '/libcrypto/ {print $1}' | head -1)
  install_name_tool -change "$old" @rpath/libcrypto.3.dylib "$dest/lib/libssl.3.dylib"
  lipo -info "$dest/lib/libssl.3.dylib" "$dest/lib/libcrypto.3.dylib"
  otool -L "$dest/lib/libssl.3.dylib"
else
  for lib in libssl libcrypto; do
    lipo -create "out-arm64/lib/$lib.a" "out-x86_64/lib/$lib.a" -output "$dest/lib/$lib.a"
  done
  lipo -info "$dest/lib/libssl.a" "$dest/lib/libcrypto.a"
fi
echo "OpenSSL $version ($kind) in $dest"
