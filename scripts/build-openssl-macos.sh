#!/usr/bin/env bash
# Builds OpenSSL's static libraries for macOS, arm64 and x86_64 joined in
# one universal file each (lipo), for macOS 11 (arm64) and 10.14 (x86_64),
# so that liboosockets.dylib needs no OpenSSL of its own on the machine.
#   scripts/build-openssl-macos.sh <version> <dest>     (dest: include/, lib/)
set -euo pipefail
version="$1"; dest="$2"
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
    ./Configure "darwin64-$arch-cc" no-shared no-tests no-docs \
      "-mmacosx-version-min=$min" --prefix="$work/out-$arch" --libdir=lib > configure.log
    make -j"$(sysctl -n hw.ncpu)" build_libs > make.log
    make install_dev > install.log
  )
done
mkdir -p "$dest/lib"
rm -rf "$dest/include"
cp -R "out-arm64/include" "$dest/include"
for lib in libssl libcrypto; do
  lipo -create "out-arm64/lib/$lib.a" "out-x86_64/lib/$lib.a" -output "$dest/lib/$lib.a"
done
lipo -info "$dest/lib/libssl.a" "$dest/lib/libcrypto.a"
echo "OpenSSL $version in $dest"
