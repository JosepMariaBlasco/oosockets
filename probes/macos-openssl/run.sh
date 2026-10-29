#!/usr/bin/env bash
# macOS: can liboosockets use the OpenSSL of Homebrew or MacPorts, loading
# without it when it is not there? Weak linking to @rpath/libssl.3.dylib,
# measured on a GitHub macOS runner. (Rony, 29/10/2026: Homebrew and
# MacPorts; no OpenSSL shipped by us.)
set -uo pipefail
cd "$(dirname "$0")"
sw_vers; uname -m
V=3.0.18                       # the oldest OpenSSL 3, so that any 3.x has its symbols
work="$PWD/work"; mkdir -p "$work"; cd "$work"

echo "== OpenSSL $V, shared, arm64 + x86_64 (to link against only: not shipped)"
curl -fsSL --retry 3 -o o.tgz "https://github.com/openssl/openssl/releases/download/openssl-$V/openssl-$V.tar.gz"
for arch in arm64 x86_64; do
  if [ "$arch" = arm64 ]; then min=11.0; else min=10.14; fi
  mkdir -p "src-$arch"; tar -xzf o.tgz -C "src-$arch" --strip-components 1
  ( cd "src-$arch" && ./Configure "darwin64-$arch-cc" shared no-tests "-mmacosx-version-min=$min" \
      --prefix="$work/out-$arch" --libdir=lib > configure.log && make -j"$(sysctl -n hw.ncpu)" build_libs > make.log \
      && make install_dev > install.log ) || { echo "build $arch failed"; tail -20 "src-$arch/make.log"; exit 1; }
done
mkdir -p ossl/lib
cp -R out-arm64/include ossl/include
for l in libssl.3 libcrypto.3; do
  lipo -create "out-arm64/lib/$l.dylib" "out-x86_64/lib/$l.dylib" -output "ossl/lib/$l.dylib"
done
install_name_tool -id @rpath/libcrypto.3.dylib ossl/lib/libcrypto.3.dylib
install_name_tool -id @rpath/libssl.3.dylib ossl/lib/libssl.3.dylib
old=$(otool -L ossl/lib/libssl.3.dylib | awk '/libcrypto/ {print $1}')
install_name_tool -change "$old" @rpath/libcrypto.3.dylib ossl/lib/libssl.3.dylib
otool -L ossl/lib/libssl.3.dylib | sed 's/^/  /'

echo "== the probe's library: weak, rpaths Homebrew (arm64, x86_64) then MacPorts"
RP="-Wl,-rpath,/opt/homebrew/opt/openssl@3/lib -Wl,-rpath,/usr/local/opt/openssl@3/lib -Wl,-rpath,/opt/local/lib/openssl-3 -Wl,-rpath,/opt/local/libexec/openssl3/lib"
cc -arch arm64 -arch x86_64 -mmacosx-version-min=10.14 -dynamiclib -o libprobe.dylib ../lib.c -Iossl/include \
   -Wl,-weak_library,ossl/lib/libssl.3.dylib -Wl,-weak_library,ossl/lib/libcrypto.3.dylib $RP
cc -arch arm64 -arch x86_64 -mmacosx-version-min=10.14 -o host ../host.c
otool -L libprobe.dylib | sed 's/^/  /'
otool -l libprobe.dylib | grep -A2 LC_RPATH | grep path | sed 's/^/  /'
lipo -info libprobe.dylib host

for d in /opt/homebrew/opt/openssl@3/lib /usr/local/opt/openssl@3/lib /opt/local/lib/openssl-3 /opt/local/libexec/openssl3/lib; do
  printf "  %s: " "$d"; ls "$d"/libssl.3.dylib >/dev/null 2>&1 && lipo -archs "$d/libssl.3.dylib" || echo "(none)"
done

echo; echo "######## 1. as the runner is (Homebrew's openssl@3)"
./host ./libprobe.dylib; echo "  exit $?"
echo; echo "######## 2. the x86_64 slice (Rosetta on Apple Silicon)"
arch -x86_64 ./host ./libprobe.dylib; echo "  exit $?"

hide() { for d in /opt/homebrew/opt/openssl@3 /usr/local/opt/openssl@3; do [ -e "$d" ] && sudo mv "$d" "$d.hidden"; done; true; }
unhide() { for d in /opt/homebrew/opt/openssl@3 /usr/local/opt/openssl@3; do [ -e "$d.hidden" ] && sudo mv "$d.hidden" "$d"; done; true; }

echo; echo "######## 3. Homebrew's openssl@3 hidden: loads? plain code? TLS?"
hide
./host ./libprobe.dylib; echo "  exit $?"
echo; echo "######## 4. hidden, DYLD_LIBRARY_PATH at our OpenSSL $V (an escape hatch)"
DYLD_LIBRARY_PATH="$work/ossl/lib" ./host ./libprobe.dylib; echo "  exit $?"
unhide

echo; echo "######## 5. MacPorts' openssl3, Homebrew's hidden"
if [ "${MACPORTS:-1}" = 1 ]; then
  ver=$(sw_vers -productVersion | cut -d. -f1)
  case "$ver" in 15) name=Sequoia;; 14) name=Sonoma;; 26) name=Tahoe;; *) name="";; esac
  pkg=$(curl -fsSL https://api.github.com/repos/macports/macports-base/releases/latest | grep -o "https://[^\"]*-$ver-$name.pkg" | head -1)
  echo "  MacPorts: $pkg"
  if [ -n "$pkg" ] && curl -fsSL -o mp.pkg "$pkg" && sudo installer -pkg mp.pkg -target / > mp.log 2>&1; then
    export PATH=/opt/local/bin:/opt/local/sbin:$PATH
    sudo port -q selfupdate > /dev/null 2>&1 || true
    time sudo port -N -q install openssl3 > port.log 2>&1 || tail -5 port.log
    port contents openssl3 2>/dev/null | grep -E 'libssl\.3\.dylib|libcrypto\.3\.dylib' | sed 's/^/  /'
    ls -l /opt/local/lib/libssl* 2>/dev/null | sed 's/^/  /'
    hide
    ./host ./libprobe.dylib; echo "  exit $?"
    arch -x86_64 ./host ./libprobe.dylib; echo "  (x86_64) exit $?"
    unhide
  else
    echo "  MacPorts could not be installed"; tail -5 mp.log 2>/dev/null
  fi
fi
