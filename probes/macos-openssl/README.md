# macOS: the OpenSSL of Homebrew or MacPorts, linked weakly

Rony (29/10/2026): ooSockets should use the OpenSSL that the system's
package manager keeps current (Homebrew, and MacPorts too), and ship none.
Can `liboosockets.dylib` find it there, and still load when it is not
there, so that the plain sockets work?

`run.sh` builds OpenSSL 3.0.18 (the oldest 3.x) as universal dylibs named
`@rpath/libssl.3.dylib` and `@rpath/libcrypto.3.dylib`, only to link
against; links `lib.c` into a universal `libprobe.dylib` with
`-weak_library` to both and four rpaths (Homebrew on Apple Silicon and on
Intel, MacPorts' two directories); and loads it with `dlopen` from
`host.c`, as ooRexx loads `liboosockets`. The workflow is
`.github/workflows/macos-openssl-probe.yml`.

Measured 29/10/2026 on GitHub's `macos-15` (Apple Silicon, macOS 15.8.2)
and `macos-15-intel` (macOS 15.7.9) runners, runs 40898680120 and
40901083501.

| Case | Apple Silicon | Intel |
|---|---|---|
| Homebrew's `openssl@3` | found, 3.6.4, `/opt/homebrew/Cellar/openssl@3/3.6.4/lib/` | found, 3.6.3, `/usr/local/Cellar/openssl@3/3.6.3/lib/` |
| the x86_64 slice (`arch -x86_64`) | not found: the arm64 Homebrew library is passed over, no failure | found (native) |
| Homebrew's hidden | **loads**, plain code runs, "not found" | the same |
| hidden, `DYLD_LIBRARY_PATH` at another OpenSSL 3 | found there (3.0.18) | the same |
| MacPorts' `openssl3` (2.12.7), Homebrew's hidden | found, 3.6.5, `/opt/local/libexec/openssl3/lib/` | the same, also for x86_64 |

"Not found" means the weak symbols are null: the library loads, and the
code checks `&SSL_CTX_new` (through a volatile, so that the compiler
cannot assume it non-null) before any TLS. MacPorts puts `libssl.3.dylib`
in `/opt/local/lib/openssl-3/` and `/opt/local/libexec/openssl3/lib/`, not
in `/opt/local/lib/` (round 1 looked there and missed it).

Built against OpenSSL 3.0.18, the library ran with 3.6.x: OpenSSL keeps
the ABI within 3.x, so linking against the oldest 3.x means any 3.x has
what it calls.

## Decision (29/10/2026)

As measured: `liboosockets.dylib` names `@rpath/libssl.3.dylib` and
`@rpath/libcrypto.3.dylib` as weak, with the rpaths
`/opt/homebrew/opt/openssl@3/lib`, `/usr/local/opt/openssl@3/lib`,
`/opt/local/lib/openssl-3`, `/opt/local/libexec/openssl3/lib`
(`CMakeLists.txt`); the release links against OpenSSL 3.0.18
(`scripts/build-openssl-macos.sh ... shared`), which is not shipped.
Without OpenSSL 3, every way into TLS and DTLS raises `TLS error: OpenSSL
3 not found; install it with "brew install openssl@3" or "sudo port
install openssl3"`; the CI checks it with Homebrew's hidden
(`scripts/no-openssl.rex`).
