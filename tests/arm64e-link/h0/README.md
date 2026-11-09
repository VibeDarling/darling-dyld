# H0 test: arm64e executable that uses libz from the dyld shared cache

Host side of the H0 guest test (plan task 3.4, hypothesis H0): an arm64e
executable that links `/usr/lib/libz.1.dylib` and `/usr/lib/libSystem.B.dylib`
and exits 0 only if libz works. On a Mac, libz lives only in the dyld shared
cache. In Darling, a split macOS cache must serve it although Darling's own
libSystem family stays on disk. Built with the 3.3a recipe (`../arm64e_link.py`,
reused as a module, not copied).

```
LD64=/path/to/aarch64-apple-darwin20-ld SDKROOT=/path/to/MacOSX.sdk \
  ruby tests/arm64e-link/h0/arm64e-link-h0.rb          # test, prints SKIP without both variables
LD64=... python3 -I tests/arm64e-link/h0/build_h0.py build --out DIR    # just build and check
```

## LINK-ONLY STUBS: NEVER INSTALL, LOAD OR RUN THEM

`libz.1.linkonly.dylib` and `libSystem.B.linkonly.dylib` (built from
`libz_stub.c`, `libz_symbols.txt`, `libsystem_symbols.txt` by `gen_stub.py`)
exist only so ld64 can resolve symbols and record install names and versions.
Every function is a `brk`, which the test verifies for every export. They carry
the real install names; a copy in a prefix would shadow the cache (a disk copy
changes precedence, plan 3.1) and trap on first use. Keep them out of every
prefix and image.

## Files

- `h0_zlib_main.c`, `zlib_decl.h`: the program and a local copy of the public
  zlib interface (no host `zlib.h`). Checks and exit codes: 1 `zlibVersion()` not
  `1.x`; 2 `compress` failed; 3 compressed size not smaller; 4 `uncompress`
  failed; 5 wrong length; 6 data differs; 7 `crc32("123456789") != 0xCBF43926`;
  8 `adler32("Wikipedia") != 0x11E60398`; 9-11 `deflateInit_/deflate/deflateEnd`;
  12-14 `inflateInit_/inflate/inflateEnd`; 15 stream length; 16 stream data.
  It prints one line on stdout through `write` ("h0 zlib OK" or "h0 zlib FAIL nn")
  and has no other libSystem import.
- `build_h0.py`: builds both stubs and the executable, then checks them (below).
- `expected.json`: the expected dependencies, imports and auth-bind flavour.
- `arm64e-link-h0.rb`: the test.

## Choices

- libz stub: compatibility 1.0.0 (any libz 1.x satisfies it, and compatibility is
  what dyld compares), current 1.2.12 (macOS's libz as far as I remember; not
  verified, never compared). Exports the public zlib 1.x API listed in
  `libz_symbols.txt` (81 names; the test uses 11).
- libSystem: what the Darling SDK offers was probed. `usr/lib/libSystem.dylib` is
  a symlink into the Darling build tree (`build/src/external/libsystem/libSystem.B.dylib`).
  It is a real dylib, not a `.tbd`, plain arm64 (cpusubtype ALL, no arm64e slice),
  install name `/usr/lib/libSystem.B.dylib`, compatibility 1.0.0, current 1281.0.0,
  platform macOS 11.0, and it re-exports `/usr/lib/system/libsystem_*`. The in-tree
  ld64 links an arm64e executable against it with `-syslibroot $SDKROOT -lSystem`
  (it finds the re-exports under the SDK root), but not by bare path (it fails on
  `/usr/lib/system/libsystem_sandbox.dylib`). Because the file is plain arm64 and
  depends on whatever the build tree holds, the default is a link-only arm64e stub
  exporting `_write`, with compat 1.0.0 like Darling's, current 1351.0.0 (from
  memory, unverified). `--libsystem sdk` links the SDK file instead; the test
  asserts the same dependencies and import table either way. The SDK is only read.
- Entry: `-e _main` is enough. With chained fixups ld64 needs no `start`, no
  `dyld_stub_binder` and no `__mh_execute_header`; it emits `LC_MAIN`, dyld hands
  `main` to libdyld's start code, which calls `exit`, so `_exit` is not imported.
- `-platform_version macos 13.0 13.0` (recipe defaults).

## What the host test proves (structure only)

Nothing is executed. The recipe's independent parser (not llvm tools) confirms:
the executable is arm64e, `LC_MAIN` is inside `__TEXT`, there is no `LC_DYLD_INFO`,
the platform is macOS, `LC_LOAD_DYLIB` entries are exactly libz then libSystem
with compat 1.0.0, and the 12 imports (11 libz, `_write`) are exactly the expected
names, each bound once from the right ordinal (1 libz, 2 libSystem). ld64 made
every GOT slot an authenticated bind in `__auth_got` with key IA, address
diversity set and diversity 0, with calls through `__auth_stubs`; dyld signs
them at load time (MachOLoaded.cpp ~1226-1253). The stubs export exactly their
symbol lists with the expected install name and versions, no dependencies, and a
`brk #1` at each entry. The test program's logic is also run natively against the
host libz, with injected failures for exit codes 1, 2, 4, 7 and 8. Failure paths
and seven mutation probes (wrong install name, wrong ordinal, caps byte not
cleared, missing export, undefined extra symbol, extra provided import, stub
without trap) each must fail.

It does not prove that Darling's dyld loads the image, signs the binds, or serves
libz from the cache.

## What a guest run asserts (later task, private build)

Exit code 0 and the status line `h0 zlib OK`, plus in the dyld log:
the split cache mapped (`DYLD_PRINT_SEGMENTS` logs the mapping);
`dyld: Using shared cached for /usr/lib/libz.1.dylib` (also `DYLD_PRINT_SEGMENTS`:
dyld2 prints it when verboseMapping is on); no rebase or bind of libz's own
pointers (`DYLD_PRINT_BINDINGS`, `DYLD_PRINT_REBASINGS` show none for
libz.1.dylib, since cache images are never rebound); and the 3.2 line
`dyld: split cache GOT override of <exporter>: ...` lines (exact format in dyld2.cpp
on feat/shared-cache-m3-patch) whose `patched` counts include the 17 libSystem-family
symbols libz imports (65 GOT slots per the 3.0b scan) and whose `symbols missing`
is 0 for them. The per-exporter totals also count the cache's other clients, so
17 and 0 are checked against the 3.2 stub-resolver output, not read off a total.

Environment variables as dyld2 names them (src/dyld2.cpp): `DYLD_PRINT_LIBRARIES`,
`DYLD_PRINT_SEGMENTS`, `DYLD_PRINT_BINDINGS`, `DYLD_PRINT_REBASINGS`,
`DYLD_PRINT_TO_STDERR`. `DYLD_SHARED_CACHE_SPLIT_DIR` (Darling only, honoured when
the process may use `allowEnvVarsSharedCache` and `allowEnvVarsPath`) names the
cache directory. Set it only on the test process (a prefix on the one command,
never `export`ed), because it makes every plain arm64 process fail.

Commands, not run here, in a PRIVATE prefix (never the default prefix), with
`<priv>` the prefix directory, `<cache>` the split cache directory and `<exe>`
the built `h0_zlib_main` copied into it:

```
# Run A: no libz on disk in the prefix or the install root; cache-only path
DPREFIX=<priv> DYLD_SHARED_CACHE_SPLIT_DIR=<cache> DYLD_PRINT_TO_STDERR=1 \
  DYLD_PRINT_LIBRARIES=1 DYLD_PRINT_SEGMENTS=1 DYLD_PRINT_BINDINGS=1 DYLD_PRINT_REBASINGS=1 \
  darling <exe>; echo rc=$?
# Run B: a libz.1.dylib IS on disk (Darling's own); precedence proof: the log must still
# say "Using shared cached for /usr/lib/libz.1.dylib" and not load the disk copy
# (same command)
# Control for B: the same command without DYLD_SHARED_CACHE_SPLIT_DIR must load the disk libz
DPREFIX=<priv> darling shutdown
```

Check first that the variables reach the guest process (the launcher may filter
the environment) and that no `*linkonly*` file exists under `<priv>`. Never kill
darling, darlingserver or mldr; use `darling shutdown`.

## Not verified

Compat and current versions of the real cache libz and libSystem (no cache access);
that `darling` forwards the `DYLD_*` variables; the exact bind log wording; that
dyld loads or runs the executable at all.
