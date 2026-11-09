# arm64e link recipe (host only)

`arm64e_link.py` builds arm64e Mach-O dylibs and executables on a Linux host
with clang and the in-tree cctools-port ld64. `arm64e-link-toy.rb` proves the
recipe on a toy dylib and executable.

```
LD64=/path/to/aarch64-apple-darwin20-ld ruby tests/arm64e-link/arm64e-link-toy.rb
```

Without `LD64` the test prints a `SKIP` line and exits 0. `ARM64E_LINK_SCRIPT`
runs it against another copy of the script (used for mutation probes).

## Recipe

1. `clang --target=arm64e-apple-macos13 -c` (flags configurable with `--cflag`).
2. Write a copy of each object with the cpusubtype caps byte cleared
   (`0x80000002` becomes `0x00000002`). The input is validated first (64-bit
   little-endian Mach-O object, cputype ARM64, subtype exactly `0x80000002`)
   and never modified.
3. `ld64 -arch arm64e -fixup_chains -platform_version macos <min> <sdk>`
   plus `-dylib`, `-install_name`, `-e`, `-no_implicit_dylibs`, `-L`, and
   link-only stub dylibs given as `--lib` (a path or `-lNAME`).
4. Verify the output with the script's own Mach-O and chained-fixups parser (no
   llvm tools): arm64e, `LC_DYLD_CHAINED_FIXUPS` with pointer format 1, no
   `LC_DYLD_INFO` rebase/bind data, every chain walkable, every bind ordinal a
   real dylib.

`-undefined dynamic_lookup` is rejected: ld64 turned it into lib ordinal -1
(main executable) instead of a flat lookup.

## Why the caps byte is cleared

Current clang stamps arm64e objects with a versioned-ABI caps byte. The in-tree
ld64 predates it, treats the object as plain arm64 ("building for macOS-arm64e
but attempting to link with file built for macOS-arm64") and links an empty
output. clang has no flag that omits the byte. Host lld cannot link
authenticated data pointers ("INVALID relocation has invalid width of 8 bytes").

## What the toy test checks

`toy/toy_lib.c` and `toy/toy_main.c` define pointers of each authentication
flavour (IA with discriminator 0 and a constant, IB, DA and DB with address
diversity, a vtable-like struct, plain data pointers) and an executable binding
to the dylib. `toy/expected.json`, derived from the C source, lists key,
address-diversity bit, 16-bit diversity, target and bind import/addend for every
fixup. The test also checks chain strides, page starts against the segments,
install name, `LC_LOAD_DYLIB`, the `__auth_got` entries, and the script's
failure paths (non-arm64e object, unexpected caps byte, in-place patch, missing
or bad `LD64`, link and compile failures, a corrupted chain).

Observed ld64 behaviour the parser relies on: auth rebase targets are offsets
from the image base, plain rebase targets are vmaddrs, and the starts record
size field is 2 bytes larger than the record (llvm-objdump rejects it as an
overlap; the script tolerates it).

## Known limits

- Nothing is executed. No Darling run, no dyld load of the output.
- Authenticated binds are checked structurally (ordinal, import name, addend,
  key, diversity). Their resolution and signing at load time are not tested.
- The toy is freestanding (`-ffreestanding`, no libSystem); stub-dylib linking
  (`--lib`) is exercised only with the toy dylib, not with text-only stubs.
- Only pointer format 1 (`DYLD_CHAINED_PTR_ARM64E`) is accepted; other formats
  and multi-start pages fail loudly.
