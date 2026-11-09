# arm64e link recipe (host only)

`arm64e_link.py` builds arm64e Mach-O dylibs and executables on a Linux host
with clang and the in-tree cctools-port ld64. `arm64e-link-toy.rb` proves the
recipe on a toy dylib and executable.

```
LD64=/path/to/aarch64-apple-darwin20-ld ruby tests/arm64e-link/arm64e-link-toy.rb
```

Without `LD64` the test prints a `SKIP` line and exits 0. The `h0/` directory builds on the recipe for the H0 guest test (see `h0/README.md`). `ARM64E_LINK_SCRIPT`
runs it against another copy of the script (used for mutation probes).

## Recipe

1. `clang --target=arm64e-apple-macos13 -c` (flags configurable with `--cflag`).
2. Write a copy of each object with the cpusubtype caps byte cleared
   (`0x80000002` becomes `0x00000002`). The input is validated first (64-bit
   little-endian Mach-O object, cputype ARM64, subtype exactly `0x80000002`)
   and never modified.
3. `ld64 -arch arm64e -fixup_chains -platform_version macos <min> <sdk>`
   plus `-dylib`, `-install_name`, `-e`, `-L`, and link-only stub dylibs given
   as `--lib` (a path or `-lNAME`). Other linker flags go through `--ld-arg`
   (`-no_implicit_dylibs` changed nothing in a re-export probe, so it has no
   option of its own until 3.4 needs it). ld64 writes to `<out>.partial` and the
   file is renamed to `--out` only after verification passes; the default
   workdir for the objects is a temporary directory that is removed afterwards.
4. Verify the output with the script's own Mach-O and chained-fixups parser (no
   llvm tools): arm64e, `LC_DYLD_CHAINED_FIXUPS` with pointer format 1, no
   `LC_DYLD_INFO` rebase/bind data, every chain walkable, every bind ordinal a
   real dylib.

`-undefined dynamic_lookup` is rejected in `--ld-arg`, `--lib` and `--lib-dir`: ld64 turned it into lib ordinal -1
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

The chained-fixups format itself specifies that, for `DYLD_CHAINED_PTR_ARM64E`,
an authenticated rebase target is an offset from the image base and a plain
rebase target is a vmaddr; the test checks both. The one ld64 quirk the parser
tolerates is that the starts record size field is 2 bytes larger than the
record (llvm-objdump rejects it as an overlap). ld64 emitted 64-bit imports
(format 3) for the toy executable because one import carries a negative addend.
`parser_unit.py` covers cases no toy produces (bind ordinals above 255, the
signed 19-bit inline addend, the special-ordinal boundary at 0xF0 and 0xFFF0).

## Known limits

- Nothing is executed. No Darling run, no dyld load of the output. The plan's
  "loaded by a toy arm64e test" is therefore met only structurally: the toy test
  decodes and checks the fixups, it does not load the images.
- Authenticated binds are checked structurally (ordinal, import name, addend,
  key, diversity). Their resolution and signing at load time are not tested.
- The toy is freestanding (`-ffreestanding`, no libSystem); stub-dylib linking
  (`--lib`) is exercised only with the toy dylib, not with text-only stubs.
- Only pointer format 1 (`DYLD_CHAINED_PTR_ARM64E`) is accepted; other formats
  and multi-start pages fail loudly.
