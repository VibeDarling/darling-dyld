# L5: serving the cache's arm64e libobjc through dyld2

The L5 exit proof is an arm64e C program that uses the macOS dyld shared cache's libobjc without an
Objective-C compiler, Foundation or AppKit. It declares the runtime entry points itself, casts
`objc_msgSend` per call and links against `/usr/lib/libobjc.A.dylib` from the cache. Darling's plain
arm64 dyld2 must load it and the six dyld4 objc SPIs must answer from the cache.

## Files

- `l5_test.c`: the probe. It reuses `../abi/abi_harness.c` (put, `run_one`'s fork plus 12 s watchdog,
  image capture) with its `main` renamed, and adds the driver, eleven selftests and checks 01-08.
- `l5_decl.h`: the runtime and SPI declarations plus the callback and section-info layouts.
- `l5_imports.txt`: the runtime names (`objc_*`, `class_*`, `object_*`, `sel_*`) the test imports from libobjc. The build fails if the test
  gains an import that is neither an SDK libSystem export nor listed here, or if a listed name goes
  unused, so the stub and the link cannot drift.
- `build_l5.py`: builds the test with `../arm64e_link.py` (the shared arm64e recipe) against a
  link-only stub of libobjc generated from the compiled test's own undefined names, and checks the
  result. `native` builds the same harness on the host.
- `run_l5.sh`: the guest runner for T10, one boot per configuration through `../abi/run_guest.sh`.
- `arm64e-l5-probe.rb`: the host test described below.

## Checks

| # | Prints one OKMARK line proving |
|---|--------------------------------|
| 01 | the image behind `objc_getClass` lies inside the shared cache range (and reports whether a disk copy exists); the driver pairs this with the loader's own `policy=` line for libobjc |
| 02 | `objc_getClass("NSObject")` returns a class whose name and isa (read with `object_getClass`, not a raw load: arm64e isas are signed or packed) are in the cache, and the measured `rw_loaded=` bit count |
| 03 | `objc_allocateClassPair`/`class_createInstance` produce a live instance |
| 04 | `objc_msgSend` answers `-hash` with the object itself and agrees with `isEqual:` |
| 05 | a registered subclass with `class_addMethod` answers 42 and reports NSObject as its superclass |
| 06 | class count 221074, `__objc_classlist` size 0x28, the absent swift5 protos section, `ro`/`rw` non-null, and `_dyld_get_dlopen_image_header` matching the image |
| 07 | libobjc's own callback registration, seen through the loader's log lines (below): one version 4 registration, libobjc reported with `refs_optimized=1` and this disk-served arm64e executable with `refs_optimized=0`, at least one init callback; the child itself proves the executable is outside and libobjc inside the cache range |
| 08 | `object_dispose` on a runtime-created object returns, then the two commpage words libobjc loads (0xd0 and 0xd8) are printed as `d0=`/`d8=`; it asserts neither value (T6 characterises them) |

Check 07 registers nothing: the loader keeps one callback state, so a second registration would replace
libobjc's. The driver reads these loader lines from the child's output (line starts only, `dyld: ` prefix
optional) and the verdict fails without them:

```
dyld: objc register_callbacks version=<n>          once per successful registration
dyld: objc mapped <path> refs_optimized=<0|1>      per image handed to the mapped callback
dyld: objc init <path> refs_optimized=<0|1>        per image handed to the init callback
```

dyld prints these only when `DYLD_PRINT_OBJC_NOTIFICATIONS=1` is set, so `run_l5.sh` sets it on the c3
command inside the guest (never on the launcher); a run without it fails check 07 with that hint. c1 does
not set it: its check 07 fails anyway because libobjc is not cache-served.

The test executable carries an empty `__objc_imageinfo` section (the build asserts it sits in a `__DATA*` segment, which is what dyld2 keys on), so
the loader reports it to the runtime; it is arm64e and disk-served, hence bit 0 beside libobjc's bit 1.
The executable path in the mapped line must equal the child's `dladdr` name (no spaces in it).

Check 02 measures the header-opt rw loaded bits; it does not assume nonzero. On the dyld2 path that
count is expected to be 0 until a libobjc notifier exists, and the check prints what it measured.

## Host proofs

```
python3 -I build_l5.py native --out /tmp/l5_native          # builds the harness on the host
/tmp/l5_native selftest                                     # ok=6 not_ok=5 expect_mismatches=0
python3 -I build_l5.py build --out /tmp/l5_build            # needs LD64 and SDKROOT
python3 -I build_l5.py check /tmp/l5_build/l5_probe [--prefix DIR]
LD64=... SDKROOT=... [PREFIX=...] ruby arm64e-l5-probe.rb
```

`arm64e-l5-probe.rb` proves, without executing Mach-O: the check table lists 01-08 in order and each
prints exactly one OKMARK line and fails before it; the native stubs fail rather than pass; the
selftests cover every verdict class; a wrong expected verdict (`selftest-wrong`) and a wrong expected
hash (`--hash-skew 1`) make the driver exit 1; the built executable is arm64e and the build derives
exactly the listed libobjc imports; the arm64e build hands `sigaction` the compiler-signed fault handler in every config (checked on the compiled assembly: `paciza`, no `xpaci`; a stripped-handler mutation is rejected), and no link-only stub is installed in the prefix, including
one renamed to `libobjc.A.dylib` (the scan finds stubs by structure, not by name).

## Guest run (T10)

```
DARLING_GUEST_BUILD=<build> PROBE_DIR=<build dir of build_l5.py> CACHE_DIR=<split cache> \
  run_l5.sh l5- 1 1
```

The boot runs `c3` (cache variable set, the proof), `c1` (control, no variable: check 01 must fail
and say the image is outside the shared cache range) and the selftests. T10 reads the logs and
expects `c3` to print `SUMMARY ... ok=8 not_ok=0` with eight OKMARK lines; no pass is claimed for
`c1`, only that its 01 line shows the image was not served from the cache. The run ends with
`darling shutdown` (run_guest.sh, which also holds the heavy-step lock and the memory cap).

Everything above is proven on the host. The guest results, including the measured `rw_loaded=` value
and the callbacks' optimized bit, are deferred to T10 because this task must not boot Darling.
