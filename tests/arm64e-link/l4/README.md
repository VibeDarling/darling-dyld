# L4 C++ test: an arm64e C++ program on the shared cache's libc++ and libc++abi

Rung L4 of the shared-cache ladder (plan: `shared-cache-m3-l4.md`, Q4). One arm64e executable
(`l4_probe_arm64e`, 3.3a recipe) uses libc++, libc++abi and the unwinder. It runs in three
configurations; the same sources built as plain arm64 are the control, and built natively on the host
they validate the checks themselves. This directory is T4 (sources, stubs, builds, host test). The guest
runs are T5 and are not in this README yet.

```
LD64=/path/to/aarch64-apple-darwin20-ld SDKROOT=/path/to/Darling/MacOSX.sdk \
LIBCXX_INCLUDE=/path/to/darling/src/external/libcxx/include \
  ruby tests/arm64e-link/l4/arm64e-l4-probe.rb          # host test; the native part needs only clang and g++
... python3 -I tests/arm64e-link/l4/build_l4.py build --out DIR          # arm64e, arm64, four stubs
python3 -I tests/arm64e-link/l4/build_l4.py native --out EXE             # the same checks on the host
PROBE_CONFIG=native EXE [list | selftest]                                # host run
DARLING_GUEST_BUILD=... PROBE_DIR=DIR CACHE_DIR=... tests/arm64e-link/l4/run_matrix.sh PREFIX 1 6   # guest boots
python3 -I tests/arm64e-link/abi/tally.py <build>/logs/run-PREFIX*.out  # per (arch/config) table
```

## Files

- `l4_checks.cpp`: the 28 checks, the expectation table, `l4_iface.h` (the harness as C++ sees it).
- `../abi/abi_harness.c`: the driver, reused (one child per check, `OKMARK`, fault handler, 12 s watchdog,
  self-test). It gained the per-configuration expectation grammar and a native branch for this test;
  `../abi/tally.py` gained a config column.
- `build_l4.py`: build, stub generation, structural checks. `../h0/gen_stub.py` (extended:
  `undefined_names`, `exported_names`, `write_symbols`) and `../h0/build_h0.py` (a `libc++` stub entry,
  `check_stub` for plain arm64) are reused. `libcxxabi_exports.txt`: the 369 names of Darling's libc++abi.
- `run_matrix.sh`: guest boots (calls `../abi/run_guest.sh`: shared lock, memory cap, `darling shutdown`).
- `arm64e-l4-probe.rb`: the host test.

## Build

- Headers: Darling's libc++ (LLVM 15.0.7, `_LIBCPP_ABI_NAMESPACE __1`, the tree that built the installed
  `libc++.1.dylib`), `-nostdinc++ -isystem $LIBCXX_INCLUDE`; C headers from the Darling SDK (`-isysroot`).
  The headers are an input (`LIBCXX_INCLUDE`), not copied here. T0 quoted LLVM 13 from an older tree; this one is 15.
- Stubs: the objects are compiled once to read their undefined names. A name is routed to the libSystem
  family when the Darling SDK exports it, to the libc++abi stub when `libcxxabi_exports.txt` lists it, to
  the libc++ stub when it is a C++ mangled name, and anything else stops the build. The stubs
  (`stubs-<arch>/*.linkonly.dylib`, 77 libc++ and 37 libc++abi names for the current sources) have the system
  install names, trap bodies, and are never installed or referenced by build path. Dependencies of the
  executable: libc++.1, libc++abi, libSystem.B (ordinals 1, 2, 3).
- Differences from a consumer built on macOS: such a binary lists libc++.1 and libSystem and binds
  libc++abi names through libc++.1 (which re-exports them); here libc++abi is a direct dependency. Both
  resolve in the cache (its libc++.1 re-exports 384 libc++abi names, T0).
- arm64e link: `-init_offsets`. Without it the main program's static initialisers are an arm64e
  `__mod_init_func` of signed pointers, and Darling's dyld calls those raw (`ImageLoaderMachO.cpp:2318`; the
  `S_INIT_FUNC_OFFSETS` branch is at 2352). The host test refuses an executable without `__init_offsets`.
  The control keeps the default `__mod_init_func`. Whether the guest dyld runs the offsets section of
  the main program is unverified (T5).
- The control is the plain arm64 build with the same flags; `pacibsp` and friends must be absent.

## Configurations and how the verdict is judged

`PROBE_CONFIG` names the configuration of a run; each check carries a table
`c1=..,c2=..,c3=..,native=..` (grammar in `../abi/abi_harness.h`). The driver compares the verdict
(`ok`, `faulted`, `hung`, `failed`) with the entry; no entry for the configuration is a mismatch.
`any` means recorded only. A non-`ok` expectation is printed as `expected_not_ok=`.

| config | build | cache variable | what the table expects |
|---|---|---|---|
| c1 | plain arm64 | unset | everything `ok`, except q1 (`failed`: not served from the cache). Proves the test |
| c2 | arm64e | unset | q1 `failed`; every other check `any`: Darling's own libc++/libc++abi/libunwind with the T1 and T2 changes, the actual result is the finding |
| c3 | arm64e | `DYLD_SHARED_CACHE_SPLIT_DIR` | everything `ok`, except the four `known_ld64_addend` checks (`any`) |
| native | host, libstdc++ | none | as c1 |

q1 prints `FACT served ... image=... in_cache=yes|no cache_base= cache_size=` and fails with "not served from
the shared cache" when the address is outside `_dyld_get_shared_cache_range`. Not served is thus a
recorded fact, never a fault. In c3 it also requires the image to be `/usr/lib/libc++.1.dylib` and
`/usr/lib/libc++abi.dylib`.

## Checks (one child process each)

| # | name | what it proves |
|---|---|---|
| 01 | q1_libcxx_function_served_from_cache | `std::locale::classic` lies inside the cache range; install name printed |
| 02 | q1_cxa_throw_served_from_cache | `__cxa_throw` likewise |
| 03-04 | q2_throw_catch_int, q2_throw_through_nested_frames | throw and catch of an int, through three frames |
| 05-06 | q2_rethrow, q2_catch_all | `throw;` into an outer handler; `catch(...)`, a double, a `const char *` |
| 07 | q2_cleanup_landing_pad | two destructors run in reverse order during unwinding, once each |
| 08 | q2_std_exception_hierarchy | `runtime_error`, `out_of_range` as `logic_error`, `invalid_argument` not as `runtime_error`, `vector::at` throwing inside libc++ |
| 09-10 | q2_exception_through_std_function, q2_exception_in_thread | an exception crossing `std::function`; unwinding on a thread's stack |
| 11-14 | q2_bad_function_call, class_base_catch, class_exact_catch, dynamic_cast, all `_known_ld64_addend` | typeinfo defined in this executable (see below) |
| 15-19 | q3_string_and_vector, map_and_unordered_map, shared_ptr_control_block, ostringstream_and_locale, cout_and_cerr | libc++ objects; locale and stream init; cout line required in the output |
| 20-24 | q4_thread_capturing_lambda, mutex_counter, condition_variable_handoff, call_once_across_threads, thread_local_destructor | threads, locks, `call_once` (also after a throwing first call), a `thread_local` destructor per thread (`_tlv_atexit`) |
| 25-26 | q5_atexit_and_static_destructor, q5_exit_flushes_cout | a static initialiser ran before `main`; atexit handlers in reverse order, then the static object's destructor, whose unflushed cout text must appear in the output; `exit` flushes cout |
| 27-28 | q6_static_local_contention, q6_static_local_init_throws | 16 guarded statics, 8 threads released together, each initialised once and never seen half-built; `__cxa_guard_abort` after a throwing initialiser |

The sources avoid `std::sort` of arithmetic ranges (T0: the `extern template` `__insertion_sort_incomplete`
set is exported by Darling's libc++ but not by the cache's; a binary calling it would not bind against the
cache). The host test checks this.

## The open ld64 defect (checks 11-14)

The in-tree ld64 drops the `+16` vtable address point from authenticated vtable binds
(`../abi/README.md`, item 3, plan R10). Every typeinfo defined in this executable
(`bad_function_call`, `Base`, `Derived`, local lambdas and `std::function` internals) starts with such a
bind. The throw and catch checks use only runtime-defined typeinfo (`std::runtime_error`, `std::exception`,
`int`). The four checks that need the executable's own typeinfo are marked `known_ld64_addend`, expect `ok`
in c1 and native, and `any` in c2 and c3: the verdict is recorded, not hidden. The host test documents the
defect on the built binary (authenticated vtable binds with addend 0). When the recipe is fixed, tighten the
`c3` entry to `ok`.

## Host validation (this branch)

Host test: 81 checks, `ALL PASS`, with LD64, SDKROOT, LIBCXX_INCLUDE, DARLING_USR_LIB and CACHE_EXPORTS_DIR
(the T0 export lists) set; 79 without the last. The native part alone needs only clang and g++.
Native run (libstdc++, aarch64 Linux, no PAC): 26 `ok`, the two q1 checks `failed` as the table says,
`expect_mismatches=0`; with `PROBE_CONFIG=c3` exactly checks 1 and 2 mismatch, with an unknown config all 28.
16 mutation probes, each rebuilt natively and each changing the verdict of exactly the named check:
dropped rethrow (05), a changed value through the frames (04), the cleanup destructor order (07), a
non-caught exception type (08, faulted), a lambda that does not throw (09), `catch(...)` replaced (06,
faulted), a lost capture (20), `call_once` bypassed (23), a thread-local destructor that does not count (24),
a lost atexit registration (25), a static destructor that prints nothing (25, the `need` text), `_Exit` instead
of `exit` (26, the `need` text), a non-static local (27), a first initialisation that does not throw (28), a
cout line not printed (19, the `need` text), and an expectation table that says `faulted` (every `EXP_STD`
check mismatches). Measured against the T0 export lists of the cache (names only): every stub name is
exported by the cache's libc++ and libc++abi respectively.
libc++ is not installed on the host, so the native run uses libstdc++ only.

## What T5 needs

- Build: `build_l4.py build --out DIR` with LD64, SDKROOT, LIBCXX_INCLUDE.
- A private guest build whose dyld has the T2 adapters (`feat/shared-cache-m3-l4-adapters`), the T3
  allow-list entries for `/usr/lib/libc++.1.dylib` and `/usr/lib/libc++abi.dylib`, and the TSD-wired line; a
  libunwind with the T1 change. None of these is in this branch.
- The cache directory (a local copy; the mount maps slowly and every child maps the cache again) holding
  `dyld_shared_cache_arm64e*` and `dyld_shared_cache_arm64e.tsdsites` from `tests/darling-tsd/emit_tsd_sites.py`.
  libc++ and libc++abi have no `mrs TPIDRRO_EL0` sites, but the TSD-wired dyld halts when an image is missing
  from the table, so the table must list both.
- `DYLD_SHARED_CACHE_SPLIT_DIR` set on the test's command inside the guest (`run_matrix.sh` does), never on the
  launcher; `PROBE_CONFIG` per configuration. 28 children per run: if c3 exceeds the 300 s cap of
  `run_guest.sh`, run one config per boot (`L4_CONFIGS=c3`).
- Mutation probes m1-m6 of the plan: the checks that should name them are 02 (m1: no libc++abi in the
  allow-list, so `__cxa_throw` stays on disk), 03-10 (m2, m3: unwinder without the return-address or
  personality strip), 25 and every exit (m4: no `__cxa_atexit` row), 20-24 and 27 (m5: no `pthread_create`
  row), the main program's binds (m6). These are the plan's expectations, not measurements.

## Not verified

Everything that needs the guest: that the executable loads, that Darling's dyld runs the main program's
`__init_offsets`, that `_dyld_get_shared_cache_range` covers libc++ in a split cache, that the c1 control passes on
Darling's libc++ 15 (the plan requires it), and every c2 and c3 verdict. The signed `__tlv_bootstrap` in
the main program's thread-local descriptors (`__thread_vars`, the `thread_local` check) is untested. The native run
uses libstdc++, not libc++. The cache's libc++ may behave differently from LLVM 15 headers in ways the export names do not show.
