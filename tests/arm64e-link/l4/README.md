# L4 C++ test: an arm64e C++ program on the shared cache's libc++ and libc++abi

Rung L4 of the shared-cache ladder (plan: `shared-cache-m3-l4.md`, Q4). One arm64e executable
(`l4_probe_arm64e`, 3.3a recipe) uses libc++, libc++abi and the unwinder. It runs in three
configurations; the same sources built as plain arm64 are the control, and built natively on the host
they validate the checks themselves. This directory is T4 (sources, stubs, builds, host test); the guest
runs of T5 are in "Measured in the guest" below, separate from the plan's expectations.

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

- `l4_checks.cpp`: the 28 checks, the 8 diagnostics x1..x8 after them, the 2 slot diagnostics y1 and y2, the 8 reverse-adapter checks
  z1..z8, the expectation table, `l4_iface.h` (the harness as C++ sees it, and `L4_SIGN`/`L4_BLEND`, the identity without pointer authentication).
- `l4_plain.c`, `build_plain_dylib.py`: `l4_plain.dylib`, a plain arm64 dylib that binds the cache's `std::set_terminate` and
  `std::get_terminate`; z1..z8 load it with `dlopen` from the directory of the probe executable (build it into the same `--out` directory:
  `python3 -I build_plain_dylib.py build --out DIR/plain; cp DIR/plain/l4_plain.dylib DIR/`).
- `../abi/abi_harness.c`: the driver, reused (one child per check, `OKMARK`, fault handler, 12 s watchdog,
  self-test). It gained the per-configuration expectation grammar and a native branch for this test;
  `../abi/tally.py` gained a config column.
- `build_l4.py`: build, stub generation, structural checks. `../h0/gen_stub.py` (extended:
  `undefined_names`, `exported_names`, `write_symbols`) and `../h0/build_h0.py` (a `libc++` stub entry,
  `check_stub` for plain arm64) are reused. `libcxxabi_exports.txt`: the exact export list of the 369
  names of Darling's libc++abi (the LLVM 15.0.7 build that made the stub list); the host test requires it
  to match the local build's export list exactly and to cover every name the stubs use.
- `run_matrix.sh`: guest boots (calls `../abi/run_guest.sh`: shared lock, memory cap, `darling shutdown`);
  `L4_POLICY=<host file>` sets `DYLD_SHARED_CACHE_SPLIT_POLICY` on the c3 command.
- `arm64e-l4-probe.rb`: the host test.

## Build

- Headers: Darling's libc++ (LLVM 15.0.7, `_LIBCPP_ABI_NAMESPACE __1`, the tree that built the installed
  `libc++.1.dylib`), `-nostdinc++ -isystem $LIBCXX_INCLUDE`; C headers from the Darling SDK (`-isysroot`).
  The headers are an input (`LIBCXX_INCLUDE`), not copied here. T0 quoted LLVM 13 from an older tree; this one is 15.
- Stubs: the objects are compiled once to read their undefined names. A name is routed to the libSystem
  family when the Darling SDK exports it, to the libc++abi stub when `libcxxabi_exports.txt` lists it, to
  the libc++ stub when it is a C++ mangled name, and anything else stops the build. The stubs
  (`stubs-<arch>/*.linkonly.dylib`, 78 libc++ and 39 libc++abi names with the documented headers and
  clang 23.1.4; the counts follow the compiler and header set, and no check pins them) have the system
  install names, trap bodies, and are never installed or referenced by build path. Dependencies of the
  executable: libc++.1, libc++abi, libSystem.B (ordinals 1, 2, 3).
- Differences from a consumer built on macOS: such a binary lists libc++.1 and libSystem and binds
  libc++abi names through libc++.1 (which re-exports them); here libc++abi is a direct dependency. Both
  resolve in the cache (its libc++.1 re-exports 384 libc++abi names, T0).
- arm64e link: `-init_offsets`. Without it the main program's static initialisers are an arm64e
  `__mod_init_func` of signed pointers, and Darling's dyld calls those raw (`ImageLoaderMachO.cpp:2318`; the
  `S_INIT_FUNC_OFFSETS` branch is at 2352). The host test refuses an executable without `__init_offsets`.
  The control keeps the default `__mod_init_func`. In the guest the c3 run's `q5_atexit_and_static_destructor`
  passes (the executable's static initialiser ran before `main`), so its dyld does run the offsets section of
  the main program (see "Measured in the guest").
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
| x1-x8 | x1_get_terminate, x2_set_get_terminate, x3_allocate_free_exception, x4-x7_init_primary_*, x8_get_unexpected_via_dlsym | diagnostics, not in the plan: public runtime API calls that bisect a throw failure; `__cxa_init_primary_exception` is found by `dlsym` with a null, a signed and a stripped destructor and a class typeinfo. Recorded only (`any` everywhere), so they never turn a run into a mismatch |
| y1-y2 | y1_handler_slots, y2_set_signed_terminate_then_init | diagnostics on the cache's `__cxa_terminate_handler` slot, the value that made every c3 throw trap (Darling's libobjc calls `std::set_terminate(&_objc_terminate)` with a plain pointer): y1 prints which key and discriminator the slot authenticates under and the image its target lies in; y2 hands the runtime a compiler-signed handler, then runs `__cxa_init_primary_exception` and a throw. Recorded only |
| z1-z8 | z1_plain_entry_is_signed ... z8_throw_after_plain_set | plain code (`l4_plain.dylib`) calls the cache's `set_terminate`/`get_terminate` through the dyld reverse adapters. z1: a plain function entry is signed IA/0 and the old handler comes back raw. z2-z4: entry + 4, an arm64e address and a data address are stored as they are. z5: a handler that arm64e code installed comes back raw and is signed again when handed back; an arm64e address never handed out is not signed. z6: a corrupted slot stops the process (expected `faulted`, credited only if the child printed its marker before the corrupting call, so an earlier crash is `failed`) instead of handing plain code a stripped pointer. z7: a null handler becomes the default. z8: a throw works after plain code installed its handler. `ok` in c3 (z6 `faulted`), recorded only elsewhere |

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

Host test: 161 checks, `ALL PASS`, with LD64, SDKROOT, LIBCXX_INCLUDE, DARLING_USR_LIB and CACHE_EXPORTS_DIR
(the T0 export lists) set (155 without the two library environments, whose six checks SKIP). The native part needs only clang and g++; the plain dylib is built and checked in the Mach-O part (plain arm64,
no PAC instruction, the two libc++ imports, system install names; a copy with one PAC instruction and the arm64e executable are refused). The native part alone needs only clang and g++.
Native run (libstdc++, aarch64 Linux, no PAC): 36 `ok` (the 26 plan checks, x1..x8, y1 and y2), the two q1 checks and z1..z8 `failed` (the plain Mach-O
dylib cannot be loaded), `expect_mismatches=0`; with `PROBE_CONFIG=c3` exactly checks 1, 2 and z1..z8 mismatch, and a
configuration that only extends a key (`c1x`, `c2x`) or is unknown mismatches on all 46.
The harness's own changes are tested natively on code extracted from or rebuilt out of `../abi/abi_harness.c` and
`run_matrix.sh`, with 34 probes: the handler policy (signed under c2 and c3, stripped everywhere else; 6), the filter for
dyld's adapter warnings (6), the matrix runner's policy variable (5) and its config-to-probe assignment (11: c1 on the plain
control, c2/c3 on the arm64e probe, the cache directory on c3 only and assigned once in the script and once in the generated
command, the executable variables assigned once, both builds in the self-test), and the driver's exit-137, adapter-warning,
required-text, exact-key and hang branches (6). Mutation probes on the checks: 20, each rebuilt natively and each changing the verdict of exactly the named check:
dropped rethrow (05), a changed value through the frames (04), the cleanup destructor order (07), a
non-caught exception type (08, faulted), a lambda that does not throw (09), `catch(...)` replaced (06,
faulted), a lost capture (20), `call_once` bypassed (23), a thread-local destructor that does not count (24),
a lost atexit registration (25), a static destructor that prints nothing (25, the `need` text), `_Exit` instead
of `exit` (26, the `need` text), a non-static local (27), a first initialisation that does not throw (28), a
cout line not printed (19, the `need` text), four diagnostics (x2, x3, x8, y2), and an expectation table that says `faulted`
(every `EXP_STD` check mismatches). Measured against the T0 export lists of the cache (names only): every stub name is
exported by the cache's libc++ and libc++abi respectively.
libc++ is not installed on the host, so the native run uses libstdc++ only.

## Measured in the guest (T5, one private guest build)

Facts from the first guest runs, not the plan's expectations (those are the tables above and "What T5 needs").

Build under test: a dyld with the TSD wiring, the arm64e adapters (`feat/shared-cache-m3-l4-adapters`) and the policy file
(PR #37), plus the libdyld change that signs the TLV thunk of an arm64e image (`feat/dyld-tlv-thunk-signing`); a libunwind with
the T1 changes (PR 4); this test with the harness changes of this branch. The cache is a hard-linked copy of the 13 unmodified
files with the `.tsdsites` sidecar for 3649 images. The policy file names libz, libexpat, libc++.1 and libc++abi, not
libunwind. Every number below is identical in all 6 boots of its configuration; one boot of 19 hung to the 300 s cap with an
empty log and was repeated. Counts are over the 36 checks (28 plan checks and x1..x8); the figure for the plan's 28 follows.

| config | ok | faulted | failed | the 28 plan checks |
|---|---|---|---|---|
| c1 (plain arm64, Darling's libs) | 30 | 0 | 6 | 26 ok, 2 failed (01, 02 as the table says) |
| c2 (arm64e, Darling's libc++ and libc++abi) | 18 | 12 | 6 | 14 ok, 12 faulted, 2 failed (01, 02) |
| c3 (arm64e, cache) | 18 | 18 | 0 | 14 ok, 14 faulted |

- c1: `expect_mismatches=0`. x4-x7 fail because `dlsym` finds no `__cxa_init_primary_exception` in Darling's libc++abi (recorded,
  `any`). The test is proven on the control.
- c2 ok: 03-07, 10, 15, 16, 20-22, 24, 27, 28, x1-x3, x8. c2 faulted: 08, 09, 11-14, 17, 18, 19, 23, 25, 26. Failed: 01, 02, x4-x7.
  Causes of the faults:
  - 08, 09, 19, 25, 26: SIGTRAP at a compiler-emitted `brk #0xc472` in this executable right after `autda` of the vtable pointer
    of an object that Darling's libc++ created (`std::runtime_error`, `ostream`/`cout`, a `std::function` target). Plain libc++
    writes unsigned vtable pointers and the arm64e client authenticates them. pc and `si_addr` carry no PAC bits.
  - 17, 18: SIGSEGV in Darling's libc++ calling a signed pointer into this executable (`si_addr` is an executable address
    with PAC bits): vtable entries of classes defined here (the shared_ptr control block, a locale facet).
  - 23: SIGSEGV with pc at a signed callback of this executable and lr in libc++: `std::__call_once(flag, void*, void(*)(void*))`
    takes a callback and has no adapter row (`__ZNSt3__111__call_onceERVmPvPFvS2_E` is in the adapters' report-mode list).
  - 11-14: SIGSEGV in Darling's libc++abi at a pointer with PAC bits, typeinfo defined in this executable (the ld64 addend defect).
  - 24 faulted before the libdyld change: pc was `tlv_get_addr` with PAC error bits, because libdyld stored the thunk unsigned and
    an arm64e image calls it with `blraaz`. With the change it is ok. Without it c2 was 13 ok and 13 faulted of the 28.
- c3: checks 01 and 02 pass: `std::locale::classic` at `0x1804108c4` in `/usr/lib/libc++.1.dylib` and `__cxa_throw` at `0x1804a2040` in
  `/usr/lib/libc++abi.dylib`, both inside the cache range (base `0x180000000`, size `0x166464000`). Passing: 01, 02, 15-22, 24-27,
  x1-x3, x8 (strings, containers, shared_ptr, streams, cout, threads, thread_local destructor, atexit, exit flush and guard
  contention on the cache's libc++). Faulted: 03-14, 23, 28, x4-x7.
  - Every faulted check except 14 (and the known 11-13) is one failure: SIGTRAP (`TRAP_BRKPT`, `si_addr` = pc, no PAC bits) at
    `/usr/lib/libc++abi.dylib` + `0x15a5c`, lr + `0x15a3c`. The nearest export at or below that offset in the cache image's export
    trie (an interface fact) is `___cxa_init_primary_exception` (`0x159d4`, next export `0x15b50`), called by `__cxa_throw`.
  - x1-x8 bisect it with public API only: `std::get_terminate`, `std::set_terminate`, `get_unexpected` (by `dlsym`),
    `__cxa_allocate_exception` and `__cxa_free_exception` work. Calling `__cxa_init_primary_exception(obj, &typeid(int), nullptr)`
    directly traps at the same pc whether the destructor is null, signed or stripped and whether the typeinfo is `int` or
    `std::runtime_error` (x4-x7). The trap does not depend on any argument the test controls.
  - Check 14 faults differently: SIGSEGV at a pointer with PAC bits, pc at libc++abi + `0x143f8`.
  - Before the libdyld change every c3 throw faulted at `tlv_get_addr`, reached from libc++abi + `0x20b8` (the exception
    globals' thread-local).
  - Understanding the `0x15a5c` trap needs the cache's implementation: it was not investigated, and is a decision for the owner.
  - dyld printed `split cache GOT override: patched=6425 missing=1431 unexplained=90` and about 96 "arm64e adapters: X is imported by
    an arm64e image and has no adapter" warnings per child (malloc zones, block sorts, dispatch, xpc, corecrypto callbacks, `__Block_*`;
    the test uses none of them). The driver drops those lines (`ADAPTER-WARNINGS-DROPPED n`).
- With the unmodified harness (handler stripped) every c2 and c3 fault died as a plain SIGSEGV or exit 137 with no report, because
  the adapters poison a code pointer that does not authenticate. Nothing is logged when dyld poisons a pointer.

Mutation probes m1-m6 of the plan, each in a rebuilt dyld or libunwind, one at a time (the checks that changed against the
baselines above; one guest child per check, because a driver run of several mutants died with no output):

| probe | change | config | checks that changed |
|---|---|---|---|
| m1 | policy without libc++abi | c3 | 02 failed; collateral: 15 and 20 abort (SIGABRT) with the cache's libc++ over Darling's libc++abi |
| m2 | libunwind without return-address authentication | c2 | 03, 04, 05, 07, 10, 28 abort with "terminating with uncaught exception"; 06 stays ok (same-frame catch) |
| m3 | libunwind without personality authentication | c2 | 03-07, 10, 28 SIGSEGV at the signed personality |
| m4 | no `___cxa_atexit` row | c2, c3 | every check faults (exit 70): the executable's startup registers destructors through it |
| m5 | no `_pthread_create` row | c2, c3 | new faults: 20, 21, 22, 24, 27 (and 10 in c2) |
| m6 | adapter hook off for the main program's binds | c2, c3 | every child dies of SIGSEGV with no report |

## Measured with the reverse adapters (c3, private guest build)

Why every c3 throw trapped: Darling's libobjc calls `std::set_terminate(&_objc_terminate)` at init in every guest process. With the cache
serving libc++abi that lands in the cache's arm64e `std::set_terminate`, which stores the pointer it is given; `__cxa_init_primary_exception`
then authenticates it (IA, discriminator 0), fails and traps (`brk #0xc470`, the compiler's trap for a failed IA authentication). y1 shows the
slot holding the unsigned address of `_objc_terminate`; y2 shows that a compiler-signed handler makes the same call pass. The adapters of
`feat/shared-cache-m3-l4-adapters` only cover an arm64e importer binding a plain exporter; the opposite direction (a plain importer binding an
export of an arm64e image) is `feat/l4-reverse-adapters`.

Build under test: the TSD-wired dyld line, the adapters with the reverse direction, the policy file (PR #37) and the libdyld change that signs
the TLV thunk, as in the T5 build; libunwind PR 4 plus the commit that authenticates the landing pad an arm64e personality passes to
`_Unwind_SetIP` (IB key, modifier SP of the resumed frame), without which the cache's personality hands a signed landing pad to a plain unwinder
that installs it raw. Cache, policy and boot method as in T5, one full c3 boot per run (46 children, about 25 s). The 46 checks:

| build | boots | ok | faulted | failed | checks that are not ok |
|---|---|---|---|---|---|
| reverse adapters, libunwind with the landing-pad commit | 8, identical | 40 | 6 | 0 | 11-14 (ld64 addend), x6 (a stripped destructor handed to `__cxa_init_primary_exception`: the arm64e callee still demands a signed one), z6 (by design) |
| control: the adapters of `feat/shared-cache-m3-l4-adapters` alone, same libunwind | 3 | 23-25 | 17-19 | 4 | every throw: 03-14, 23, 28 (28 and x5 passed in one boot, not investigated), x4-x7, z8; y2 passes (a compiler-signed handler); z1, z5, z6, z7 fail and z2-z4 pass, since nothing is signed |
| reverse adapters, libunwind PR 4 without the landing-pad commit | 2, identical | 28 | 18 | 0 | every throw check faults at the signed landing pad: 03-14, 23, 28, y2, z8, plus x6 and z6 |

The control has the T5 failure (`__cxa_init_primary_exception` trap) in every check that throws. With the reverse adapters the 28 plan checks
are 24 ok and 4 faulted (11-14, the ld64 addend defect, unchanged), in 8 of 8 boots; z1-z5, z7 and z8 are ok and z6 stops the process, in the same boots.

Mutants of the dyld change, one rebuild each, one boot each, checks that changed from the 40 ok / 6 faulted baseline:

| mutant | rule | changed |
|---|---|---|
| arm64e check removed from the entry predicate | an address in an arm64e image is never signed | z3 failed |
| function-starts match removed | only a function entry is signed | z2 failed |
| authenticate replaced by strip on the result | never strip without authenticating | z6 failed (plain code was handed a bad pointer instead of stopping) |
| failed authentication ignored | a handler that does not authenticate stops the process | z6 failed |
| authenticate with a wrong modifier | IA with discriminator 0 | no verdict: the probe driver itself dies of SIGTRAP (exit 133) when libobjc calls `set_terminate` |
| signing skipped | signed IA/0 | z1 faulted and z2-z8 changed, with every throw |
| entry check removed | predicate or round trip | z2, z3, z4, z5 failed |
| round-trip ring accepts any value | only a handler handed back is signed again | z2, z3, z4, z5 failed |
| hook of the chained fixups removed | a plain dylib's binds | z1, z5, z6, z7 failed, z8 faulted; the throws still pass |
| hook of the dyld-info binds removed | libobjc's bind | every throw faults, as in the control |
| executable-segment check removed | defence in depth | nothing changed: the function-starts check already refuses a data address |
| shared-cache check removed | defence in depth | nothing changed: the cache images are arm64e |

The last two are equivalent on this cache. z6's message in a single child names the symbol (`__ZSt13get_terminatev returned a handler that does
not authenticate (IA, discriminator 0)`); the driver counts it with the other adapter warnings (97 instead of 96). Boots: 18 first boots in a
row after the dyld, libunwind and libdyld binaries of the private prefix were replaced died within seconds with no output (`mldr` SIGABRT in the
shell, exit 134) until two trivial boots had run, and later boots shortly after a rebuild did the same; none of them ran the test.

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
  row), the main program's binds (m6). These are the plan's expectations; the measurements are above.

## Not verified

The guest runs above measured that the executable loads, that the c1 control passes on Darling's libc++, that
`_dyld_get_shared_cache_range` covers libc++ and libc++abi in a split cache, and every c2 and c3 verdict. The cause of the c3 trap in the cache's `__cxa_init_primary_exception` (every c3 throw) is the unsigned handler that Darling's libobjc
stores through `std::set_terminate` (see "Measured with the reverse adapters"). Still open: the four `known_ld64_addend` checks; plain
C++ code that throws or creates objects with vtables that cross into the cache's libc++abi and libc++ (plain vtables and typeinfo are
unsigned, which a register thunk cannot fix); `dlsym` by plain code of a cache export (returns the raw address); the other 22 rows of the
reverse table, which no guest check drives (only `set_terminate` and `get_terminate` are driven, by z1-z8, and `set_terminate` by libobjc in
every boot). The `thread_local` check depended on the libdyld thunk signing. The native run
uses libstdc++, not libc++. The cache's libc++ may behave differently from LLVM 15 headers in ways the export names do not show.
