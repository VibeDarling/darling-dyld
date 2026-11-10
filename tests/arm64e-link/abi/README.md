# ABI probe: signed pointers from an arm64e executable into Darling's plain-arm64 libs

Rung L2 of the shared-cache ladder. No shared cache is involved. One arm64e executable
(`abi_probe_arm64e`, built with the 3.3a recipe) hands PAC-signed pointers to Darling's plain
arm64 libSystem family, libc++abi and libunwind, and reports for each of 16 numbered checks
whether the callee could use them. The same sources built as plain arm64 are the control. The
result decides whether cache-served arm64e libraries can run on Darling's libs with per-API
adapters (ADAPTER) or need arm64e rebuilds of those libs (REBUILD).

```
LD64=/path/to/aarch64-apple-darwin20-ld SDKROOT=/path/to/Darling/MacOSX.sdk \
  ruby tests/arm64e-link/abi/arm64e-abi-probe.rb            # host test, SKIP without both
LD64=... SDKROOT=... python3 -I tests/arm64e-link/abi/build_abi.py build --out DIR
<guest> DIR/abi_probe_arm64e [mutate | selftest | list]      # in a private Darling prefix
python3 -I tests/arm64e-link/abi/symbolize_faults.py GUEST-LOG   # names the function behind pc/lr
```

The link-only `libc++abi.*.linkonly.dylib` stubs are never installed (see `../h0/README.md`).

## Files

- `abi_decl.h`: local declarations (the Darling SDK header symlinks do not resolve outside its build tree).
- `abi_harness.[ch]`: output, fault handler, driver, self-test. `abi_checks.c`: the 16 checks. `abi_cxx.cpp`: the C++ ones.
- `build_abi.py`: builds `abi_probe_arm64e`, `abi_probe_arm64` (control) and three arm64e variants, then checks their structure.
- `arm64e-abi-probe.rb`, `symbolize_faults.py`, `libcxxabi_symbols.txt`.

## How a check is judged

The driver forks and execs itself once per check (`run N`), reads the child's output through a
pipe and applies a 12 second watchdog (SIGKILL, verdict `hung`). Verdicts: `ok` (exit 0 and the
child printed `OKMARK N`), `faulted` (fault handler exit 70, or killed by a signal), `hung`,
`failed` (ran, wrong result). The child's handler prints signal, `si_code`, `si_addr`, `pc`, `lr`,
the pointer handed over (`orig`, `handed`, `orig_signed`, `handed_signed`) and whether `si_addr`
and `pc` carry PAC bits, and names the image that `pc` and `lr` lie in. The handler itself is
installed with its signature stripped (the harness is not the subject). `selftest` runs six
deliberate children (ok, fault in the main thread, in a thread, in a TSD destructor at thread
exit, hang, failed): all four verdict classes come out as expected, with one limit: a fault in a
TSD destructor at thread exit is a SIGSEGV kill with no handler output (check 03 is judged by its
`HAND` line and the signal).

PAC collision: a signed pointer whose PAC field is all zero is a valid plain pointer (7 PAC bits,
about 1 in 128 per signing). An `ok` of the arm64e build on such a pointer is flagged
`pac_field_was_zero=yes` and is not a pass. The personality slot cannot be inspected, so a rare
`ok` of a C++ check in a signed build may be a collision too; the tables count runs.

## Variants (the mutation probes)

- `mutate` mode (checks 01-10): every pointer is stripped with `xpaci` immediately before it is handed over.
- `noret`: compiled with `-fno-ptrauth-returns`: return addresses are plain.
- `noret_unsigned`: `noret` plus every authenticated bind outside `__auth_got` rewritten as a plain bind to the same import (the personality GOT slot and the typeinfo vtable pointers). The `__auth_got` entries stay signed because the call stubs authenticate them.
- `nosign`: `noret_unsigned` plus `-fno-ptrauth-calls` (function pointers, vtable pointers, destructor pointers).
- control: plain arm64, no PAC instruction in the file (checked by the build script).

## Results

Guest: the private Darling build (`superproject b456e0f1b`, dyld `a5ac1eb`), host Apple M1 under
Asahi Linux (PAuth present, no FPAC: a failed authentication does not trap by itself). Six
independent boots, each running every configuration once (96 checks per boot over six
configurations, plus the self-test). 6 of 6 boots completed; no boot or shellspawn failure. Twelve earlier boots of
the same sources (a monolithic build and the 15-check build) gave the same table apart from
collisions. Cells are
counts over the six boots; `ok` in a signed column is explained below.

| # | check | control (arm64) | arm64e | arm64e, mutate | noret | noret_unsigned | nosign |
|---|---|---|---|---|---|---|---|
| 01 | atexit | 6 ok | 1 ok, 5 faulted | 6 ok | 6 faulted | 6 faulted | 6 ok |
| 02 | cxa_atexit | 6 ok | 6 faulted | 6 ok | 6 faulted | 6 faulted | 6 ok |
| 03 | pthread_key_destructor | 6 ok | 6 faulted | 6 ok | 6 faulted | 6 faulted | 6 ok |
| 04 | pthread_create_start | 6 ok | 6 faulted | 6 ok | 6 faulted | 6 faulted | 6 ok |
| 05 | pthread_once | 6 ok | 6 faulted | 6 ok | 6 faulted | 6 faulted | 6 ok |
| 06 | qsort_comparator | 6 ok | 6 faulted | 6 ok | 6 faulted | 6 faulted | 6 ok |
| 07 | dispatch_async_stack_block | 6 ok | 6 faulted | 6 ok | 6 faulted | 6 faulted | 6 ok |
| 08 | dispatch_async_global_block | 6 ok | 6 faulted | 6 ok | 6 faulted | 6 faulted | 6 ok |
| 09 | dispatch_once_block | 6 ok | 6 faulted | 6 ok | 6 faulted | 6 faulted | 6 ok |
| 10 | dyld_add_image_callback | 6 ok | 6 faulted | 6 ok | 6 faulted | 6 faulted | 6 ok |
| 11 | cxx_throw_catch_same_frame | 6 ok | 6 faulted | 6 faulted | 6 faulted | 6 ok | 6 ok |
| 12 | cxx_throw_through_callee_frame | 6 ok | 6 faulted | 6 faulted | 1 ok, 5 faulted | 6 ok | 6 ok |
| 13 | cxx_throw_class_base_catch | 6 ok | 6 faulted | 6 faulted | 6 faulted | 6 faulted | 6 ok |
| 14 | cxx_cleanup_landing_pad | 6 ok | 6 faulted | 6 faulted | 6 faulted | 6 ok | 6 ok |
| 15 | libunwind_walk_signed_frames (diagnostic) | 6 ok | 6 failed | 6 failed | 6 ok | 6 ok | 6 ok |
| 16 | dlsym_result_called_by_arm64e (reverse direction) | 6 ok | 6 ok | 6 ok | 6 ok | 6 ok | 6 faulted |

- The two lone `ok` cells in the arm64e columns are PAC collisions. In check 01 the harness saw
  `pac_field_was_zero=yes`. In check 12 (`noret`) the pointer in question is the personality slot,
  which the harness cannot inspect; one in 16 cells fits the 1 in 128 rate per signed pointer.
- Mutate mode only touches checks 01-10 (and re-signs in 16); it cannot change the C++ checks, which
  have no source-level pointer. Their mutation probes are the three build variants.
- `nosign` signs nothing, so its check 16 faults: Darling's `dlsym` signs its result for an arm64e
  caller (below) and a non-PAC caller then branches to a signed address. That cell is an artefact.
- Failure modes: every fault in 01, 02, 04-10 is `SIGSEGV`, `si_code` 1 (SEGV_MAPERR), `si_addr` equal
  to `pc` equal to the signed pointer handed over, PAC bits set in both, `esr` not reported by Darling.
  Check 03 is killed by SIGSEGV with no handler output (the self-test shows the same for any fault in
  a TSD destructor at thread exit). 11, 12, 14: SIGABRT after `libc++abi: terminating with uncaught
  exception of type int`. 13: SIGSEGV on a data address with PAC bits, in `__dynamic_cast`.

## Reading the failures

Function that took the signed pointer (from `symbolize_faults.py`, `lr` of the fault; `pc` is the
signed pointer with its signature stripped, i.e. the first instruction of the probe's callback):

| check | Darling callee |
|---|---|
| 01, 02 | libsystem_c `__cxa_finalize_ranges` (runs the atexit list) |
| 04 | libsystem_pthread `_pthread_start` |
| 05 | libsystem_pthread `__pthread_once_handler` |
| 06 | libsystem_c `med3` (qsort) |
| 07, 08 | libdispatch `_dispatch_call_block_and_release` (calls the block's `invoke`) |
| 09 | libdispatch `_dispatch_client_callout` |
| 10 | Darling's dyld, outside the image list (add-image notification) |
| 13 | libc++abi `__dynamic_cast`, from `__class_type_info::can_catch` |

Strip the signature and 01-10 pass in all six boots (`mutate`): the signature is the only
obstacle, a plain `blr` to the unsigned address of arm64e code works, and the arm64e callback
returns through its own `retab` into plain code. Check 07 shows `Block_copy` of a stack block with a
signed `invoke` in Darling's libclosure did not fault by itself; the fault is the call.

C++ (11, 12, 14 throw an `int`; 13 throws a class). Four independent defects, each isolated by one variant:

1. Return addresses. With signed return addresses, `libunwind`'s `unw_step` (check 15) reports the
   end of the stack after the first frame (`frames=1`), so no handler is found and
   `std::terminate` runs. With `noret` the same walk sees six frames, `ip_signed=no`, unwind info
   found for every frame (`frames=6`).
2. Personality pointer. With `noret`, 11, 12, 14 fault in libunwind `_unwind_phase1` calling
   `__gxx_personality_v0` through a pointer with PAC bits (the GOT slot is an authenticated bind: key
   IA, address diversity, diversity 0, in `__DATA_CONST,__got`). Unsigning that slot and the
   typeinfo vtable pointers (`noret_unsigned`) makes 11, 12, 14 pass in all six boots.
3. Exception object. With `noret_unsigned`, 13 still faults, in libc++abi `__dynamic_cast` (inferred:
   the read of the thrown object's vtable pointer, which the arm64e constructor signs at run time and
   Darling's plain libc++abi reads unauthenticated). The typeinfo's own vtable pointer (an
   authenticated bind to the libc++abi vtable, DA, discriminator 0; unsigned in `noret_unsigned`) and the
   `__cxa_throw` destructor pointer are in the same class. `nosign` passes 13, so the cause is a
   compiler-signed pointer; the exact one was not isolated further.
4. `nosign` (no signed returns, binds or function/vtable pointers) passes all 15.

Reverse direction (16): a function pointer that Darling's `dlsym` returns to arm64e code already
arrives signed (`orig_signed=yes`, IA) and the call works in all six boots, so the dyld side
signs for arm64e callers today. The same call faults when the signature is missing (the `nosign` cell
shows the converse: a signed pointer reaching a caller that does not authenticate).

## Recommendation

Evidence in favour of each side.

ADAPTER, for every API that takes a callback and only calls it from plain code (checks 01-10): the
strip-at-entry mutation passes 60 of 60 runs, and the failing point is always the plain callee's
unauthenticated `blr` on a pointer carrying a signature. An adapter is one `xpaci` (a
`ptrauth_strip` of the argument) at the entry of each such export of libsystem_c, libsystem_pthread,
libdispatch and Darling's dyld. Measured earlier: the callback-taking exports imported by cache
images number 2 (libc++ pair), 12 (libobjc + libc++), 54 (Foundation set), 56 (AppKit), 60
(Notes closure). The set is mechanical and grows with the closure, and it must cover pointers hidden in structs and
objects (`sigaction`, `pthread_attr`, dispatch sources), which this probe did not exercise.

REBUILD (or a PAC-aware patch), for libunwind: no API boundary carries the signed values; they sit in
stack frames (return addresses) and unwind tables (personality), so no per-API adapter can reach
them. Checks 11, 12, 14 and 15 fail on the return address alone and then on the personality
pointer. That is one small library (strip the return address when stepping, authenticate or strip the
personality pointer), not the libSystem family. Check 13's remaining defects are in the plain
libc++abi; in the cache plan libc++abi and libc++ come from the cache as arm64e, so they would
not exist there (not verified here: this probe used Darling's plain libc++abi).

Verdict: hybrid. Adapters for the libSystem-family callbacks plus a PAC-aware libunwind. Nothing in
the evidence requires an arm64e rebuild of libsystem_c, libsystem_pthread, libdispatch or
libsystem_kernel for the callback class. Blocks need one more step than stripping (below).

## Not verified

- Blocks: only the plain callee's call of `invoke` was tested. arm64e code calling a block that
  plain libclosure copied (`Block_copy` moves the literal; `invoke` is address-diversified) was not.
  Stripping fixes the plain call but leaves a block that arm64e code cannot call, so a block
  adapter must re-sign on copy.
- Other callback carriers: `sigaction` handlers, dispatch sources and groups, `qsort_b`, `atexit_b`,
  `pthread_cleanup_push`, `signal` return values, ObjC IMPs, and DA/IB-signed data pointers. Only IA
  discriminator 0 function pointers and IA address-diversified block invokes were handed over.
- The cache's arm64e libc++abi and libc++ with Darling's libunwind (L4): this probe used Darling's
  plain libc++abi for 11-14.
- The fault location of check 03 (the handler does not run at thread exit); the signal and the
  `HAND` line show it is the destructor pointer, and the strip mutation passes.
- Compiler: upstream clang 23 with its arm64e defaults and the 3.3a caps-byte rule, not Apple's;
  the ABI version bits it would stamp are cleared by the recipe. Hardware: one M1 host, no FPAC.
- Collisions: a signed pointer has a 1 in 128 chance of a zero PAC field, so a lone `ok` among
  faults in a signed column needs `pac_field_was_zero` or another run, not a rule change.
