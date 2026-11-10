# ABI probe: signed pointers from an arm64e executable into Darling's plain-arm64 libs

Rung L2 of the shared-cache ladder. No shared cache is involved. One arm64e executable
(`abi_probe_arm64e`, built with the 3.3a recipe) hands PAC-signed pointers to Darling's plain
arm64 libSystem family, libc++abi and libunwind, and reports for each of 20 numbered checks
whether the callee could use them. The same sources built as plain arm64 are the control. The
result decides whether cache-served arm64e libraries can run on Darling's libs with per-API
adapters (ADAPTER) or need arm64e rebuilds of those libs (REBUILD).

```
LD64=/path/to/aarch64-apple-darwin20-ld SDKROOT=/path/to/Darling/MacOSX.sdk \
  ruby tests/arm64e-link/abi/arm64e-abi-probe.rb            # host test, SKIP without both
LD64=... SDKROOT=... python3 -I tests/arm64e-link/abi/build_abi.py build --out DIR
<guest> DIR/abi_probe_arm64e [mutate | selftest | list]      # in a private Darling prefix
DARLING_GUEST_BUILD=... PROBE_DIR=DIR tests/arm64e-link/abi/run_matrix.sh PREFIX 1 6   # 6 boots, every variant
python3 -I tests/arm64e-link/abi/tally.py <build>/logs/run-PREFIX*.out
python3 -I tests/arm64e-link/abi/symbolize_faults.py GUEST-LOG   # names the function behind pc/lr
```

The link-only `libc++abi.*.linkonly.dylib` stubs are never installed (see `../h0/README.md`).

## Files

- `abi_decl.h`: local declarations (the Darling SDK header symlinks do not resolve outside its build tree).
- `abi_harness.[ch]`: output, fault handler, driver, self-test. `abi_checks.c`: the 20 checks. `abi_cxx.cpp`: the C++ ones.
- `build_abi.py`: builds `abi_probe_arm64e`, `abi_probe_arm64` (control) and four arm64e variants, then checks their structure.
- `run_guest.sh`, `run_matrix.sh`, `tally.py`: the guest runner (shared lock, memory cap) and the per-variant tally.
- `arm64e-abi-probe.rb`, `symbolize_faults.py`, `libcxxabi_symbols.txt`.

## How a check is judged

The driver forks and execs itself once per check (`run N`), reads the child's output through a
pipe and applies a 12 second watchdog (SIGKILL, verdict `hung`). Verdicts: `ok` (exit 0 and the
child printed `OKMARK N`), `faulted` (fault handler exit 70, or killed by a signal), `hung`,
`failed` (ran, wrong result). The child's handler prints signal, `si_code`, `si_addr`, `pc`, `lr`,
the pointer handed over (`orig`, `handed`, `orig_signed`, `handed_signed`) and whether `si_addr`
and `pc` carry PAC bits, and names the image that `pc` and `lr` lie in. The handler itself is
installed with its signature stripped (the harness is not the subject), except when `PROBE_CONFIG` is
`c2` or `c3` (the L4 test under the dyld adapters, which poison a stripped code pointer): there it is the
compiler-signed pointer, and so are the thread callbacks and the destructor of the self-test. `selftest` runs eleven
deliberate children, each with an expected verdict that the driver compares in code
(`EXPECT-MISMATCH`, `expect_mismatches=`, exit status 1): ok, fault in the main thread, in a thread,
in a TSD destructor at thread exit, hang, failed, exit 0 without `OKMARK` (must be `failed`),
exit 137 (must be `faulted`), a line shaped like dyld's adapter warning (must be dropped and counted),
`hand()` returns the right pointer and the strip/sign round trip. It runs plain and under `mutate`.
A check whose expectation names `faulted` and carries `;need=TEXT` is credited only when the child
printed TEXT: a death before that point is `failed`, so a fault in the wrong place cannot satisfy the
expectation (L4's z6 relies on this). The `needstop` set checks that rule (a death before the text is
`failed`, a death after it stays `faulted`, a hang stays `hung`) and is expected to exit 1 with two
mismatches; the `selftest` and a configured `checks` run expect none.
One limit: a fault in a TSD destructor at thread exit is a SIGSEGV kill with no handler output
(check 03 is judged by its `HAND` line and the signal). Exit status above 128 (Darling's
signal-trampoline death, check 18: 137) counts as `faulted`. A child that writes more than the
driver's buffer is drained and flagged `output_truncated=yes`, not killed by SIGPIPE.

PAC collision: a signed pointer whose PAC field is all zero is a valid plain pointer (7 PAC bits,
about 1 in 128 per signing). An `ok` on a pointer the compiler signed (`HAND ... expect_signed=yes
orig_signed=no`) is flagged `pac_field_was_zero=yes` and is not a pass; the flag cannot fire in a
build that signs nothing (`nosign`, the control). The personality slot cannot be inspected, so a
rare `ok` of a C++ check in a signed build may be a collision too; the tables count runs.

## Variants (the mutation probes)

- `noret`: compiled with `-fno-ptrauth-returns`: return addresses are plain.
- `noret_unsigned`: `noret` plus every authenticated bind outside `__auth_got` rewritten as a plain bind to the same import (the personality GOT slot and the typeinfo vtable pointers). The `__auth_got` entries stay signed because the call stubs authenticate them. The rewrite keeps no addend (ld64 had already dropped it).
- `noret_unsigned_addend`: `noret_unsigned` plus the `+16` vtable address point put back on the typeinfo vtable binds (below).
- `nosign`: `noret_unsigned` plus `-fno-ptrauth-calls` (function pointers, vtable pointers, destructor pointers).
- `mutate` mode hands the pointer in the form an adapter would: stripped (01-10, 18, and 20's destructor pointer), re-signed for the block copy (17) and for the handler `signal` returns (19); in 16 it strips what Darling's dyld signed (the call must fault).
- control: plain arm64, no PAC instruction in the file (checked by the build script).

## Checks 21-32: unwinder pointer authentication

Added for the PAC-aware Darling libunwind (VibeDarling/darling-libunwind). They exercise libunwind with
function pointers and frames the arm64e executable signs, and corrupt the signature to show that the
unwinder authenticates instead of stripping. Expected results are for a libunwind that authenticates;
against the unmodified one, 29 fails, 30 faults and 32 is `ok` (the unsigned return address resumes).

| # | check | what it does | arm64e expectation |
|---|---|---|---|
| 21 | x_unwind_delete_exception_cleanup | `_Unwind_DeleteException` on an exception whose `exception_cleanup` the compiler signed (IA, discriminator 0) | ok |
| 22 | x_unwind_backtrace_callback | `_Unwind_Backtrace` with a signed trace function | ok |
| 23 | x_unwind_forced_stop_callback | `_Unwind_ForcedUnwind` with a signed stop function | ok |
| 24 | neg_corrupt_return_address | flip a PAC bit in the saved lr of the throwing frame, then throw | faulted (terminate) |
| 25-27 | neg_corrupt_* | flip a PAC bit in the cleanup, trace or stop pointer | faulted |
| 28 | neg_corrupt_personality_slot | flip a PAC bit in the personality GOT slot (found through `__unwind_info`), then throw | faulted |
| 29 | dwarf_frame_walk | walk through a hand-written frame forced into DWARF unwind mode (`.cfi_escape`), saved lr signed with pacibsp and no negate_ra_state CFI, as Apple's compilers emit for Mach-O | ok |
| 30 | dwarf_frame_throw_catch | C++ throw and catch through that frame | ok |
| 31 | neg_dwarf_frame_flip_pac_bit | same, saved lr with a PAC bit flipped | faulted |
| 32 | neg_dwarf_frame_unsigned_lr | same, saved lr overwritten with the raw unsigned address (1 in 128 per boot: the correct signature may be zero) | faulted |

The negative checks mean nothing in the plain-arm64 control (it has no signatures; a flipped bit just corrupts
the pointer) and in the `noret*` variants (an arm64e image with unsigned return addresses, which libunwind
no longer walks). Read them in the `arm64e` column. A strip in place of the authentication makes 24-27, 28,
31 and 32 `ok`.

## Results

Guest: the private Darling build (superproject `b456e0f1b`, dyld `a5ac1eb`), host Apple M1 under
Asahi Linux (PAuth present, no FPAC: a failed authentication does not trap by itself). Six
independent boots, each running every configuration once, plus the self-test (plain and under
`mutate`) for the arm64e probe and the control: 6 of 6 boots completed, no boot or shellspawn
failure, 0 `EXPECT-MISMATCH` in 162 self-test children. Cells are counts over the six boots.

| # | check | control | arm64e | arm64e mutate | noret | noret_unsigned | +addend | +addend mutate | nosign |
|---|---|---|---|---|---|---|---|---|---|
| 01 | atexit | 6 ok | 6 faulted | 6 ok | 6 faulted | 6 faulted | 6 faulted | 6 ok | 6 ok |
| 02 | cxa_atexit | 6 ok | 6 faulted | 6 ok | 6 faulted | 6 faulted | 6 faulted | 6 ok | 6 ok |
| 03 | pthread_key_destructor | 6 ok | 6 faulted | 6 ok | 6 faulted | 6 faulted | 6 faulted | 6 ok | 6 ok |
| 04 | pthread_create_start | 6 ok | 6 faulted | 6 ok | 6 faulted | 1 ok, 5 faulted | 6 faulted | 6 ok | 6 ok |
| 05 | pthread_once | 6 ok | 6 faulted | 6 ok | 6 faulted | 6 faulted | 6 faulted | 6 ok | 6 ok |
| 06 | qsort_comparator | 6 ok | 6 faulted | 6 ok | 6 faulted | 6 faulted | 6 faulted | 6 ok | 6 ok |
| 07 | dispatch_async_stack_block | 6 ok | 1 ok, 5 faulted | 6 ok | 6 faulted | 6 faulted | 1 ok, 5 faulted | 6 ok | 6 ok |
| 08 | dispatch_async_global_block | 6 ok | 6 faulted | 6 ok | 6 faulted | 6 faulted | 6 faulted | 6 ok | 6 ok |
| 09 | dispatch_once_block | 6 ok | 6 faulted | 6 ok | 6 faulted | 6 faulted | 6 faulted | 6 ok | 6 ok |
| 10 | dyld_add_image_callback | 6 ok | 6 faulted | 6 ok | 6 faulted | 6 faulted | 6 faulted | 6 ok | 6 ok |
| 11 | cxx_throw_catch_same_frame | 6 ok | 6 faulted | 6 faulted | 6 faulted | 6 ok | 6 ok | 6 ok | 6 ok |
| 12 | cxx_throw_through_callee_frame | 6 ok | 6 faulted | 6 faulted | 6 faulted | 6 ok | 6 ok | 6 ok | 6 ok |
| 13 | cxx_throw_class_base_catch | 6 ok | 6 faulted | 6 faulted | 6 faulted | 6 faulted | 6 faulted | 6 faulted | 6 ok |
| 14 | cxx_cleanup_landing_pad | 6 ok | 6 faulted | 6 faulted | 6 faulted | 6 ok | 6 ok | 6 ok | 6 ok |
| 15 | libunwind_walk_signed_frames | 6 ok | 6 failed | 6 failed | 6 ok | 6 ok | 6 ok | 6 ok | 6 ok |
| 16 | dlsym_result_called_by_arm64e | 6 ok | 6 ok | 6 faulted | 6 ok | 6 ok | 6 ok | 6 faulted | 6 faulted |
| 17 | block_copy_then_called_by_arm64e | 6 ok | 6 faulted | 6 ok | 6 faulted | 6 faulted | 6 faulted | 6 ok | 6 ok |
| 18 | sigaction_handler_in_struct | 6 ok | 6 faulted | 6 ok | 6 faulted | 6 faulted | 6 faulted | 6 ok | 6 ok |
| 19 | signal_return_value_called_by_arm64e | 6 ok | 6 faulted | 6 ok | 6 faulted | 6 faulted | 6 faulted | 6 ok | 6 ok |
| 20 | cxx_class_throw_manual_dtor_pointer | 6 ok | 6 faulted | 6 faulted | 6 faulted | 6 faulted | 6 faulted | 6 ok | 6 ok |

- A lone `ok` in a signed column is a PAC collision: arm64e check 07, `noret_unsigned` check 04 and
  `+addend` check 07 each carry `pac_field_was_zero=yes` in their log (3 of 240 signed callback
  hand-overs in checks 01-10, about the 1 in 128 expected).
- `mutate` is defined per check (see Variants). For 16 it strips the pointer Darling's dyld signed, so
  a fault there is the expected result; `nosign` faults in 16 because it is a non-PAC caller of a
  signed pointer (an artefact).
- Failure modes: faults in 01, 02, 04-10, 17, 19 are SIGSEGV, `si_code` 1 (SEGV_MAPERR) at the
  signed or stale-signed pointer (PAC bits set in `si_addr` and `pc`). Check 03: SIGSEGV kill, no
  handler output. Check 18: exit status 137 (Darling's trampoline death). 11, 12, 14: SIGABRT after
  `libc++abi: terminating with uncaught exception of type int`. Earlier boots of the previous builds gave
  the same results for the checks they had.

## Reading the failures

Function that took the signed pointer (`symbolize_faults.py`, `lr` of the fault; `pc` is the
signed pointer with its signature stripped, i.e. the first instruction of the probe's callback):

| check | where it faulted |
|---|---|
| 01, 02 | Darling libsystem_c `__cxa_finalize_ranges` (runs the atexit list) |
| 04 | libsystem_pthread `_pthread_start` |
| 05 | libsystem_pthread `__pthread_once_handler` |
| 06 | libsystem_c `med3` (qsort) |
| 07, 08 | libdispatch `_dispatch_call_block_and_release` (calls the block's `invoke`) |
| 09 | libdispatch `_dispatch_client_callout` |
| 10 | Darling's dyld, outside the image list (add-image notification) |
| 17 | the probe's own `blraa` of the copied block: `lr` is in the probe, so arm64e code rejected the copy |
| 18 | not delivered: the process ends with exit status 137 |
| 19 | the probe's own call of the returned handler, `lr` in the probe |

Callbacks that plain code calls once (01-10): strip the signature and they pass in all six boots, so the
signature is the only obstacle there.

The reverse and stored shapes (16-19):

- 16: Darling's `dlsym` already returns the pointer signed (`orig_signed=yes`) to an arm64e caller;
  the call works, and works only because of that: stripped, the same call faults.
- 17: `Block_copy` of a stack block moves the literal; the copy's `invoke` keeps the signature made for
  the old address (`orig_signed=yes`) and arm64e code calling it faults. Re-signing the copy for its
  new address makes it pass.
- 18: a function pointer inside `struct sigaction`, signed by arm64e code, is called later by
  Darling's signal path (inferred: the fault site was not identified): the process dies (exit 137).
  Stripped, it works. Check 18 hands a signed pointer to `sigaction`; check 19's `signal` also goes
  through `sigaction`, and the harness calls `sigaction` in every child, but with stripped pointers.
- 19: `signal` hands back the raw pointer it stored (unsigned: `HAND signal.return ... orig_signed=no`);
  arm64e code calling it faults on its own authentication. Signed, it passes.

So stripping before the hand-off fixes pointers that plain code only calls. It breaks, or does not
help, pointers that plain code creates or stores and arm64e code later authenticates: 17 and 19 need the
opposite (a signature).

C++ (11, 12, 14 throw an `int`; 13 and 20 throw a class). Four independent defects, each isolated by
one variant:

1. Return addresses. With signed return addresses, libunwind's `unw_step` (check 15) reports the end
   of the stack after the first frame (`frames=1`), so no handler is found and `std::terminate` runs.
   With `noret` the same walk sees six frames, unwind info found for every frame.
2. Personality pointer. With `noret`, 11, 12, 14 fault in libunwind `_unwind_phase1` calling
   `__gxx_personality_v0` through a signed pointer (the GOT slot is an authenticated bind: key IA,
   address diversity, diversity 0, in `__DATA_CONST,__got`). Unsigning that slot and the typeinfo
   vtable pointers (`noret_unsigned`) makes 11, 12, 14 pass in all six boots.
3. A link-time defect, not signing: the in-tree ld64 drops the `+16` addend (the vtable address point)
   from the authenticated bind of a typeinfo's vtable pointer. Raw words of `__ZTI4Base` (the
   `Base` typeinfo): arm64e `0xc00c000000000032` (auth bind; pointer format 1 has no addend field and
   the import table entry has addend 0), `noret_unsigned` `0x4008000000000032` (plain bind, addend 0),
   `nosign` `0x4008001000000032` (plain bind, addend 16; the same ld64 keeps the addend on a plain
   bind). With the addend 0, the typeinfo's vptr points 16 bytes before the vtable's first function, so
   (inferred) libc++abi's virtual call on the typeinfo reads the vtable header instead. Evidence: in
   `noret_unsigned`, 13 faults in libc++abi at the same `pc` and the same `si_addr`
   (`0x37bfdd101042f`) in all six boots; keys differ per process, so it is not a signature. `noret_unsigned_addend` puts the 16 back; the fault moves to a different place.
   This is not caused by signing. `nosign` passes 13 because it has both this and the next item fixed,
   which is why the earlier reading ("the object's vtable pointer is signed at run time") was wrong.
4. The destructor pointer that `__cxa_throw` stores. In `noret_unsigned_addend`, 13 faults with `pc` at
   `Derived::~Derived` (the signed destructor pointer, stripped) called by libc++abi
   `__cxa_decrement_exception_refcount`. Check 20 is 13 spelled out with `__cxa_throw` called by hand:
   in `noret_unsigned_addend mutate` the destructor pointer is stripped and 20 passes 6 of 6, with the
   thrown object's vtable pointer still signed at run time by the arm64e constructor. So that vtable
   pointer is not an obstacle on this throw/catch path; a catch through a virtual base would make plain libc++abi read it.

Is the addend loss a defect of the 3.3a link recipe? It comes from the in-tree ld64 that the recipe
drives, and it affects any image the recipe links that contains an authenticated pointer to
`imported_symbol + offset`: here every typeinfo of a class (`+16` into libc++abi's
`class_type_info` / `si_class_type_info` vtables). The H0 and pac-leaf test binaries are C and have no
such bind, and images in the real cache are linked by Apple's linker, so neither is affected. Whether this
ld64 can emit an addend (import formats with addends) was not tried. Follow-up for the recipe (not edited
here): detect and fix or reject an authenticated bind whose import has a non-zero addend in the
source, and add a toy with a C++ class typeinfo to `tests/arm64e-link/toy/`.

## Recommendation

What the data supports, and what it does not.

Supported: for ten shapes (an IA-key, discriminator-0 function pointer, and an IA address-diversified
block invoke pointer), each handed to Darling's libsystem_c, libsystem_pthread, libdispatch and dyld
and called once from plain code, stripping the signature before the hand-off was sufficient (60 of 60
runs). In the plain-callee shape the failing point is always the callee's unauthenticated branch.

Not supported:

- Pointers that plain code creates or stores and arm64e code authenticates later. Strip-at-entry
  does not help and breaks some of them: a copied block (17: plain `Block_copy` leaves a stale
  signature; an adapter must re-sign on copy), `signal` return values (19: the lib returns the raw
  pointer; an adapter must sign it on return). By the same shape, IMPs, vtables and
  `dispatch_block_create` results are untested.
- Pointers inside structs (18 shows `sigaction.sa_handler` dying (exit 137, probably in Darling's signal path);
  `pthread_attr`, dispatch sources and similar were not tried).
- Data-key pointers: the stack block's `isa` (DA, address-diversified) reaches libdispatch and
  libclosure in checks 07, 09 and 17, and `mutate` never strips it, and check 20 hands libc++abi an
  object with a signed vtable pointer; those paths tolerate it. Other data-key uses (ObjC `isa` use,
  vtable reads by plain code such as a catch through a virtual base) are untested.
- libsystem_kernel: only check 18 hands it a signed pointer (`sigaction`); check 19 and the harness
  call `sigaction` with stripped or unsigned pointers.
- Any claim that nothing needs an arm64e rebuild of libsystem_*. The evidence is "ten callback shapes
  are adapter-fixable"; the sizes measured earlier (2 to 60 callback-taking exports per cache closure)
  are a lower bound on what must be adapted, in both directions, not a count of one-line strips.

libunwind is the part where an adapter cannot work: the signed values are in frames and unwind
tables, not arguments. Checks 11, 12, 14, 15 fail on the return address alone and then on the
personality pointer (and the destructor pointer of a thrown class, 13/20, is stored by `__cxa_throw`
in the exception). A PAC-aware libunwind (strip the return address when stepping, authenticate or
strip the personality pointer) is needed; whether libc++abi from the cache closes the rest of 13/20 was
not tested.

So: an adapter layer is plausible for call-once callbacks, but this probe does not show that it is
sufficient or that it is cheaper than rebuilding the touched libs; that needs the stored and struct
shapes measured per API. Decision input only.

## Not verified

- Pointers plain code stores and arm64e code authenticates later, beyond blocks (17) and `signal` (19):
  IMPs, `dispatch_block_create`, `sigaction` through `signal`'s old-action out parameter.
- Pointers inside other structs (`pthread_attr`, dispatch sources, `qsort_b`, `atexit_b`).
- Data-key (DA/DB) pointers beyond the block `isa` (checks 07, 09, 17) and the thrown object's vtable
  pointer (20), which plain libs tolerated on those paths.
- The cache's arm64e libc++abi with Darling's libunwind (L4): this probe used Darling's plain libc++abi.
- Whether the in-tree ld64 can emit an addend on an authenticated bind (not tried).
- Check 03's fault location: the handler does not run at thread exit; the signal and the `HAND` line
  show it is the destructor pointer, and the strip mutation passes. Check 18's fault location: the
  process ends with status 137 and no handler output.
- Compiler: upstream clang 23 with its arm64e defaults and the 3.3a caps-byte rule, not Apple's.
  Hardware: one M1 host, no FPAC.
- Collisions: a signed pointer has a 1 in 128 chance of a zero PAC field; the harness flags the ones
  it can see (`pac_field_was_zero`), not the personality slot.
- Runtime-harness mutants that the host cannot kill because it cannot execute Mach-O: `hand()`
  stripping nothing, `STRIP` as identity, a faulted exit counted ok, `ok` without `OKMARK`, a missing
  re-sign in 16/17/19, check 03 not handing its pointer, the collision flag removed. The guest
  self-test (`selftest`, `selftest mutate`, expectations compared in code) kills the first four and the
  `exit 0` variant; the others are visible only in the guest matrix (e.g. a missing re-sign turns the
  `mutate` column of 17 or 19 from ok to faulted), so they are killed by comparing a guest run
  against this table, not by a script.
