# DARLING_DYLD_COLLECT_MISSING

`DARLING_DYLD_COLLECT_MISSING=<file>` on a guest command makes dyld record every unresolved symbol (one TAB-separated line
each: referrer, symbol, expected library, ordinal, strong|weak, lazy|nonlazy|chained, zero|trap|guard, slot, pid) and keep going
instead of aborting at the first one. Functions bind to a per-symbol thunk that halts with "a collected missing symbol was
called: <name>"; names that look like data bind to a slot of a region with no access, so a read faults. It also binds all lazy
pointers at link, else a missing lazy import would only show when called. Unset, nothing differs.

## Host check

    ruby tests/dyld-collect-missing.rb            # also runs the probes (a scratch copy of the source is edited; each must fail the checks)

Compiles dyld3/DarlingCollectMissing.cpp natively on ARM64 Linux with `dyld::halt` stubbed and `open`/`write` watched (flags, a symlink path, an unopenable path, a short write, the 8192 caps, the signed ordinals), enters the thunks (including through
a pointer signed IA/0 and called with blraaz, the arm64e sequence) and faults on the guard.

## Guest fixture

Sources: `collect-missing-guest.c` (the program), `collect-missing-full.c` (the library it is linked against: exports the four
imports), `collect-missing-stub.c` (the library it runs against: same install name `@executable_path/libcollectmissing.dylib`,
none of the four), `collect-missing-plugin.c` (a bundle). Build with the Darling SDK flags of a guest test build:

- `libcollectmissing.dylib` from the full source (to link against) and from the stub source (to run against)
- `collect-missing-guest`: guest.c linked against the full library
- `collect-missing-flat`: the same object linked `-flat_namespace`
- `collect-missing-host`: guest.c built with `-DHOST_FULL` and `-Wl,-export_dynamic` (only to link the bundle)
- `collect-missing-plugin.bundle`: `-bundle -bundle_loader collect-missing-host`

Put the program, the flat program, the bundle and the stub library in one directory D, then inside the guest:

    tests/collect-missing-check.sh D tests/collect-missing-guest.expected

It runs every case (mode off and on, a call of each missing function, a data read, the plugin's main-executable bind with
ordinal -1, the flat program with ordinal -2), prints a transcript of return codes, message lines and the fixture's own list
lines (names only: no slot, no pid, no addresses) and diffs it with the expected file; exit 1 on a difference. Set the variable
on the guest command, never on the launcher: the launcher forwards its environment to launchd.

The hooks (`sBindKind`, the ordinals, forcing the lazy binds, the `issetugid()` gate) have no host test; this transcript is
their check. The gate itself cannot be tested without a setuid binary (needs root): it is by reading of src/dyld2.cpp.
