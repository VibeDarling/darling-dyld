# DARLING_DYLD_COLLECT_MISSING

`DARLING_DYLD_COLLECT_MISSING=<file>` on a guest command makes dyld record every unresolved symbol (one TAB-separated line
each: referrer, symbol, expected library, ordinal, strong|weak, lazy|nonlazy|chained, zero|trap|guard, slot) and keep going
instead of aborting at the first one. Functions bind to a per-symbol thunk that halts with "a collected missing symbol was
called: <name>"; names that look like data bind to a slot of a region with no access, so a read faults. It also binds all lazy
pointers at link, else a missing lazy import would only show when called. Unset, nothing differs.

## Host check

    ruby tests/dyld-collect-missing.rb            # also runs the probes (a scratch copy of the source is edited; each must fail the checks)

Compiles dyld3/DarlingCollectMissing.cpp natively on ARM64 Linux with `dyld::halt` stubbed, enters the thunks (including through
a pointer signed IA/0 and called with blraaz, the arm64e sequence) and faults on the guard.

## Guest fixture

`collect-missing-guest.c` is linked against the library built from `collect-missing-full.c` and run against the one built from
`collect-missing-stub.c` (same install name `@executable_path/libcollectmissing.dylib`, none of the four imports). Build all three
with the Darling SDK flags of a guest test build and put the program and the stub library in one directory:

    collect-missing-guest present           # mode off: dyld ends the launch: Symbol not found: _kCollectMissingData
    env DARLING_DYLD_COLLECT_MISSING=/tmp/list.txt collect-missing-guest present   # runs; /tmp/list.txt names all four
    ... a | b | c                           # calls a missing function: halts naming it
    ... data                                # reads the missing data symbol: SIGSEGV on the guard

Run these inside the guest (set the variable on the guest command, never on the launcher: the launcher forwards its environment
to launchd).
