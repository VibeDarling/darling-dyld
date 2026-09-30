`ruby tests/arm64-cache-tsd-veneers.rb .` executes the production cache TSD
veneer generator on ARM64 Linux. It covers 400000 reads across four threads,
null-slot trap fallback, invalid metadata, out-of-range branches, XZR, and
occupied mapping preservation. The signal handler is test scaffolding.

The kernel getter returns the native-loader-owned ELF TLS offset, or ~0UL for
an older loader. Reachable cache reads branch to a fresh allocation below the
cache; each veneer reads the native TP and then the dedicated Darwin TSD slot,
with a UDF fallback if that thread's slot is still null. It branches back without
changing LR, SP, or NZCV. Sites beyond the branch range retain the UDF path.
The allocation is RW during construction and RX before running cache code.

Native loader, kernel and dyld must agree on the slot contract. In particular,
the slot must not alias legacy TLS-restoration callback storage. Full iTerm2
validation is separate from this generator test; the current integration test
uses staged dependencies and does not establish a clean full upstream build.

The public mapper test also executes the production mapping translator against
synthetic private cache mappings. It checks that data mappings remain untouched,
CPU-index reads become zero, XZR becomes NOP, translated code executes, and a
protection failure is reported. This ports the TSD consumer to upstream's cache
mapper; it does not add modern split-cache loading or unrelated ARM64e fixups.
