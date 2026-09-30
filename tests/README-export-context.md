# Export lookup cycle regressions

Run `ruby tests/check-export-context.rb` with Clang and Ruby. It extracts the
actual ImageLoaderMachO traversal and supplies controlled shallow-export behavior.
ASan/UBSan covers self/mutual cycles, a valid alternate branch, renamed aliases,
renamed cycles, search-mode transitions, a 512-image chain and concurrent callers.
The shallow collaborator is a model, not the real export-trie decoder.

For a real guest test, `ruby tests/build-reexport-cycle.rb WORKSPACE` uses an
existing `WORKSPACE/build-arm64-stage18` Controls recipe and `WORKSPACE/source`
SDK setup. It prints a temporary library directory containing A, B and Leaf:
A re-exports B and Leaf; B re-exports A. Compile `reexport-cycle-main.c` as a
Darling executable with the same SDK/libSystem and copy the three dylibs into
`/probe-libraries` in its disposable guest root. This build helper is intentionally
staged-workspace-specific, not a clean build system or installation command.

The guest opens A with RTLD_FIRST so symbol lookup traverses re-exports, checks
the Leaf function and a missing symbol, then closes the image. Ordinary dlsym
breadth-first search is not a substitute for this RTLD_FIRST regression.

The candidate passes this real ARM64 guest fixture; unchanged upstream 25dd116
exits 139 with the same fixture and dependency stack. All 64 staged dyld/libdyld
objects compile and both binaries link. Existing staged-link warnings remain.
Real renamed-symbol tries, x86/i386 guest execution and MegaDylib's separate
internal cache-graph traversal are not covered by that guest result. The latter
traversal is unchanged. Internal virtual signatures change, so rebuild the loader
coherently; do not mix old and new ImageLoader objects.
