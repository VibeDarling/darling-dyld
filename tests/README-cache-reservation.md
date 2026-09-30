# Private cache reservation regression

From this checkout, with Ruby and Clang installed:

```
ruby tests/check-cache-reservation.rb
ruby tests/check-private-cache-mapping.rb
```

Both run with UBSan and real host mmap/munmap/mincore calls. The first extracts
the actual reservation class and checks occupied/partial collisions, ownership
release, committed reservations and integer overflow rejection. The second
extracts the actual mapCachePrivate function, supplies controlled cache metadata,
and injects failures into its file-mapping/rebase collaborators. It checks:

- occupied and partly occupied regions reject before any MAP_FIXED call;
- partial mapping and rebasing failures release the entire owned span;
- out-of-region mappings reject before destructive operations;
- success keeps the file mappings and reserved gaps;
- the cache file descriptor closes on all these paths.

For a negative control, use the original upstream mapping function while keeping
the same fixture and unused reservation helper:

```
BASELINE_MAPPER_REF=25dd116 ruby tests/check-private-cache-mapping.rb
```

That command is expected to fail the first occupied-region assertion because the
old function replaces the mapping instead of rejecting the collision. The test
runs in its own process and creates only temporary, immediately unlinked files.

Preflight, rebasing and DataConstScopedWriter are controlled collaborators here;
these tests do not boot a shared cache or verify Darwin VM semantics. The changed
SharedCacheRuntime.cpp also compiles with the staged ARM64 loader recipe. There
is no full-tree build, slid-cache boot or x86/i386 guest claim.
