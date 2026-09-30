# Shared-cache TLV descriptor compatibility

Run the host checks from this checkout with Ruby and Clang:

```
ruby tests/check-tlv-cache-gate.rb
ruby tests/check-tlv-normalize.rb
ruby tests/check-tlv-storage.rb
ruby tests/check-tlv-allocation.rb
```

These extract the actual helpers/allocator from the source. They check cache
membership and the advertised format bit; legacy and packed offsets; malformed
section extents and zero-based templates; and builder-shaped positive, negative
and zero initial-content deltas with real pthread isolation. They do not execute
the Mach-O loader. The initializer's existing load-command traversal is not made
into a general malformed-image validator by the bounded span helper.

`tlv-guest.c` is a standalone Darling guest fixture for ordinary compiler-generated
TLS. Build it with the Darling SDK and link libSystem. It verifies initialized
and zerofill variables in the main thread and two successive pthreads. Setting
TEST_REQUIRE_CACHE additionally requires a nonempty active cache range; it does
not turn the executable's legacy descriptors into cached v2 descriptors.

Validation for this contribution compiled all 28 libdyld objects with the staged
ARM64 recipes and linked libdyld. The upstream-based candidate passes this guest
fixture without a cache. The broader cache loader is separate work, not supplied
by this contribution. Cache-enabled startup with an upstream-based Objective-C
runtime is not established by the legacy test.

A separate composed-loader test calls MLAssetIO's real cached descriptor through
the installed thunk. Its 64-byte regular template matches both fresh guest
threads, and mutations remain thread-local. That test also passes with upstream's
full-width ARM64 descriptor-offset load. Fixtures and exact limitations are in
[the validation repository](https://github.com/deepai-org/darling-aarch64-getting-started/blob/9f7c1bb/probes/cache-tlv-runtime.m).
The composed loader supplies modern cache mapping/notifications not included here.

The conversion intentionally retains the existing section-based allocator.
The inspected Apple cache builder derives the packed descriptor's initial
content and size from that same section template. Read-only validation of a
macOS 26.5 cache found agreement for all 446 optimized descriptors in 80 images.
Arbitrary alternative cache layouts, other cache versions, and constructor-bearing
cached TLS are not runtime-validated by this result. No cache binaries are included.
