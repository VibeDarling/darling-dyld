# Shared-cache alias fallback

Run from the repository root with Ruby and clang++ available:

```sh
ruby tests/cache-alias-lookup.rb .
LOOKUP_SOURCE_REF=25dd116 ruby tests/cache-alias-lookup.rb .
```

The first command passes under AddressSanitizer and UndefinedBehaviorSanitizer.
The second is a negative control: the unchanged upstream function fails its first
alias assertion. The fixture extracts the actual lookup function, with controlled
cache structures and trie/ImageArray collaborators. It checks recorded alias
resolution, the canonical result path and slide, absent ImageArray fallback,
out-of-range indices, absent trie/header fields, canonical linear scanning,
the existing closure route, and a null cache. It does not exercise the real trie
parser, map a cache, validate signatures, or demonstrate complete modern-cache
support.
