# Struct offsets and slide-info-v5 bit layout of dyld_cache_format.h, checked against constants measured
# on a real split cache (header offsets, entry sizes, chain bit positions) and written down here
# independently of the header. The header also carries static_asserts, so a wrong offset fails the
# compile before this test even runs.
# Usage: ruby tests/split-cache-format.rb [checkout]
require 'tmpdir'
require 'open3'
root = File.realpath(ARGV.fetch(0, File.expand_path('..', __dir__)))

EXPECTED = {
  'uuid' => 0x58, 'patchInfoAddr' => 0x98, 'sharedRegionStart' => 0xe0, 'sharedRegionSize' => 0xe8,
  'mappingWithSlideOffset' => 0x138, 'mappingWithSlideCount' => 0x13c,
  'subCacheArrayOffset' => 0x188, 'subCacheArrayCount' => 0x18c,
  'imagesOffsetSplit' => 0x1c0, 'imagesCountSplit' => 0x1c4, 'header_size' => 0x228,
  'mapping_and_slide_size' => 56, 'subcache_entry_size' => 56, 'subcache_cacheVMOffset' => 16,
  'subcache_fileSuffix' => 24, 'image_info_size' => 32, 'slide5_value_add' => 16, 'slide5_page_starts' => 24,
}.freeze

Dir.mktmpdir('split-cache-format-') do |dir|
  File.write("#{dir}/test.cpp", <<~CPP)
    #include <stdint.h>
    #include <stdio.h>
    #include <string.h>
    #include "dyld_cache_format.h"
    #define OFF(name, expr) printf("%s %zu\\n", name, (size_t)(expr))
    int main() {
      OFF("uuid", offsetof(dyld_cache_header, uuid));
      OFF("patchInfoAddr", offsetof(dyld_cache_header, patchInfoAddr));
      OFF("sharedRegionStart", offsetof(dyld_cache_header, sharedRegionStart));
      OFF("sharedRegionSize", offsetof(dyld_cache_header, sharedRegionSize));
      OFF("mappingWithSlideOffset", offsetof(dyld_cache_header, mappingWithSlideOffset));
      OFF("mappingWithSlideCount", offsetof(dyld_cache_header, mappingWithSlideCount));
      OFF("subCacheArrayOffset", offsetof(dyld_cache_header, subCacheArrayOffset));
      OFF("subCacheArrayCount", offsetof(dyld_cache_header, subCacheArrayCount));
      OFF("imagesOffsetSplit", offsetof(dyld_cache_header, imagesOffsetSplit));
      OFF("imagesCountSplit", offsetof(dyld_cache_header, imagesCountSplit));
      OFF("header_size", sizeof(dyld_cache_header));
      OFF("mapping_and_slide_size", sizeof(dyld_cache_mapping_and_slide_info));
      OFF("subcache_entry_size", sizeof(dyld_subcache_entry));
      OFF("subcache_cacheVMOffset", offsetof(dyld_subcache_entry, cacheVMOffset));
      OFF("subcache_fileSuffix", offsetof(dyld_subcache_entry, fileSuffix));
      OFF("image_info_size", sizeof(dyld_cache_image_info));
      OFF("slide5_value_add", offsetof(dyld_cache_slide_info5, value_add));
      OFF("slide5_page_starts", offsetof(dyld_cache_slide_info5, page_starts));
      // plain: runtimeOffset 0x12345 | high8 0x80 << 34 | next 7 << 52
      dyld_cache_slide_pointer5 p; p.raw = 0x12345ULL | (0x80ULL << 34) | (7ULL << 52);
      printf("plain %llx %x %x %d\\n", (unsigned long long)p.regular.runtimeOffset, (unsigned)p.regular.high8, (unsigned)p.regular.next, (int)p.auth.auth);
      // auth: runtimeOffset 0x777 | diversity 0xbeef << 34 | addrDiv << 50 | keyIsData << 51 | next 0x7ff << 52 | auth << 63
      dyld_cache_slide_pointer5 a; a.raw = 0x777ULL | (0xbeefULL << 34) | (1ULL << 50) | (1ULL << 51) | (0x7ffULL << 52) | (1ULL << 63);
      printf("auth %llx %x %u %u %x %d\\n", (unsigned long long)a.auth.runtimeOffset, (unsigned)a.auth.diversity, (unsigned)a.auth.addrDiv,
             (unsigned)a.auth.keyIsData, (unsigned)a.auth.next, (int)a.auth.auth);
      dyld_cache_header legacy; memset(&legacy, 0, sizeof legacy); legacy.mappingOffset = sizeof legacy;
      printf("legacy_is_split %d\\n", (int)dyld_cache_header_is_split(legacy));
      legacy.imagesCountSplit = 1;
      printf("split_is_split %d\\n", (int)dyld_cache_header_is_split(legacy));
      legacy.mappingOffset = 0x138;
      printf("short_header_is_split %d\\n", (int)dyld_cache_header_is_split(legacy));
    }
  CPP
  out, st = Open3.capture2e('clang++', '-std=c++17', "-I#{root}/dyld3/shared-cache", "#{dir}/test.cpp", '-o', "#{dir}/test")
  abort out unless st.success?
  out, st = Open3.capture2e("#{dir}/test")
  abort out unless st.success?
  lines = out.lines.map(&:split)
  failures = []
  EXPECTED.each do |name, want|
    row = lines.find { |l| l[0] == name }
    failures << "#{name}: want #{want}, got #{row ? row[1] : 'nothing'}" unless row && row[1].to_i == want
  end
  { 'plain' => %w[plain 12345 80 7 0], 'auth' => %w[auth 777 beef 1 1 7ff 1],
    'legacy_is_split' => %w[legacy_is_split 0], 'split_is_split' => %w[split_is_split 1],
    'short_header_is_split' => %w[short_header_is_split 0] }.each do |name, want|
    row = lines.find { |l| l[0] == name }
    failures << "#{name}: want #{want.inspect}, got #{row.inspect}" unless row == want
  end
  abort failures.join("\n") unless failures.empty?
  puts 'PASS split-cache header offsets, entry sizes, slide v5 pointer bit layout and split predicate'
end
