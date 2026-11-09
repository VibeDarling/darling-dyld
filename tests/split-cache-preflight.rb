# The actual pre-signature validation block of preflightCacheFile against the main file of a synthetic
# split cache (tests/gen-split-cache-fixture.py) and corrupted variants of it. Signature registration and
# mmap are not executed. The legacy single-file rules are covered by cache-preflight-ranges.rb.
# Usage: ruby tests/split-cache-preflight.rb [checkout]
require 'tmpdir'
require 'open3'
root = File.realpath(ARGV.fetch(0, File.expand_path('..', __dir__)))
source = File.read("#{root}/dyld3/SharedCacheRuntime.cpp")
helper = source[/static bool cacheRangeContains\(.*?(?=^static bool preflightCacheFile)/m] or abort 'helpers missing'
block = source[/    if \( \(cache->header.mappingCount < (?:3\)|\(dyld_cache_header_is_split).*?(?=    \/\/ register code signature)/m] or abort 'mapping validation missing'
header = File.read("#{root}/dyld3/shared-cache/dyld_cache_format.h")
max_mappings = File.read("#{root}/dyld3/shared-cache/DyldSharedCache.h")[/MaxMappings = (\d+)/, 1] or abort 'mapping limit missing'
structs = %w[dyld_cache_header dyld_cache_mapping_info dyld_cache_mapping_and_slide_info dyld_cache_image_info].map do |name|
  header[/struct #{name}\s*\{.*?^\};/m] or abort "missing #{name}"
end.join("\n") + "\n" + (header.scan(/static inline bool dyld_cache_\w+\(.*?^\}/m).join("\n") or abort 'split predicate missing')

# variant => true when the main file must be accepted, else the error it must be rejected with
VARIANTS = {
  'valid' => true,
  'bad_uuid' => true,          # sub-cache problems are not visible from the main file alone
  'main_overlap' => 'split mappings are invalid',
  'bad_mapping_offset' => 'file mappings are invalid',
  'bad_codesig' => 'split signature does not cover',
  'sig_before_eof' => 'split signature does not cover',
  'sig_inside_mapping' => 'split signature does not cover',
  'main_mapping_offset' => 'split header is not mapped',
  'main_wrong_start' => 'split header is not mapped',
  'image_table_outside' => 'split header is not mapped',
  'main_wx' => 'split mappings are invalid',
  'main_count_mismatch' => 'slide mappings are invalid',
  'main_not_split' => 'file mappings are invalid',   # no images in the split table: judged by the legacy rules (needs 3 mappings)
}

Dir.mktmpdir('split-cache-preflight-') do |dir|
  File.write("#{dir}/test.cpp", <<~CPP)
    #include <stdint.h>
    #include <stddef.h>
    #include <assert.h>
    #include <stdio.h>
    #include <string.h>
    #include <unistd.h>
    #include <fcntl.h>
    #include <errno.h>
    #define __offsetof offsetof
    typedef unsigned char uuid_t[16];
    enum { VM_PROT_READ=1, VM_PROT_WRITE=2, VM_PROT_EXECUTE=4 };
    #{structs}
    struct DyldSharedCache { dyld_cache_header header; enum { MaxMappings=#{max_mappings} }; };
    struct Result { const char *errorMessage=nullptr; };
    #{helper}
    static bool verify(int fd, const uint8_t (&firstPage)[0x4000], uint64_t cacheFileLength, Result *results) {
      const DyldSharedCache *cache = reinterpret_cast<const DyldSharedCache *>(firstPage);
    #{block}
      return true;
    }
    int main(int argc, char **argv) {
      assert(argc == 2);
      int fd = open(argv[1], O_RDONLY); assert(fd >= 0);
      alignas(16) uint8_t firstPage[0x4000];
      off_t length = lseek(fd, 0, SEEK_END); assert(length >= 0x4000);
      assert(pread(fd, firstPage, sizeof firstPage, 0) == (ssize_t)sizeof firstPage);
      Result result;
      bool accepted = verify(fd, firstPage, (uint64_t)length, &result);
      if (accepted) { assert(!result.errorMessage && fcntl(fd, F_GETFD) >= 0); printf("RESULT accepted\\n"); }
      else { assert(result.errorMessage); errno = 0; assert(fcntl(fd, F_GETFD) == -1 && errno == EBADF); printf("RESULT rejected: %s\\n", result.errorMessage); }
      return 0;
    }
  CPP
  out, st = Open3.capture2e('clang++', '-std=c++17', '-fsanitize=undefined', "-I#{root}/dyld3/shared-cache", "#{dir}/test.cpp", '-o', "#{dir}/test")
  abort out unless st.success?
  failures = 0
  VARIANTS.each do |variant, accepted|  # accepted: true or the expected rejection text
    fixture = "#{dir}/#{variant}"
    out, st = Open3.capture2e('python3', '-I', "#{root}/tests/gen-split-cache-fixture.py", fixture, '--variant', variant)
    abort out unless st.success?
    out, st = Open3.capture2e("#{dir}/test", "#{fixture}/cache")
    result = out[/^RESULT .*$/]
    good = st.success? && result && (accepted == true ? result == 'RESULT accepted' : (result.start_with?('RESULT rejected') && result.include?(accepted)))
    puts "#{good ? 'ok  ' : 'FAIL'} #{variant} (#{result})"
    unless good
      failures += 1
      puts out.lines.last(6).join
    end
  end
  abort "#{failures} split preflight scenario(s) failed" unless failures.zero?
  puts 'PASS split-cache main file accepted; overlapping, out-of-page, unsigned-gap, unmapped-header and non-split headers rejected'
end
