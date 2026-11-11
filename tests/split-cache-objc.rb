# Split-cache objcOpt()/objcOptPtrs(): both accessors find libobjc through the split cache's image
# table and never the dyld3 image array (which a split cache lacks), and each returns null when its
# section is absent. Runs the real accessors, extracted from DyldSharedCache.cpp, against the
# synthetic split cache from tests/gen-split-cache-fixture.py. No Apple cache content is used.
# Requires Linux (MAP_FIXED, /proc/self/maps), Ruby, python3 and clang++.
# Usage: ruby tests/split-cache-objc.rb [checkout] [base-address]
require 'tmpdir'
require 'open3'
root = File.realpath(ARGV.fetch(0, File.expand_path('..', __dir__)))
base = ARGV.fetch(1, '0x180000000')
require_relative 'split-cache-harness'

cache_src = File.read("#{root}/dyld3/shared-cache/DyldSharedCache.cpp")
objc_opt_fn = cache_src[/^const objc_opt::objc_opt_t\* DyldSharedCache::objcOpt\(\) const \{.*?^\}/m] or abort 'objcOpt missing'
objc_ptrs_fn = cache_src[/^const void\* DyldSharedCache::objcOptPtrs\(\) const \{.*?^\}/m] or abort 'objcOptPtrs missing'

Dir.mktmpdir('split-cache-objc-') do |dir|
  File.write("#{dir}/test.cpp", <<~CPP)
    #{SplitCacheHarness.prefix(root, objc: true)}
    #{objc_opt_fn}
    #{objc_ptrs_fn}

    static int failures = 0;
    #define CHECK(cond) do { if (!(cond)) { printf("FAIL line %d: %s\\n", __LINE__, #cond); ++failures; } } while (0)

    int main(int argc, char **argv) {
      assert(argc >= 2);
      std::string dir = argv[1];
      FILE *manifest = fopen((dir + "/manifest.txt").c_str(), "r"); assert(manifest);
      uint64_t base = 0, objcAddr = 0, roAddr = 0, ptrsAddr = 0, regionSize = 0;
      char word[32], a[64], b[64], c[64], d[64], line[256];
      while (fgets(line, sizeof line, manifest)) {
        if (sscanf(line, "%31s %63s %63s %63s %63s", word, a, b, c, d) < 1) continue;
        if (!strcmp(word, "base")) base = strtoull(a, nullptr, 16);
        else if (!strcmp(word, "region")) regionSize = strtoull(b, nullptr, 16);
        else if (!strcmp(word, "objc")) {
          objcAddr = strtoull(a, nullptr, 16);
          roAddr = strtoull(b, nullptr, 16);
          ptrsAddr = strtoull(c, nullptr, 16);
        }
      }
      fclose(manifest);
      assert(objcAddr != 0 && regionSize != 0);

      SharedCacheLoadInfo result = {}; SplitCacheMapStats stats;
      std::string mainFile = dir + "/cache";
      bool ok = mapSplitCachePrivate(mainFile.c_str(), true, &result, &stats, kSplitCacheAuthLeaveAlone);
      assert(ok && result.errorMessage == nullptr);
      const DyldSharedCache *cache = result.loadAddress;
      assert(cache != nullptr && (uintptr_t)cache == base);
      CHECK(cache->isSplitCache());

      // By construction the split fixture has no dyld3 image array: reaching it would return null and
      // crash the accessor, so the call count after both accessors is the proof they did not read it.
      CHECK(cache->cachedDylibsImageArray() == nullptr);
      gCachedDylibsImageArrayCalls = 0;
      const objc_opt::objc_opt_t *opt = cache->objcOpt();
      const void *ptrs = cache->objcOptPtrs();
      CHECK(gCachedDylibsImageArrayCalls == 0);

      // libobjc is image 1 of the split image table, found by path
      uint32_t index = 0;
      CHECK(cache->hasImagePath("/usr/lib/libobjc.A.dylib", index) && index == 1);

      if (roAddr != 0) {
        CHECK(opt != nullptr);
        CHECK((uintptr_t)opt == roAddr);
        CHECK(opt != nullptr && opt->version == objc_opt::VERSION);
      } else {
        CHECK(opt == nullptr);
      }
      if (ptrsAddr != 0) {
        CHECK(ptrs == (const void *)ptrsAddr);
      } else {
        CHECK(ptrs == nullptr);
      }

      if (failures) { printf("%d failure(s)\\n", failures); return 1; }
      printf("RESULT ok ro=%s ptrs=%s\\n", opt ? "present" : "absent", ptrs ? "present" : "absent");
      return 0;
    }
  CPP
  failed_build = SplitCacheHarness.compile(root, dir, ["-I#{root}/include", '-fsanitize=address,undefined'])
  abort failed_build if failed_build
  failures = 0
  # Both sections present, then each section absent alone (absent, or too short to hold objc_opt_t):
  # the accessor is null only for its own section.
  %w[objc objc_no_ro objc_no_ptrs objc_short_ro].each do |variant|
    fixture = "#{dir}/#{variant}"
    out, st = Open3.capture2e('python3', '-I', "#{root}/tests/gen-split-cache-fixture.py", fixture, '--base', base, '--variant', variant)
    abort out unless st.success?
    out, st = Open3.capture2e("#{dir}/test", fixture)
    good = st.success? && out.include?('RESULT ok')
    puts "#{good ? 'ok  ' : 'FAIL'} #{variant} (#{out[/^RESULT .*$/] || out.lines.last&.strip})"
    unless good
      failures += 1
      puts out.lines.last(10).join
    end
  end
  abort "#{failures} split-cache objc scenario(s) failed" unless failures.zero?
  puts 'PASS split-cache objcOpt/objcOptPtrs find libobjc through the image table, never the image array, and null per absent section'
end
