# Actual mapSplitCachePrivate, slide-info-v5 rebase and the DyldSharedCache image helpers, run against
# a synthetic 3-file split cache (tests/gen-split-cache-fixture.py). No Apple cache content is used.
# Requires Linux (MAP_FIXED, /proc/self/maps), Ruby, python3 and clang++.
# Usage: ruby tests/split-cache-mapping.rb [checkout] [base-address]
# The synthetic region is mapped at base-address (default 0x180000000), which must be free.
require 'tmpdir'
require 'open3'
root = File.realpath(ARGV.fetch(0, File.expand_path('..', __dir__)))
base = ARGV.fetch(1, '0x180000000')
require_relative 'split-cache-harness'

# variant => nil (maps) or the substring the error message must contain
host_page = `getconf PAGESIZE`.to_i
VARIANTS = {
  'valid' => nil,
  'bad_uuid' => 'does not match the main file',
  'bad_vm_offset' => 'vm offset does not match',
  'main_overlap' => 'mappings overlap',
  'sub_overlap' => 'mappings overlap',
  'short_sub_file' => 'lies outside its file',
  'sub_outside_region' => 'outside the shared region',
  'suffix_slash' => 'suffix is invalid',
  'main_not_split' => 'main file header is invalid',
  'bad_mapping_offset' => 'mapping tables disagree',
  'main_mapping_offset' => 'does not start with its header',
  'main_wrong_start' => 'does not map its header tables',
  'image_table_outside' => 'does not map its header tables',
  'page_starts_range' => 'covers more pages than its mapping',
  'page_starts_truncated' => 'page_starts exceed the slide info',
  'chain_leaves_page' => 'chain leaves its page',
  'chain_start_outside' => 'chain starts outside its page',
  'unknown_slide_version' => 'unknown version',
  'target_outside_region' => 'outside the cache region',
  'bad_page_size' => 'invalid page size',
  'sub_first_mapping_offset' => 'does not start with its header',
  'bad_alignment' => host_page > 0x1000 ? 'empty or misaligned' : :skip,  # 0x5000 is a whole page on a 4 KiB host
  'sub_bad_magic' => 'does not match the main file',
  'sub_bad_platform' => 'does not match the main file',
  'sub_wx_prot' => 'protections are invalid',
  'sub_bad_prot_bits' => 'protections are invalid',
  'main_wx' => 'protections are invalid',
  'slide_outside_file' => 'slide info lies outside its file',
  'chain_start_unaligned' => 'chain start is misaligned',
  'main_count_mismatch' => 'does not map its header tables',
}

Dir.mktmpdir('split-cache-mapping-') do |dir|
  File.write("#{dir}/test.cpp", <<~CPP)
    #{SplitCacheHarness.prefix(root)}

    static unsigned long long hex(const char *s) { return strtoull(s, nullptr, 16); }
    static std::string permissions(uint64_t address) {
      FILE *maps = fopen("/proc/self/maps", "r"); assert(maps);
      char line[512]; std::string perms = "unmapped";
      while (fgets(line, sizeof line, maps)) {
        unsigned long long start, end; char p[8];
        if (sscanf(line, "%llx-%llx %7s", &start, &end, p) == 3 && address >= start && address < end) { perms = p; break; }
      }
      fclose(maps); return perms;
    }
    static const char *current;
    static unsigned seenImages; static char seenName[128];
    static unsigned regionCount; static uint64_t regionAddress[8]; static const void *regionContent[8]; static uint32_t regionProt[8];

    static unsigned countRegions(const DyldSharedCache *cache) {
      regionCount = 0;
      cache->forEachRegion(^(const void *, uint64_t, uint64_t, uint32_t, uint32_t, uint64_t) { ++regionCount; });
      return regionCount;
    }
    // Overwrites a word of a mapped header (private pages), checks the region walk gives up, then restores it.
    template <typename T> static void corruptAndCheck(const DyldSharedCache *cache, uint64_t address, T value) {
      uint64_t page = (uint64_t)sysconf(_SC_PAGESIZE);
      assert(mprotect((void *)(address & ~(page - 1)), page, PROT_READ | PROT_WRITE) == 0);
      T saved = *(T *)address; *(T *)address = value;
      assert(countRegions(cache) == 0);
      *(T *)address = saved;
      assert(countRegions(cache) == 3);
    }

    int main(int argc, char **argv) {
      assert(argc == 2);
      std::string dir = argv[1];
      FILE *manifest = fopen((dir + "/manifest.txt").c_str(), "r"); assert(manifest);
      uint64_t base = 0, imageAddress = 0, regionSize = 0;
      char installName[128] = "", word[32], a[64], b[64], c[64], d[64], e[64];
      unsigned files = 0, mappingsExpected = 0; unsigned long long pages = 0, plainExpected = 0, authExpected = 0;
      struct Slot { uint64_t address, value; }; Slot expect[16], untouched[16]; unsigned nExpect = 0, nUntouched = 0;
      char line[256];
      while (fgets(line, sizeof line, manifest)) {
        if (sscanf(line, "%31s %63s %63s %63s %63s %63s", word, a, b, c, d, e) < 1) continue;
        if (!strcmp(word, "base")) base = hex(a);
        else if (!strcmp(word, "image")) { imageAddress = hex(a); strcpy(installName, b); }
        else if (!strcmp(word, "region")) regionSize = hex(b);
        else if (!strcmp(word, "stats")) sscanf(line, "stats files=%u mappings=%u pages=%llu plain=%llu auth=%llu", &files, &mappingsExpected, &pages, &plainExpected, &authExpected);
        else if (!strcmp(word, "expect")) expect[nExpect++] = {hex(a), hex(b)};
        else if (!strcmp(word, "untouched")) untouched[nUntouched++] = {hex(a), hex(b)};
      }
      fclose(manifest);

      SharedCacheLoadInfo result = {}; SplitCacheMapStats stats;
      bool ok = mapSplitCachePrivate((dir + "/cache").c_str(), true, &result, &stats, kSplitCacheAuthLeaveAlone);
      if (!ok) {
        assert(result.errorMessage && !result.loadAddress);
        // A failed map must leave the whole region free again.
        void *probe = mmap((void *)base, regionSize, PROT_NONE, MAP_PRIVATE | MAP_ANON | MAP_FIXED_NOREPLACE, -1, 0);
        assert(probe == (void *)base); munmap(probe, regionSize);
        printf("RESULT error: %s\\n", result.errorMessage);
        return 0;
      }
      assert(!result.errorMessage && result.loadAddress == (const DyldSharedCache *)base && result.slide == 0);
      assert(stats.files == files && stats.mappings == mappingsExpected && stats.pagesWithChains == pages);
      assert(stats.plainRebased == plainExpected && stats.authLeftAlone == authExpected);
      for (unsigned i = 0; i < nExpect; ++i) assert(*(uint64_t *)expect[i].address == expect[i].value);
      for (unsigned i = 0; i < nUntouched; ++i) assert(*(uint64_t *)untouched[i].address == untouched[i].value);

      // private copy-on-write: the file keeps the on-disk chain value that the mapping has rewritten
      int fd = ::open((dir + "/cache.02.dylddata").c_str(), O_RDONLY); assert(fd >= 0);
      uint64_t onDisk = 0; assert(pread(fd, &onDisk, 8, 0x4000 + 0x10) == 8); close(fd);
      assert(onDisk != *(uint64_t *)expect[0].address && (onDisk & 0xffffffff) == 0x8000);
      // final protections follow initProt only after rebasing
      assert(permissions(base) == "r-xp" && permissions(base + 0x8000) == "r-xp" && permissions(base + 0xC000) == "r-xp");
      assert(permissions(base + 0x10000) == "rw-p" && permissions(base + 0x1C000) == "rw-p");
      assert(permissions(base + 0x4000) == "r-xp" && permissions(base + 0x20000) == "---p");

      // image helpers over the mapped main header
      const DyldSharedCache *cache = result.loadAddress;
      uint32_t index = 99;
      assert(cache->hasImagePath(installName, index) && index == 0);
      assert(!cache->hasImagePath("/usr/lib/libnothere.dylib", index));
      assert(strcmp(cache->getIndexedImagePath(0), installName) == 0);
      uint64_t mTime, inode;
      const mach_header *mh = cache->getIndexedImageEntry(0, mTime, inode);
      assert((uint64_t)mh == imageAddress && mh->magic == 0xFEEDFACF);
      const uint32_t *idCommand = (const uint32_t *)((const char *)mh + 32);
      assert(idCommand[0] == 0xD && strcmp((const char *)idCommand + idCommand[2], installName) == 0);
      uint32_t found = 99; assert(cache->findMachHeaderImageIndex(mh, found) && found == 0);
      cache->forEachImage(^(const mach_header *header, const char *name) {
        ++seenImages; strncpy(seenName, name, sizeof seenName - 1); assert(header == (const mach_header *)imageAddress);
      });
      assert(seenImages == 1 && strcmp(seenName, installName) == 0);
      assert(cache->mappedSize() == regionSize);
      // all three files' mappings are enumerated, with content at the mapped VM address
      cache->forEachRegion(^(const void *content, uint64_t address, uint64_t, uint32_t initProt, uint32_t, uint64_t) {
        regionAddress[regionCount] = address; regionContent[regionCount] = content; regionProt[regionCount++] = initProt;
      });
      assert(regionCount == 3);
      assert(regionAddress[0] == base && regionAddress[1] == base + 0x8000 && regionAddress[2] == base + 0x10000);
      for (unsigned i = 0; i < 3; ++i) assert(regionContent[i] == (const void *)regionAddress[i]);
      assert(regionProt[0] == 5 && regionProt[1] == 5 && regionProt[2] == 3);
      uint32_t tableCount = 0; assert(cache->isSplitCache() && cache->imageTable(tableCount) && tableCount == 1);
      // The walk reads the mapped headers: a table that is not inside its header's first mapping, an
      // entry that does not point at a header, or a first mapping that does not start the file each make
      // it enumerate nothing.
      assert(countRegions(cache) == 3);
      corruptAndCheck<uint32_t>(cache, base + 0x8000 + 0x138, 0x8000);        // .01 table offset outside its first mapping
      corruptAndCheck<uint32_t>(cache, base + 0x8000 + 0x138, 0x100000);     // .01 table offset past the region: must not be read
      corruptAndCheck<uint32_t>(cache, base + 0x8000 + 0x13c, 0);             // .01 mapping count 0
      corruptAndCheck<uint32_t>(cache, base + 0x8000 + 0x13c, 21);            // .01 mapping count too large
      corruptAndCheck<uint32_t>(cache, base + 0x10000 + 0x138, 3);            // .02 table offset misaligned
      corruptAndCheck<uint64_t>(cache, base + 0x8000 + 0x280, base + 0x9000); // .01 first mapping elsewhere than its header
      corruptAndCheck<uint32_t>(cache, base + 0x18c, 33);                     // main sub-cache count too large
      corruptAndCheck<uint32_t>(cache, base + 0x188, 0x7ff8);                 // main sub-cache array outside its first mapping
      corruptAndCheck<uint32_t>(cache, base + 0x188, 0x100000);               // ... far outside: must not be read
      corruptAndCheck<uint64_t>(cache, base + 0x300 + 16, regionSize);        // sub-cache entry outside the region
      corruptAndCheck<uint64_t>(cache, base + 0x280 + 16, 0x4000);            // main first mapping not at file offset 0
      // a table at a misaligned offset, otherwise valid (a copy of .01's own table)
      {
        uint8_t *header = (uint8_t *)(base + 0x8000);
        assert(mprotect(header, (size_t)sysconf(_SC_PAGESIZE), PROT_READ | PROT_WRITE) == 0);
        memcpy(header + 0x3c1, header + 0x280, 56);
        corruptAndCheck<uint32_t>(cache, base + 0x8000 + 0x138, 0x3c1);
      }
      // more sub-caches than the walk allows, all of them well formed (entries pointing back at the main header)
      {
        uint8_t *entries = (uint8_t *)(base + 0x300);
        std::vector<uint8_t> saved(entries + 112, entries + 33 * 56);
        memset(entries + 112, 0, saved.size());
        corruptAndCheck<uint32_t>(cache, base + 0x18c, 33);
        memcpy(entries + 112, saved.data(), saved.size());
        assert(countRegions(cache) == 3);
      }
      printf("RESULT ok\\n");
      return 0;
    }
  CPP
  failed_build = SplitCacheHarness.compile(root, dir, ['-fsanitize=address,undefined'])
  abort failed_build if failed_build
  failures = 0
  VARIANTS.each do |variant, expected_error|
    next puts("skip #{variant} (needs a host page larger than 4 KiB)") if expected_error == :skip
    fixture = "#{dir}/#{variant}"
    out, st = Open3.capture2e('python3', '-I', "#{root}/tests/gen-split-cache-fixture.py", fixture, '--base', base, '--variant', variant)
    abort out unless st.success?
    out, st = Open3.capture2e("#{dir}/test", fixture)
    result = out[/^RESULT .*$/]
    good = st.success? && result &&
           (expected_error ? (result.start_with?('RESULT error:') && result.include?(expected_error)) : result == 'RESULT ok')
    puts "#{good ? 'ok  ' : 'FAIL'} #{variant}#{result ? " (#{result})" : ''}"
    unless good
      failures += 1
      puts out.lines.last(8).join
    end
  end
  # a second cache at another base, mapped by a fresh process, enumerates its own regions
  other = '0x1c0000000'
  out, st = Open3.capture2e('python3', '-I', "#{root}/tests/gen-split-cache-fixture.py", "#{dir}/other", '--base', other)
  abort out unless st.success?
  out, st = Open3.capture2e("#{dir}/test", "#{dir}/other")
  puts "#{out[/^RESULT .*$/] == 'RESULT ok' && st.success? ? 'ok  ' : 'FAIL'} valid at #{other}"
  failures += 1 unless out[/^RESULT .*$/] == 'RESULT ok' && st.success?
  abort "#{failures} split-cache mapping scenario(s) failed" unless failures.zero?
  puts 'PASS split cache mapping, plain rebase, authenticated entries untouched and counted, and image lookup'
end
