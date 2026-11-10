# Actual mapSplitCachePrivate, slide-info-v5 rebase and the DyldSharedCache image helpers, run against
# a synthetic 3-file split cache (tests/gen-split-cache-fixture.py). No Apple cache content is used.
# Authenticated entries are checked with the PAC instructions themselves (autia/autda, executed with the
# process's own keys), so this needs an arm64 Linux host with pointer authentication for the signing scenarios.
# Requires Linux (MAP_FIXED, /proc/self/maps), Ruby, python3 and clang++.
# Usage: ruby tests/split-cache-mapping.rb [checkout] [base-address]
# The synthetic region is mapped at base-address (default 0x180000000), which must be free.
require 'tmpdir'
require 'open3'
require 'rbconfig'
require 'fileutils'
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

HWCAP_PACA = 1 << 30
EXECUTES_PAC = %w[sign_host auth_target_outside_region]
def auxv(*pairs) = (pairs + [[0, 0]]).map { |t, v| [t, v].pack('QQ') }.join

# The host's own capability decides whether the signing scenario can run: the PAC instructions are undefined
# without it. Only the scenarios in EXECUTES_PAC run them (auth_target_outside_region signs the page-1 slots before it
# reaches the bad one); the other fabricated auxiliary vectors stop the mapper before the first signature.
host_hwcap = File.binread('/proc/self/auxv').unpack('Q*').each_slice(2).find { |type, _| type == 16 }&.last.to_i
host_pac = RbConfig::CONFIG['host_cpu'] =~ /aarch64|arm64/ && (host_hwcap & HWCAP_PACA) != 0

# name => [fixture variant, mode, auxv file content (nil: the host's own), expected result]. The auxiliary vector
# is how the mapper learns whether the host can sign; the fabricated ones stand in for hosts that cannot.
SCENARIOS = {
  'sign_host' => ['valid', 'sign', nil, nil],
  'auth_target_outside_region' => ['auth_target_outside_region', 'sign', auxv([16, HWCAP_PACA]), 'outside the cache region'],
  'leave_alone' => ['valid', 'leave', nil, nil],
  'leave_alone_no_pac' => ['valid', 'leave', auxv([16, 3]), nil],
  'no_pac_fails' => ['valid', 'sign', auxv([16, 3]), 'has no pointer authentication'],
  'no_pac_without_auth_entries_maps' => ['no_auth', 'sign', auxv([16, 3]), nil],
  'no_hwcap_fails' => ['valid', 'sign', auxv([6, 16384]), 'has no AT_HWCAP'],
  'auxv_truncated_fails' => ['valid', 'sign', [16].pack('Q'), 'is unreadable'],
  'auxv_missing_fails' => ['valid', 'sign', :missing, 'cannot be opened'],
}

missing_src = File.read("#{root}/dyld3/SharedCacheRuntime.cpp")[/^bool splitCacheMainFileIsMissing\(.*?^\}/m] or abort 'splitCacheMainFileIsMissing missing'

Dir.mktmpdir('split-cache-mapping-') do |dir|
  File.write("#{dir}/test.cpp", <<~CPP)
    #{SplitCacheHarness.prefix(root)}
    #include <sys/wait.h>

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
    // --- independent oracle: the PAC instructions, written here and not shared with the mapper ---
    __attribute__((target("arch=armv8.3-a"))) static uint64_t authenticate(int isData, uint64_t signedValue, uint64_t modifier, int otherKey) {
      // otherKey: 0 = the key named by isData, 1 = the other A key class (IA <-> DA), 2 = IB or DB
      const int cls = (otherKey == 1) ? !isData : isData;
      if (otherKey == 2) { if (isData) asm("autdb %0, %1" : "+r"(signedValue) : "r"(modifier)); else asm("autib %0, %1" : "+r"(signedValue) : "r"(modifier)); }
      else if (cls) asm("autda %0, %1" : "+r"(signedValue) : "r"(modifier));
      else asm("autia %0, %1" : "+r"(signedValue) : "r"(modifier));
      return signedValue;
    }
    // True when authentication hands back exactly the target. A hardware that traps on failure (FPAC) kills the
    // child, which counts as a failed authentication.
    static bool authenticates(int isData, uint64_t signedValue, uint64_t modifier, int otherKey, uint64_t target) {
      fflush(stdout);
      pid_t pid = fork(); assert(pid >= 0);
      if (pid == 0) _exit(authenticate(isData, signedValue, modifier, otherKey) == target ? 0 : 1);
      int status = 0; assert(waitpid(pid, &status, 0) == pid);
      return WIFEXITED(status) && WEXITSTATUS(status) == 0;
    }
    // PAC is a truncated MAC (about 7 bits with a 48-bit address space), so one wrong guess can pass by chance
    // (1 in 128). The checks that a wrong input is rejected therefore pool their trials and ask for a clear majority.
    struct Rejections { const char *name; unsigned trials = 0, rejected = 0;
      void add(bool authenticated) { ++trials; if (!authenticated) ++rejected; }
      void check() const { printf("rejected %s: %u of %u\\n", name, rejected, trials); assert(trials >= 4 && rejected * 2 > trials); } };

    // The real "no cache for this architecture" test, on the real directory the harness lays out below.
    namespace dyld3 {
      static int stat(const char *path, struct stat *buf) { return ::stat(path, buf); }
      #{missing_src}
    }

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
      assert(argc >= 3);
      std::string dir = argv[1];
      const bool sign = !strcmp(argv[2], "sign");
      if (argc > 3) gAuxvPath = argv[3];
      FILE *manifest = fopen((dir + "/manifest.txt").c_str(), "r"); assert(manifest);
      uint64_t base = 0, imageAddress = 0, regionSize = 0;
      char installName[128] = "", word[32], a[64], b[64], c[64], d[64], e[64];
      unsigned files = 0, mappingsExpected = 0; unsigned long long pages = 0, plainExpected = 0, authExpected = 0;
      struct Slot { uint64_t address, value; }; Slot expect[16], untouched[16]; unsigned nExpect = 0, nUntouched = 0;
      struct AuthSlot { uint64_t address, target, raw; int key, addrDiv; uint16_t diversity; }; AuthSlot auths[32]; unsigned nAuth = 0;
      char line[256];
      while (fgets(line, sizeof line, manifest)) {
        if (sscanf(line, "%31s %63s %63s %63s %63s %63s", word, a, b, c, d, e) < 1) continue;
        if (!strcmp(word, "base")) base = hex(a);
        else if (!strcmp(word, "image")) { imageAddress = hex(a); strcpy(installName, b); }
        else if (!strcmp(word, "region")) regionSize = hex(b);
        else if (!strcmp(word, "stats")) sscanf(line, "stats files=%u mappings=%u pages=%llu plain=%llu auth=%llu", &files, &mappingsExpected, &pages, &plainExpected, &authExpected);
        else if (!strcmp(word, "expect")) expect[nExpect++] = {hex(a), hex(b)};
        else if (!strcmp(word, "auth")) { unsigned long long x, t, r; int k, ad; unsigned dv; sscanf(line, "auth %llx %llx %d %d %x %llx", &x, &t, &k, &ad, &dv, &r); auths[nAuth++] = {x, t, r, k, ad, (uint16_t)dv}; }
        else if (!strcmp(word, "untouched")) untouched[nUntouched++] = {hex(a), hex(b)};
      }
      fclose(manifest);

      SharedCacheLoadInfo result = {}; SplitCacheMapStats stats;
      std::string mainFile = dir + "/cache";
      if (argc > 4 && !strcmp(argv[4], "named")) {
        // macOS ships dyld_shared_cache_arm64e only: an arm64 process finds no main file there, an arm64e one maps it
        assert(dyld3::splitCacheMainFileIsMissing(dir.c_str(), (dir + "/dyld_shared_cache_arm64").c_str()));
        assert(!dyld3::splitCacheMainFileIsMissing(dir.c_str(), (dir + "/dyld_shared_cache_arm64e").c_str()));
        assert(!dyld3::splitCacheMainFileIsMissing((dir + "/no-such-dir").c_str(), (dir + "/no-such-dir/dyld_shared_cache_arm64").c_str()));
        mainFile = dir + "/dyld_shared_cache_arm64e";
      }
      bool ok = mapSplitCachePrivate(mainFile.c_str(), true, &result, &stats, sign ? kSplitCacheAuthSign : kSplitCacheAuthLeaveAlone);
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
      assert(stats.plainRebased == plainExpected);
      assert(stats.authSigned == (sign ? authExpected : 0) && stats.authLeftAlone == (sign ? 0 : authExpected));
      for (unsigned i = 0; i < nExpect; ++i) assert(*(uint64_t *)expect[i].address == expect[i].value);
      assert(nAuth == authExpected);
      if (!sign) for (unsigned i = 0; i < nAuth; ++i) assert(*(uint64_t *)auths[i].address == auths[i].raw);
      if (sign && nAuth) {
        Rejections wrongModifier = {"a wrong modifier"}, wrongKey = {"a wrong key"}, blendOmitted = {"the address blend omitted"}, blendAdded = {"a blend nobody asked for"};
        bool seenKey[2] = {}, seenAddrDiv[2] = {}, seenZero = false, seenMax = false;
        for (unsigned i = 0; i < nAuth; ++i) {
          const AuthSlot &a = auths[i];
          const uint64_t signedValue = *(uint64_t *)a.address;
          const uint64_t blend = (a.address & 0x0000ffffffffffffULL) | ((uint64_t)a.diversity << 48);
          const uint64_t modifier = a.addrDiv ? blend : a.diversity;
          // the right key and modifier give back exactly the target, the same address the plain entries get
          assert(authenticates(a.key, signedValue, modifier, 0, a.target));
          for (unsigned bit = 0; bit < 16; ++bit) wrongModifier.add(authenticates(a.key, signedValue, modifier ^ (1ULL << bit), 0, a.target));
          wrongKey.add(authenticates(a.key, signedValue, modifier, 1, a.target));
          wrongKey.add(authenticates(a.key, signedValue, modifier, 2, a.target));
          (a.addrDiv ? blendOmitted : blendAdded).add(authenticates(a.key, signedValue, a.addrDiv ? a.diversity : blend, 0, a.target));
          seenKey[a.key] = seenAddrDiv[a.addrDiv] = true; seenZero |= a.diversity == 0; seenMax |= a.diversity == 0xffff;
        }
        assert(seenKey[0] && seenKey[1] && seenAddrDiv[0] && seenAddrDiv[1] && seenZero && seenMax);
        wrongModifier.check(); wrongKey.check(); blendOmitted.check(); blendAdded.check();
        printf("authenticated %u signed slots\\n", nAuth);
      }
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
  run = lambda do |label, variant, mode, auxv_content, expected_error|
    fixture = "#{dir}/#{label}"
    out, st = Open3.capture2e('python3', '-I', "#{root}/tests/gen-split-cache-fixture.py", fixture, '--base', base, '--variant', variant)
    abort out unless st.success?
    args = [fixture, mode]
    if auxv_content
      auxv_path = "#{fixture}/auxv"
      File.binwrite(auxv_path, auxv_content) unless auxv_content == :missing
      args << (auxv_content == :missing ? "#{fixture}/no-such-auxv" : auxv_path)
    end
    out, st = Open3.capture2e("#{dir}/test", *args)
    result = out[/^RESULT .*$/]
    good = st.success? && result &&
           (expected_error ? (result.start_with?('RESULT error:') && result.include?(expected_error)) : result == 'RESULT ok')
    puts "#{good ? 'ok  ' : 'FAIL'} #{label}#{result ? " (#{result})" : ''}"
    out.each_line { |l| puts "       #{l}" if l.start_with?('rejected', 'authenticated') }
    unless good
      failures += 1
      puts out.lines.last(8).join
    end
  end
  # The structural variants fail before any authenticated entry matters, so they run in the host-independent mode.
  VARIANTS.each do |variant, expected_error|
    next puts("skip #{variant} (needs a host page larger than 4 KiB)") if expected_error == :skip
    run.call(variant, variant, 'leave', nil, expected_error)
  end
  SCENARIOS.each do |label, (variant, mode, auxv_content, expected_error)|
    next puts("skip #{label} (host has no pointer authentication)") if EXECUTES_PAC.include?(label) && !host_pac
    run.call(label, variant, mode, auxv_content, expected_error)
  end
  # The directory as macOS lays it out: the arm64e main file and its sub-caches under their real names, nothing for arm64.
  out, st = Open3.capture2e('python3', '-I', "#{root}/tests/gen-split-cache-fixture.py", "#{dir}/named", '--base', base)
  abort out unless st.success?
  %w[cache cache.01 cache.02.dylddata].each { |f| FileUtils.cp("#{dir}/named/#{f}", "#{dir}/named/dyld_shared_cache_arm64e#{f.sub('cache', '')}") }
  out, st = Open3.capture2e("#{dir}/test", "#{dir}/named", 'leave', '/proc/self/auxv', 'named')
  named_ok = st.success? && out[/^RESULT .*$/] == 'RESULT ok'
  puts "#{named_ok ? 'ok  ' : 'FAIL'} arm64e main file by its real name maps, arm64 has none (#{out[/^RESULT .*$/]})"
  failures += 1 unless named_ok
  # the log names the file only, never the directory it was found in
  mapped_line = out[/^LOG mapped split dyld cache private to process \(.*$/]
  hidden = mapped_line&.start_with?('LOG mapped split dyld cache private to process (dyld_shared_cache_arm64e):') && !out.include?(dir)
  puts "#{hidden ? 'ok  ' : 'FAIL'} the mapping log carries the file name and not the directory"
  failures += 1 unless hidden
  # a second cache at another base, mapped by a fresh process, enumerates its own regions
  other = '0x1c0000000'
  out, st = Open3.capture2e('python3', '-I', "#{root}/tests/gen-split-cache-fixture.py", "#{dir}/other", '--base', other)
  abort out unless st.success?
  out, st = Open3.capture2e("#{dir}/test", "#{dir}/other", 'leave')
  puts "#{out[/^RESULT .*$/] == 'RESULT ok' && st.success? ? 'ok  ' : 'FAIL'} valid at #{other}"
  failures += 1 unless out[/^RESULT .*$/] == 'RESULT ok' && st.success?
  abort "#{failures} split-cache mapping scenario(s) failed" unless failures.zero?
  puts 'PASS split cache mapping, plain rebase, authenticated entries signed (or left alone on request), PAC-less hosts rejected, and image lookup'
end
