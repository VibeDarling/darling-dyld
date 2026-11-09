# Maps a real split dyld shared cache with the actual mapSplitCachePrivate and checks the result against an
# independent walk of the slide info (pread of the files, no mapping code shared with the mapper), then
# exercises the DyldSharedCache image helpers on the mapped cache. Authenticated slots are checked with the
# PAC instructions (autia/autda with the process's own keys, so this needs a PAC-capable arm64 Linux host)
# against the independently decoded key, modifier and target. Opt-in: it reads the cache you point it at
# and the process peaks at several GB of memory, so it is skipped unless DYLD_REAL_CACHE_DIR is set.
#
#   DYLD_REAL_CACHE_DIR   directory holding dyld_shared_cache_arm64e and its sub-cache files
#   DYLD_REAL_CACHE_IMAGE install name to look up (optional; without it only the image count is checked)
#
# Usage: DYLD_REAL_CACHE_DIR=... [DYLD_REAL_CACHE_IMAGE=...] ruby tests/real-cache-check.rb [checkout]
# The cache is mapped at its own preferred address (0x180000000 for an arm64e macOS cache), which must be free.
require 'tmpdir'
require 'open3'
root = File.realpath(ARGV.fetch(0, File.expand_path('..', __dir__)))
dir_env = ENV['DYLD_REAL_CACHE_DIR']
main_file = dir_env && File.join(dir_env, 'dyld_shared_cache_arm64e')
unless main_file && File.file?(main_file)
  puts 'SKIP real-cache-check: set DYLD_REAL_CACHE_DIR to a directory containing dyld_shared_cache_arm64e'
  exit 0
end
require_relative 'split-cache-harness'

Dir.mktmpdir('real-cache-check-') do |dir|
  File.write("#{dir}/test.cpp", <<~CPP)
    #{SplitCacheHarness.prefix(root, real_trie: true)}
    #include <unordered_map>

    // Standard export-trie walk (the tests stub the dyld one): the terminal info of symbol, or null.
    const uint8_t *dyld3::MachOLoaded::trieWalk(Diagnostics&, const uint8_t *start, const uint8_t *end, const char *symbol) {
      Diagnostics d; const uint8_t *p = start; const char *s = symbol;
      while (p < end) {
        const uint8_t *q = p; uint64_t termSize = dyld3::MachOFile::read_uleb128(d, q, end);
        if (*s == 0) return termSize ? q : nullptr;
        const uint8_t *c = q + termSize; if (c >= end) return nullptr;
        unsigned count = *c++; const uint8_t *next = nullptr;
        for (unsigned i = 0; i < count && c < end; ++i) {
          const char *t = s; const char *l = (const char *)c;
          while (*l && *t == *l) { ++l; ++t; }
          const uint8_t *e = c; while (*e) ++e; ++e;
          uint64_t off = dyld3::MachOFile::read_uleb128(d, e, end);
          if (*l == 0) { next = start + off; s = t; break; }
          c = e;
        }
        if (!next) return nullptr;
        p = next;
      }
      return nullptr;
    }

    // Independent of the mapper: authenticate a signed slot, 0 = IA key, 1 = DA key; returns the stripped pointer or garbage.
    // On hardware with FPAC a failed authentication faults here and kills the process before the counts below are
    // printed, which is still a loud failure of the check.
    __attribute__((target("arch=armv8.3-a"))) static uint64_t authenticate(int isData, uint64_t value, uint64_t modifier) {
      if (isData) asm("autda %0, %1" : "+r"(value) : "r"(modifier)); else asm("autia %0, %1" : "+r"(value) : "r"(modifier));
      return value;
    }

    struct StubSlot { uint64_t raw = 0, valueAdd = 0; bool found = false; };

    static unsigned gImages, gRegions;
    static uint64_t le64(const uint8_t *p) { uint64_t v; memcpy(&v, p, 8); return v; }
    static uint32_t le32(const uint8_t *p) { uint32_t v; memcpy(&v, p, 4); return v; }
    static void preadall(int fd, void *buf, size_t n, uint64_t off) {
      size_t d = 0; while (d < n) { ssize_t r = pread(fd, (char *)buf + d, n - d, off + d); assert(r > 0); d += (size_t)r; }
    }

    int main(int argc, char **argv) {
      setvbuf(stdout, NULL, _IONBF, 0);
      assert(argc >= 2);
      std::string mainPath = argv[1];
      const char *image = argc > 2 ? argv[2] : nullptr;
      SharedCacheLoadInfo result = {}; SplitCacheMapStats stats = {};
      if (!mapSplitCachePrivate(mainPath.c_str(), true, &result, &stats)) {
        printf("RESULT error: %s\\n", result.errorMessage ? result.errorMessage : "(none)");
        return 1;
      }
      printf("mapped: load=%p files=%u mappings=%u pagesWithChains=%llu plainRebased=%llu authSigned=%llu authLeftAlone=%llu\\n",
             (const void *)result.loadAddress, stats.files, stats.mappings, (unsigned long long)stats.pagesWithChains,
             (unsigned long long)stats.plainRebased, (unsigned long long)stats.authSigned, (unsigned long long)stats.authLeftAlone);

      // independent walk of every slide-info chain straight from the files, compared with the mapped memory
      std::vector<std::string> paths; paths.push_back(mainPath);
      int mfd = ::open(mainPath.c_str(), O_RDONLY); assert(mfd >= 0);
      uint8_t hdr[0x400]; preadall(mfd, hdr, sizeof hdr, 0);
      uint32_t subOffset = le32(hdr + 0x188), subCount = le32(hdr + 0x18c);
      for (uint32_t i = 0; i < subCount; ++i) {
        uint8_t e[56]; preadall(mfd, e, 56, subOffset + (uint64_t)i * 56);
        char suffix[33] = {0}; memcpy(suffix, e + 24, 32); paths.push_back(mainPath + suffix);
      }
      close(mfd);
      uint64_t regionStart = le64(hdr + 0xe0), regionSize = le64(hdr + 0xe8);
      uint64_t pages = 0, plain = 0, auth = 0, bad = 0, outside = 0, shown = 0, authBad = 0, authOutside = 0;

      // Consumer cross-check of the key and diversity bits: every arm64e auth stub (adrp x17; add x17, x17, #lo12;
      // ldr x16, [x17]; braa x16, x17) authenticates its GOT slot with the IA key and the slot address as modifier, so
      // that slot's chain entry must say IA, address diversity and diversity 0. The images are found through the
      // image table and their Mach-O headers parsed here, not through the mapper's helpers.
      std::unordered_map<uint64_t, StubSlot> stubSlots; uint64_t stubs = 0;
      {
        int ifd = ::open(mainPath.c_str(), O_RDONLY); assert(ifd >= 0);
        uint32_t imagesOffset = le32(hdr + 0x1c0), imagesCount = le32(hdr + 0x1c4);
        const uint64_t regionEnd = regionStart + regionSize;
        for (uint32_t i = 0; i < imagesCount; ++i) {
          uint8_t info[32]; preadall(ifd, info, sizeof info, imagesOffset + (uint64_t)i * 32);
          uint64_t imageAddress = le64(info); assert(imageAddress >= regionStart && imageAddress + 32 < regionEnd);
          const uint8_t *header = (const uint8_t *)imageAddress; assert(le32(header) == 0xFEEDFACF);
          uint32_t ncmds = le32(header + 16), sizeofcmds = le32(header + 20);
          assert(sizeofcmds <= 0x100000 && imageAddress + 32 + sizeofcmds <= regionEnd);
          const uint8_t *cmd = header + 32, *cmdsEnd = cmd + sizeofcmds;
          for (uint32_t c = 0; c < ncmds; ++c) {
            assert(cmd + 8 <= cmdsEnd); uint32_t id = le32(cmd), size = le32(cmd + 4); assert(size >= 8 && cmd + size <= cmdsEnd);
            if (id == 0x19 && size >= 72) {
              uint32_t nsects = le32(cmd + 64); assert(72 + 80ULL * nsects <= size);
              for (uint32_t k = 0; k < nsects; ++k) {
                const uint8_t *sect = cmd + 72 + 80 * k;
                if (strncmp((const char *)sect, "__auth_stubs", 16) != 0) continue;
                uint64_t sectAddress = le64(sect + 32), sectSize = le64(sect + 40);
                assert(sectAddress >= regionStart && sectAddress + sectSize <= regionEnd);
                for (uint64_t off = 0; off + 16 <= sectSize; off += 16) {
                  const uint8_t *stub = (const uint8_t *)(sectAddress + off);
                  uint32_t adrp = le32(stub), add = le32(stub + 4);
                  if ((adrp & 0x9F00001F) != 0x90000011 || (add & 0xFF8003FF) != 0x91000231 || le32(stub + 8) != 0xF9400230 || le32(stub + 12) != 0xD71F0A11) continue;
                  int64_t pageDelta = (int64_t)(((adrp >> 5) & 0x7FFFF) << 2 | ((adrp >> 29) & 3));
                  if (pageDelta & 0x100000) pageDelta -= 0x200000;
                  uint64_t imm12 = (add >> 10) & 0xFFF; if ((add >> 22) & 1) imm12 <<= 12;
                  uint64_t slot = (((sectAddress + off) & ~0xFFFULL) + (uint64_t)(pageDelta * 4096)) + imm12;
                  stubSlots.emplace(slot, StubSlot()); ++stubs;
                }
              }
            }
            cmd += size;
          }
        }
        close(ifd);
      }
      for (const std::string &p : paths) {
        int fd = ::open(p.c_str(), O_RDONLY); assert(fd >= 0);
        uint8_t h[0x200]; preadall(fd, h, sizeof h, 0);
        uint32_t tableOffset = le32(h + 0x138), tableCount = le32(h + 0x13c);
        for (uint32_t m = 0; m < tableCount; ++m) {
          uint8_t e[56]; preadall(fd, e, 56, tableOffset + (uint64_t)m * 56);
          uint64_t addr = le64(e), size = le64(e + 8), fileOffset = le64(e + 16), slideOffset = le64(e + 24), slideSize = le64(e + 32);
          if (!slideSize) continue;
          std::vector<uint8_t> si(slideSize); preadall(fd, si.data(), slideSize, slideOffset);
          assert(le32(si.data()) == 5);
          uint32_t pageSize = le32(si.data() + 4), pageCount = le32(si.data() + 8); uint64_t valueAdd = le64(si.data() + 16);
          std::vector<uint8_t> page(pageSize);
          for (uint32_t i = 0; i < pageCount; ++i) {
            uint16_t start; memcpy(&start, si.data() + 24 + 2 * i, 2);
            if (start == 0xFFFF) continue;
            ++pages;
            uint64_t pageAddr = addr + (uint64_t)i * pageSize; assert(pageAddr + pageSize <= addr + size);
            preadall(fd, page.data(), pageSize, fileOffset + (pageAddr - addr));
            uint32_t off = start;
            for (;;) {
              assert(off + 8 <= pageSize);
              uint64_t raw = le64(page.data() + off), loc = pageAddr + off, mapped = *(const uint64_t *)loc, expect;
              auto stubSlot = stubSlots.find(loc);
              if (stubSlot != stubSlots.end()) stubSlot->second = {raw, valueAdd, true};
              if (raw >> 63) {
                // signed in place: the key, modifier and target are decoded here from the on-disk entry
                ++auth;
                uint64_t target = valueAdd + (raw & 0x3ffffffffULL), diversity = (raw >> 34) & 0xffff;
                uint64_t modifier = ((raw >> 50) & 1) ? ((loc & 0x0000ffffffffffffULL) | (diversity << 48)) : diversity;
                if (target < regionStart || target >= regionStart + regionSize) ++authOutside;
                if (authenticate((raw >> 51) & 1, mapped, modifier) != target) ++authBad;
                expect = mapped;   // the signed value itself is not predictable, authentication is its check
              }
              else {
                ++plain;
                expect = (valueAdd + (raw & 0x3ffffffffULL)) | (((raw >> 34) & 0xff) << 56);
                uint64_t target = expect & 0x00ffffffffffffffULL;
                if (target < regionStart || target >= regionStart + regionSize) ++outside;
              }
              if (mapped != expect) {
                ++bad;
                if (shown++ < 5) printf("MISMATCH at region offset %#llx (%s)\\n", (unsigned long long)(loc - regionStart), (raw >> 63) ? "auth" : "plain");
              }
              unsigned next = (raw >> 52) & 0x7ff; if (!next) break; off += next * 8;
            }
          }
        }
        close(fd);
      }
      printf("independent walk: pages=%llu plain=%llu auth=%llu plain-targets-outside-region=%llu mismatches=%llu auth-targets-outside-region=%llu auth-failures=%llu\\n",
             (unsigned long long)pages, (unsigned long long)plain, (unsigned long long)auth, (unsigned long long)outside, (unsigned long long)bad,
             (unsigned long long)authOutside, (unsigned long long)authBad);
      assert(pages == stats.pagesWithChains && plain == stats.plainRebased && auth == stats.authSigned && stats.authLeftAlone == 0);
      assert(bad == 0 && outside == 0 && authOutside == 0 && authBad == 0);

      uint64_t checked = 0, notChain = 0, notAuth = 0, wrongKey = 0, wrongAddrDiv = 0, wrongDiversity = 0, stubAuthBad = 0;
      for (const auto &entry : stubSlots) {
        const StubSlot &s = entry.second;
        if (!s.found) { ++notChain; continue; }
        ++checked;
        if (!(s.raw >> 63)) { ++notAuth; continue; }
        wrongKey += (s.raw >> 51) & 1;
        wrongAddrDiv += !((s.raw >> 50) & 1);
        wrongDiversity += ((s.raw >> 34) & 0xffff) != 0;
        if (authenticate(0, *(const uint64_t *)entry.first, entry.first & 0x0000ffffffffffffULL) != s.valueAdd + (s.raw & 0x3ffffffffULL)) ++stubAuthBad;
      }
      uint64_t violations = notAuth + wrongKey + wrongAddrDiv + wrongDiversity + stubAuthBad;
      printf("auth stubs: stubs=%llu slots=%zu checked=%llu not-chain-entries=%llu violations=%llu (not-auth=%llu wrong-key=%llu no-addr-div=%llu diversity-not-0=%llu autia-failures=%llu)\\n",
             (unsigned long long)stubs, stubSlots.size(), (unsigned long long)checked, (unsigned long long)notChain, (unsigned long long)violations,
             (unsigned long long)notAuth, (unsigned long long)wrongKey, (unsigned long long)wrongAddrDiv, (unsigned long long)wrongDiversity, (unsigned long long)stubAuthBad);
      assert(checked > 0 && violations == 0);

      const DyldSharedCache *cache = result.loadAddress;
      if (image) {
        uint32_t index = 0; assert(cache->hasImagePath(image, index));
        uint64_t mTime, inode; const mach_header *mh = cache->getIndexedImageEntry(index, mTime, inode);
        printf("hasImagePath(%s) index %u, header magic %#x\\n", image, index, mh->magic);
        assert(mh->magic == 0xFEEDFACF && strcmp(cache->getIndexedImagePath(index), image) == 0);
      }
      cache->forEachImage(^(const mach_header *, const char *) { ++gImages; });
      cache->forEachRegion(^(const void *, uint64_t, uint64_t, uint32_t, uint32_t, uint64_t) { ++gRegions; });
      uint32_t tableImages = 0; cache->imageTable(tableImages);
      printf("forEachImage=%u imageTable=%u forEachRegion=%u mappings=%u mappedSize=%#llx\\n", gImages, tableImages, gRegions,
             stats.mappings, (unsigned long long)cache->mappedSize());
      assert(gImages == tableImages && gRegions == stats.mappings && cache->mappedSize() == regionSize);
      printf("RESULT ok\\n");
      return 0;
    }
  CPP
  failed_build = SplitCacheHarness.compile(root, dir)
  abort failed_build if failed_build
  args = [main_file]
  args << ENV['DYLD_REAL_CACHE_IMAGE'] if ENV['DYLD_REAL_CACHE_IMAGE'] && !ENV['DYLD_REAL_CACHE_IMAGE'].empty?
  out, st = Open3.capture2e("#{dir}/test", *args)
  puts out
  abort 'real-cache check failed' unless st.success? && out.include?('RESULT ok')
  puts 'PASS real cache mapped, plain slots match an independent walk, every authenticated slot authenticates to its target, auth stubs agree with the key and diversity bits, image helpers agree'
end
