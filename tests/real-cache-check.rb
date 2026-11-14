# Maps a real split dyld shared cache with the actual mapSplitCachePrivate and checks the result against an
# independent walk of the slide info (pread of the files, no mapping code shared with the mapper), then
# exercises the DyldSharedCache image helpers on the mapped cache. Opt-in: it reads the cache you point it at
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
      printf("mapped: load=%p files=%u mappings=%u pagesWithChains=%llu plainRebased=%llu authLeftAlone=%llu\\n",
             (const void *)result.loadAddress, stats.files, stats.mappings, (unsigned long long)stats.pagesWithChains,
             (unsigned long long)stats.plainRebased, (unsigned long long)stats.authLeftAlone);

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
      uint64_t pages = 0, plain = 0, auth = 0, bad = 0, outside = 0, shown = 0;
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
              if (raw >> 63) { ++auth; expect = raw; }
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
      printf("independent walk: pages=%llu plain=%llu auth=%llu plain-targets-outside-region=%llu mismatches=%llu\\n",
             (unsigned long long)pages, (unsigned long long)plain, (unsigned long long)auth, (unsigned long long)outside, (unsigned long long)bad);
      assert(pages == stats.pagesWithChains && plain == stats.plainRebased && auth == stats.authLeftAlone);
      assert(bad == 0 && outside == 0);

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
  puts 'PASS real cache mapped, every slide-info slot matches an independent walk, image helpers agree'
end
