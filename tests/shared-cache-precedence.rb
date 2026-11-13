# The cache-versus-disk precedence rule for split caches: the actual chooseSharedCacheLoadSource,
# sharedCachePathIsAllowListed, pathIsPinnedToSharedCache and findInSharedCacheImage from
# dyld3/SharedCacheRuntime.cpp, with the DyldSharedCache accessors stubbed. The legacy rows assert the
# behaviour dyld had before the rule existed (a file on disk wins; the allow-list is ignored).
# Usage: ruby tests/shared-cache-precedence.rb [checkout]
require 'tmpdir'
require 'open3'
root = File.realpath(ARGV.fetch(0, File.expand_path('..', __dir__)))
source = File.read("#{root}/dyld3/SharedCacheRuntime.cpp")
header = File.read("#{root}/dyld3/SharedCacheRuntime.h")
lookup = source[/bool findInSharedCacheImage\(.*?^\}/m] or abort 'lookup missing'
policy = source[/^static const char\* const kSharedCacheServedOverDisk\[\].*?^bool pathIsPinnedToSharedCache\(.*?^\}/m] or abort 'policy missing'
decls = (header[/^static const uint32_t kNoCacheImageIndex.*?^\};/m] or abort 'results struct missing') + "\n" +
        (header[/^enum SharedCacheLoadSource.*?^bool pathIsPinnedToSharedCache\(.*?;/m] or abort 'policy declarations missing')

Dir.mktmpdir('shared-cache-precedence-') do |dir|
  File.write("#{dir}/test.cpp", <<~CPP)
    #include <stdint.h>
    #include <stddef.h>
    #include <string.h>
    #include <assert.h>
    #include <stdio.h>
    #include <string>
    #define TARGET_OS_IPHONE 0
    struct mach_header {};
    struct dyld_cache_image_info { uint64_t address,modTime,inode; uint32_t pathFileOffset,pad; };
    namespace dyld3 {
    namespace closure { const unsigned kFormatVersion=1; struct Image { uintptr_t cacheOffset() const { return 0; } const char *path() const { return ""; } }; struct ImageArray { const Image *imageForNum(uint32_t) const { return nullptr; } }; }
    struct DyldSharedCache {
      struct Header { unsigned formatVersion=2,mappingOffset=0x200,imagesOffset=0,imagesCount=0; uint64_t dylibsImageArrayAddr=0,dylibsTrieAddr=1,dylibsTrieSize=1; } header;
      bool split=true;
      bool isSplitCache() const { return split; }
      const dyld_cache_image_info *imageTable(uint32_t &count) const { count=header.imagesCount; return (const dyld_cache_image_info*)((const char*)this+header.imagesOffset); }
      // The trie knows the canonical names and the aliases the real cache records.
      bool hasImagePath(const char *path, uint32_t &index) const {
        if ( !strcmp(path,"/usr/lib/libz.dylib") ) { index=0; return true; }
        if ( !strcmp(path,"/usr/lib/libz.1.dylib") ) { index=0; return true; }
        if ( !strcmp(path,"/usr/lib/libobjc.A.dylib") ) { index=1; return true; }
        return false;
      }
      const closure::ImageArray *cachedDylibsImageArray() const { return nullptr; }
    };
    struct SharedCacheLoadInfo { const DyldSharedCache *loadAddress; long slide; };
    #{decls}
    #{lookup}
    #{policy}
    } // namespace dyld3
    using namespace dyld3;

    struct Fixture { DyldSharedCache cache; dyld_cache_image_info images[2]; char libz[32]; char objc[1200]; };
    static const SharedCacheAllowList kNone = { nullptr, 0 };
    static const char* const kTwo[] = { "/usr/lib/foo.dylib", "/usr/lib/system/*" };
    static const SharedCacheAllowList kCustom = { kTwo, 2 };
    static const char* const kLibz[] = { "/usr/lib/libz.1.dylib" };
    static const SharedCacheAllowList kLibzList = { kLibz, 1 };
    static const SharedCacheLoadSource C = kSharedCacheLoadFromCache, D = kSharedCacheLoadFromDisk;
    static int failures = 0;
    #define CHECK(cond) do { if (!(cond)) { printf("FAIL line %d: %s\\n", __LINE__, #cond); ++failures; } } while (0)

    int main() {
      const char* kLibzPath = "/usr/lib/libz.1.dylib";
      const char* kOther = "/usr/lib/libobjc.A.dylib";
      // The shipped list is exactly two entries, each a canonical install name: libz and libexpat.
      CHECK(sharedCacheAllowList().count == 2 && strcmp(sharedCacheAllowList().paths[0], kLibzPath) == 0
            && strcmp(sharedCacheAllowList().paths[1], "/usr/lib/libexpat.1.dylib") == 0);
      CHECK(sharedCachePathIsAllowListed("/usr/lib/libexpat.1.dylib", sharedCacheAllowList()));
      CHECK(!sharedCachePathIsAllowListed("/usr/lib/libexpat.dylib", sharedCacheAllowList()));   // an alias is not the canonical name

      // Full matrix. Columns: split, inCache, existsOnDisk, allow-listed.
      struct Row { bool split, inCache, disk, listed; SharedCacheLoadSource want; };
      static const Row rows[] = {
        // split cache, not in the cache: always disk, whatever the list says
        {1,0,0,0,D}, {1,0,0,1,D}, {1,0,1,0,D}, {1,0,1,1,D},
        // split cache, in the cache and allow-listed: the cache, with or without a disk copy
        {1,1,0,1,C}, {1,1,1,1,C},
        // split cache, in the cache, not allow-listed: a disk copy wins, otherwise the cache
        {1,1,0,0,C}, {1,1,1,0,D},
        // old caches: a file on disk wins, the allow-list is ignored
        {0,0,0,0,D}, {0,0,0,1,D}, {0,0,1,0,D}, {0,0,1,1,D},
        {0,1,0,0,C}, {0,1,0,1,C}, {0,1,1,0,D}, {0,1,1,1,D},
      };
      for (const Row& r : rows) {
        const char* path = r.listed ? kLibzPath : kOther;
        CHECK(chooseSharedCacheLoadSource(r.split, r.inCache, r.disk, path, kLibzList) == r.want);
      }
      // The same decision with the list that really ships.
      CHECK(chooseSharedCacheLoadSource(true, true, true, kLibzPath, sharedCacheAllowList()) == C);
      CHECK(chooseSharedCacheLoadSource(true, true, true, kOther, sharedCacheAllowList()) == D);

      // Exact matches only: no glob, prefix, suffix or case folding; an empty or custom list is honoured.
      CHECK(chooseSharedCacheLoadSource(true, true, true, "/usr/lib/system/libdyld.dylib", kCustom) == D);
      CHECK(chooseSharedCacheLoadSource(true, true, true, "/usr/lib/foo.dylib", kCustom) == C);
      CHECK(chooseSharedCacheLoadSource(true, true, true, "/usr/lib/foo.dylib", kNone) == D);
      CHECK(chooseSharedCacheLoadSource(true, true, true, "/usr/lib/libz.1.dylib2", kLibzList) == D);
      CHECK(chooseSharedCacheLoadSource(true, true, true, "/usr/lib/libz.1.dyli", kLibzList) == D);
      CHECK(chooseSharedCacheLoadSource(true, true, true, "/usr/lib/LIBZ.1.dylib", kLibzList) == D);
      CHECK(chooseSharedCacheLoadSource(true, true, true, "/usr/lib/libz.dylib", kLibzList) == D);   // an alias is not the canonical name

      // An unusable canonical path (NULL, empty, relative, 1024 characters or more) is just not allow-listed:
      // today's rule, the file wins when there is one and the cache otherwise.
      std::string longer = "/" + std::string(1100, 'a');
      for (const char* odd : { (const char*)nullptr, "", "usr/lib/libz.1.dylib", "./usr/lib/libz.1.dylib", longer.c_str() }) {
        CHECK(chooseSharedCacheLoadSource(true, true, true, odd, kLibzList) == D);
        CHECK(chooseSharedCacheLoadSource(true, true, false, odd, kLibzList) == C);
        CHECK(!sharedCachePathIsAllowListed(odd, kLibzList));
      }
      // A path that is not in the cache needs no canonical name.
      CHECK(chooseSharedCacheLoadSource(true, false, true, nullptr, kLibzList) == D);
      CHECK(chooseSharedCacheLoadSource(true, false, false, "", kLibzList) == D);
      // Old caches never look at the path: the answer is the old one for anything.
      CHECK(chooseSharedCacheLoadSource(false, true, false, nullptr, kLibzList) == C);
      CHECK(chooseSharedCacheLoadSource(false, true, true, "", kLibzList) == D);
      CHECK(chooseSharedCacheLoadSource(false, true, true, longer.c_str(), kLibzList) == D);
      CHECK(chooseSharedCacheLoadSource(false, true, false, "relative", kLibzList) == C);

      // Aliases: the lookup yields the canonical name and the cache table index, the rule decides on that name.
      Fixture f = {};
      strcpy(f.libz, kLibzPath); strcpy(f.objc, kOther);
      f.cache.header.imagesOffset = offsetof(Fixture, images); f.cache.header.imagesCount = 2;
      f.images[0].address = 0x100000; f.images[0].pathFileOffset = offsetof(Fixture, libz);
      f.images[1].address = 0x200000; f.images[1].pathFileOffset = offsetof(Fixture, objc);
      SharedCacheLoadInfo load = { &f.cache, 0 };
      SharedCacheFindDylibResults res = {};
      // the lookup first, as loadPhase1 does, then the pin of what it found
      auto pinnedByPath = [&](const SharedCacheLoadInfo& info, const char* path) { SharedCacheFindDylibResults r = {}; findInSharedCacheImage(info, path, &r); return pathIsPinnedToSharedCache(info, r); };
      for (const char* name : { "/usr/lib/libz.dylib", "/usr/lib/libz.1.dylib" }) {
        CHECK(findInSharedCacheImage(load, name, &res) && res.cacheImageIndex == 0 && strcmp(res.pathInCache, kLibzPath) == 0);
        CHECK(chooseSharedCacheLoadSource(true, true, true, res.pathInCache, sharedCacheAllowList()) == C);
        CHECK(pinnedByPath(load, name));
      }
      // The alias string itself must not be what the rule sees: it is not allow-listed, so a disk copy would win.
      CHECK(chooseSharedCacheLoadSource(true, true, true, "/usr/lib/libz.dylib", sharedCacheAllowList()) == D);
      CHECK(findInSharedCacheImage(load, kOther, &res) && res.cacheImageIndex == 1);
      CHECK(!pinnedByPath(load, kOther));
      CHECK(!pinnedByPath(load, "/usr/lib/libnotthere.dylib"));
      CHECK(!pinnedByPath(load, "/usr/lib/libz.1.dylibx"));
      // Both routes agree on a cache image whose recorded path is unusable: not pinned, today's rule.
      for (const char* odd : { "", "relative/libobjc.dylib", longer.c_str() }) {
        strcpy(f.objc, odd);
        CHECK(findInSharedCacheImage(load, kOther, &res) && strcmp(res.pathInCache, odd) == 0);
        CHECK(!pinnedByPath(load, kOther));
        CHECK(chooseSharedCacheLoadSource(true, true, true, res.pathInCache, sharedCacheAllowList()) == D);
        CHECK(chooseSharedCacheLoadSource(true, true, false, res.pathInCache, sharedCacheAllowList()) == C);
      }
      strcpy(f.objc, kOther);
      // Old caches and a missing cache pin nothing, even for the allow-listed path.
      f.cache.split = false;
      CHECK(!pinnedByPath(load, kLibzPath));
      f.cache.split = true;
      SharedCacheLoadInfo none = { nullptr, 0 };
      CHECK(!pinnedByPath(none, kLibzPath));
      // The lookup itself is not filtered by the list: a path that is in the cache but not allow-listed is still found.
      CHECK(findInSharedCacheImage(load, kOther, &res) && strcmp(res.pathInCache, kOther) == 0);

      if (failures) { printf("%d failure(s)\\n", failures); return 1; }
      puts("PASS precedence matrix (split and old caches), exact allow-list matching, unusable paths, alias canonicalisation");
      return 0;
    }
  CPP
  out, ok = Open3.capture2e('clang++', '-std=c++14', '-fsanitize=address,undefined', "#{dir}/test.cpp", '-o', "#{dir}/test")
  abort out unless ok.success?
  out, ok = Open3.capture2e("#{dir}/test")
  puts out
  abort 'shared cache precedence regression failed' unless ok.success?
end
