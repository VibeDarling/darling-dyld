# The precedence rule as dyld2.cpp applies it: the actual loadPhase5load (extracted from src/dyld2.cpp, with
# its collaborators stubbed and the real findInSharedCacheImage and chooseSharedCacheLoadSource behind it),
# the loadPhase1 non-overridable test and the gSharedCacheOverridden test. Checks which copy is loaded,
# that the stat of a shadowed disk file never reaches the cache image, that "disk image overrides cache
# index N" is recorded, and that the lookups stay unfiltered. Rule matrix: tests/shared-cache-precedence.rb.
# Usage: ruby tests/shared-cache-precedence-wiring.rb [checkout]
require 'tmpdir'
require 'open3'
root = File.realpath(ARGV.fetch(0, File.expand_path('..', __dir__)))
dyld2 = File.read("#{root}/src/dyld2.cpp")
dyld2_h = File.read("#{root}/src/dyld2.h")
runtime = File.read("#{root}/dyld3/SharedCacheRuntime.cpp")
runtime_h = File.read("#{root}/dyld3/SharedCacheRuntime.h")
without_root = dyld2[/^static const char\* pathWithoutRoot\(.*?^\}/m] or abort 'pathWithoutRoot missing'
load5 = dyld2[/^static ImageLoader\* loadPhase5load\(.*?^\}/m] or abort 'loadPhase5load missing'
relative = dyld2[/^static bool isFileRelativePath\(.*?^\}/m] or abort 'isFileRelativePath missing'
records = (dyld2[/^static std::vector<DiskOverrideOfCacheImage> sDiskOverridesOfCacheImages;.*?^\}/m] or abort 'override vector missing') + "\n" +
          (dyld2[/^static bool useCacheImageWithoutClosure\(.*?^static void recordDiskOverrideOfCacheImage\(.*?^\}/m] or abort 'override records missing')
forget = dyld2[/\t\/\/ a record of a cache image that this image stood in for.*?sDiskOverridesOfCacheImages\.end\(\)\);/m] or abort 'removeImage erase missing'
record_struct = dyld2_h[/^\tstruct DiskOverrideOfCacheImage \{.*?^\t\};/m] or abort 'override record struct missing'
in_cache = dyld2[/^bool inSharedCache\(const char\* path\)\n\{.*?^\}/m] or abort 'inSharedCache missing'
overridden = dyld2[/if \( !gSharedCacheOverridden && !image->inSharedCache\(\).*?^\t\t\}/m] or abort 'gSharedCacheOverridden test missing'
pinned = dyld2[/bool pathIsInDyldCacheWhichCannotBeOverridden = false;\n\tif \( sSharedCacheLoadInfo.loadAddress != nullptr \) \{.*?^\t\}/m] or abort 'non-overridable test missing'
lookup = runtime[/bool findInSharedCacheImage\(.*?^\}/m] or abort 'lookup missing'
in_cache_lookup = runtime[/^bool pathIsInSharedCacheImage\(.*?^\}/m] or abort 'pathIsInSharedCacheImage missing'
policy = runtime[/^static const char\* const kSharedCacheServedOverDisk\[\].*?^bool pathIsPinnedToSharedCache\(.*?^\}/m] or abort 'policy missing'
decls = (runtime_h[/^static const uint32_t kNoCacheImageIndex.*?^\};/m] or abort 'results struct missing') + "\n" +
        (runtime_h[/^enum SharedCacheLoadSource.*?^bool pathIsPinnedToSharedCache\(.*?;/m] or abort 'policy declarations missing')

Dir.mktmpdir('shared-cache-precedence-wiring-') do |dir|
  File.write("#{dir}/test.cpp", <<~CPP)
    #include <stdint.h>
    #include <stddef.h>
    #include <stdarg.h>
    #include <string.h>
    #include <strings.h>
    #include <assert.h>
    #include <stdio.h>
    #include <errno.h>
    #include <sys/stat.h>
    #include <sys/types.h>
    #include <string>
    #include <vector>
    #include <map>
    #include <algorithm>
    #define SUPPORT_ACCELERATE_TABLES 0
    #define TARGET_OS_SIMULATOR 0
    #define TARGET_OS_IPHONE 0
    #define SUPPORT_ROOT_PATH 1
    // The block runtime is not linked: these blocks are never copied or escaped.
    extern "C" { void *_NSConcreteStackBlock[32]; void *_NSConcreteGlobalBlock[32];
                 void _Block_object_assign(void*, const void*, const int) {}
                 void _Block_object_dispose(const void*, const int) {} }
    struct mach_header { uint32_t magic; };
    typedef struct mach_header macho_header;
    struct dyld_cache_image_info { uint64_t address,modTime,inode; uint32_t pathFileOffset,pad; };
    namespace dyld3 {
      namespace closure {
        const unsigned kFormatVersion = 1;
        struct Image { uintptr_t cacheOffset() const { return 0; } const char* path() const { return ""; } uint32_t imageNum() const { return 0; }
                       bool overridableDylib() const { return true; } bool hasFileModTimeAndInode(uint64_t&, uint64_t&) const { return false; } };
        struct ImageArray { const Image* imageForNum(uint32_t) const { return nullptr; } };
      }
      enum Platform { kPlatformMacOS = 1 };
      struct MachOFile { bool loadableIntoProcess(Platform, const char*) const { return true; } static const char* platformName(Platform) { return "macOS"; } };
      struct DyldSharedCache {
        struct Header { unsigned formatVersion=2,mappingOffset=0x200,imagesOffset=0,imagesCount=0; uint64_t dylibsImageArrayAddr=0,dylibsTrieAddr=1,dylibsTrieSize=1; bool dylibsExpectedOnDisk=false; } header;
        bool split = true;
        bool isSplitCache() const { return split; }
        const dyld_cache_image_info* imageTable(uint32_t& count) const { count = header.imagesCount; return (const dyld_cache_image_info*)((const char*)this + header.imagesOffset); }
        // The trie records the canonical names and the aliases of the real cache.
        bool hasImagePath(const char* path, uint32_t& index) const {
          if ( !strcmp(path, "/usr/lib/libz.dylib") || !strcmp(path, "/usr/lib/libz.1.dylib") ) { index = 0; return true; }
          if ( !strcmp(path, "/usr/lib/libobjc.A.dylib") ) { index = 1; return true; }
          return false;
        }
        bool hasNonOverridablePath(const char*) const { return false; }
        const closure::ImageArray* cachedDylibsImageArray() const { return nullptr; }
      };
      struct SharedCacheLoadInfo { const DyldSharedCache* loadAddress; long slide; };
      struct SharedCacheFindDylibResults;
      #{decls}
      #{lookup}
      #{in_cache_lookup}
      #{policy}
      static std::map<std::string, int> gDisk;             // path -> inode of the file at that path
      int stat(const char* path, struct ::stat* sb) {
        auto it = gDisk.find(path);
        if ( it == gDisk.end() ) { errno = ENOENT; return -1; }   // like the real call, leaves sb untouched
        memset(sb, 0, sizeof(*sb)); sb->st_ino = it->second; sb->st_mtime = 777; return 0;
      }
    }
    using namespace dyld3;
    class ImageLoader {
    public:
      struct LinkContext { bool allowEnvVarsPath = true; const char* const* rootPaths = nullptr; };
      int tag = 0;                       // 1 = cache, 2 = disk
      const void* mh = nullptr;
      uint32_t overrides = 0;
      const void* machHeader() const { return mh; }
      void setOverridesCachedDylib(uint32_t n) { overrides = n; }
    };
    static ImageLoader gPool[64]; static int gPoolUsed = 0;
    static ImageLoader* newImage(int tag) { ImageLoader* i = &gPool[gPoolUsed++]; *i = ImageLoader(); i->tag = tag; return i; }
    struct ImageLoaderMachO {
      static ImageLoader* instantiateFromCache(macho_header*, const char*, long, const struct stat&, ImageLoader::LinkContext&);
    };
    namespace dyld {
      struct LoadContext { bool dontLoad = false; bool mustBeDylib = false; };
      struct ProcessInfo { int platform; } gProcessInfoStorage = { 1 };
      ProcessInfo* gProcessInfo = &gProcessInfoStorage;
      ImageLoader::LinkContext gLinkContext;
      dyld3::SharedCacheLoadInfo sSharedCacheLoadInfo;
      std::vector<ImageLoader*> sAllImages;
      bool gSharedCacheOverridden = false;
      struct { bool onDiskFileIsRoot(const char*, const DyldSharedCache*, const closure::Image*, const void*, uint64_t, uint64_t) const { return false; } } sRootsChecker;
      struct Seen { std::string cachePath; long ino=-1, mtime=-1; int cacheCalls=0, diskCalls=0; } seen;
      static ImageLoader* loadPhase5check(const char*, const char*, const LoadContext&) { return nullptr; }
      ImageLoader* findLoadedImage(const struct stat&) { return nullptr; }
      static ImageLoader* checkandAddImage(ImageLoader* image, const LoadContext&) { return image; }
      ImageLoader* gOpenReturns = nullptr;   // an image that is already loaded under the same install name
      static ImageLoader* loadPhase5open(const char*, const LoadContext&, const struct stat&, std::vector<const char*>*) {
        ++seen.diskCalls; return gOpenReturns ? gOpenReturns : newImage(2);
      }
      bool sandboxBlockedStat(const char*) { return false; }
      const char* mkstringf(const char*, ...) { return ""; }
      bool gLogCachePolicy = false;           // DARLING_DYLD_POLICY_LOG is not exercised here
      void log(const char*, ...) {}
      __attribute__((noreturn)) void throwf(const char* fmt, ...) { char buf[256]; va_list ap; va_start(ap, fmt); vsnprintf(buf, sizeof buf, fmt, ap); va_end(ap); throw std::string(buf); }
      #{record_struct}
      #{relative}
      #{records}
      #{in_cache}
      #{without_root}
      #{load5}
    }
    ImageLoader* ImageLoaderMachO::instantiateFromCache(macho_header*, const char* path, long, const struct stat& sb, ImageLoader::LinkContext&) {
      dyld::seen.cachePath = path; dyld::seen.ino = sb.st_ino; dyld::seen.mtime = sb.st_mtime; ++dyld::seen.cacheCalls;
      return newImage(1);
    }

    struct Fixture { DyldSharedCache cache; dyld_cache_image_info images[2]; char libz[32]; char objc[32]; };
    static int failures = 0;
    #define CHECK(cond) do { if (!(cond)) { printf("FAIL line %d: %s\\n", __LINE__, #cond); ++failures; } } while (0)

    // Loads path; returns the image's tag (1 cache, 2 disk, 0 nothing, -1 threw).
    static int load(const char* path, ImageLoader** out = nullptr) {
      dyld::seen = dyld::Seen();
      dyld::LoadContext ctx; unsigned idx = 0; std::vector<const char*> ex;
      try { ImageLoader* i = dyld::loadPhase5load(path, path, ctx, idx, &ex); if (out) *out = i; return i ? i->tag : 0; }
      catch (const std::string&) { return -1; }   // a throw is a failure of the rule
    }

    // Like load, for a path that loadPhase0 put DYLD_ROOT_PATH in front of: orgPath is the unprefixed one.
    static int loadRooted(const char* path, const char* orgPath, ImageLoader** out = nullptr) {
      dyld::seen = dyld::Seen();
      dyld::LoadContext ctx; unsigned idx = 0; std::vector<const char*> ex;
      try { ImageLoader* i = dyld::loadPhase5load(path, orgPath, ctx, idx, &ex); if (out) *out = i; return i ? i->tag : 0; }
      catch (const std::string&) { return -1; }
    }

    int main() {
      Fixture f = {};
      strcpy(f.libz, "/usr/lib/libz.1.dylib"); strcpy(f.objc, "/usr/lib/libobjc.A.dylib");
      f.cache.header.imagesOffset = offsetof(Fixture, images); f.cache.header.imagesCount = 2;
      f.images[0].address = 0x100000; f.images[0].pathFileOffset = offsetof(Fixture, libz);
      f.images[1].address = 0x200000; f.images[1].pathFileOffset = offsetof(Fixture, objc);
      dyld::sSharedCacheLoadInfo = { &f.cache, 0 };
      const char* kLibz = "/usr/lib/libz.1.dylib"; const char* kLibzAlias = "/usr/lib/libz.dylib"; const char* kObjc = "/usr/lib/libobjc.A.dylib";
      ImageLoader* img = nullptr;

      // --- split cache ---
      // allow-listed canonical path and its alias: the cache wins although a disk copy exists, and the disk
      // file's inode and mtime stay off the cache image
      for (const char* p : { kLibz, kLibzAlias }) {
        dyld3::gDisk.clear(); dyld3::gDisk[p] = 555; dyld::sDiskOverridesOfCacheImages.clear();
        CHECK(load(p, &img) == 1);
        CHECK(dyld::seen.diskCalls == 0 && dyld::seen.cacheCalls == 1 && dyld::seen.cachePath == kLibz);
        CHECK(dyld::seen.ino == 0 && dyld::seen.mtime == 0);
        CHECK(dyld::sDiskOverridesOfCacheImages.empty());
        dyld3::gDisk.clear();
        CHECK(load(p) == 1 && dyld::seen.ino == 0 && dyld::seen.mtime == 0);   // no disk copy: the cache, as before
      }
      // not allow-listed, disk copy exists: disk wins and the override of cache image 1 is recorded
      dyld3::gDisk.clear(); dyld3::gDisk[kObjc] = 556; dyld::sDiskOverridesOfCacheImages.clear();
      CHECK(load(kObjc, &img) == 2 && dyld::seen.cacheCalls == 0);
      CHECK(dyld::sDiskOverridesOfCacheImages.size() == 1 && dyld::sDiskOverridesOfCacheImages[0].image == img
            && dyld::sDiskOverridesOfCacheImages[0].cacheImageIndex == 1);
      CHECK(img->overrides == 0);   // the closure-based override hook is not used for split caches
      // not allow-listed, no disk copy: the cache, with a zeroed stat
      dyld3::gDisk.clear(); dyld::sDiskOverridesOfCacheImages.clear();
      CHECK(load(kObjc) == 1 && dyld::seen.ino == 0 && dyld::seen.mtime == 0 && dyld::sDiskOverridesOfCacheImages.empty());
      // path not in the cache: disk, nothing recorded; absent everywhere: nothing
      dyld3::gDisk.clear(); dyld3::gDisk["/usr/lib/libnotincache.dylib"] = 9; dyld::sDiskOverridesOfCacheImages.clear();
      CHECK(load("/usr/lib/libnotincache.dylib") == 2 && dyld::sDiskOverridesOfCacheImages.empty());
      dyld3::gDisk.clear();
      CHECK(load("/usr/lib/libnotincache.dylib") == 0);
      // a canonical path the cache gives back that is unusable is just not allow-listed: today's rule
      f.libz[0] = '\0'; dyld3::gDisk.clear(); dyld3::gDisk[kLibz] = 1;
      CHECK(load(kLibz) == 2);
      dyld3::gDisk.clear();
      CHECK(load(kLibz) == 1);
      f.libz[0] = '/';
      // loading can return an image that is already loaded: it is recorded once
      dyld3::gDisk.clear(); dyld3::gDisk[kObjc] = 556; dyld::sDiskOverridesOfCacheImages.clear();
      CHECK(load(kObjc, &img) == 2);
      dyld::gOpenReturns = img;
      CHECK(load(kObjc) == 2 && load(kObjc) == 2);
      dyld::gOpenReturns = nullptr;
      CHECK(dyld::sDiskOverridesOfCacheImages.size() == 1 && dyld::diskOverridesOfCacheImages().size() == 1);
      // removeImage forgets exactly the records of the image it removes
      ImageLoader* other = newImage(2);
      dyld::sDiskOverridesOfCacheImages.push_back({ other, 0 });
      auto removeImage = [&](ImageLoader* image) {
        #{forget.gsub('sDiskOverridesOfCacheImages', 'dyld::sDiskOverridesOfCacheImages').gsub('const DiskOverrideOfCacheImage&', 'const dyld::DiskOverrideOfCacheImage&')}
      };
      removeImage(img);
      CHECK(dyld::sDiskOverridesOfCacheImages.size() == 1 && dyld::sDiskOverridesOfCacheImages[0].image == other);
      removeImage(img);
      CHECK(dyld::sDiskOverridesOfCacheImages.size() == 1);
      removeImage(other);
      CHECK(dyld::sDiskOverridesOfCacheImages.empty());

      // --- DYLD_ROOT_PATH: Darling's prefix is in front of the path that reaches loadPhase5load ---
      static const char* const kRoots[] = { "/prefix", nullptr };
      dyld::gLinkContext.rootPaths = kRoots;
      // allow-listed: the cache wins over the prefix's own copy, and that copy's stat stays off the cache image
      dyld3::gDisk.clear(); dyld3::gDisk["/prefix/usr/lib/libz.1.dylib"] = 555; dyld::sDiskOverridesOfCacheImages.clear();
      CHECK(loadRooted("/prefix/usr/lib/libz.1.dylib", kLibz) == 1);
      CHECK(dyld::seen.diskCalls == 0 && dyld::seen.cacheCalls == 1 && dyld::seen.cachePath == kLibz);
      CHECK(dyld::seen.ino == 0 && dyld::seen.mtime == 0 && dyld::sDiskOverridesOfCacheImages.empty());
      // not allow-listed: the prefix's copy wins and the override of cache image 1 is recorded
      dyld3::gDisk.clear(); dyld3::gDisk["/prefix/usr/lib/libobjc.A.dylib"] = 556; dyld::sDiskOverridesOfCacheImages.clear();
      CHECK(loadRooted("/prefix/usr/lib/libobjc.A.dylib", kObjc, &img) == 2 && dyld::seen.cacheCalls == 0);
      CHECK(dyld::sDiskOverridesOfCacheImages.size() == 1 && dyld::sDiskOverridesOfCacheImages[0].cacheImageIndex == 1);
      // not allow-listed and absent from the prefix: the cache
      dyld3::gDisk.clear(); dyld::sDiskOverridesOfCacheImages.clear();
      CHECK(loadRooted("/prefix/usr/lib/libobjc.A.dylib", kObjc) == 1 && dyld::seen.cachePath == kObjc);
      // only a whole leading directory is the root: "/prefixed" is a different tree and has no cache entry
      dyld3::gDisk.clear(); dyld3::gDisk["/prefixed/usr/lib/libz.1.dylib"] = 557;
      CHECK(loadRooted("/prefixed/usr/lib/libz.1.dylib", "/prefixed/usr/lib/libz.1.dylib") == 2 && dyld::seen.cacheCalls == 0);
      // the unprefixed path of the same load still reaches the cache
      dyld3::gDisk.clear(); dyld3::gDisk[kLibz] = 555;
      CHECK(loadRooted(kLibz, kLibz) == 1 && dyld::seen.cachePath == kLibz);
      dyld::gLinkContext.rootPaths = nullptr;
      // no root path: a prefixed-looking path has no cache entry
      dyld3::gDisk.clear(); dyld3::gDisk["/prefix/usr/lib/libz.1.dylib"] = 555;
      CHECK(loadRooted("/prefix/usr/lib/libz.1.dylib", kLibz) == 2 && dyld::seen.cacheCalls == 0);

      // --- old caches (no closure Image here either): a file on disk wins, even for the allow-listed path ---
      f.cache.split = false;
      dyld3::gDisk.clear(); dyld3::gDisk[kLibz] = 555; dyld::sDiskOverridesOfCacheImages.clear();
      CHECK(load(kLibz) == 2 && dyld::seen.cacheCalls == 0 && dyld::sDiskOverridesOfCacheImages.empty());
      dyld3::gDisk.clear();
      CHECK(load(kLibz) == 1 && dyld::seen.cachePath == kLibz && dyld::seen.cacheCalls == 1);
      dyld3::gDisk[kObjc] = 556;
      CHECK(load(kObjc) == 2 && dyld::sDiskOverridesOfCacheImages.empty());
      f.cache.split = true;

      // --- the lookups stay unfiltered: gSharedCacheOverridden is set for any disk image shadowing a cache path ---
      struct FakeImage { bool inCache; bool inSharedCache() const { return inCache; } bool isDylib() const { return true; } };
      struct EligibleStub { static bool isSharedCacheEligiblePath(const char*) { return true; } };
      auto overriddenFor = [&](const char* path, bool imageInCache) {
        dyld::gSharedCacheOverridden = false;
        FakeImage imageStorage = { imageInCache }; FakeImage* image = &imageStorage;
        #{overridden.gsub('dyld3::MachOFile::isSharedCacheEligiblePath', 'EligibleStub::isSharedCacheEligiblePath').gsub(/\bgSharedCacheOverridden\b/, 'dyld::gSharedCacheOverridden').gsub('inSharedCache(path)', 'dyld::inSharedCache(path)').gsub('dyld::dyld::', 'dyld::')}
        return dyld::gSharedCacheOverridden;
      };
      CHECK(overriddenFor(kObjc, false));          // a disk image over a cache path that is not allow-listed
      CHECK(overriddenFor(kLibz, false));          // and over an allow-listed one
      CHECK(overriddenFor(kLibzAlias, false));
      CHECK(!overriddenFor("/usr/lib/libnotincache.dylib", false));
      CHECK(!overriddenFor(kLibz, true));          // the image itself came from the cache

      // --- loadPhase1: an allow-listed path (any alias) cannot be replaced by a search-path override ---
      auto cannotOverride = [&](const char* path) {
        #{pinned.gsub('sSharedCacheLoadInfo', 'dyld::sSharedCacheLoadInfo')}
        return pathIsInDyldCacheWhichCannotBeOverridden;
      };
      CHECK(cannotOverride(kLibz) && cannotOverride(kLibzAlias));
      CHECK(!cannotOverride(kObjc) && !cannotOverride("/usr/lib/libnotincache.dylib"));
      f.cache.split = false;
      CHECK(!cannotOverride(kLibz));
      f.cache.split = true;

      if (failures) { printf("%d failure(s)\\n", failures); return 1; }
      puts("PASS loadPhase5load precedence (split and old caches), stat zeroing, override record, unfiltered lookups, pinned search paths");
      return 0;
    }
  CPP
  out, ok = Open3.capture2e('clang++', '-std=c++14', '-fblocks', '-fsanitize=address,undefined', '-Wno-everything', "#{dir}/test.cpp", '-o', "#{dir}/test")
  abort out unless ok.success?
  out, ok = Open3.capture2e("#{dir}/test")
  puts out
  abort 'shared cache precedence wiring regression failed' unless ok.success?
end
