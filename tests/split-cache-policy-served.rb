# A split cache's policy file together with the loader's rooted-path lookup (DYLD_ROOT_PATH): the real
# loadSplitCachePolicy loads a policy file, and the real loadPhase5load (src/dyld2.cpp, collaborators stubbed) then
# decides which copy of a library loads. A set policy is an exact replacement of the built-in list, so the policy a
# guest test uses must name every library it needs. The cache here is synthetic (five images, no Apple bytes).
# Usage: ruby tests/split-cache-policy-served.rb [checkout]
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
preadall = runtime[/^static bool preadAll\(.*?^\}/m] or abort 'preadAll missing'
loader = runtime[/^\/\/ ---- the cache policy file \(DYLD_SHARED_CACHE_SPLIT_POLICY\) ----.*?^const char\* loadSplitCachePolicy\(.*?^\}/m] or abort 'policy loader missing'
decls = (runtime_h[/^static const uint32_t kNoCacheImageIndex.*?^\};/m] or abort 'results struct missing') + "\n" +
        (runtime_h[/^enum SharedCacheLoadSource.*?^bool pathIsPinnedToSharedCache\(.*?;/m] or abort 'policy declarations missing') + "\n" +
        (runtime_h[/^const char\* loadSplitCachePolicy\(.*?;/m] or abort 'loader declaration missing')

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
    #include <stdlib.h>
    #include <unistd.h>
    #include <fcntl.h>
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
          static const char* const kNames[] = { "/usr/lib/libz.1.dylib", "/usr/lib/libexpat.1.dylib", "/usr/lib/libc++.1.dylib", "/usr/lib/libc++abi.dylib", "/usr/lib/libobjc.A.dylib" };
          for (uint32_t i = 0; i != 5; ++i) { if ( !strcmp(path, kNames[i]) ) { index = i; return true; } }
          if ( !strcmp(path, "/usr/lib/libz.dylib") ) { index = 0; return true; }   // aliases the real cache records
          if ( !strcmp(path, "/usr/lib/libc++.dylib") ) { index = 2; return true; }
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
      static int open(const char* path, int flags, int mode) { return ::open(path, flags, mode); }
      #{preadall}
      #{policy}
      #{loader}
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
      struct LinkContext { bool allowEnvVarsPath = true; bool iOSonMac = false; const char* const* rootPaths = nullptr; };
      int tag = 0;                       // 1 = cache, 2 = disk
      const void* mh = nullptr;
      uint32_t overrides = 0;
      const void* machHeader() const { return mh; }
      const char* install = nullptr;     // the image's own install name
      const char* getInstallPath() const { return install; }
      bool inSharedCache() const { return tag == 1; }
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
      const char* gOpenInstall = nullptr;    // install name of a freshly opened disk image
      static ImageLoader* loadPhase5open(const char*, const LoadContext&, const struct stat&, std::vector<const char*>*) {
        ++seen.diskCalls;
        if ( gOpenReturns ) return gOpenReturns;
        ImageLoader* i = newImage(2); i->install = gOpenInstall; return i;
      }
      bool sandboxBlockedStat(const char*) { return false; }
      const char* mkstringf(const char*, ...) { return ""; }
      bool gLogCachePolicy = false;           // DYLD_PRINT_CACHE_POLICY is not exercised here
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

    struct Fixture { DyldSharedCache cache; dyld_cache_image_info images[5]; char names[5][40]; };
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

    int main(int argc, char** argv) {
      const char* const kPaths[5] = { "/usr/lib/libz.1.dylib", "/usr/lib/libexpat.1.dylib", "/usr/lib/libc++.1.dylib", "/usr/lib/libc++abi.dylib", "/usr/lib/libobjc.A.dylib" };
      Fixture f = {};
      f.cache.header.imagesOffset = offsetof(Fixture, images); f.cache.header.imagesCount = 5;
      for (int i = 0; i != 5; ++i) { strcpy(f.names[i], kPaths[i]); f.images[i].address = 0x100000 * (i + 1); f.images[i].pathFileOffset = offsetof(Fixture, names) + 40 * i; }
      dyld::sSharedCacheLoadInfo = { &f.cache, 0 };
      static const char* const kRoots[] = { "/prefix", nullptr };
      std::string dir = argv[1];
      auto writePolicy = [&](const char* name, const std::string& names) {
        std::string path = dir + "/" + name;
        FILE* file = fopen(path.c_str(), "w"); fputs(("darling-dyld-cache-policy 1\\n" + names).c_str(), file); fclose(file);
        return path;
      };
      // Which copy loads for library i, with Darling's own copy in the prefix (the common case) or without one.
      // DYLD_ROOT_PATH is /prefix: loadPhase0 hands loadPhase5load the prefixed path and the unprefixed one.
      auto served = [&](int i) {
        dyld::gLinkContext.rootPaths = kRoots;
        std::string prefixed = std::string("/prefix") + kPaths[i];
        dyld3::gDisk.clear(); dyld3::gDisk[prefixed] = 700 + i; dyld::sDiskOverridesOfCacheImages.clear();
        const int withDisk = loadRooted(prefixed.c_str(), kPaths[i]);
        const bool cacheGotIt = dyld::seen.cacheCalls == 1 && dyld::seen.cachePath == kPaths[i] && dyld::seen.diskCalls == 0 && dyld::seen.ino == 0;
        dyld3::gDisk.clear();
        const int without = loadRooted(prefixed.c_str(), kPaths[i]);   // no copy in the prefix: the cache serves it either way
        dyld::gLinkContext.rootPaths = nullptr;
        CHECK(without == 1);
        return withDisk == 1 && cacheGotIt;
      };
      auto servedSet = [&]() { std::string s; for (int i = 0; i != 5; ++i) if ( served(i) ) s += char('0' + i); return s; };

      // the variable unset: the built-in list, which is libz and libexpat (the #31 default); libc++ and libc++abi come from disk
      CHECK(servedSet() == "01");

      // the policy a guest test of the C++ runtime uses: every library it needs, because a policy is an exact replacement
      const std::string all = "/usr/lib/libz.1.dylib\\n/usr/lib/libexpat.1.dylib\\n/usr/lib/libc++.1.dylib\\n/usr/lib/libc++abi.dylib\\n";
      size_t line = 0;
      CHECK(loadSplitCachePolicy(writePolicy("all.policy", all).c_str(), &line) == nullptr);
      CHECK(servedSet() == "0123");          // libobjc is not listed: Darling's own copy in the prefix wins
      // the unprefixed lookups serve them too, and an alias of libc++ reaches the same canonical name
      dyld3::gDisk.clear(); dyld3::gDisk[kPaths[2]] = 5;
      CHECK(load("/usr/lib/libc++.dylib") == 1 && dyld::seen.cachePath == kPaths[2] && dyld::seen.diskCalls == 0);
      CHECK(!served(4));
      // libc++ and libc++abi alone, as the policy of a test that needs no libexpat: libz and libexpat then come from disk
      CHECK(loadSplitCachePolicy(writePolicy("cxx.policy", "/usr/lib/libc++.1.dylib\\n/usr/lib/libc++abi.dylib\\n").c_str(), &line) == nullptr);
      CHECK(servedSet() == "23");
      // a name the cache does not have is accepted and serves nothing
      CHECK(loadSplitCachePolicy(writePolicy("extra.policy", all + "/usr/lib/libnotincache.dylib\\n").c_str(), &line) == nullptr);
      CHECK(servedSet() == "0123");
      dyld3::gDisk.clear(); dyld3::gDisk["/usr/lib/libnotincache.dylib"] = 9;
      CHECK(load("/usr/lib/libnotincache.dylib") == 2);
      // a refused policy leaves the list in force
      CHECK(loadSplitCachePolicy(writePolicy("bad.policy", all + "usr/lib/libobjc.A.dylib\\n").c_str(), &line) != nullptr && line == 6);
      CHECK(servedSet() == "0123");
      // an empty policy serves nothing over a disk copy, not even libz
      CHECK(loadSplitCachePolicy(writePolicy("empty.policy", "").c_str(), &line) == nullptr);
      CHECK(servedSet() == "");

      if (failures) { printf("%d failure(s)\\n", failures); return 1; }
      puts("PASS a policy listing libz, libexpat, libc++ and libc++abi serves them under DYLD_ROOT_PATH; the default list and exact replacement");
      return 0;
    }
  CPP
  out, ok = Open3.capture2e('clang++', '-std=c++14', '-fblocks', '-fsanitize=address,undefined', '-Wno-everything', "#{dir}/test.cpp", '-o', "#{dir}/test")
  abort out unless ok.success?
  out, ok = Open3.capture2e({ 'ASAN_OPTIONS' => 'detect_leaks=0' }, "#{dir}/test", dir)
  puts out
  abort 'split cache policy served test failed' unless ok.success?
end
