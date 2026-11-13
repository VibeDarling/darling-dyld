# Every spelling of a split cache image's path gets the same policy decision. The real loadSplitCachePolicy loads a
# policy file, and the real loadPhase5load and findInSharedCacheImageBySpelling (src/dyld2.cpp, collaborators stubbed) decide which
# copy loads when the path reaches the image through directory symlinks that the cache's path table does not list, as
# CoreServices.framework/Frameworks/LaunchServices.framework/LaunchServices does. The cache is synthetic (two images, no
# Apple bytes); the symlinks are real, in a temporary directory.
# Usage: ruby tests/split-cache-policy-alias.rb [checkout]
require 'tmpdir'
require 'open3'
root = File.realpath(ARGV.fetch(0, File.expand_path('..', __dir__)))
dyld2 = File.read("#{root}/src/dyld2.cpp")
dyld2_h = File.read("#{root}/src/dyld2.h")
runtime = File.read("#{root}/dyld3/SharedCacheRuntime.cpp")
runtime_h = File.read("#{root}/dyld3/SharedCacheRuntime.h")
without_root = dyld2[/^static const char\* pathWithoutRoot\(.*?^\}/m] or abort 'pathWithoutRoot missing'
spelling = dyld2[/^static bool findInSharedCacheImageBySpelling\(.*?^\}/m] or abort 'findInSharedCacheImageBySpelling missing'
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
    #include <limits.h>
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
          for (uint32_t i = 0; i != 2; ++i) { if ( !strcmp(path, (const char*)this + header.imagesOffset + sizeof(dyld_cache_image_info) * 2 + 200 * i) ) { index = i; return true; } }
          return false;   // the trie lists the canonical names only: no alias of a symlinked directory
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
      bool gLogCachePolicy = false;           // DYLD_PRINT_CACHE_POLICY is not exercised here
      void log(const char*, ...) {}
      __attribute__((noreturn)) void throwf(const char* fmt, ...) { char buf[256]; va_list ap; va_start(ap, fmt); vsnprintf(buf, sizeof buf, fmt, ap); va_end(ap); throw std::string(buf); }
      #{record_struct}
      #{relative}
      #{records}
      #{in_cache}
      #{without_root}
      #{spelling}
      #{load5}
    }
    ImageLoader* ImageLoaderMachO::instantiateFromCache(macho_header*, const char* path, long, const struct stat& sb, ImageLoader::LinkContext&) {
      dyld::seen.cachePath = path; dyld::seen.ino = sb.st_ino; dyld::seen.mtime = sb.st_mtime; ++dyld::seen.cacheCalls;
      return newImage(1);
    }

    struct Fixture { DyldSharedCache cache; dyld_cache_image_info images[2]; char names[2][200]; };
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
      char* real = realpath(argv[1], nullptr);
      std::string dir = real; free(real);
      auto touch = [&](const std::string& p) { std::string d = p.substr(0, p.rfind('/')); system(("mkdir -p '" + d + "'").c_str()); FILE* f = fopen(p.c_str(), "w"); fputs("x", f); fclose(f); };
      auto link = [&](const std::string& target, const std::string& p) { std::string d = p.substr(0, p.rfind('/')); system(("mkdir -p '" + d + "'").c_str()); symlink(target.c_str(), p.c_str()); };
      // Darling's layout: a framework whose sub-framework directory is reached through Versions/Current
      const std::string kFw = "/System/Library/Frameworks/Outer.framework";
      const std::string kCanonical = kFw + "/Versions/A/Frameworks/Inner.framework/Versions/A/Inner";
      const std::string kAliasA = kFw + "/Frameworks/Inner.framework/Inner";        // through two symlinks
      const std::string kAliasB = kFw + "/Versions/Current/Frameworks/Inner.framework/Versions/Current/Inner";
      const std::string kOther = "/usr/lib/libother.dylib";                          // not in the cache
      const std::string kOtherAlias = "/usr/lib/libother-alias.dylib";
      static const char* const kRoots[1] = { nullptr };
      auto build = [&](const std::string& root) {
        touch(root + kCanonical); touch(root + kOther);
        link("A", root + kFw + "/Versions/Current"); link("Versions/Current/Frameworks", root + kFw + "/Frameworks");
        link("Versions/Current/Inner", root + kFw + "/Versions/A/Frameworks/Inner.framework/Inner");
        link("A", root + kFw + "/Versions/A/Frameworks/Inner.framework/Versions/Current");
        link("libother.dylib", root + kOtherAlias);
        link("libgone.dylib", root + "/usr/lib/libdangling.dylib");
      };
      auto writePolicy = [&](const std::string& names) {
        std::string path = dir + "/policy"; FILE* file = fopen(path.c_str(), "w"); fputs(("darling-dyld-cache-policy 1\\n" + names).c_str(), file); fclose(file);
        size_t line = 0; CHECK(loadSplitCachePolicy(path.c_str(), &line) == nullptr);
      };
      for (int rooted = 0; rooted != 2; ++rooted) {
        // rooted: DYLD_ROOT_PATH is the prefix and the cache indexes the path without it; unrooted: the guest sees /System directly
        const std::string root = rooted ? dir + "/prefix" : dir + "/flat";
        const std::string prefix = rooted ? root : "";
        std::string cacheName = rooted ? kCanonical : root + kCanonical;
        std::vector<std::string> names = { cacheName, "/usr/lib/libz.1.dylib" };
        Fixture f = {};
        f.cache.header.imagesOffset = offsetof(Fixture, images); f.cache.header.imagesCount = 2;
        for (int i = 0; i != 2; ++i) { strcpy(f.names[i], names[i].c_str()); f.images[i].address = 0x100000 * (i + 1); f.images[i].pathFileOffset = offsetof(Fixture, names) + 200 * i; }
        dyld::sSharedCacheLoadInfo = { &f.cache, 0 };
        build(root);
        static const char* rootList[2]; std::string rootStr = root; rootList[0] = rootStr.c_str(); rootList[1] = nullptr;
        dyld::gLinkContext.rootPaths = rooted ? rootList : nullptr;
        auto spell = [&](const std::string& s) { return rooted ? s : root + s; };
        // the unrooted run names the whole path, so its spellings carry the directory
        auto decide = [&]() {
          std::string out;
          for (const std::string& s : { kCanonical, kAliasA, kAliasB }) {
            std::string p = spell(s);
            dyld3::gDisk.clear(); dyld3::gDisk[rooted ? root + s : p] = 700; dyld::sDiskOverridesOfCacheImages.clear();
            int r = rooted ? loadRooted((root + s).c_str(), s.c_str()) : load(p.c_str());
            out += char('0' + r);
          }
          return out;
        };
        writePolicy(cacheName + "\\n");
        CHECK(decide() == "111");                     // listed: every spelling is served from the cache
        writePolicy("/usr/lib/libz.1.dylib\\n");
        CHECK(decide() == "222");                     // not listed: Darling's own copy, whatever the spelling
        writePolicy("");
        CHECK(decide() == "222");
        // the lookup answers with the cache's canonical path for each spelling, and finds nothing behind a path that no cache image is behind
        writePolicy(cacheName + "\\n");
        char buf[PATH_MAX];
        dyld3::SharedCacheFindDylibResults found;
        for (const std::string& s : { kCanonical, kAliasA, kAliasB }) {
          const std::string given = rooted ? root + s : spell(s);
          CHECK(dyld::findInSharedCacheImageBySpelling(given.c_str(), buf, found) && std::string(found.pathInCache) == cacheName);
        }
        const std::string otherAlias = root + kOtherAlias, dangling = root + "/usr/lib/libdangling.dylib";
        CHECK(!dyld::findInSharedCacheImageBySpelling(otherAlias.c_str(), buf, found));
        CHECK(!dyld::findInSharedCacheImageBySpelling(dangling.c_str(), buf, found));
        // a relative spelling is never resolved against the working directory: found as the cache lists it or not at all
        { char here[PATH_MAX]; getcwd(here, sizeof here); const std::string d = root + std::string(kCanonical).substr(0, std::string(kCanonical).rfind('/'));
          CHECK(chdir(d.c_str()) == 0);
          CHECK(!dyld::findInSharedCacheImageBySpelling("Inner", buf, found) && !dyld::findInSharedCacheImageBySpelling("./Inner", buf, found));
          CHECK(chdir(here) == 0); }
        // a disk-only library reached through a symlink is not turned into a cache image
        dyld3::gDisk.clear(); dyld3::gDisk[root + kOtherAlias] = 5;
        CHECK((rooted ? loadRooted((root + kOtherAlias).c_str(), kOtherAlias.c_str()) : load((root + kOtherAlias).c_str())) == 2);
      }
      if (failures) { printf("%d failure(s)\\n", failures); return 1; }
      puts("PASS an alias of a split cache image's path (symlinked directories) gets the same policy decision as its canonical path, rooted and unrooted");
      return 0;
    }
  CPP
  out, ok = Open3.capture2e('clang++', '-std=c++14', '-fblocks', '-fsanitize=address,undefined', '-Wno-everything', "#{dir}/test.cpp", '-o', "#{dir}/test")
  abort out unless ok.success?
  out, ok = Open3.capture2e({ 'ASAN_OPTIONS' => 'detect_leaks=0' }, "#{dir}/test", dir)
  puts out
  abort 'split cache policy alias test failed' unless ok.success?
end
