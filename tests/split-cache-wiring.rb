# The pieces dyld uses to wire a split macOS cache into a process (DYLD_SHARED_CACHE_SPLIT_DIR): the cache
# file name derived from the main executable's architecture, the directory validation and the main file
# path. Each check runs the real function extracted from dyld3/SharedCacheRuntime.cpp.
# Usage: ruby tests/split-cache-wiring.rb [checkout]
require 'tmpdir'
require 'open3'
root = File.realpath(ARGV.fetch(0, File.expand_path('..', __dir__)))
runtime = File.read("#{root}/dyld3/SharedCacheRuntime.cpp")
runtime_h = File.read("#{root}/dyld3/SharedCacheRuntime.h")

def run_cpp(dir, name, source, root)
  File.write("#{dir}/#{name}.cpp", source)
  out, ok = Open3.capture2e('clang++', '-std=c++17', '-fblocks', '-fsanitize=address,undefined', '-Wno-everything',
                            "-I#{root}/dyld3/shared-cache", "#{dir}/#{name}.cpp", '-o', "#{dir}/#{name}")
  abort out unless ok.success?
  out, ok = Open3.capture2e("#{dir}/#{name}")
  puts out
  abort "split cache wiring test #{name} failed" unless ok.success?
end

COMMON = <<~CPP
  #include <stdint.h>
  #include <stddef.h>
  #include <stdio.h>
  #include <stdlib.h>
  #include <string.h>
  #include <string>
  #define DARLING 1
  #define TARGET_OS_SIMULATOR 0
  #if !__GLIBC_PREREQ(2, 38)
  static size_t strlcpy(char *d, const char *s, size_t n) { size_t l=strlen(s); if (n) { size_t c=l<n-1?l:n-1; memcpy(d,s,c); d[c]=0; } return l; }
  static size_t strlcat(char *d, const char *s, size_t n) { size_t dl=strnlen(d,n); if (dl==n) return n+strlen(s); return dl+strlcpy(d+dl,s,n-dl); }
  #endif
  // The block runtime is not linked: these blocks are never copied or escaped.
  extern "C" { void *_NSConcreteStackBlock[32]; void *_NSConcreteGlobalBlock[32];
               void _Block_object_assign(void*, const void*, const int) {}
               void _Block_object_dispose(const void*, const int) {} }
  static int failures = 0;
  #define CHECK(cond) do { if (!(cond)) { printf("FAIL line %d: %s\\n", __LINE__, #cond); ++failures; } } while (0)
CPP

names_src = (runtime[/^\/\/ The longest directory accepted.*?^const char\* splitCacheMainFilePath\(.*?^\}/m] or abort 'name helpers missing')
decls = %w[splitCacheArchName splitCacheDirError splitCacheMainFilePath].map { |n| runtime_h[/^const char\* #{n}\(.*?;/m] }.join("\n")
abort 'name helper declarations missing' if decls.scan(/splitCache/).size != 3

Dir.mktmpdir('split-cache-wiring-') do |dir|
  run_cpp(dir, 'names', <<~CPP, root)
    #{COMMON}
    #include "dyld_cache_format.h"
    #define CPU_TYPE_ARM64 0x0100000C
    #define CPU_TYPE_ARM64_32 0x0200000C
    #define CPU_TYPE_X86_64 0x01000007
    #define CPU_TYPE_ARM 12
    #define CPU_SUBTYPE_MASK 0xff000000
    #define CPU_SUBTYPE_ARM64_ALL 0
    #define CPU_SUBTYPE_ARM64_V8 1
    #define CPU_SUBTYPE_ARM64E 2
    #{decls}
    #{names_src}

    static const char* path_for(const char* dir, uint32_t type, uint32_t sub, std::string* out) {
      char path[256]; memset(path, 'x', sizeof path);
      const char* error = splitCacheMainFilePath(dir, type, sub, path, sizeof path);
      if (!error) *out = path;
      return error;
    }

    int main() {
      // --- the name: arch of the main executable, flag bits ignored ---
      CHECK(!strcmp(splitCacheArchName(CPU_TYPE_ARM64, CPU_SUBTYPE_ARM64E), "arm64e"));
      CHECK(!strcmp(splitCacheArchName(CPU_TYPE_ARM64, 0x80000002), "arm64e"));    // pointer authentication ABI byte
      CHECK(!strcmp(splitCacheArchName(CPU_TYPE_ARM64, 0x00000002), "arm64e"));
      CHECK(!strcmp(splitCacheArchName(CPU_TYPE_ARM64, CPU_SUBTYPE_ARM64_ALL), "arm64"));
      CHECK(!strcmp(splitCacheArchName(CPU_TYPE_ARM64, CPU_SUBTYPE_ARM64_V8), "arm64"));
      CHECK(!strcmp(splitCacheArchName(CPU_TYPE_X86_64, 3), "x86_64"));
      CHECK(!strcmp(splitCacheArchName(CPU_TYPE_X86_64, 8), "x86_64"));
      CHECK(splitCacheArchName(CPU_TYPE_ARM64, 3) == nullptr);                       // an unknown arm64 subtype
      CHECK(splitCacheArchName(CPU_TYPE_ARM64, 0x80000003) == nullptr);
      CHECK(splitCacheArchName(CPU_TYPE_ARM64_32, 1) == nullptr);
      CHECK(splitCacheArchName(CPU_TYPE_ARM, 9) == nullptr);
      CHECK(splitCacheArchName(0, 0) == nullptr);

      // --- the main file path ---
      std::string p;
      CHECK(!path_for("/cache", CPU_TYPE_ARM64, 0x80000002, &p) && p == "/cache/dyld_shared_cache_arm64e");
      CHECK(!path_for("/cache/", CPU_TYPE_ARM64, CPU_SUBTYPE_ARM64E, &p) && p == "/cache/dyld_shared_cache_arm64e");
      CHECK(!path_for("/", CPU_TYPE_ARM64, CPU_SUBTYPE_ARM64E, &p) && p == "/dyld_shared_cache_arm64e");
      CHECK(!path_for("/a b/c", CPU_TYPE_ARM64, CPU_SUBTYPE_ARM64_V8, &p) && p == "/a b/c/dyld_shared_cache_arm64");
      // refusals say why, and leave nothing usable behind
      const char* e;
      e = path_for("/cache", CPU_TYPE_X86_64, 3, &p);
      CHECK(e && strstr(e, "x86_64"));
      e = path_for("/cache", CPU_TYPE_ARM64_32, 1, &p);
      CHECK(e && strstr(e, "architecture"));
      e = path_for("/cache", CPU_TYPE_ARM64, 7, &p);
      CHECK(e && strstr(e, "architecture"));
      e = path_for("relative/dir", CPU_TYPE_ARM64, CPU_SUBTYPE_ARM64E, &p);
      CHECK(e && strstr(e, "absolute"));
      // a path longer than the buffer is refused, not truncated
      char small[20];
      e = splitCacheMainFilePath("/cache", CPU_TYPE_ARM64, CPU_SUBTYPE_ARM64E, small, sizeof small);
      CHECK(e && strstr(e, "too long"));

      // --- the directory ---
      CHECK(splitCacheDirError("/cache") == nullptr);
      CHECK(splitCacheDirError("/") == nullptr);
      CHECK(splitCacheDirError("/a b/c.d") == nullptr);
      CHECK(splitCacheDirError(nullptr) != nullptr);
      CHECK(strstr(splitCacheDirError(""), "empty"));
      CHECK(strstr(splitCacheDirError("cache"), "absolute"));
      CHECK(strstr(splitCacheDirError("./cache"), "absolute"));
      CHECK(strstr(splitCacheDirError(" /cache"), "absolute"));
      CHECK(strstr(splitCacheDirError("/cache\\n"), "control"));            // trailing newline
      CHECK(strstr(splitCacheDirError("/cache\\t/x"), "control"));
      CHECK(strstr(splitCacheDirError("/cache\\x7f"), "control"));
      CHECK(strstr(splitCacheDirError("/cache\\x01"), "control"));
      // an embedded NUL ends the C string, so the value is judged by what precedes it
      CHECK(splitCacheDirError("/cache\\0junk") == nullptr);
      CHECK(strstr(splitCacheDirError("\\0/cache"), "empty"));
      // length bound: kSplitCacheDirMaxLength is accepted, one more is not, and a huge string is not read past the bound
      std::string at_limit = "/" + std::string(kSplitCacheDirMaxLength - 1, 'a');
      std::string over = at_limit + "a";
      CHECK(splitCacheDirError(at_limit.c_str()) == nullptr);
      CHECK(strstr(splitCacheDirError(over.c_str()), "too long"));
      std::string huge = "/" + std::string(1 << 20, 'a');
      CHECK(strstr(splitCacheDirError(huge.c_str()), "too long"));
      // the bound leaves room for the main file name and a sub-cache suffix in SharedCacheLoadInfo::path (256 bytes)
      CHECK(kSplitCacheDirMaxLength + 1 + strlen("dyld_shared_cache_arm64e") + strlen(".dyldlinkedit") < 256);
      CHECK(!path_for(at_limit.c_str(), CPU_TYPE_ARM64, CPU_SUBTYPE_ARM64E, &p) && p.size() < 256);

      if (failures) { printf("%d failure(s)\\n", failures); return 1; }
      puts("PASS split cache name derivation, directory validation and main file path");
      return 0;
    }
  CPP

  # --- the process-wide state of a mapped cache: one helper, shared by the legacy and the split path ---
  dyld2 = File.read("#{root}/src/dyld2.cpp")
  images_h = File.read("#{root}/include/mach-o/dyld_images.h")
  squash = ->(text) { text.gsub(%r{//[^\n]*}, '').gsub(/\s+/, ' ').strip }
  state_fn = dyld2[/^static void installSharedCacheGlobalState\(.*?^\}/m] or abort 'installSharedCacheGlobalState missing'
  const_fn = dyld2[/^static void matchSharedCacheDataConstState\(.*?^\}/m] or abort 'matchSharedCacheDataConstState missing'
  legacy_fn = dyld2[/^static void mapSharedCache\(.*?^\}/m] or abort 'mapSharedCache missing'

  # The statements mapSharedCache ran inline before the helper existed, verbatim: the legacy path must keep them.
  legacy_state = <<~'GOLDEN'
    static void installSharedCacheGlobalState(bool forcePrivate) {
    if ( sSharedCacheLoadInfo.loadAddress != nullptr ) {
    gLinkContext.dyldCache = sSharedCacheLoadInfo.loadAddress;
    dyld::gProcessInfo->processDetachedFromSharedRegion = forcePrivate;
    dyld::gProcessInfo->sharedCacheSlide = sSharedCacheLoadInfo.slide;
    dyld::gProcessInfo->sharedCacheBaseAddress = (unsigned long)sSharedCacheLoadInfo.loadAddress;
    sSharedCacheLoadInfo.loadAddress->getUUID(dyld::gProcessInfo->sharedCacheUUID);
    dyld3::kdebug_trace_dyld_image(DBG_DYLD_UUID_SHARED_CACHE_A, sSharedCacheLoadInfo.path, (const uuid_t *)&dyld::gProcessInfo->sharedCacheUUID[0], {0,0}, {{ 0, 0 }}, (const mach_header *)sSharedCacheLoadInfo.loadAddress);
    } }
  GOLDEN
  legacy_const = <<~'GOLDEN'
    static void matchSharedCacheDataConstState(bool sharedCacheDataConstIsEnabled) {
    if ( (sSharedCacheLoadInfo.loadAddress != nullptr) && (gEnableSharedCacheDataConst != sharedCacheDataConstIsEnabled) ) {
    uint32_t permissions = gEnableSharedCacheDataConst ? VM_PROT_READ : (VM_PROT_READ | VM_PROT_WRITE);
    sSharedCacheLoadInfo.loadAddress->changeDataConstPermissions(mach_task_self(), permissions, (gLinkContext.verboseMapping ? &dyld::log : nullptr));
    } }
  GOLDEN
  legacy_map = <<~'GOLDEN'
    static void mapSharedCache(uintptr_t mainExecutableSlide) {
    dyld3::SharedCacheOptions opts;
    opts.cacheDirOverride = sSharedCacheOverrideDir;
    opts.forcePrivate = (gLinkContext.sharedRegionMode == ImageLoader::kUsePrivateSharedRegion);
    #if __x86_64__ && !TARGET_OS_SIMULATOR
    opts.useHaswell = sHaswell;
    #else
    opts.useHaswell = false;
    #endif
    opts.verbose = gLinkContext.verboseMapping;
    opts.disableASLR = (mainExecutableSlide == 0) && dyld3::internalInstall();
    loadDyldCache(opts, &sSharedCacheLoadInfo);
    installSharedCacheGlobalState(opts.forcePrivate);
    }
  GOLDEN
  abort 'the legacy global-state statements changed' unless squash.(state_fn) == legacy_state.gsub(/\s+/, ' ').strip
  abort 'the legacy DATA_CONST statements changed' unless squash.(const_fn) == legacy_const.gsub(/\s+/, ' ').strip
  abort 'mapSharedCache changed' unless squash.(legacy_fn) == legacy_map.gsub(/\s+/, ' ').strip

  # Every field of dyld_all_image_infos that describes the cache is set by the helper: a new one in the header
  # or a new assignment in the helper breaks this until both agree.
  all_infos = images_h[/^struct dyld_all_image_infos \{.*?^\};/m] or abort 'dyld_all_image_infos missing'
  header_fields = all_infos.scan(/^\s*[\w\s\*]*?\b(\w*(?:sharedCache|SharedRegion)\w*)(?:\[\d+\])?;/).flatten.sort
  assigned = state_fn.scan(/dyld::gProcessInfo->(\w+)/).flatten.uniq.sort
  assigned_link = state_fn.scan(/gLinkContext\.(\w+)\s*=/).flatten.sort
  abort "cache fields of dyld_all_image_infos: #{header_fields} versus assigned #{assigned}" unless header_fields == assigned
  abort 'gLinkContext fields assigned changed' unless assigned_link == ['dyldCache']
  abort 'header has no cache fields?' if header_fields.size != 4

  # Neither mapper assigns that state itself: the legacy function only calls the helper.
  abort 'mapSharedCache sets cache state itself' if legacy_fn =~ /gLinkContext\.dyldCache|gProcessInfo->shared|processDetached/

  run_cpp(dir, 'state', <<~CPP, root)
    #{COMMON}
    #include <string.h>
    #define VM_PROT_READ 1
    #define VM_PROT_WRITE 2
    #define DBG_DYLD_UUID_SHARED_CACHE_A 77
    typedef unsigned char uuid_t[16];
    struct mach_header {};
    struct DyldSharedCache {
      uint8_t uuid[16];
      int dataConstCalls = 0; uint32_t lastPermissions = 0; bool loggerPassed = false;
      void getUUID(uint8_t* out) const { memcpy(out, uuid, 16); }
      void changeDataConstPermissions(int, uint32_t permissions, void (*log)(const char*, ...)) const {
        const_cast<DyldSharedCache*>(this)->dataConstCalls++; const_cast<DyldSharedCache*>(this)->lastPermissions = permissions;
        const_cast<DyldSharedCache*>(this)->loggerPassed = (log != nullptr);
      }
    };
    namespace dyld3 {
      struct SharedCacheLoadInfo { const DyldSharedCache* loadAddress; long slide; const char* errorMessage; char path[256]; };
      struct Trace { int calls = 0; int code = 0; const void* mh = nullptr; const void* uuid = nullptr; const char* path = nullptr; } trace;
      struct Pair { int a, b; }; struct Pairs { Pair x; };
      void kdebug_trace_dyld_image(int code, const char* path, const uuid_t* uuid, Pair, Pairs, const mach_header* mh) {
        ++trace.calls; trace.code = code; trace.mh = mh; trace.uuid = uuid; trace.path = path;
      }
    }
    namespace dyld {
      struct ProcessInfo { #{(all_infos.scan(/^\s*[\w\s\*]*?\b(\w*(?:sharedCache|SharedRegion)\w*)(\[\d+\])?;/).map { |n, a| n == 'processDetachedFromSharedRegion' ? "bool #{n};" : n == 'sharedCacheUUID' ? "uint8_t #{n}#{a};" : "uintptr_t #{n};" }).join(' ')} } storage, *gProcessInfo = &storage;
      static void log(const char*, ...) {}
    }
    struct { const DyldSharedCache* dyldCache = nullptr; bool verboseMapping = false; } gLinkContext;
    static bool gEnableSharedCacheDataConst = false;
    static dyld3::SharedCacheLoadInfo sSharedCacheLoadInfo;
    static int mach_task_self() { return 5; }
    #{squash.(state_fn)}
    #{const_fn}

    static void poison() {
      memset(&dyld::storage, 0x5a, sizeof dyld::storage); gLinkContext.dyldCache = (const DyldSharedCache*)0x77;
      dyld3::trace = dyld3::Trace();
    }

    int main() {
      static DyldSharedCache cache;
      for (int i = 0; i < 16; ++i) cache.uuid[i] = (uint8_t)(0xa0 + i);
      // no cache mapped: nothing is touched
      poison(); sSharedCacheLoadInfo = {}; installSharedCacheGlobalState(true);
      CHECK(gLinkContext.dyldCache == (const DyldSharedCache*)0x77 && dyld::storage.sharedCacheSlide == 0x5a5a5a5a5a5a5a5aULL && dyld3::trace.calls == 0);

      for (bool priv : { true, false }) {
        poison();
        sSharedCacheLoadInfo.loadAddress = &cache; sSharedCacheLoadInfo.slide = 0x1234;
        strcpy(sSharedCacheLoadInfo.path, "/cache/dyld_shared_cache_arm64e");
        installSharedCacheGlobalState(priv);
        CHECK(gLinkContext.dyldCache == &cache);
        CHECK(dyld::storage.sharedCacheBaseAddress == (uintptr_t)&cache);
        CHECK(dyld::storage.sharedCacheSlide == 0x1234);
        CHECK(memcmp(dyld::storage.sharedCacheUUID, cache.uuid, 16) == 0);
        CHECK(dyld::storage.processDetachedFromSharedRegion == priv);
        CHECK(dyld3::trace.calls == 1 && dyld3::trace.code == DBG_DYLD_UUID_SHARED_CACHE_A);
        CHECK(dyld3::trace.mh == (const void*)&cache && dyld3::trace.uuid == (const void*)dyld::storage.sharedCacheUUID);
        CHECK(!strcmp(dyld3::trace.path, "/cache/dyld_shared_cache_arm64e"));
      }

      // __DATA_CONST: only a process whose state differs from the cache's gets its permissions changed
      cache.dataConstCalls = 0;
      gEnableSharedCacheDataConst = true;  matchSharedCacheDataConstState(true);
      gEnableSharedCacheDataConst = false; matchSharedCacheDataConstState(false);
      CHECK(cache.dataConstCalls == 0);
      gEnableSharedCacheDataConst = false; matchSharedCacheDataConstState(true);
      CHECK(cache.dataConstCalls == 1 && cache.lastPermissions == (VM_PROT_READ | VM_PROT_WRITE) && !cache.loggerPassed);
      gEnableSharedCacheDataConst = true; gLinkContext.verboseMapping = true; matchSharedCacheDataConstState(false);
      CHECK(cache.dataConstCalls == 2 && cache.lastPermissions == VM_PROT_READ && cache.loggerPassed);
      sSharedCacheLoadInfo = {}; matchSharedCacheDataConstState(false);
      CHECK(cache.dataConstCalls == 2);

      if (failures) { printf("%d failure(s)\\n", failures); return 1; }
      puts("PASS global state of a mapped cache and the __DATA_CONST override");
      return 0;
    }
  CPP

  # --- libdyld asks every mapped cache for its objc tables: a split cache has none of the dyld3 image arrays ---
  cache_src = File.read("#{root}/dyld3/shared-cache/DyldSharedCache.cpp")
  objc_opt_fn = cache_src[/^const objc_opt::objc_opt_t\* DyldSharedCache::objcOpt\(\) const \{.*?^\}/m] or abort 'objcOpt missing'
  objc_range_fn = cache_src[/^std::pair<const void\*, uint64_t> DyldSharedCache::getObjCConstantRange\(\) const \{.*?^\}/m] or abort 'getObjCConstantRange missing'
  run_cpp(dir, 'objc', <<~CPP, root)
    #{COMMON}
    #include <utility>
    #define TARGET_OS_OSX 1
    namespace objc_opt { struct objc_opt_t { uint32_t version; }; static const uint32_t VERSION = 16; }
    static int arrayCalls = 0;
    static objc_opt::objc_opt_t gOpt = { objc_opt::VERSION };
    static char gRanges[16];
    namespace dyld3 {
      namespace closure { struct Image { uint32_t cacheOffset() const { return 0; } };
                          struct ImageArray { const Image* imageForNum(uint32_t) const { static Image i; return &i; } }; }
      struct MachOAnalyzer {
        struct SegmentInfo { const char* segName; };
        struct SectionInfo { SegmentInfo segInfo; uint64_t sectAddr; const char* sectName; };
        int64_t getSlide() const { return 0; }
        void forEachSection(void (^cb)(const SectionInfo&, bool, bool&)) const {
          SectionInfo info = { { "__TEXT" }, (uint64_t)(uintptr_t)&gOpt, "__objc_opt_ro" }; bool stop = false; cb(info, false, stop);
        }
        const void* findSectionContent(const char*, const char*, uint64_t& size) const { size = sizeof gRanges; return gRanges; }
      };
    }
    struct DyldSharedCache {
      bool split = false;
      bool isSplitCache() const { return split; }
      bool hasImagePath(const char*, uint32_t& index) const { index = 0; return true; }
      const dyld3::closure::ImageArray* cachedDylibsImageArray() const { ++arrayCalls; static dyld3::closure::ImageArray a; return &a; }
      const objc_opt::objc_opt_t* objcOpt() const;
      std::pair<const void*, uint64_t> getObjCConstantRange() const;
    };
    #{objc_opt_fn}
    #{objc_range_fn}
    int main() {
      DyldSharedCache cache;
      // an ordinary cache is read exactly as before
      CHECK(cache.objcOpt() == &gOpt);
      CHECK(cache.getObjCConstantRange().first == gRanges && cache.getObjCConstantRange().second == sizeof gRanges);
      CHECK(arrayCalls > 0);
      // a split cache has no tables to give and the image array (which it does not have) is never read
      arrayCalls = 0; cache.split = true;
      CHECK(cache.objcOpt() == nullptr);
      CHECK(cache.getObjCConstantRange().first == nullptr && cache.getObjCConstantRange().second == 0);
      CHECK(arrayCalls == 0);
      if (failures) { printf("%d failure(s)\\n", failures); return 1; }
      puts("PASS objc tables of a split cache are absent, not read through a missing image array");
      return 0;
    }
  CPP
end
