# The pieces dyld uses to wire a split macOS cache into a process (DYLD_SHARED_CACHE_SPLIT_DIR): the cache
# file name derived from the main executable's architecture, the directory validation and the main file
# path. Each check runs the real function extracted from dyld3/SharedCacheRuntime.cpp.
# Usage: ruby tests/split-cache-wiring.rb [checkout]
require 'tmpdir'
require 'open3'
require 'fileutils'
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

CPU_DEFS = <<~CPP
  #define CPU_TYPE_ARM64 0x0100000C
  #define CPU_TYPE_ARM64_32 0x0200000C
  #define CPU_TYPE_X86_64 0x01000007
  #define CPU_TYPE_ARM 12
  #define CPU_TYPE_I386 7
  #define CPU_SUBTYPE_MASK 0xff000000
  #define CPU_SUBTYPE_ARM64_ALL 0
  #define CPU_SUBTYPE_ARM64_V8 1
  #define CPU_SUBTYPE_ARM64E 2
CPP

names_src = (runtime[/^\/\/ The longest directory accepted.*?^const char\* splitCacheMainFilePath\(.*?^\}/m] or abort 'name helpers missing')
decls = %w[splitCacheArchName splitCacheDirError splitCacheMainFilePath].map { |n| runtime_h[/^const char\* #{n}\(.*?;/m] }.join("\n") + "\n" + runtime_h[/^bool splitCacheArchHasMapper\(.*?;/m].to_s
abort 'name helper declarations missing' if decls.scan(/splitCache/).size != 4

Dir.mktmpdir('split-cache-wiring-') do |dir|
  run_cpp(dir, 'names', <<~CPP, root)
    #{COMMON}
    #include "dyld_cache_format.h"
    #{CPU_DEFS}
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
      // --- which architectures have a mapper: arm64 and arm64e only (x86_64 has a cache name but no mapper) ---
      CHECK(splitCacheArchHasMapper(CPU_TYPE_ARM64, CPU_SUBTYPE_ARM64E) && splitCacheArchHasMapper(CPU_TYPE_ARM64, 0x80000002));
      CHECK(splitCacheArchHasMapper(CPU_TYPE_ARM64, CPU_SUBTYPE_ARM64_ALL) && splitCacheArchHasMapper(CPU_TYPE_ARM64, CPU_SUBTYPE_ARM64_V8));
      CHECK(!splitCacheArchHasMapper(CPU_TYPE_X86_64, 3) && !splitCacheArchHasMapper(CPU_TYPE_X86_64, 8));
      CHECK(!splitCacheArchHasMapper(CPU_TYPE_I386, 3) && !splitCacheArchHasMapper(CPU_TYPE_ARM64, 3) && !splitCacheArchHasMapper(CPU_TYPE_ARM64_32, 1));
      CHECK(!splitCacheArchHasMapper(CPU_TYPE_ARM, 9) && !splitCacheArchHasMapper(0, 0));

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

  # The legacy (non-DARLING) cache block in _main: the original statements with the DATA_CONST block as a call.
  legacy_main = dyld2[/^#ifndef DARLING\n\t\/\/ While the shared cache code.*?^#else\n(?=\t\/\/ Off unless)/m] or abort 'legacy cache block in _main missing'
  legacy_main_golden = <<~'GOLDEN'
    #ifndef DARLING
    checkSharedRegionDisable((dyld3::MachOLoaded*)mainExecutableMH, mainExecutableSlide);
    if ( gLinkContext.sharedRegionMode != ImageLoader::kDontUseSharedRegion ) {
    #if TARGET_OS_SIMULATOR
    if ( sSharedCacheOverrideDir)
    mapSharedCache(mainExecutableSlide);
    #else
    mapSharedCache(mainExecutableSlide);
    #endif
    matchSharedCacheDataConstState(sharedCacheDataConstIsEnabled);
    }
    #else
  GOLDEN
  abort 'the legacy cache block in _main changed' unless squash.(legacy_main) == legacy_main_golden.gsub(/\s+/, ' ').strip

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

  # --- DYLD_SHARED_CACHE_SPLIT_DIR: parsed like DYLD_SHARED_CACHE_DIR, ignored by restricted processes ---
  env_branch = dyld2[/^\telse if \( \(strcmp\(key, "DYLD_SHARED_CACHE_SPLIT_DIR"\) == 0\).*?^\t\}/m] or abort 'environment branch missing'
  policy_branch = dyld2[/^\telse if \( \(strcmp\(key, "DYLD_SHARED_CACHE_SPLIT_POLICY"\) == 0\).*?^\t\}/m] or abort 'policy environment branch missing'
  abort 'the DYLD_SHARED_CACHE_SPLIT_DIR branch is not inside #ifdef DARLING' unless dyld2.include?("#ifdef DARLING\n\t// A restricted process must not choose which cache it maps, so this needs the path permission as well.\n\telse if")
  abort 'processDyldEnvironmentVariable does not hold the branch' unless dyld2[/^void processDyldEnvironmentVariable\(.*?^\}/m].to_s.include?(env_branch)
  abort 'processDyldEnvironmentVariable does not hold the policy branch' unless dyld2[/^void processDyldEnvironmentVariable\(.*?^\}/m].to_s.include?(policy_branch)
  # LC_DYLD_ENVIRONMENT load commands only feed *_PATH variables, so a binary cannot name a cache directory
  lc_filter = dyld2[/^static void checkLoadCommandEnvironmentVariables\(\).*?^\}/m].to_s
  abort 'the load command filter changed' unless lc_filter.include?('strncmp(&equals[-5], "_PATH", 5) == 0') && !'DYLD_SHARED_CACHE_SPLIT_DIR'.end_with?('_PATH')

  run_cpp(dir, 'env', <<~CPP, root)
    #{COMMON}
    static struct { bool allowEnvVarsSharedCache, allowEnvVarsPath; } gLinkContext;
    static const char* sSharedCacheSplitDir;
    static const char* sSharedCacheSplitPolicy;
    static void process(const char* key, const char* value) {
      if ( false ) {}
      #{env_branch}
      #{policy_branch}
    }
    int main() {
      const char* kDir = "/some/dir";
      struct Case { bool shared, path; const char* key; bool stored; } cases[] = {
        { true,  true,  "DYLD_SHARED_CACHE_SPLIT_DIR", true  },
        { true,  false, "DYLD_SHARED_CACHE_SPLIT_DIR", false },   // restricted: no path variables
        { false, true,  "DYLD_SHARED_CACHE_SPLIT_DIR", false },   // custom caches not allowed
        { false, false, "DYLD_SHARED_CACHE_SPLIT_DIR", false },
        { true,  true,  "DYLD_SHARED_CACHE_DIR",       false },   // another variable
        { true,  true,  "DYLD_SHARED_CACHE_SPLIT_DIR_X", false },
        { true,  true,  "dyld_shared_cache_split_dir", false },
      };
      for (const Case& c : cases) {
        sSharedCacheSplitDir = nullptr;
        gLinkContext.allowEnvVarsSharedCache = c.shared; gLinkContext.allowEnvVarsPath = c.path;
        process(c.key, kDir);
        CHECK((sSharedCacheSplitDir == kDir) == c.stored);
        CHECK(c.stored || sSharedCacheSplitDir == nullptr);
      }
      // the policy variable follows the same permissions, and neither variable sets the other
      for (const Case& c : cases) {
        sSharedCacheSplitDir = nullptr; sSharedCacheSplitPolicy = nullptr;
        gLinkContext.allowEnvVarsSharedCache = c.shared; gLinkContext.allowEnvVarsPath = c.path;
        const bool policyKey = !strcmp(c.key, "DYLD_SHARED_CACHE_SPLIT_DIR");
        process(policyKey ? "DYLD_SHARED_CACHE_SPLIT_POLICY" : c.key, kDir);
        CHECK((sSharedCacheSplitPolicy == kDir) == (policyKey && c.stored));
        CHECK(sSharedCacheSplitDir == nullptr);
      }
      sSharedCacheSplitPolicy = nullptr; gLinkContext.allowEnvVarsSharedCache = true; gLinkContext.allowEnvVarsPath = true;
      process("DYLD_SHARED_CACHE_SPLIT_POLICY_X", kDir); process("dyld_shared_cache_split_policy", kDir);
      CHECK(sSharedCacheSplitPolicy == nullptr);
      process("DYLD_SHARED_CACHE_SPLIT_POLICY", "");   // set but empty stays set: the loader rejects it loudly
      CHECK(sSharedCacheSplitPolicy != nullptr && sSharedCacheSplitPolicy[0] == '\\0');
      // a set but empty value is kept as set: the mapping step rejects it loudly rather than ignoring the request
      sSharedCacheSplitDir = nullptr; gLinkContext.allowEnvVarsSharedCache = true; gLinkContext.allowEnvVarsPath = true;
      process("DYLD_SHARED_CACHE_SPLIT_DIR", "");
      CHECK(sSharedCacheSplitDir != nullptr && sSharedCacheSplitDir[0] == '\\0');
      if (failures) { printf("%d failure(s)\\n", failures); return 1; }
      puts("PASS DYLD_SHARED_CACHE_SPLIT_DIR and _POLICY parsing and restricted processes");
      return 0;
    }
  CPP

  # --- the only entry into the new code is guarded by the variable and by DARLING ---
  # Every use of the split wiring must sit in a DARLING-only region of the preprocessor.
  wiring = /sSharedCacheSplitDir|sSharedCacheSplitPolicy|mapSplitSharedCache|mapSplitCachePrivate|splitCacheMainFilePath|splitCacheMainFileIsMissing|loadSplitCachePolicy/
  stack = []
  stray = []
  dyld2.each_line.with_index(1) do |line, number|
    case line
    when /^\s*#\s*ifdef\s+DARLING\b/ then stack.push(:darling)
    when /^\s*#\s*ifndef\s+DARLING\b/ then stack.push(:not_darling)
    when /^\s*#\s*if/ then stack.push(:other)
    when /^\s*#\s*elif\b/ then stack[-1] = :other
    when /^\s*#\s*else\b/ then stack[-1] = { darling: :not_darling, not_darling: :darling }.fetch(stack[-1], stack[-1])
    when /^\s*#\s*endif\b/ then stack.pop
    else stray << number if line =~ wiring && line !~ %r{^\s*//} && !stack.include?(:darling)
    end
  end
  abort "split wiring outside a DARLING-only region at dyld2.cpp lines #{stray}" unless stray.empty?
  abort 'mapSplitSharedCache has an unexpected number of uses' unless dyld2.scan(/\bmapSplitSharedCache\(/).size == 2
  entry = dyld2[/^#else\n(\t\/\/ Off unless DYLD_SHARED_CACHE_SPLIT_DIR.*?)^#endif \/\/ !DARLING/m, 1] or abort 'DARLING branch of the cache block missing'
  abort 'the call is not guarded by the variable' unless entry =~ /\A[^\n]*\n\s*if \( sSharedCacheSplitDir != nullptr \) \{\n(?:\s*\/\/[^\n]*\n)?\s*gLinkContext\.sharedRegionMode = ImageLoader::kUsePrivateSharedRegion;\n\s*if \( mapSplitSharedCache\(mainExecutableMH\) \) \{/
  abort 'more than the guarded block' unless entry.scan(/^\t\S/).size == 3  # comment line, the if, its closing brace

  run_cpp(dir, 'entry', <<~CPP, root)
    #{COMMON}
    #include <vector>
    struct macho_header { uint32_t magic; int cputype, cpusubtype; };
    enum class ClosureMode { Unset, Off, On, PreBuiltOnly };
    static ClosureMode sClosureMode = ClosureMode::PreBuiltOnly;
    static const char* sSharedCacheSplitDir;
    static std::vector<std::string> calls;
    struct ImageLoader { enum SharedRegionMode { kUseSharedRegion, kUsePrivateSharedRegion, kDontUseSharedRegion }; };
    static struct { ImageLoader::SharedRegionMode sharedRegionMode = ImageLoader::kUseSharedRegion; } gLinkContext;
    // the mapper is called with the process already in private-region mode
    static bool mapped = true;
    static bool mapSplitSharedCache(const macho_header*) { calls.push_back(gLinkContext.sharedRegionMode == ImageLoader::kUsePrivateSharedRegion ? "map" : "map-not-private"); return mapped; }
    static void matchSharedCacheDataConstState(bool enabled) { calls.push_back(enabled ? "match1" : "match0"); }
    static void entry(const macho_header* mainExecutableMH, bool sharedCacheDataConstIsEnabled) {
      #{entry}
    }
    int main() {
      macho_header mh = { 0, 0, 0 };
      // variable not set: nothing runs and nothing changes
      sSharedCacheSplitDir = nullptr; entry(&mh, true);
      CHECK(calls.empty() && sClosureMode == ClosureMode::PreBuiltOnly && gLinkContext.sharedRegionMode == ImageLoader::kUseSharedRegion);
      // set (even to an empty string): the cache is mapped first, then the closures are turned off, then DATA_CONST is
      // matched against what the mapper produced (read-only), whatever the process's own snapshot says
      for (const char* value : { "/d", "" }) {
        for (bool snapshot : { true, false }) {
          calls.clear(); sClosureMode = ClosureMode::PreBuiltOnly; sSharedCacheSplitDir = value; gLinkContext.sharedRegionMode = ImageLoader::kUseSharedRegion;
          entry(&mh, snapshot);
          CHECK(calls.size() == 2 && calls[0] == "map" && calls[1] == "match1" && sClosureMode == ClosureMode::Off
                && gLinkContext.sharedRegionMode == ImageLoader::kUsePrivateSharedRegion);
        }
      }
      // no cache for this architecture: nothing but the attempt, closures and DATA_CONST stay as they were
      mapped = false;
      for (bool snapshot : { true, false }) {
        calls.clear(); sClosureMode = ClosureMode::PreBuiltOnly; sSharedCacheSplitDir = "/d";
        entry(&mh, snapshot);
        CHECK(calls.size() == 1 && calls[0] == "map" && sClosureMode == ClosureMode::PreBuiltOnly);
      }
      if (failures) { printf("%d failure(s)\\n", failures); return 1; }
      puts("PASS the split cache block is entered only when the variable is set");
      return 0;
    }
  CPP

  # --- a failure to map the cache the user asked for is fatal and says why; a directory with no cache for this
  # architecture is not a failure; no message names the host's directory ---
  map_fn = dyld2[/^static bool mapSplitSharedCache\(.*?^\}/m] or abort 'mapSplitSharedCache missing'
  basename_fn = dyld2[/^static const char\* basename\(.*?^\}/m] or abort 'basename missing'
  missing_src = runtime[/^bool splitCacheMainFileIsMissing\(.*?^\}/m] or abort 'splitCacheMainFileIsMissing missing'
  missing_decl = runtime_h[/^bool splitCacheMainFileIsMissing\(.*?;/m] or abort 'splitCacheMainFileIsMissing declaration missing'
  store = "#{dir}/Volumes/SystemRoot/home/someone/.darling-launcher/dyld-cache/arm64e-0123"
  FileUtils.mkdir_p(store)
  File.write("#{store}/dyld_shared_cache_arm64e", '')
  FileUtils.mkdir_p("#{dir}/emptystore")
  File.write("#{dir}/store-is-a-file", '')
  FileUtils.mkdir_p("#{dir}/dangling")
  File.symlink("#{dir}/no-such-target", "#{dir}/dangling/dyld_shared_cache_arm64")   # a store whose file went missing
  noaccess_check = Process.uid == 0 ? '// (the unreadable-directory case is skipped as root: permissions do not apply)' :
    "m = attempt(\"#{dir}/noaccess\", CPU_TYPE_ARM64, CPU_SUBTYPE_ARM64_ALL);\n      CHECK(m.empty() && lastResult && dyld3::mapper.calls == 1);"
  FileUtils.mkdir_p("#{dir}/noaccess")
  File.chmod(0, "#{dir}/noaccess")   # a directory whose files cannot be looked up: not the same as "no such file"
  run_cpp(dir, 'map', <<~CPP, root)
    #{COMMON}
    #include <vector>
    #include <stdarg.h>
    #include <errno.h>
    #include <sys/stat.h>
    #{CPU_DEFS}
    struct macho_header { uint32_t magic; int cputype, cpusubtype; };
    #include "dyld_cache_format.h"
    namespace dyld3 {
      struct SharedCacheLoadInfo { const void* loadAddress; long slide; const char* errorMessage; char path[256]; };
      struct SplitCacheMapStats {};
      struct SharedCacheAllowList { const char* const* paths; size_t count; };
      struct SharedCacheFindDylibResults { const char* pathInCache; };
      static int stat(const char* path, struct stat* buf) { return ::stat(path, buf); }
      #{decls}
      #{missing_decl}
      #{names_src}
      #{missing_src}
      static struct { bool ok = true; const char* error = "the cache is gone"; int calls = 0; std::string path; bool verbose = false; } mapper;
      bool mapSplitCachePrivate(const char* path, bool verbose, SharedCacheLoadInfo* results, SplitCacheMapStats*) {
        ++mapper.calls; mapper.path = path; mapper.verbose = verbose;
        results->errorMessage = mapper.ok ? nullptr : mapper.error;
        return mapper.ok;
      }
      // the policy loader: refuses what the test says it refuses, with the line it says
      static struct { const char* error = nullptr; size_t line = 0; int calls = 0; std::string path; } policy;
      const char* loadSplitCachePolicy(const char* path, size_t* line) { ++policy.calls; policy.path = path; *line = policy.line; return policy.error; }
      // the allow-list as the policy left it; "/usr/lib/libalias.dylib" is a cache alias, whose canonical name differs
      static const char* const kList[] = { "/usr/lib/libz.1.dylib", "/usr/lib/libnot-in-cache.dylib", "/usr/lib/libalias.dylib" };
      static SharedCacheAllowList list = { kList, 3 };
      const SharedCacheAllowList& sharedCacheAllowList() { return list; }
      bool findInSharedCacheImage(const SharedCacheLoadInfo&, const char* path, SharedCacheFindDylibResults* r) {
        if ( !strcmp(path, "/usr/lib/libz.1.dylib") ) { r->pathInCache = "/usr/lib/libz.1.dylib"; return true; }
        if ( !strcmp(path, "/usr/lib/libalias.dylib") ) { r->pathInCache = "/usr/lib/libcanonical.dylib"; return true; }
        return false;
      }
    }
    static dyld3::SharedCacheLoadInfo sSharedCacheLoadInfo;
    static struct { bool verboseMapping = false; } gLinkContext;
    static const char* sSharedCacheSplitDir;
    static const char* sSharedCacheSplitPolicy;
    static int installCalls = 0; static bool installArg = false;
    static void installSharedCacheGlobalState(bool forcePrivate) { ++installCalls; installArg = forcePrivate; }
    static std::vector<std::string> logs;
    static const char* mkstringf(const char* format, ...) {
      static char buffers[4][1024]; static int next = 0; char* b = buffers[next++ % 4];
      va_list ap; va_start(ap, format); vsnprintf(b, 1024, format, ap); va_end(ap); return b;
    }
    namespace dyld { using ::mkstringf; static void log(const char* f, ...) { char b[1024]; va_list a; va_start(a, f); vsnprintf(b, sizeof b, f, a); va_end(a); logs.push_back(b); } }
    // halt() never returns: the test throws instead
    [[noreturn]] static void halt(const char* message) { throw std::string(message); }
    // the host's string.h declares its own basename
    #define basename dyld_basename
    #{basename_fn}
    #{map_fn}

    static bool lastResult = false;
    // runs the function; returns the halt message, or "" when it returned
    static std::string attempt(const char* dir, int cputype, int cpusubtype, const char* policyPath = nullptr) {
      sSharedCacheSplitDir = dir; sSharedCacheSplitPolicy = policyPath;
      dyld3::mapper.calls = 0; installCalls = 0; dyld3::mapper.path.clear(); dyld3::policy.calls = 0; logs.clear(); lastResult = false;
      macho_header mh = { 0, cputype, cpusubtype };
      try { lastResult = mapSplitSharedCache(&mh); } catch (const std::string& m) { return m; }
      return "";
    }
    static bool logged(const char* what) { for (const std::string& l : logs) if (l.find(what) != std::string::npos) return true; return false; }
    int main() {
      std::string m;
      // success: maps <dir>/dyld_shared_cache_arm64e privately, then installs the global state
      m = attempt("/cache", CPU_TYPE_ARM64, 0x80000002);
      CHECK(m.empty() && lastResult && dyld3::mapper.calls == 1 && dyld3::mapper.path == "/cache/dyld_shared_cache_arm64e" && installCalls == 1 && installArg == true);
      gLinkContext.verboseMapping = true; attempt("/cache", CPU_TYPE_ARM64, 2); CHECK(dyld3::mapper.verbose); gLinkContext.verboseMapping = false;
      // the mapper fails: halt, with the file and the mapper's reason; the state is not installed
      dyld3::mapper.ok = false;
      m = attempt("/cache", CPU_TYPE_ARM64, CPU_SUBTYPE_ARM64E);
      CHECK(!m.empty() && m.find("dyld_shared_cache_arm64e") != std::string::npos && m.find("the cache is gone") != std::string::npos);
      CHECK(installCalls == 0 && dyld3::mapper.calls == 1);
      dyld3::mapper.error = nullptr;
      m = attempt("/cache", CPU_TYPE_ARM64, CPU_SUBTYPE_ARM64E);
      CHECK(m.find("no reason given") != std::string::npos && installCalls == 0);
      dyld3::mapper.ok = true; dyld3::mapper.error = "unused";
      // the variable is invalid: halt without touching the mapper
      const char* bad[] = { "", "relative/dir", "/cache\\n" };
      const char* why[] = { "empty", "absolute", "control" };
      for (int i = 0; i < 3; ++i) {
        m = attempt(bad[i], CPU_TYPE_ARM64, CPU_SUBTYPE_ARM64E);
        CHECK(m.find("DYLD_SHARED_CACHE_SPLIT_DIR") != std::string::npos && m.find(why[i]) != std::string::npos);
        CHECK(dyld3::mapper.calls == 0 && installCalls == 0);
      }
      // children inherit the variable: an architecture with no split mapper (x86_64, i386) or no cache at all runs without one,
      // whatever the directory or the policy are, silently unless verbose
      const struct { int type, subtype; } noMapper[] = { { CPU_TYPE_X86_64, 3 }, { CPU_TYPE_X86_64, 8 }, { CPU_TYPE_I386, 3 }, { CPU_TYPE_ARM64_32, 1 }, { CPU_TYPE_ARM64, 7 } };
      for (const auto& a : noMapper) {
        for (const char* dir : { "/cache", "relative", "" }) {
          m = attempt(dir, a.type, a.subtype, "/p");
          CHECK(m.empty() && !lastResult && dyld3::mapper.calls == 0 && installCalls == 0 && dyld3::policy.calls == 0 && logs.empty());
        }
      }
      gLinkContext.verboseMapping = true;
      m = attempt("/Volumes/SystemRoot/x", CPU_TYPE_X86_64, 3);
      CHECK(m.empty() && !lastResult && logs.size() == 1 && logs[0] == "dyld: continuing without a shared cache: no split cache mapper for this architecture\\n" && logs[0].find("SystemRoot") == std::string::npos);
      gLinkContext.verboseMapping = false;

      // --- the directory holds only the arm64e cache (what macOS ships) ---
      const std::string store = "#{store}";
      // an arm64e process maps it
      m = attempt(store.c_str(), CPU_TYPE_ARM64, 0x80000002);
      CHECK(m.empty() && lastResult && dyld3::mapper.calls == 1 && dyld3::mapper.path == store + "/dyld_shared_cache_arm64e" && installCalls == 1);
      // a plain arm64 process wants dyld_shared_cache_arm64: it runs without a cache, silently unless verbose
      for (int subtype : { CPU_SUBTYPE_ARM64_ALL, CPU_SUBTYPE_ARM64_V8 }) {
        m = attempt(store.c_str(), CPU_TYPE_ARM64, subtype);
        CHECK(m.empty() && !lastResult && dyld3::mapper.calls == 0 && installCalls == 0 && logs.empty());
      }
      gLinkContext.verboseMapping = true;
      m = attempt(store.c_str(), CPU_TYPE_ARM64, CPU_SUBTYPE_ARM64_ALL);
      CHECK(m.empty() && !lastResult && logs.size() == 1 && logs[0] == "dyld: continuing without a shared cache: dyld_shared_cache_arm64 not found\\n");
      CHECK(logs[0].find("SystemRoot") == std::string::npos && logs[0].find(store) == std::string::npos);
      gLinkContext.verboseMapping = false;
      // only a missing file in a real directory counts: a missing or non-directory dir, or a dir that is a file, stays fatal
      // (the mapper is then reached and reports it)
      m = attempt("#{dir}/no-such-dir", CPU_TYPE_ARM64, CPU_SUBTYPE_ARM64_ALL);
      CHECK(m.empty() && lastResult && dyld3::mapper.calls == 1);
      m = attempt("#{dir}/store-is-a-file", CPU_TYPE_ARM64, CPU_SUBTYPE_ARM64_ALL);
      CHECK(m.empty() && lastResult && dyld3::mapper.calls == 1);
      #{noaccess_check}
      // a dangling symbolic link at the main file's name is a broken store, not a missing architecture: the mapper reports it
      m = attempt("#{dir}/dangling", CPU_TYPE_ARM64, CPU_SUBTYPE_ARM64_ALL);
      CHECK(m.empty() && lastResult && dyld3::mapper.calls == 1);
      // an empty real directory has no cache for any architecture
      m = attempt("#{dir}/emptystore", CPU_TYPE_ARM64, CPU_SUBTYPE_ARM64E);
      CHECK(m.empty() && !lastResult && dyld3::mapper.calls == 0);
      // a file that is there but cannot be mapped is a genuine error: the mapper's refusal halts
      dyld3::mapper.ok = false; dyld3::mapper.error = "split cache file has wrong magic";
      m = attempt(store.c_str(), CPU_TYPE_ARM64, 0x80000002);
      CHECK(m.find("wrong magic") != std::string::npos && dyld3::mapper.calls == 1 && installCalls == 0);
      dyld3::mapper.ok = true;

      // --- no message names the host's directory ---
      dyld3::mapper.ok = false;
      const std::string hostDir = "/Volumes/SystemRoot/home/someone/.darling-launcher/dyld-cache/arm64e-0123";
      m = attempt(hostDir.c_str(), CPU_TYPE_ARM64, 0x80000002);
      CHECK(m.find("dyld_shared_cache_arm64e") != std::string::npos);
      CHECK(m.find("SystemRoot") == std::string::npos && m.find("someone") == std::string::npos && m.find(hostDir) == std::string::npos);
      dyld3::mapper.ok = true;
      m = attempt((hostDir + "\\n").c_str(), CPU_TYPE_ARM64, 0x80000002);
      CHECK(m.find("control") != std::string::npos && m.find("SystemRoot") == std::string::npos && m.find("someone") == std::string::npos);
      const std::string longDir = "/Volumes/SystemRoot/" + std::string(300, 'a');
      m = attempt(longDir.c_str(), CPU_TYPE_ARM64, 0x80000002);
      CHECK(m.find("too long") != std::string::npos && m.find("SystemRoot") == std::string::npos);

      // --- the policy ---
      // not set: the loader is not called
      m = attempt("/cache", CPU_TYPE_ARM64, 0x80000002);
      CHECK(m.empty() && dyld3::policy.calls == 0);
      // set and good: loaded before the cache is mapped, then the process maps it
      m = attempt("/cache", CPU_TYPE_ARM64, 0x80000002, "/.darling-launcher/dyld-cache.policy");
      CHECK(m.empty() && lastResult && dyld3::policy.calls == 1 && dyld3::policy.path == "/.darling-launcher/dyld-cache.policy" && dyld3::mapper.calls == 1);
      // set and bad: halt with the file name, the reason and the line, before anything is mapped, and the path is not in the message
      dyld3::policy.error = "the install name is listed twice"; dyld3::policy.line = 7;
      m = attempt("/cache", CPU_TYPE_ARM64, 0x80000002, "/.darling-launcher/dyld-cache.policy");
      CHECK(m.find("dyld-cache.policy") != std::string::npos && m.find("listed twice") != std::string::npos && m.find("line 7") != std::string::npos);
      CHECK(m.find("/.darling-launcher") == std::string::npos && dyld3::mapper.calls == 0 && installCalls == 0);
      // a process that maps no cache has no use for the policy, so a bad one cannot halt it: not an arm64 child
      // whose directory holds only the arm64e cache, and (above) not an x86_64 child
      m = attempt(store.c_str(), CPU_TYPE_ARM64, CPU_SUBTYPE_ARM64_ALL, "/Volumes/SystemRoot/x/dyld-cache.policy");
      CHECK(m.empty() && !lastResult && dyld3::policy.calls == 0 && dyld3::mapper.calls == 0);
      // a bad directory is reported before the policy is read
      m = attempt("relative", CPU_TYPE_ARM64, 0x80000002, "/p");
      CHECK(m.find("DYLD_SHARED_CACHE_SPLIT_DIR") != std::string::npos && dyld3::policy.calls == 0);
      // a bad policy halts a process that does map the cache, and the cache is not mapped
      m = attempt(store.c_str(), CPU_TYPE_ARM64, 0x80000002, "/Volumes/SystemRoot/x/dyld-cache.policy");
      CHECK(!m.empty() && m.find("SystemRoot") == std::string::npos && dyld3::policy.calls == 1 && dyld3::mapper.calls == 0);
      // a refusal that is not about one line says no line
      dyld3::policy.error = "the policy file does not exist"; dyld3::policy.line = 0;
      m = attempt("/cache", CPU_TYPE_ARM64, 0x80000002, "/.darling-launcher/dyld-cache.policy");
      CHECK(m.find("does not exist") != std::string::npos && m.find("line") == std::string::npos && m.find("dyld-cache.policy") != std::string::npos);
      dyld3::policy.error = nullptr;
      // a good policy and a process with no cache: no halt, nothing read, nothing mapped
      m = attempt(store.c_str(), CPU_TYPE_ARM64, CPU_SUBTYPE_ARM64_ALL, "/p");
      CHECK(m.empty() && !lastResult && dyld3::policy.calls == 0 && dyld3::mapper.calls == 0);

      // --- list entries that are not images of the cache are ignored, and only said so when verbose ---
      m = attempt("/cache", CPU_TYPE_ARM64, 0x80000002);
      CHECK(m.empty() && logs.empty());
      gLinkContext.verboseMapping = true;
      m = attempt("/cache", CPU_TYPE_ARM64, 0x80000002);
      CHECK(m.empty() && lastResult && logs.size() == 2 && logged("'/usr/lib/libnot-in-cache.dylib'") && logged("'/usr/lib/libalias.dylib'") && !logged("libz"));
      gLinkContext.verboseMapping = false;
      if (failures) { printf("%d failure(s)\\n", failures); return 1; }
      puts("PASS mapping failures abort with the reason, a missing architecture runs without a cache, messages hide the directory, only a process that maps a cache reads the policy");
      return 0;
    }
  CPP

  # --- interposing must not patch a split cache with the old patch table layout ---
  loader = File.read("#{root}/src/ImageLoader.cpp")
  interpose_fn = loader[/^void ImageLoader::applyInterposingToDyldCache\(.*?^\}/m] or abort 'applyInterposingToDyldCache missing'
  run_cpp(dir, 'interpose', <<~CPP, root)
    #{COMMON}
    #include <vector>
    #include <stdarg.h>
    typedef int mach_port_t;
    static int mach_task_self() { return 1; }
    struct dyld_cache_patchable_location { uint32_t cacheOffset; bool authenticated, usesAddressDiversity; uint16_t discriminator; uint8_t key; };
    namespace dyld3 { namespace closure { typedef uint32_t ImageNum; struct Image { const char* path() const { return ""; } };
                                          struct ImageArray { const Image* imageForNum(uint32_t) const { return nullptr; } }; } }
    static int writers = 0, tableReads = 0, imageArrayReads = 0;
    typedef int (*LogFunc)(const char*, ...);
    struct DyldSharedCache {
      struct { bool builtFromChainedFixups = true; } header;
      bool split = false;
      bool isSplitCache() const { return split; }
      struct DataConstScopedWriter { DataConstScopedWriter(const DyldSharedCache*, mach_port_t, void (*)(const char*, ...)) { ++writers; } };
      bool addressInText(uint32_t, uint32_t* i) const { ++tableReads; *i = 0; return true; }
      void forEachPatchableExport(uint32_t, void (^cb)(uint32_t, const char*)) const { ++tableReads; }
      void forEachPatchableUseOfExport(uint32_t, uint32_t, void (^cb)(dyld_cache_patchable_location)) const { ++tableReads; }
      const dyld3::closure::ImageArray* cachedDylibsImageArray() const { ++imageArrayReads; return nullptr; }
      static uint64_t getAddend(dyld_cache_patchable_location) { return 0; }
      static const char* keyName(dyld_cache_patchable_location) { return ""; }
    };
    static std::vector<std::string> logs;
    namespace dyld { static void log(const char* f, ...) { char b[256]; va_list a; va_start(a, f); vsnprintf(b, sizeof b, f, a); va_end(a); logs.push_back(b); } }
    class ImageLoader {
    public:
      struct LinkContext { const DyldSharedCache* dyldCache = nullptr; bool verboseMapping = false, verboseInterposing = false; };
      struct InterposeTuple { uintptr_t replacement, neverImage, onlyImage, replacee; };
      static std::vector<InterposeTuple> fgInterposingTuples;
      static void applyInterposingToDyldCache(const LinkContext&);
    };
    std::vector<ImageLoader::InterposeTuple> ImageLoader::fgInterposingTuples;
    #{interpose_fn}
    int main() {
      DyldSharedCache cache; ImageLoader::LinkContext ctx; ctx.dyldCache = &cache;
      ImageLoader::fgInterposingTuples.push_back({ 0x2000, 0, 0, (uintptr_t)&cache + 0x100 });
      // an ordinary cache keeps being patched
      ImageLoader::applyInterposingToDyldCache(ctx);
      CHECK(writers == 1 && tableReads > 0);
      // a split cache is left alone, loudly when asked: nothing is made writable and no patch table is read
      writers = tableReads = imageArrayReads = 0; cache.split = true; ctx.verboseInterposing = true;
      ImageLoader::applyInterposingToDyldCache(ctx);
      CHECK(writers == 0 && tableReads == 0 && imageArrayReads == 0);
      CHECK(!logs.empty() && logs.back().find("split shared cache") != std::string::npos);
      // quiet unless verbose, and a cache that was not built from chained fixups is still skipped
      logs.clear(); ctx.verboseInterposing = false;
      ImageLoader::applyInterposingToDyldCache(ctx);
      CHECK(logs.empty() && writers == 0 && tableReads == 0);
      if (failures) { printf("%d failure(s)\\n", failures); return 1; }
      puts("PASS interposing leaves a split cache's patch table alone");
      return 0;
    }
  CPP
end
