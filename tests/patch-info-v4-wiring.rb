# How dyld2.cpp applies the patch info override: the actual overrideSplitCacheGotSlots (extracted from src/dyld2.cpp,
# with the cache, the images and halt stubbed, and the real allow-list code of SharedCacheRuntime.cpp behind it).
# Checks which loaded images are treated as exporters (only a loaded dylib the cache does not serve, whose install
# name is in the cache and not allow-listed), that nothing runs without version 4 patch info or without a cache,
# that the symbols are looked up in the loaded image with dyld's own export lookup, that the totals add up, that a
# second pass counts nothing twice, that a reader error halts with the exporter's name, and that the two hooks sit
# in front of every initializer pass. The reader and the signing are tested in tests/patch-info-v4-override.rb.
# Usage: ruby tests/patch-info-v4-wiring.rb [checkout]
require 'tmpdir'
require 'open3'
root = File.realpath(ARGV.fetch(0, File.expand_path('..', __dir__)))
dyld2 = File.read("#{root}/src/dyld2.cpp")
dyld2_h = File.read("#{root}/src/dyld2.h")
runtime = File.read("#{root}/dyld3/SharedCacheRuntime.cpp")
runtime_h = File.read("#{root}/dyld3/SharedCacheRuntime.h")
override_fn = dyld2[/^static SplitCachePatchTotals sSplitCachePatchTotals;.*?^static void overrideSplitCacheGotSlots\(\).*?^\}/m] or abort 'overrideSplitCacheGotSlots missing'
totals_struct = dyld2_h[/^\tstruct SplitCachePatchTotals \{.*?^\t\};/m] or abort 'SplitCachePatchTotals missing'
allow_list = runtime[/^\/\/ libz is a leaf library.*?^bool sharedCachePathIsAllowListed\(.*?^\}/m] or abort 'allow-list code missing'
allow_decl = runtime_h[/^struct SharedCacheAllowList \{.*?^\};/m] or abort 'SharedCacheAllowList missing'

# The hooks: one call in front of the first initializer of the launch pass, one in front of the dlopen pass.
init_main = dyld2[/^void initializeMainExecutable\(\)\n\{.*?^\}/m] or abort 'initializeMainExecutable missing'
run_init = dyld2[/^void runInitializers\(ImageLoader\* image\)\n\{.*?^\}/m] or abort 'runInitializers missing'
[['initializeMainExecutable', init_main, 'runInitializers('], ['runInitializers', run_init, 'image->runInitializers(']].each do |name, body, first|
  hook = body.index('overrideSplitCacheGotSlots();')
  abort "#{name} does not call overrideSplitCacheGotSlots" unless hook
  abort "#{name} runs an initializer before the GOT override" unless hook < body.index(first)
  abort "#{name}: the call is not under #ifdef DARLING" unless body[0...hook].rindex('#ifdef DARLING') && body[hook..].include?('#endif')
end
puts 'ok   both initializer passes call overrideSplitCacheGotSlots first'

Dir.mktmpdir('patch-info-v4-wiring-') do |dir|
  File.write("#{dir}/test.cpp", <<~CPP)
    #include <stdint.h>
    #include <stddef.h>
    #include <stdarg.h>
    #include <string.h>
    #include <stdio.h>
    #include <stdlib.h>
    #include <string>
    #include <vector>
    #include <map>
    #include <set>
    #include <stdexcept>
    extern "C" { void *_NSConcreteStackBlock[32]; void *_NSConcreteGlobalBlock[32];
                 void _Block_object_assign(void*, const void*, const int) {}
                 void _Block_object_dispose(const void*, const int) {} }
    static int failures = 0;
    #define CHECK(cond) do { if (!(cond)) { printf("FAIL line %d: %s\\n", __LINE__, #cond); ++failures; } } while (0)
    struct DyldSharedCache;
    namespace dyld3 {
      #{allow_decl}
      #{allow_list}
      struct SharedCacheLoadInfo { const struct ::DyldSharedCache* loadAddress; };
    }
    // The cache: which images it has, whether it has version 4 patch info, and what overridePatchGotSlots does.
    struct DyldSharedCache {
      struct PatchOverrideStats { uint64_t exports, slots, patched, unexplained, missingExports, missingSlots; bool alreadyApplied; };
      typedef void (*DataConstLogFunc)(const char*, ...);
      bool patchInfo = true;
      std::vector<std::string> images = {"/usr/lib/libSystem.B.dylib", "/usr/lib/system/libsystem_kernel.dylib", "/usr/lib/system/libsystem_c.dylib", "/usr/lib/libz.1.dylib"};
      mutable std::vector<uint32_t> calls; mutable std::set<uint32_t> applied;
      const char *error = nullptr;                 // what overridePatchGotSlots returns for index 2
      const char *headerError = nullptr;           // what checkPatchInfoV4Headers returns
      bool hasPatchInfoV4() const { return patchInfo; }
      const char *checkPatchInfoV4Headers() const { return headerError; }
      bool hasImagePath(const char *path, uint32_t &index) const { for (uint32_t i = 0; i < images.size(); ++i) if (images[i] == path) { index = i; return true; } return false; }
      const char *getIndexedImagePath(uint32_t i) const { return images[i].c_str(); }
      // symbols the exporter has in its GOT: two the loaded image defines and one it does not
      const char *overridePatchGotSlots(uint32_t index, bool (^resolve)(const char *symbol, uint64_t *address), DataConstLogFunc, PatchOverrideStats *s) const {
        calls.push_back(index);
        memset(s, 0, sizeof *s);
        if (applied.count(index)) { s->alreadyApplied = true; return nullptr; }
        if (index == 2 && error) return error;
        applied.insert(index);
        for (const char *name : {"_open", "_close", "_nosuchsymbol"}) {
          uint64_t address = 0; ++s->exports; s->slots += 2;
          if (resolve(name, &address)) { s->patched += 2; lastAddress[name] = address; } else { ++s->missingExports; s->missingSlots += 2; }
        }
        return nullptr;
      }
      mutable std::map<std::string, uint64_t> lastAddress;
    };
    struct ImageLoader {
      struct LinkContext { bool verboseMapping = false; };
      std::string install; bool dylib = true, inCache = false; std::map<std::string, uintptr_t> exports;
      bool isDylib() const { return dylib; }
      const char *getInstallPath() const { return install.empty() ? nullptr : install.c_str(); }
      bool inSharedCache() const { return inCache; }
      // the real lookup is ImageLoader::findExportedSymbolAddress (searchReExports, resolvers run for a GOT pointer)
      bool findExportedSymbolAddress(const LinkContext &, const char *name, const ImageLoader *requestor, int ordinal, bool runResolver, const ImageLoader **foundIn, uintptr_t *address) const {
        if (requestor != nullptr || ordinal != -1 || !runResolver) return false;
        auto it = exports.find(name); if (it == exports.end()) return false;
        *foundIn = this; *address = it->second; return true;
      }
    };
    namespace dyld {
      #{totals_struct}
      ImageLoader::LinkContext gLinkContext;
      dyld3::SharedCacheLoadInfo sSharedCacheLoadInfo = {nullptr};
      std::vector<ImageLoader*> sAllImages;
      std::vector<std::string> logged; std::string halted;
      void log(const char *format, ...) { char buffer[512]; va_list a; va_start(a, format); vsnprintf(buffer, sizeof buffer, format, a); va_end(a); logged.push_back(buffer); }
      const char *mkstringf(const char *format, ...) { static char buffer[512]; va_list a; va_start(a, format); vsnprintf(buffer, sizeof buffer, format, a); va_end(a); return buffer; }
      void halt(const char *message) { throw std::runtime_error(message); }
      #{override_fn}
    }
    using namespace dyld;

    static ImageLoader *image(const char *install, bool inCache = false, bool dylib = true) {
      ImageLoader *i = new ImageLoader; i->install = install ? install : ""; i->inCache = inCache; i->dylib = dylib;
      i->exports = {{"_open", 0x1000}, {"_close", 0x2000}}; return i;   // _nosuchsymbol is not exported
    }
    static void reset(DyldSharedCache &cache) { sAllImages.clear(); cache.calls.clear(); cache.applied.clear(); cache.lastAddress.clear(); cache.error = nullptr; cache.patchInfo = true; logged.clear(); }

    int main() {
      DyldSharedCache cache;
      // --- no cache, no patch info: nothing is touched, not even a lookup ---
      sAllImages = {image("/usr/lib/system/libsystem_kernel.dylib")};
      overrideSplitCacheGotSlots();
      CHECK(cache.calls.empty() && splitCachePatchTotals().exporters == 0);
      sSharedCacheLoadInfo.loadAddress = &cache;
      cache.patchInfo = false;
      overrideSplitCacheGotSlots();
      CHECK(cache.calls.empty() && splitCachePatchTotals().exporters == 0);
      cache.patchInfo = true;

      // --- a damaged header halts before any exporter is looked at, naming the reason; the check is retried until it passes ---
      cache.headerError = "patch info array is not 4-byte aligned";
      bool headerHalted = false;
      try { overrideSplitCacheGotSlots(); } catch (const std::runtime_error &e) { headerHalted = true; CHECK(strstr(e.what(), "patch info array is not 4-byte aligned")); }
      CHECK(headerHalted && cache.calls.empty());
      cache.headerError = nullptr;

      // --- which loaded images are exporters ---
      reset(cache);
      sAllImages = {image(nullptr, false, false),                              // the main executable: not a dylib
                    image("/usr/lib/system/libsystem_kernel.dylib", true),     // served from the cache
                    image("/usr/lib/libnotincache.dylib"),                     // no such image in the cache
                    image(nullptr),                                            // no install path
                    image("/usr/lib/libz.1.dylib"),                            // allow-listed: the cache serves it
                    image("/usr/lib/system/libsystem_kernel.dylib")};          // the exporter Darling provides
      overrideSplitCacheGotSlots();
      CHECK(cache.calls == std::vector<uint32_t>{1});
      CHECK(cache.lastAddress.size() == 2 && cache.lastAddress["_open"] == 0x1000 && cache.lastAddress["_close"] == 0x2000);   // the loaded image's addresses
      CHECK(splitCachePatchTotals().exporters == 1 && splitCachePatchTotals().slots == 6 && splitCachePatchTotals().patched == 4);
      CHECK(splitCachePatchTotals().missingExports == 1 && splitCachePatchTotals().missingSlots == 2 && splitCachePatchTotals().unexplained == 0);

      // --- a second pass (the dlopen hook) does not count the same exporter twice, and new exporters are added ---
      sAllImages.push_back(image("/usr/lib/libSystem.B.dylib"));
      overrideSplitCacheGotSlots();
      CHECK((cache.calls == std::vector<uint32_t>{1, 1, 0}));
      CHECK(splitCachePatchTotals().exporters == 2 && splitCachePatchTotals().slots == 12 && splitCachePatchTotals().missingExports == 2);

      // --- the verbose log names the missing symbol and the totals; silent otherwise ---
      CHECK(logged.empty());
      reset(cache); cache.applied.clear();
      gLinkContext.verboseMapping = true;
      sAllImages = {image("/usr/lib/system/libsystem_kernel.dylib")};
      overrideSplitCacheGotSlots();
      bool sawMissing = false, sawTotals = false;
      for (const std::string &l : logged) { sawMissing |= l.find("_nosuchsymbol") != std::string::npos && l.find("libsystem_kernel") != std::string::npos; sawTotals |= l.find("4 patched") != std::string::npos; }
      CHECK(sawMissing && sawTotals);
      gLinkContext.verboseMapping = false;

      // --- a reader error halts, naming the exporter and the reason; the totals stay ---
      reset(cache);
      cache.error = "patch info is damaged";
      sAllImages = {image("/usr/lib/system/libsystem_c.dylib")};
      const uint64_t exportersBefore = splitCachePatchTotals().exporters;
      bool threw = false;
      try { overrideSplitCacheGotSlots(); } catch (const std::runtime_error &e) { threw = true; CHECK(strstr(e.what(), "libsystem_c.dylib") && strstr(e.what(), "patch info is damaged")); }
      CHECK(threw && splitCachePatchTotals().exporters == exportersBefore);
      printf(failures ? "RESULT failed (%d)\\n" : "RESULT ok\\n", failures);
      return failures != 0;
    }
  CPP
  out, st = Open3.capture2e('clang++', '-std=c++17', '-fblocks', '-Wno-everything', "#{dir}/test.cpp", '-o', "#{dir}/test")
  abort out unless st.success?
  out, st = Open3.capture2e("#{dir}/test")
  puts out
  abort 'patch info v4 wiring test failed' unless st.success? && out.include?('RESULT ok')
  puts 'PASS patch info override wiring in dyld2.cpp'
end
