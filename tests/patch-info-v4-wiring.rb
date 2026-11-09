# How dyld2.cpp applies the patch info override: the actual overrideSplitCacheGotSlots (extracted from src/dyld2.cpp,
# with the cache, the images and halt stubbed, and the real allow-list code of SharedCacheRuntime.cpp behind it).
# Checks that the exporters are the disk images that loadPhase5 recorded as standing in for a cache image (and not an
# allow-listed one), that nothing runs without a cache, without version 4 patch info, without records or without a cache
# image in the process, that the symbols are looked up in the loaded image with dyld's own export lookup, that a second
# pass counts nothing twice, that a reader error halts with the exporter's name, and that exactly one summary line is
# printed per pass (always when a slot kept the cache's pointer, otherwise only with the verbose mapping option). It also
# checks where the hook sits: at the end of link(), which runs under dyld's lock, and in neither initializer pass (those
# run after dlopen has released the lock). The reader and the signing are tested in tests/patch-info-v4-override.rb.
# Usage: ruby tests/patch-info-v4-wiring.rb [checkout]
require 'tmpdir'
require 'open3'
root = File.realpath(ARGV.fetch(0, File.expand_path('..', __dir__)))
dyld2 = File.read("#{root}/src/dyld2.cpp")
dyld2_h = File.read("#{root}/src/dyld2.h")
runtime = File.read("#{root}/dyld3/SharedCacheRuntime.cpp")
runtime_h = File.read("#{root}/dyld3/SharedCacheRuntime.h")
override_fn = dyld2[/^static struct \{ uint64_t patched, missing, unexplained; \} sSplitCachePatchTotals;.*?^static void overrideSplitCacheGotSlots\(\).*?^\}/m] or abort 'overrideSplitCacheGotSlots missing'
record_struct = dyld2_h[/^\tstruct DiskOverrideOfCacheImage \{.*?^\t\};/m] or abort 'DiskOverrideOfCacheImage missing'
allow_list = runtime[/^\/\/ libz is a leaf library.*?^bool sharedCachePathIsAllowListed\(.*?^\}/m] or abort 'allow-list code missing'
allow_decl = runtime_h[/^struct SharedCacheAllowList \{.*?^\};/m] or abort 'SharedCacheAllowList missing'

# The hook: at the end of link() (under dyld's lock), after the image and everything it needs are linked, and nowhere else.
link_fn = dyld2[/^void link\(ImageLoader\* image, bool forceLazysBound.*?^\}/m] or abort 'link missing'
init_main = dyld2[/^void initializeMainExecutable\(\)\n\{.*?^\}/m] or abort 'initializeMainExecutable missing'
run_init = dyld2[/^void runInitializers\(ImageLoader\* image\)\n\{.*?^\}/m] or abort 'runInitializers missing'
hook = link_fn.index('overrideSplitCacheGotSlots();') or abort 'link() does not call overrideSplitCacheGotSlots'
abort 'the override runs before the image is linked' unless hook > link_fn.index('image->link(gLinkContext')
abort 'link(): the call is not under #ifdef DARLING' unless link_fn[0...hook].rindex('#ifdef DARLING') > link_fn.index('image->link(gLinkContext') && link_fn[hook..].include?('#endif')
abort 'the override is skipped when link() throws and still run after the catch' if link_fn.index('catch') < hook
[['initializeMainExecutable', init_main], ['runInitializers', run_init]].each do |name, body|
  abort "#{name} calls overrideSplitCacheGotSlots without dyld's lock (dlopen releases it before the initializers)" if body.include?('overrideSplitCacheGotSlots')
end
puts 'ok   the override runs at the end of link() and in neither initializer pass'

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
      std::vector<std::string> images = {"/usr/lib/libSystem.B.dylib", "/usr/lib/system/libsystem_kernel.dylib", "/usr/lib/system/libsystem_c.dylib", "/usr/lib/libz.1.dylib", "/usr/lib/system/libsystem_malloc.dylib"};
      mutable std::vector<uint32_t> calls; mutable std::set<uint32_t> applied;
      const char *error = nullptr;                 // what overridePatchGotSlots returns for index 2
      bool hasPatchInfoV4() const { return patchInfo; }
      const char *getIndexedImagePath(uint32_t i) const { return images[i].c_str(); }
      // symbols the exporter has in its GOT: two the loaded image defines and one it does not; index 4 has two unexplained slots instead
      const char *overridePatchGotSlots(uint32_t index, bool (^resolve)(const char *symbol, uint64_t *address), DataConstLogFunc, PatchOverrideStats *s) const {
        calls.push_back(index);
        memset(s, 0, sizeof *s);
        if (applied.count(index)) { s->alreadyApplied = true; return nullptr; }
        if (index == 2 && error) return error;
        applied.insert(index);
        if (index == 4) { s->exports = 1; s->slots = 2; s->unexplained = 2; return nullptr; }
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
      std::string install; bool inCache = false; std::map<std::string, uintptr_t> exports;
      const char *getInstallPath() const { return install.c_str(); }
      bool inSharedCache() const { return inCache; }
      // the real lookup is ImageLoader::findExportedSymbolAddress (searchReExports, resolvers run for a GOT pointer)
      bool findExportedSymbolAddress(const LinkContext &, const char *name, const ImageLoader *requestor, int ordinal, bool runResolver, const ImageLoader **foundIn, uintptr_t *address) const {
        if (requestor != nullptr || ordinal != -1 || !runResolver) return false;
        auto it = exports.find(name); if (it == exports.end()) return false;
        *foundIn = this; *address = it->second; return true;
      }
    };
    namespace dyld {
      #{record_struct}
      ImageLoader::LinkContext gLinkContext;
      dyld3::SharedCacheLoadInfo sSharedCacheLoadInfo = {nullptr};
      std::vector<ImageLoader*> sAllImages;
      std::vector<DiskOverrideOfCacheImage> sDiskOverridesOfCacheImages;
      std::vector<std::string> logged;
      void log(const char *format, ...) { char buffer[512]; va_list a; va_start(a, format); vsnprintf(buffer, sizeof buffer, format, a); va_end(a); logged.push_back(buffer); }
      const char *mkstringf(const char *format, ...) { static char buffer[512]; va_list a; va_start(a, format); vsnprintf(buffer, sizeof buffer, format, a); va_end(a); return buffer; }
      void halt(const char *message) { throw std::runtime_error(message); }
      #{override_fn}
    }
    using namespace dyld;

    static ImageLoader *image(const char *install, bool inCache = false) {
      ImageLoader *i = new ImageLoader; i->install = install; i->inCache = inCache;
      i->exports = {{"_open", 0x1000}, {"_close", 0x2000}}; return i;   // _nosuchsymbol is not exported
    }
    // a disk image standing in for cache image `index`, as loadPhase5 records it
    static void shadow(const char *install, uint32_t index) { ImageLoader *i = image(install); sAllImages.push_back(i); sDiskOverridesOfCacheImages.push_back({i, index}); }
    static void reset(DyldSharedCache &cache) { sAllImages.clear(); sDiskOverridesOfCacheImages.clear(); cache.calls.clear(); cache.applied.clear(); cache.lastAddress.clear(); cache.error = nullptr; cache.patchInfo = true; logged.clear(); }
    static unsigned summaries() { unsigned n = 0; for (const std::string &l : logged) n += l.find("split cache GOT override: patched=") != std::string::npos; return n; }

    int main() {
      DyldSharedCache cache;
      // --- no cache, no patch info, no records, no cache image in the process: nothing is touched, not even a lookup ---
      shadow("/usr/lib/system/libsystem_kernel.dylib", 1); sAllImages.push_back(image("/usr/lib/libz.1.dylib", true));
      overrideSplitCacheGotSlots();
      CHECK(cache.calls.empty() && logged.empty());
      sSharedCacheLoadInfo.loadAddress = &cache;
      cache.patchInfo = false;
      overrideSplitCacheGotSlots();
      CHECK(cache.calls.empty() && logged.empty());
      cache.patchInfo = true;
      sDiskOverridesOfCacheImages.clear();
      overrideSplitCacheGotSlots();
      CHECK(cache.calls.empty() && logged.empty());                       // nothing is shadowed
      reset(cache); shadow("/usr/lib/system/libsystem_kernel.dylib", 1);
      overrideSplitCacheGotSlots();
      CHECK(cache.calls.empty() && logged.empty());                       // no image of the cache is loaded: nothing to fix, no mapping is touched

      // --- the exporters are the recorded disk images; an allow-listed cache path is never overridden ---
      sAllImages.push_back(image("/usr/lib/libz.1.dylib", true));
      shadow("/usr/lib/libz.1.dylib", 3);
      overrideSplitCacheGotSlots();
      CHECK(cache.calls == std::vector<uint32_t>{1});
      CHECK(cache.lastAddress.size() == 2 && cache.lastAddress["_open"] == 0x1000 && cache.lastAddress["_close"] == 0x2000);   // the loaded image's addresses
      CHECK(summaries() == 1 && logged.size() == 1 && logged[0].find("patched=4 missing=2 unexplained=0") != std::string::npos);   // a missing symbol is always reported

      // --- a second pass (the next link) does not count the same exporter twice, a new one is added; the line is cumulative ---
      logged.clear();
      shadow("/usr/lib/libSystem.B.dylib", 0);
      overrideSplitCacheGotSlots();
      CHECK((cache.calls == std::vector<uint32_t>{1, 1, 0}));
      CHECK(summaries() == 1 && logged[0].find("patched=8 missing=4 unexplained=0") != std::string::npos);
      logged.clear();
      overrideSplitCacheGotSlots();
      CHECK(logged.empty());                                              // nothing new, nothing to say

      // --- slots that are left because they cannot be explained are reported too ---
      shadow("/usr/lib/system/libsystem_malloc.dylib", 4);
      overrideSplitCacheGotSlots();
      CHECK(summaries() == 1 && logged[0].find("unexplained=2") != std::string::npos);

      // --- all good: silent, unless the verbose mapping option asks for the line; the missing symbol is named then ---
      reset(cache);
      sAllImages.push_back(image("/usr/lib/libz.1.dylib", true));
      ImageLoader *kernel = image("/usr/lib/system/libsystem_kernel.dylib"); kernel->exports["_nosuchsymbol"] = 0x3000;
      sAllImages.push_back(kernel); sDiskOverridesOfCacheImages.push_back({kernel, 1});
      overrideSplitCacheGotSlots();
      CHECK(logged.empty() && cache.calls.size() == 1);
      cache.applied.clear(); gLinkContext.verboseMapping = true;
      overrideSplitCacheGotSlots();
      CHECK(summaries() == 1);                                            // nothing missing, but the verbose mapping option asks for the line
      logged.clear(); cache.applied.clear(); kernel->exports.erase("_nosuchsymbol");
      overrideSplitCacheGotSlots();
      bool sawMissing = false;
      for (const std::string &l : logged) sawMissing |= l.find("_nosuchsymbol") != std::string::npos && l.find("libsystem_kernel") != std::string::npos;
      CHECK(sawMissing && summaries() == 1);
      gLinkContext.verboseMapping = false;

      // --- a reader error halts, naming the exporter and the reason ---
      reset(cache);
      cache.error = "patch info is damaged";
      sAllImages.push_back(image("/usr/lib/libz.1.dylib", true));
      shadow("/usr/lib/system/libsystem_c.dylib", 2);
      bool threw = false;
      try { overrideSplitCacheGotSlots(); } catch (const std::runtime_error &e) { threw = true; CHECK(strstr(e.what(), "libsystem_c.dylib") && strstr(e.what(), "patch info is damaged")); }
      CHECK(threw);
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
