# How dyld2.cpp applies the patch info override: the actual overrideSplitCacheGotSlots (extracted from src/dyld2.cpp,
# with the cache, the images and halt stubbed, and the real allow-list code of SharedCacheRuntime.cpp behind it).
# Checks that the exporters are the disk images that loadPhase5 recorded as standing in for a cache image (and not an
# allow-listed one), that nothing runs without a cache, without version 4 patch info, without records or without a cache
# image in the process, that the symbols are looked up in the loaded image with dyld's own export lookup, that a second
# pass counts nothing twice, that a reader error halts with the exporter's name, and that exactly one summary line is
# printed per pass (always for an anomaly, otherwise only with the verbose mapping option) and that the verbose option adds one line per patched symbol. It also
# checks where the hook sits: in the bound notification that link() sends (under dyld's lock), before the add-image callbacks, and in neither initializer pass (those
# run after dlopen has released the lock). The reader and the signing are tested in tests/patch-info-v4-override.rb.
# Usage: ruby tests/patch-info-v4-wiring.rb [checkout]
require 'tmpdir'
require 'open3'
root = File.realpath(ARGV.fetch(0, File.expand_path('..', __dir__)))
dyld2 = File.read("#{root}/src/dyld2.cpp")
dyld2_h = File.read("#{root}/src/dyld2.h")
runtime = File.read("#{root}/dyld3/SharedCacheRuntime.cpp")
runtime_h = File.read("#{root}/dyld3/SharedCacheRuntime.h")
override_fn = dyld2[/^static struct \{[^}]*\} sSplitCachePatchTotals;.*?^static void overrideSplitCacheGotSlots\(\).*?^\}/m] or abort 'overrideSplitCacheGotSlots missing'
record_struct = dyld2_h[/^\tstruct DiskOverrideOfCacheImage \{.*?^\t\};/m] or abort 'DiskOverrideOfCacheImage missing'
allow_list = runtime[/^static const char\* const kSharedCacheServedOverDisk\[\].*?^bool sharedCachePathIsAllowListed\(.*?^\}/m] or abort 'allow-list code missing'
allow_decl = runtime_h[/^struct SharedCacheAllowList \{.*?^\};/m] or abort 'SharedCacheAllowList missing'

# The hook: in the bound notification that ImageLoader::link() sends once the closure is bound, before any callback runs (add-image callbacks and
# objc's mapped callback read and write the cache images' data), and not at the end of link(), after the callbacks.
link_fn = dyld2[/^void link\(ImageLoader\* image, bool forceLazysBound.*?^\}/m] or abort 'link missing'
notify_fn = dyld2[/^static void notifyBatch\(dyld_image_states state, bool preflightOnly\)\n\{.*?^\}/m] or abort 'notifyBatch missing'
abort 'link() runs the override after the bound notification has gone out' if link_fn.include?('overrideSplitCacheGotSlots')
hook = notify_fn.index('overrideSplitCacheGotSlots();') or abort 'the bound notification does not run the override'
abort 'the override is not before the callbacks' unless hook < notify_fn.index('notifyBatchPartial(')
abort 'the override is not limited to the bound notification' unless notify_fn[0...hook] =~ /state == dyld_image_state_bound\) && !preflightOnly/
abort 'notifyBatch: the call is not under #ifdef DARLING' unless notify_fn[0...hook].rindex('#ifdef DARLING') && notify_fn[hook..].index('#endif') < notify_fn.index('notifyBatchPartial(')
loader = File.read("#{root}/src/ImageLoader.cpp")
loader_link = loader[/^void ImageLoader::link\(.*?^\}/m] or abort 'ImageLoader::link missing'
steps = ['recursiveBindWithAccounting(', 'this->weakBind(', 'recursiveApplyInterposing(', 'recursiveMakeDataReadOnly(', 'notifyBatch(dyld_image_state_bound'].map { |t| loader_link.index(t) or abort "ImageLoader::link: #{t} missing" }
abort 'ImageLoader::link does not send the bound notification after the binds, weak binds and interposing' unless steps == steps.sort
init_main = dyld2[/^void initializeMainExecutable\(\)\n\{.*?^\}/m] or abort 'initializeMainExecutable missing'
run_init = dyld2[/^void runInitializers\(ImageLoader\* image\)\n\{.*?^\}/m] or abort 'runInitializers missing'
[['initializeMainExecutable', init_main], ['runInitializers', run_init]].each do |name, body|
  abort "#{name} calls overrideSplitCacheGotSlots without dyld's lock (dlopen releases it before the initializers)" if body.include?('overrideSplitCacheGotSlots')
end
main_fn = dyld2[/^_main\(const macho_header.*?^\}/m] or abort '_main missing'
bind = main_fn.index('sMainExecutable->recursiveBindWithAccounting(') or abort '_main does not bind the main executable'
inserted_bind = main_fn.index('image->recursiveBind(gLinkContext', bind) or abort '_main does not bind the inserted images'
launch_hook = main_fn.index('overrideSplitCacheGotSlots();') or abort '_main does not run the override'
abort '_main runs the override before the launch binds are done' unless launch_hook > inserted_bind
abort '_main runs the override while linkingMainExecutable is still set (it is a no-op then)' unless launch_hook > main_fn.index('gLinkContext.linkingMainExecutable = false;', inserted_bind)
abort '_main runs the override after the initializers' unless (init_call = main_fn.index('initializeMainExecutable();', bind)) && launch_hook < init_call
abort '_main calls the override outside #ifdef DARLING' unless main_fn[0...launch_hook].rindex('#ifdef DARLING') > inserted_bind
abort 'overrideSplitCacheGotSlots does not skip the launch links' unless override_fn.include?('gLinkContext.linkingMainExecutable')
puts 'ok   the override runs in the bound notification, before the callbacks, and in neither initializer pass'
abort 'overrideSplitCacheGotSlots calls a libc printf-family function, which crashes before the locale state is usable: format through dyld::log (_simple_vsprintf)' if override_fn =~ /\bv?(?:f|s|sn|as|d)?printf\s*\(/
puts 'ok   at launch the override is skipped by the links and runs once after the binds'
puts 'ok   the override formats only through dyld::log, no snprintf'

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
      // The adapters themselves are tested in darling-arm64e-adapters*.rb; here only what the override hands them and what it stores.
      namespace darling {
        const uint64_t kThunkBit = 1ull << 40;
        inline bool cpusubtypeIsArm64e(int subtype) { return subtype == 2; }
        inline uint64_t adaptedTarget(const char *symbol, uint64_t target, bool targetIsArm64e) { return targetIsArm64e ? target : target | kThunkBit; }
      }
    }
    struct mach_header { int cpusubtype; uint32_t cacheIndex = 0; };   // cacheIndex: where the cache lists the image, for the images that are in it
    // The cache: which images it has, whether it has version 4 patch info, and what overridePatchGotSlots does.
    struct DyldSharedCache {
      struct PatchOverrideStats { uint64_t exports, slots, patched, unexplained, missingExports, missingSlots, plainSlots, plainPatched, plainUnexplained, plainMissing, plainClientsRunning; bool alreadyApplied; };
      enum { kPlainClientIgnore = 0, kPlainClientPatch = 1, kPlainClientRunning = 2 };
      typedef void (*DataConstLogFunc)(const char*, ...);
      bool patchInfo = true;
      std::vector<std::string> images = {"/usr/lib/libSystem.B.dylib", "/usr/lib/system/libsystem_kernel.dylib", "/usr/lib/system/libsystem_c.dylib", "/usr/lib/libz.1.dylib", "/usr/lib/system/libsystem_malloc.dylib", "/usr/lib/system/libsystem_platform.dylib"};
      mutable std::vector<uint32_t> calls; mutable std::set<uint32_t> applied;
      const char *error = nullptr;                 // what overridePatchGotSlots returns for index 2
      bool hasPatchInfoV4() const { return patchInfo; }
      const char *getIndexedImagePath(uint32_t i) const { return images[i].c_str(); }
      bool findMachHeaderImageIndex(const mach_header *mh, uint32_t &index) const { index = mh->cacheIndex; return true; }
      // Every image of the cache is a client of every exporter, with one plain location per symbol. Symbols the exporter has in its GOT: two the loaded
      // image defines and one it does not; index 4 has two unexplained slots, and index 5 only a refused plain location, per client to patch.
      const char *overridePatchGotSlots(uint32_t index, bool (^resolve)(const char *symbol, bool classExport, uint64_t *address), int (^clientAction)(uint32_t), DataConstLogFunc logFunc, PatchOverrideStats *s) const {
        calls.push_back(index); logOn.push_back(logFunc != nullptr); actionNull.push_back(clientAction == nullptr);
        memset(s, 0, sizeof *s);
        const bool wasApplied = applied.count(index) != 0;
        if (wasApplied) { s->alreadyApplied = true; if (!clientAction) return nullptr; }
        else { if (index == 2 && error) return error; applied.insert(index); }
        uint64_t patchClients = 0;
        if (clientAction) for (uint32_t c = 0; c < images.size(); ++c) { const int a = clientAction(c); patchClients += a == kPlainClientPatch; if (a == kPlainClientRunning && !wasApplied) ++s->plainClientsRunning; }
        patchedClients.push_back(patchClients);
        if (index == 5) { if (!wasApplied) { s->exports = 1; s->slots = 1; s->patched = 1; } s->plainSlots = 2 * patchClients; s->plainPatched = patchClients; s->plainUnexplained = patchClients; return nullptr; }
        if (index == 4) { if (!wasApplied) { s->exports = 1; s->slots = 2; s->unexplained = 2; } s->plainSlots = patchClients; s->plainUnexplained = patchClients; return nullptr; }
        std::vector<std::string> names = {"_open", "_close", "_nosuchsymbol"}; names.insert(names.end(), moreNames.begin(), moreNames.end());
        for (const std::string &nameString : names) {
          const char *name = nameString.c_str();
          uint64_t address = 0;
          if (wasApplied && patchClients == 0) break;
          const bool found = resolve(name, classNames.count(name) != 0, &address);
          if (found) lastAddress[name] = address;
          if (!wasApplied) { ++s->exports; s->slots += 2; if (found) s->patched += 2; else { ++s->missingExports; s->missingSlots += 2; } }
          s->plainSlots += patchClients; (found ? s->plainPatched : s->plainMissing) += patchClients;
        }
        return nullptr;
      }
      std::vector<std::string> moreNames; mutable std::map<std::string, uint64_t> lastAddress; mutable std::vector<bool> logOn, actionNull; mutable std::vector<uint64_t> patchedClients; std::set<std::string> classNames;   // the symbols the cache has as kind 8 exports
    };
    struct ImageLoader {
      struct LinkContext { bool verboseMapping = false; bool linkingMainExecutable = false; };
      std::string install, path; bool inCache = false; mach_header header = {1}; std::map<std::string, uintptr_t> exports; std::map<std::string, const ImageLoader*> reexportedFrom; std::vector<const ImageLoader*> reExports;
      bool bound = true; std::map<std::string, std::pair<uintptr_t, uintptr_t>> resolvers; mutable unsigned resolverRuns = 0, resolverFaults = 0, stubLookups = 0;   // stub-and-resolver exports: {stub, resolver's result}
      const char *getInstallPath() const { return install.c_str(); }
      const char *getPath() const { return path.c_str(); }
      bool inSharedCache() const { return inCache; }
      const mach_header *machHeader() const { return &header; }
      void forEachReExportDependent(void (^callback)(const ImageLoader*, bool &stop)) const { bool stop = false; for (const ImageLoader *i : reExports) { callback(i, stop); if (stop) break; } }
      // the real lookup is ImageLoader::findExportedSymbolAddress (searchReExports, resolvers run for a GOT pointer)
      bool findExportedSymbolAddress(const LinkContext &, const char *name, const ImageLoader *requestor, int ordinal, bool runResolver, const ImageLoader **foundIn, uintptr_t *address) const {
        if (requestor != nullptr || ordinal != -1) return false;
        auto res = resolvers.find(name);
        if (res != resolvers.end()) {
          // like exportedSymbolAddress: with runResolver the resolver's answer, which needs the image's own bound slots (a native shim reads _elfcalls through its
          // __got); without it the stub, whose call reaches the resolver through __la_resolver and the stub helper, which keep fewer registers than a lazy binder would
          *foundIn = this;
          if (!runResolver) { ++stubLookups; *address = res->second.first; return true; }
          ++resolverRuns; if (!bound) { ++resolverFaults; return false; }
          *address = res->second.second; return true;
        }
        if (!runResolver) return false;
        auto it = exports.find(name); if (it == exports.end()) return false;
        auto via = reexportedFrom.find(name);
        *foundIn = via == reexportedFrom.end() ? this : via->second; *address = it->second; return true;
      }
    };
    namespace dyld {
      #{record_struct}
      ImageLoader::LinkContext gLinkContext; bool gLogCachePolicy = false;
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
      ImageLoader *i = new ImageLoader; i->install = install; i->path = std::string("/prefix") + install; i->inCache = inCache;
      for (uint32_t n = 0; n != DyldSharedCache().images.size(); ++n) if (DyldSharedCache().images[n] == install) i->header.cacheIndex = n;
      i->exports = {{"_open", 0x1000}, {"_close", 0x2000}}; return i;   // _nosuchsymbol is not exported
    }
    // a disk image standing in for cache image `index`, as loadPhase5 records it
    static void shadow(const char *install, uint32_t index) { ImageLoader *i = image(install); sAllImages.push_back(i); sDiskOverridesOfCacheImages.push_back({i, index}); }
    static void reset(DyldSharedCache &cache) { sAllImages.clear(); sDiskOverridesOfCacheImages.clear(); cache.calls.clear(); cache.applied.clear(); cache.lastAddress.clear(); cache.logOn.clear(); cache.actionNull.clear(); cache.patchedClients.clear(); sCacheImagesSeen.clear(); sCacheExportersDone.clear(); cache.classNames.clear(); cache.moreNames.clear(); cache.error = nullptr; cache.patchInfo = true; logged.clear(); }
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
      CHECK(cache.lastAddress.size() == 2 && cache.lastAddress["_open"] == (0x1000 | dyld3::darling::kThunkBit) && cache.lastAddress["_close"] == (0x2000 | dyld3::darling::kThunkBit));   // the loaded image's addresses, through the adapters for a plain exporter
      CHECK(logged.empty());                                              // a symbol Darling lacks is normal: no line without the verbose mapping option

      // --- a second pass (the next link) does not count the same exporter twice, a new one is added ---
      shadow("/usr/lib/libSystem.B.dylib", 0);
      overrideSplitCacheGotSlots();
      CHECK((cache.calls == std::vector<uint32_t>{1, 1, 0}));
      CHECK(logged.empty());

      // --- an anomaly (slots refused for their encoding or kind) is always reported, once, with the cumulative totals ---
      shadow("/usr/lib/system/libsystem_malloc.dylib", 4);
      overrideSplitCacheGotSlots();
      // libz was seen by the first pass: a stand-in that appears later leaves its plain locations alone (libSystem and malloc patch none)
      CHECK(summaries() == 1 && logged.size() == 1 && logged[0].find("patched=8 missing=4 unexplained=2 plain-patched=2 plain-missing=1 plain-unexplained=0") != std::string::npos);
      logged.clear();
      overrideSplitCacheGotSlots();
      CHECK(logged.empty());                                              // nothing new, nothing to say
      CHECK(cache.actionNull.back());                                     // an exporter that is done and no new client: not even the plain check is asked for
      // a dlopen loads a cache image (libsystem_c, index 2) and a stand-in for libsystem_platform (index 5): the new image is patched for every
      // exporter, the old ones included, before it runs; a plain location refused for its encoding is an anomaly too, even when no GOT slot is
      cache.calls.clear(); cache.patchedClients.clear(); cache.actionNull.clear();
      sAllImages.push_back(image("/usr/lib/system/libsystem_c.dylib", true));
      shadow("/usr/lib/system/libsystem_platform.dylib", 5);
      overrideSplitCacheGotSlots();
      CHECK((cache.calls == std::vector<uint32_t>{1, 0, 4, 5}) && (cache.patchedClients == std::vector<uint64_t>{1, 1, 1, 1}));   // exactly one client to patch each: libsystem_c
      CHECK(summaries() == 1 && logged.size() == 1 && logged[0].find("patched=9 missing=4 unexplained=2 plain-patched=7 plain-missing=3 plain-unexplained=2") != std::string::npos);
      logged.clear();
      // the images seen are not patched again, however many passes
      cache.calls.clear(); cache.actionNull.clear();
      overrideSplitCacheGotSlots();
      CHECK((cache.actionNull == std::vector<bool>{true, true, true, true}) && logged.empty());
      // under the cache policy option a stand-in that comes after the images ran says how many keep the cache's pointers
      gLogCachePolicy = true; logged.clear();
      shadow("/usr/lib/system/libsystem_kernel.dylib", 1);
      sDiskOverridesOfCacheImages.pop_back(); sDiskOverridesOfCacheImages.erase(sDiskOverridesOfCacheImages.begin());   // keep only a new exporter: libSystem.B
      cache.applied.erase(0);
      sCacheExportersDone[0] = false;
      overrideSplitCacheGotSlots();
      { unsigned running = 0; for (const std::string &l : logged) running += l.find("2 cache image(s) in the process have run already") != std::string::npos; CHECK(running == 1); }
      gLogCachePolicy = false;

      // --- the verbose mapping option: one line per patched symbol and the summary; none without it ---
      reset(cache);
      sAllImages.push_back(image("/usr/lib/libz.1.dylib", true));
      ImageLoader *kernel = image("/usr/lib/system/libsystem_kernel.dylib"); kernel->exports["_nosuchsymbol"] = 0x3000;
      sAllImages.push_back(kernel); sDiskOverridesOfCacheImages.push_back({kernel, 1});
      overrideSplitCacheGotSlots();
      CHECK(logged.empty() && cache.calls.size() == 1);
      cache.applied.clear(); gLinkContext.verboseMapping = true;
      overrideSplitCacheGotSlots();
      unsigned patchedLines = 0; bool sawOpen = false;
      for (const std::string &l : logged) { patchedLines += l.rfind("dyld: patched ", 0) == 0; sawOpen |= l == "dyld: patched /usr/lib/system/libsystem_kernel.dylib _open -> /prefix/usr/lib/system/libsystem_kernel.dylib\\n"; }
      CHECK(patchedLines == 3 && sawOpen && summaries() == 1 && logged.size() == 4);
      logged.clear(); cache.applied.clear(); kernel->exports.erase("_nosuchsymbol");
      overrideSplitCacheGotSlots();
      bool sawMissing = false; patchedLines = 0;
      for (const std::string &l : logged) { sawMissing |= l.find("_nosuchsymbol") != std::string::npos && l.find("defines _nosuchsymbol") != std::string::npos; patchedLines += l.rfind("dyld: patched ", 0) == 0; }
      CHECK(sawMissing && patchedLines == 2 && summaries() == 1);
      gLinkContext.verboseMapping = false;

      // --- the exporter's own cpu subtype decides whether the adapters wrap the target: an arm64e exporter is bound as it is ---
      reset(cache); sAllImages.push_back(image("/usr/lib/libz.1.dylib", true));
      ImageLoader *signedKernel = image("/usr/lib/system/libsystem_kernel.dylib"); signedKernel->header.cpusubtype = 2;
      sAllImages.push_back(signedKernel); sDiskOverridesOfCacheImages.push_back({signedKernel, 1});
      overrideSplitCacheGotSlots();
      CHECK(cache.lastAddress.size() == 2 && cache.lastAddress["_open"] == 0x1000 && cache.lastAddress["_close"] == 0x2000);
      reset(cache); sAllImages.push_back(image("/usr/lib/libz.1.dylib", true)); shadow("/usr/lib/system/libsystem_kernel.dylib", 1);
      overrideSplitCacheGotSlots();
      CHECK(cache.lastAddress["_open"] == (0x1000 | dyld3::darling::kThunkBit));   // the control: the same exporter as a plain image
      // a symbol the recorded image re-exports belongs to the image that defines it, and its subtype is the one that counts
      reset(cache); sAllImages.push_back(image("/usr/lib/libz.1.dylib", true));
      ImageLoader *definer = image("/usr/lib/system/libsystem_c.dylib"); definer->header.cpusubtype = 2;
      ImageLoader *facade = image("/usr/lib/system/libsystem_kernel.dylib"); facade->reexportedFrom["_close"] = definer;
      sAllImages.push_back(facade); sDiskOverridesOfCacheImages.push_back({facade, 1});
      overrideSplitCacheGotSlots();
      CHECK(cache.lastAddress["_open"] == (0x1000 | dyld3::darling::kThunkBit) && cache.lastAddress["_close"] == 0x2000);

      // --- a kind 8 (class) export is held back when the image that defines it is plain, whichever image is recorded; counted as missing ---
      auto classCase = [&](ImageLoader *recorded) {
        reset(cache); cache.classNames = {"_open", "_close"}; sAllImages.push_back(image("/usr/lib/libz.1.dylib", true));
        sAllImages.push_back(recorded); sDiskOverridesOfCacheImages.push_back({recorded, 1});
        overrideSplitCacheGotSlots();
      };
      ImageLoader *armKernel = image("/usr/lib/system/libsystem_kernel.dylib"); armKernel->header.cpusubtype = 2;
      classCase(armKernel);                                                // an arm64e image's own classes are overridden
      CHECK(cache.lastAddress.size() == 2 && cache.lastAddress["_open"] == 0x1000 && cache.lastAddress["_close"] == 0x2000);
      classCase(image("/usr/lib/system/libsystem_kernel.dylib"));          // a plain image's classes are not
      CHECK(cache.lastAddress.empty() && logged.empty());                  // the cache keeps its own, silently without the cache policy option
      gLogCachePolicy = true; cache.applied.clear(); logged.clear();
      overrideSplitCacheGotSlots();
      CHECK(logged.size() == 3 && logged[0].find("class export of a non-arm64e image") != std::string::npos && logged[1].find("class export of a non-arm64e image") != std::string::npos);   // one line per held back class and one for the symbol nobody defines, no summary line
      gLogCachePolicy = false;
      ImageLoader *plainDefiner = image("/usr/lib/system/libsystem_c.dylib");
      ImageLoader *armFacade = image("/usr/lib/system/libsystem_kernel.dylib"); armFacade->header.cpusubtype = 2; armFacade->reexportedFrom["_close"] = plainDefiner;
      classCase(armFacade);                                                // an arm64e substitute re-exporting a plain image's class: held back
      CHECK(cache.lastAddress.size() == 1 && cache.lastAddress["_open"] == 0x1000);
      ImageLoader *armDefiner = image("/usr/lib/system/libsystem_c.dylib"); armDefiner->header.cpusubtype = 2;
      ImageLoader *plainFacade = image("/usr/lib/system/libsystem_kernel.dylib"); plainFacade->reexportedFrom["_close"] = armDefiner;
      classCase(plainFacade);                                              // a plain substitute re-exporting an arm64e image's class: allowed (the definer counts)
      CHECK(cache.lastAddress.size() == 1 && cache.lastAddress["_close"] == 0x2000);
      cache.classNames.clear(); cache.applied.clear();                     // a non-class export of a plain image is still overridden
      overrideSplitCacheGotSlots();
      CHECK(cache.lastAddress.size() == 2 && cache.lastAddress["_open"] == (0x1000 | dyld3::darling::kThunkBit));

      // --- an export that is not in the stand-in is taken from the siblings that its umbrella re-exports (Darling's reallocf is in libsystem_c, not libsystem_malloc) ---
      // the stand-in (cache image 1) lacks _close; libSystem.B re-exports it, a sibling defining _close, and a sibling that does not
      auto familyCase = [&](ImageLoader *umbrellaExports, bool umbrellaInCache, ImageLoader *sibling, ImageLoader *other) {
        const std::set<std::string> classes = cache.classNames; reset(cache); cache.classNames = classes;
        sAllImages.push_back(image("/usr/lib/libz.1.dylib", true));
        ImageLoader *standIn = image("/usr/lib/system/libsystem_malloc.dylib"); standIn->exports.erase("_close"); other->exports.clear();
        ImageLoader *umbrella = image("/usr/lib/libSystem.B.dylib"); umbrella->inCache = umbrellaInCache;
        umbrella->reExports = {other, standIn, sibling}; if (umbrellaExports) umbrella->reExports.push_back(umbrellaExports);
        sAllImages.push_back(sibling); sAllImages.push_back(other); sAllImages.push_back(umbrella); sAllImages.push_back(standIn);
        sDiskOverridesOfCacheImages.push_back({standIn, 1});
        overrideSplitCacheGotSlots();
      };
      auto sibling = [&](const char *install, uintptr_t close, int subtype = 1) { ImageLoader *i = image(install); i->exports = {{"_close", close}}; i->header.cpusubtype = subtype; return i; };
      familyCase(nullptr, false, sibling("/usr/lib/system/libsystem_c.dylib", 0x5000), image("/usr/lib/system/libsystem_info.dylib"));
      CHECK(cache.lastAddress.size() == 2 && cache.lastAddress["_open"] == (0x1000 | dyld3::darling::kThunkBit));
      CHECK(cache.lastAddress["_close"] == (0x5000 | dyld3::darling::kThunkBit));              // the sibling's definition, through the adapters of a plain sibling
      familyCase(nullptr, false, sibling("/usr/lib/system/libsystem_c.dylib", 0x5000, 2), image("/usr/lib/system/libsystem_info.dylib"));
      CHECK(cache.lastAddress["_close"] == 0x5000);                                           // an arm64e sibling is bound as it is
      CHECK(logged.empty());
      gLinkContext.verboseMapping = true;
      familyCase(nullptr, false, sibling("/usr/lib/system/libsystem_c.dylib", 0x5000), image("/usr/lib/system/libsystem_info.dylib"));
      bool sawSibling = false; for (const std::string &l : logged) sawSibling |= l == "dyld: patched /usr/lib/system/libsystem_malloc.dylib _close -> /prefix/usr/lib/system/libsystem_c.dylib\\n";
      CHECK(sawSibling);                                                                      // the line names the image that defines it
      gLinkContext.verboseMapping = false;
      // the stand-in's own definition wins over a sibling's
      { ImageLoader *c = sibling("/usr/lib/system/libsystem_c.dylib", 0x5000); familyCase(nullptr, false, c, image("/usr/lib/system/libsystem_info.dylib"));
        sAllImages.back()->exports["_close"] = 0x2222; cache.applied.clear(); cache.lastAddress.clear(); overrideSplitCacheGotSlots();
        CHECK(cache.lastAddress["_close"] == (0x2222 | dyld3::darling::kThunkBit)); }
      // two siblings define the symbol: the first in the umbrella's re-export order wins, as in dyld's own override
      { familyCase(nullptr, false, sibling("/usr/lib/system/libsystem_c.dylib", 0x5000), image("/usr/lib/system/libsystem_info.dylib"));
        ImageLoader *umbrella = nullptr, *first = nullptr; for (ImageLoader *i : sAllImages) { if (i->install == "/usr/lib/libSystem.B.dylib") umbrella = i; if (i->install == "/usr/lib/system/libsystem_info.dylib") first = i; }
        first->exports["_close"] = 0x6000; cache.applied.clear(); cache.lastAddress.clear(); overrideSplitCacheGotSlots();
        CHECK(cache.lastAddress["_close"] == (0x6000 | dyld3::darling::kThunkBit));              // libsystem_info is listed before libsystem_c
        std::swap(umbrella->reExports[0], umbrella->reExports[2]); cache.applied.clear(); cache.lastAddress.clear(); overrideSplitCacheGotSlots();
        CHECK(cache.lastAddress["_close"] == (0x5000 | dyld3::darling::kThunkBit)); }
      // only an umbrella that re-exports the stand-in counts: with the umbrella no longer re-exporting it, nothing is borrowed
      familyCase(nullptr, false, sibling("/usr/lib/system/libsystem_c.dylib", 0x5000), image("/usr/lib/system/libsystem_info.dylib"));
      cache.applied.clear(); cache.lastAddress.clear();
      for (ImageLoader *i : sAllImages) if (i->install == "/usr/lib/libSystem.B.dylib") i->reExports.erase(i->reExports.begin() + 1);
      overrideSplitCacheGotSlots();
      CHECK(cache.lastAddress.size() == 1 && cache.lastAddress.count("_close") == 0);         // the cache keeps its pointer
      // a sibling or an umbrella that is a cache image is never a source (the cache's own definition is what is already there)
      { ImageLoader *c = sibling("/usr/lib/system/libsystem_c.dylib", 0x5000); c->inCache = true; familyCase(nullptr, false, c, image("/usr/lib/system/libsystem_info.dylib")); }
      CHECK(cache.lastAddress.count("_close") == 0);
      familyCase(nullptr, true, sibling("/usr/lib/system/libsystem_c.dylib", 0x5000), image("/usr/lib/system/libsystem_info.dylib"));
      CHECK(cache.lastAddress.count("_close") == 0);
      // a symbol that no Darling image defines keeps the cache's pointer and says so with the cache policy option alone
      familyCase(nullptr, false, sibling("/usr/lib/system/libsystem_c.dylib", 0x5000), image("/usr/lib/system/libsystem_info.dylib"));
      CHECK(cache.lastAddress.count("_nosuchsymbol") == 0 && logged.empty());                  // the three symbols of the stub: _nosuchsymbol is undefined everywhere
      gLogCachePolicy = true; cache.applied.clear(); logged.clear();
      overrideSplitCacheGotSlots();
      CHECK(logged.size() == 1 && logged[0].find("/usr/lib/system/libsystem_malloc.dylib: 1 export(s) that no Darling image defines keep the cache's definition (first: _nosuchsymbol)") != std::string::npos);   // one line per exporter, under the policy option
      gLogCachePolicy = false; cache.applied.clear(); logged.clear(); gLinkContext.verboseMapping = true;
      overrideSplitCacheGotSlots();
      { unsigned perSymbol = 0, perExporter = 0; for (const std::string &l : logged) { perSymbol += l.find("defines _nosuchsymbol") != std::string::npos; perExporter += l.find("1 export(s) that no Darling image defines") != std::string::npos; } CHECK(perSymbol == 1 && perExporter == 1); }   // the per-symbol line is for the verbose mapping option
      gLinkContext.verboseMapping = false;
      // thousands of misses (a real cache has 3843 for an empty libswiftCore stand-in) stay one bounded line under the policy option, and none without an option
      familyCase(nullptr, false, sibling("/usr/lib/system/libsystem_c.dylib", 0x5000), image("/usr/lib/system/libsystem_info.dylib"));
      for (int i = 0; i < 4000; ++i) cache.moreNames.push_back("_missing" + std::to_string(i));
      cache.applied.clear(); logged.clear();
      overrideSplitCacheGotSlots();
      CHECK(logged.empty());
      gLogCachePolicy = true; cache.applied.clear(); logged.clear();
      overrideSplitCacheGotSlots();
      CHECK(logged.size() == 1 && logged[0].find(": 4001 export(s) that no Darling image defines keep the cache's definition (first: _nosuchsymbol, _missing0, _missing1, ...)") != std::string::npos && logged[0].size() < 400);
      gLogCachePolicy = false; cache.moreNames.clear();
      // the class-export gate looks at the image that defines the symbol, here the sibling
      auto classFamily = [&](int siblingSubtype) { familyCase(nullptr, false, sibling("/usr/lib/system/libsystem_c.dylib", 0x5000, siblingSubtype), image("/usr/lib/system/libsystem_info.dylib")); };
      cache.classNames = {"_close"}; classFamily(1); CHECK(cache.lastAddress.count("_close") == 0);
      classFamily(2); CHECK(cache.lastAddress["_close"] == 0x5000);
      cache.classNames.clear();

      // --- resolver exports: the override stores what the resolver returns (a stub would reach it through __la_resolver and lose registers), and never before the exporter is bound ---
      // _close of the exporter is stub 0x2000 and resolver (result 0x9000), in the stand-in itself or in a sibling. At launch the links of the main program and
      // of the inserted libraries run before the bind (ImageLoader::link skips it while linkingMainExecutable), so the exporters are not bound then.
      auto resolverCase = [&](bool inSibling, int subtype) {
        reset(cache); sAllImages.push_back(image("/usr/lib/libz.1.dylib", true));
        ImageLoader *standIn = image("/usr/lib/system/libsystem_kernel.dylib"); standIn->bound = false; standIn->header.cpusubtype = subtype;
        ImageLoader *c = image("/usr/lib/system/libsystem_c.dylib"); c->exports.clear(); c->bound = false; c->header.cpusubtype = subtype;
        ImageLoader *holder = inSibling ? c : standIn; holder->resolvers["_close"] = {0x2000, 0x9000}; holder->exports["_close"] = 0x2000;
        if (inSibling) standIn->exports.erase("_close");
        ImageLoader *umbrella = image("/usr/lib/libSystem.B.dylib"); umbrella->reExports = {standIn, c};
        sAllImages.push_back(umbrella); sAllImages.push_back(standIn); sAllImages.push_back(c); sDiskOverridesOfCacheImages.push_back({standIn, 1});
        return std::make_pair(standIn, c);
      };
      for (bool inSibling : {false, true}) {
        auto images = resolverCase(inSibling, 1);
        gLinkContext.linkingMainExecutable = true;                       // the launch's link(): nothing is bound yet
        overrideSplitCacheGotSlots();
        CHECK(cache.calls.empty() && cache.lastAddress.empty() && logged.empty());           // nothing is looked up, run or stored
        CHECK(images.first->resolverRuns + images.second->resolverRuns == 0 && images.first->stubLookups + images.second->stubLookups == 0);
        gLinkContext.linkingMainExecutable = false; images.first->bound = images.second->bound = true;   // _main has bound them
        overrideSplitCacheGotSlots();
        CHECK(images.first->resolverRuns + images.second->resolverRuns == 1 && images.first->resolverFaults + images.second->resolverFaults == 0);
        CHECK(images.first->stubLookups + images.second->stubLookups == 0);                  // the stub is never what is stored
        CHECK(cache.lastAddress["_close"] == (0x9000 | dyld3::darling::kThunkBit));         // the resolved value, through the adapters of a plain exporter
        CHECK(cache.lastAddress["_open"] == (0x1000 | dyld3::darling::kThunkBit));          // the other exports are as before
        resolverCase(inSibling, 2); // arm64e exporters
        for (ImageLoader *i : sAllImages) i->bound = true;
        overrideSplitCacheGotSlots();
        CHECK(cache.lastAddress["_close"] == 0x9000);
      }
      // a dlopen's link() ends with its closure bound: the override runs there and resolves at once
      { auto images = resolverCase(false, 1); images.first->bound = images.second->bound = true; overrideSplitCacheGotSlots();
        CHECK(cache.lastAddress["_close"] == (0x9000 | dyld3::darling::kThunkBit) && images.first->resolverFaults == 0); }
      // the unbound control: the pass that is not skipped would have run the resolver on an image that is not bound
      { auto images = resolverCase(false, 1); overrideSplitCacheGotSlots(); CHECK(images.first->resolverFaults == 1 && cache.lastAddress.count("_close") == 0); }

      // --- the log function is passed under the cache policy option too ---
      reset(cache); sAllImages.push_back(image("/usr/lib/libz.1.dylib", true)); shadow("/usr/lib/libSystem.B.dylib", 0);
      overrideSplitCacheGotSlots();
      CHECK((cache.logOn == std::vector<bool>{false}));
      cache.applied.clear(); cache.logOn.clear(); gLogCachePolicy = true;
      overrideSplitCacheGotSlots();
      CHECK((cache.logOn == std::vector<bool>{true}));
      gLogCachePolicy = false;

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
