# The bind hooks (three for an arm64e importer, two for a plain importer) and the environment switch of the arm64e adapters, replayed: the exact text of each hook is cut out
# of src/dyld2.cpp, src/ImageLoaderMachOCompressed.cpp and src/dyldAPIs.cpp, wrapped in stubs of the dyld types it touches
# and run against the real adapter module on this host (arm64 Linux with pointer authentication, SKIP otherwise). Mutants
# of the three sources (a guard removed, a condition inverted, the gate dropped) must each fail the replay.
# Usage: ruby tests/darling-arm64e-adapters-hooks.rb [checkout]
require 'tmpdir'
require_relative 'darling-arm64e-adapters-support'

root = File.realpath(ARGV.fetch(0, File.expand_path('..', __dir__)))
unless AdapterSupport.pac_host?
  puts 'SKIP darling-arm64e-adapters-hooks: needs an arm64 Linux host with pointer authentication and clang++'
  exit 0
end

$failures = 0
def check(desc, ok, detail = nil)
  if ok
    puts "PASS #{desc}"
  else
    $failures += 1
    puts "FAIL #{desc}#{detail ? ": #{detail}" : ''}"
  end
end

SOURCES = { dyld2: 'src/dyld2.cpp', loader: 'src/ImageLoaderMachOCompressed.cpp', api: 'src/dyldAPIs.cpp' }.freeze

# the text of each hook, or nil when it is not where it must be
def snippets(src)
  {
    got: src[:dyld2][/^\t+\*address = dyld3::darling::adaptedTarget\(symbol, found, [^\n]*;$/],
    fixups: src[:loader][/#ifdef DARLING\n\t+\/\/ arm64e code binding[^\n]*\n(.*?)#endif/m, 1],
    sign_define: src[:api][/^\t#define DARLING_DLSYM_SIGN\(p\) \(\(void\*\)dyld3::MachOLoaded[^\n]*$/],
    sign_function: src[:api][/^\tstatic void\* darlingDlsymSignForCaller\(.*?^\t\}\n/m],
    env: src[:dyld2][/^\telse if \( \(strcmp\(key, "DYLD_DARLING_ARM64E_ADAPTERS"\).*?^\t\}\n/m],
    plain_entry: src[:loader][/^static bool darlingAddressIsPlainFunctionEntry\(.*?^\}\n/m],
    plain_import: src[:loader][/^static uintptr_t darlingPlainImportTarget\(.*?^\}\n/m],
    bind_at: src[:loader][/#ifdef DARLING\n\t\/\/ a plain image's dyld-info and lazy binds[^\n]*\n(.*?)#endif/m, 1],
  }
end

REPLAY = <<~'CPP'
  #include <stdint.h>
  #include <stdio.h>
  #include <string.h>
  #include "DarlingArm64eAdapters.h"
  #include "MachOLoaded.h"
  using namespace dyld3::darling;

  namespace dyld { void warn(const char*, ...) { } }
  struct MachHeader { int cpusubtype; };
  struct ImageLoader {
    MachHeader mh; uint64_t lo, hi;
    // images with a real header and segments, for the function-entry predicate
    const MachHeader* header = nullptr; bool shared = false; unsigned nseg = 0;
    struct Seg { bool exec; uint64_t lo, hi; } segs[4] = {};
    const MachHeader* machHeader() const { return header ? header : &mh; }
    bool containsAddress(const void* a) const { return (uint64_t)a >= lo && (uint64_t)a < hi; }
    bool inSharedCache() const { return shared; }
    unsigned segmentCount() const { return nseg; }
    bool segExecutable(unsigned i) const { return segs[i].exec; }
    uintptr_t segActualLoadAddress(unsigned i) const { return segs[i].lo; }
    uintptr_t segActualEndAddress(unsigned i) const { return segs[i].hi; }
  };
  struct Diagnostics { bool err = false; bool hasError() const { return err; } };
  // what the fake getLinkEditPointers reports for an image: keyed by the image's mach header address
  struct FakeLinkEdit { uint64_t header; linkedit_data_command cmd; bool hasStarts; bool diagError; dyld3::MachOLoaded::LayoutInfo layout; };
  static FakeLinkEdit gLinkEdit[8];
  static unsigned gLinkEditCount;
  void dyld3::MachOLoaded::getLinkEditPointers(Diagnostics& d, LinkEditInfo& info) const {
    for (unsigned i = 0; i != gLinkEditCount; ++i) {
      if ( gLinkEdit[i].header != (uint64_t)this ) continue;
      d.err = gLinkEdit[i].diagError;
      info.functionStarts = gLinkEdit[i].hasStarts ? &gLinkEdit[i].cmd : nullptr;
      info.layout = gLinkEdit[i].layout;
    }
  }
  static const int BIND_TYPE_THREADED_REBASE = 102, BIND_TYPE_POINTER = 1;
  static ImageLoader gArm64eCaller = { { 2 }, 0x1000, 0x2000 };
  static ImageLoader gPlainCaller = { { 0 }, 0x2000, 0x3000 };
  static ImageLoader gPlainTarget = { { 0 }, 0x3000, 0x4000 };
  static ImageLoader gArm64eTarget = { { 2 }, 0x5000, 0x6000 };
  // images with memory behind them, for the function-entry predicate: P plain, A arm64e, C plain in the cache, N plain without
  // function starts, B plain whose function-starts table lies outside its LINKEDIT, E plain whose load commands do not parse
  enum { kP, kA, kC, kN, kB, kE, kImages };
  static ImageLoader gReal[kImages];
  // the cache lookup darlingDlsymSignForCaller makes for a caller that is in no image: this replay has no cache
  struct DyldSharedCache { struct { char magic[16]; } header; uint64_t mappedSize() const { return 0; } };
  namespace dyld {
    const void* imMemorySharedCacheHeader() { return nullptr; }
    ImageLoader* findImageContainingAddress(const void* a) {
      ImageLoader* all[] = { &gArm64eCaller, &gPlainCaller, &gPlainTarget, &gArm64eTarget,
                             &gReal[kP], &gReal[kA], &gReal[kC], &gReal[kN], &gReal[kB], &gReal[kE] };
      for (ImageLoader* i : all) if (i->containsAddress(a)) return i;
      return nullptr;
    }
  }
  __attribute__((target("arch=armv8.3-a"))) static uint64_t oracleSign(uint64_t p, uint64_t m) { asm("pacia %0, %1" : "+r"(p) : "r"(m)); return p; }

  static int gFailures, gChecks;
  #define CHECK(cond, ...) do { ++gChecks; if (!(cond)) { ++gFailures; printf("FAIL %d %s: ", __LINE__, #cond); printf(__VA_ARGS__); printf("\n"); } } while (0)

  // A value free of a PAC fixed point (pacia(x, 0) == x, about one process in 140 here): searches [first, last) by
  // `step`, which keeps it where the test needs it; callers assert that a value was found (0 means none was).
  static uint64_t notAFixedPoint(uint64_t first, uint64_t last, uint64_t step)
  {
    for (uint64_t v = first; v < last; v += step)
      if ( oracleSign(v, 0) != v )
        return v;
    return 0;
  }

  // hook 1: the split cache's GOT override
  static uint64_t hook1(const char* symbol, uintptr_t found, const ImageLoader* foundIn) {
    uint64_t value = 0; uint64_t* address = &value;
    @GOT@
    return value;
  }

  // hooks 4 and 5: a plain image's binds of an arm64e export (the predicate, the decision, and the dyld-info and lazy bind site)
  @PLAIN_ENTRY@
  @PLAIN_IMPORT@
  static uint64_t hook4(ImageLoader* image, int type, const char* symbolName, uint64_t addend, uintptr_t resolved, const ImageLoader* resolvedImage) {
    const ImageLoader* targetImage = resolvedImage;
    uintptr_t symbolAddress = resolved;
    @BIND_AT@
    return symbolAddress + addend;
  }

  // hook 2: the chained fixups of an arm64e image loaded from disk
  struct Importer : ImageLoader {
    Importer(int subtype) { mh.cpusubtype = subtype; lo = hi = 0; }
    uint64_t bind(const char* symbolName, uint64_t addend, uintptr_t resolved, const ImageLoader* resolvedImage) {
      const ImageLoader* targetImage = resolvedImage;
      uintptr_t symbolAddress = resolved;
  @FIXUPS@
      return symbolAddress + addend;
    }
  };

  // the fake arm64e callee of a reverse thunk
  static uint64_t gSeen[8];
  static uint64_t fakeCallee(uint64_t a0, uint64_t a1, uint64_t a2, uint64_t a3, uint64_t a4, uint64_t a5, uint64_t a6, uint64_t a7) {
    const uint64_t a[8] = { a0, a1, a2, a3, a4, a5, a6, a7 };
    memcpy(gSeen, a, sizeof(a));
    return 0;
  }
  typedef uint64_t (*Fn8)(uint64_t, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t);
  static void setupRealImages() {
    // each image: 0x4000 bytes, the header at 0, executable segment [0x1000, 0x2000), data [0x2000, 0x3000), LINKEDIT at 0x3000
    // (file offset 0x9000, slide 0x7000). Function starts 0x1000, 0x1040 and 0x2010 (in the data segment).
    static uint8_t arena[kImages][0x8000] __attribute__((aligned(16384)));
    // P's starts 0x1000 and 0x1040 are the addresses the signing checks use; move the image in its slot until neither is a
    // PAC fixed point, and assert the choice, so that a signature the hooks add is always visible.
    uintptr_t shift = 0;
    for (; shift < 0x1000; shift += 0x40) {
      const uint64_t b = (uint64_t)arena[kP] + shift;
      if ( (oracleSign(b + 0x1000, 0) != b + 0x1000) && (oracleSign(b + 0x1040, 0) != b + 0x1040) )
        break;
    }
    CHECK(shift < 0x1000, "every placement of the plain image is a PAC fixed point");
    const uint8_t starts[] = { 0x80, 0x20, 0x40, 0xD0, 0x1F, 0x00 };
    for (int k = 0; k != kImages; ++k) {
      uint8_t* base = arena[k] + ((k == kP) ? shift : 0);
      memcpy(base + 0x3010, starts, sizeof(starts));
      ((MachHeader*)base)->cpusubtype = (k == kA) ? 2 : 0;
      ImageLoader& im = gReal[k];
      im.header = (const MachHeader*)base; im.lo = (uint64_t)base; im.hi = (uint64_t)base + 0x4000;
      im.shared = (k == kC); im.nseg = 2;
      im.segs[0] = { true, (uint64_t)base + 0x1000, (uint64_t)base + 0x2000 };
      im.segs[1] = { false, (uint64_t)base + 0x2000, (uint64_t)base + 0x3000 };
      FakeLinkEdit& le = gLinkEdit[gLinkEditCount++];
      le.header = (uint64_t)base; le.hasStarts = (k != kN); le.diagError = (k == kE);
      le.cmd = { 0x26, 16, 0x9010, (uint32_t)sizeof(starts) };
      if ( k == kB ) le.cmd.datasize = 0x2000;
      le.layout = { 0x7000, 0, (uintptr_t)base + 0x3000 - 0x7000, 0x9000, 0x1000, 2, 2 };
    }
  }

  // hook 3: dlsym
  @SIGN_DEFINE@
  @SIGN_FUNCTION@

  // the environment switch
  static struct { bool allowEnvVarsPath, allowEnvVarsSharedCache; } gLinkContext = { true, true };
  static void environment(const char* key, const char* value) {
    if ( 0 ) { }
  @ENV@
  }

  int main() {
    // raw and the thunk made for it are both values the dlsym hook signs; a PAC fixed point would let a check that they
    // came out signed pass with the signing removed, so move the bind target inside the plain image until neither is one.
    uint64_t raw = 0;
    for (uint64_t candidate = 0x3500; (candidate < 0x4000) && (raw == 0); candidate += 0x40) {
      if ( oracleSign(candidate, 0) == candidate )
        continue;
      const uint64_t made = hook1("_atexit", candidate, &gPlainTarget);
      if ( oracleSign(made, 0) != made )
        raw = candidate;
    }
    CHECK((raw != 0) && (oracleSign(raw, 0) != raw), "every bind target in the plain image is a PAC fixed point");
    // hook 1
    CHECK(hook1("_atexit", raw, &gPlainTarget) != raw, "a plain exporter's callback-taking function was not thunked");
    CHECK(hook1("_atexit", raw, &gArm64eTarget) == raw, "an arm64e exporter was thunked");
    CHECK(hook1("_not_a_row", raw, &gPlainTarget) == raw, "a symbol with no row was changed");
    CHECK(hook1("_atexit_b", raw, &gPlainTarget) == raw, "an unsupported row changed the binding");
    CHECK(hook1("_atexit", raw, &gPlainTarget) == hook1("_atexit", raw, &gPlainTarget), "the same target got two thunks");

    // hook 2
    Importer arm64e(2), plain(0);
    uint64_t thunk = arm64e.bind("_atexit", 0, raw, &gPlainTarget);
    CHECK(thunk != raw, "an arm64e importer of a plain export got no thunk");
    CHECK(oracleSign(thunk, 0) != thunk, "the thunk is a PAC fixed point: the dlsym check could not tell signing from no signing");
    CHECK(thunk == hook1("_atexit", raw, &gPlainTarget), "the fixups and the GOT override made different thunks for one target");
    CHECK(plain.bind("_atexit", 0, raw, &gPlainTarget) == raw, "a plain importer got a thunk");
    CHECK(arm64e.bind("_atexit", 8, raw, &gPlainTarget) == raw + 8, "a bind with an addend was thunked");
    CHECK(arm64e.bind("_atexit", 0, 0x5500, &gArm64eTarget) == 0x5500, "an arm64e target was thunked");
    const ImageLoader* volatile noImage = nullptr;
    CHECK(arm64e.bind("_atexit", 0, raw, noImage) == raw, "a bind with no target image was changed");
    CHECK(arm64e.bind("_atexit", 0, 0, &gPlainTarget) == 0, "a missing weak import was changed");
    CHECK(arm64e.bind("_atexit", 0, 0x9000, &gPlainTarget) == 0x9000, "an interposed address, outside the target image, was thunked");
    CHECK(arm64e.bind("_not_a_row", 0, raw, &gPlainTarget) == raw, "a symbol with no row was changed by the fixups");

    // hooks 4 and 5: a plain importer binding an export of an arm64e image
    setupRealImages();
    const uint64_t P = (uint64_t)gReal[kP].header, A = (uint64_t)gReal[kA].header, C = (uint64_t)gReal[kC].header;
    const uint64_t N = (uint64_t)gReal[kN].header, B = (uint64_t)gReal[kB].header, E = (uint64_t)gReal[kE].header;
    // the function-entry predicate
    CHECK(darlingAddressIsPlainFunctionEntry(P + 0x1000) && darlingAddressIsPlainFunctionEntry(P + 0x1040), "a function start of a plain image was refused");
    CHECK(!darlingAddressIsPlainFunctionEntry(P + 0x1004) && !darlingAddressIsPlainFunctionEntry(P + 0x1080) && !darlingAddressIsPlainFunctionEntry(P), "a mid-function address or the header was accepted");
    CHECK(!darlingAddressIsPlainFunctionEntry(P + 0x2010), "a function start in a segment that is not executable was accepted");
    CHECK(!darlingAddressIsPlainFunctionEntry(A + 0x1000), "an address in an arm64e image was accepted");
    CHECK(!darlingAddressIsPlainFunctionEntry(C + 0x1000), "an address in a plain image of the shared cache was accepted");
    CHECK(!darlingAddressIsPlainFunctionEntry(N + 0x1000), "an image with no function starts signed an address");
    CHECK(!darlingAddressIsPlainFunctionEntry(B + 0x1000), "a function-starts table outside the LINKEDIT was read");
    CHECK(!darlingAddressIsPlainFunctionEntry(E + 0x1000), "an image whose load commands do not parse signed an address");
    CHECK(!darlingAddressIsPlainFunctionEntry(0) && !darlingAddressIsPlainFunctionEntry(0x1234), "an address in no image was accepted");
    CHECK(!darlingAddressIsPlainFunctionEntry(oracleSign(P + 0x1000, 0)), "an already signed address was accepted");
    // the decision
    ImageLoader calleeImage = { { 2 }, (uint64_t)&fakeCallee, (uint64_t)&fakeCallee + 0x40 };
    const uint64_t callee = (uint64_t)&fakeCallee;
    const char* setT = "__ZSt13set_terminatePFvvE";
    Importer plainImporter(0), arm64eImporter(2);
    const uint64_t viaBindAt = hook4(&plainImporter, BIND_TYPE_POINTER, setT, 0, callee, &calleeImage);
    CHECK(viaBindAt != callee, "a plain image's dyld-info bind of an arm64e export got no thunk");
    CHECK(plainImporter.bind(setT, 0, callee, &calleeImage) == viaBindAt, "the dyld-info and the chained-fixups binds made different thunks");
    CHECK(hook4(&plainImporter, BIND_TYPE_POINTER, "_not_a_row", 0, callee, &calleeImage) == callee, "a symbol with no reverse row was changed");
    CHECK(hook4(&plainImporter, BIND_TYPE_POINTER, setT, 8, callee, &calleeImage) == callee + 8, "a bind with an addend was thunked");
    CHECK(hook4(&plainImporter, BIND_TYPE_POINTER, setT, 0, raw, &gPlainTarget) == raw, "a plain exporter was thunked");
    CHECK(hook4(&arm64eImporter, BIND_TYPE_POINTER, setT, 0, callee, &calleeImage) == callee, "an arm64e importer of an arm64e export was thunked");
    CHECK(arm64eImporter.bind(setT, 0, callee, &calleeImage) == callee, "an arm64e importer of an arm64e export was thunked by the fixups");
    CHECK(hook4(&plainImporter, BIND_TYPE_POINTER, setT, 0, 0x9000, &calleeImage) == 0x9000, "an interposer's address, outside the exporter, was thunked");
    CHECK(hook4(&plainImporter, BIND_TYPE_POINTER, setT, 0, callee, noImage) == callee, "a bind with no target image was thunked");
    CHECK(hook4(&plainImporter, BIND_TYPE_THREADED_REBASE, setT, 0, 0, nullptr) == 0, "a threaded rebase was changed");
    // an image of the shared cache keeps its GOT in cache memory: no thunk address may be written there
    ImageLoader cacheImporter = { { 0 }, 0x2000, 0x3000 };
    cacheImporter.shared = true;
    CHECK(hook4(&cacheImporter, BIND_TYPE_POINTER, setT, 0, callee, &calleeImage) == callee, "an importer in the shared cache was thunked");
    // through the thunk, with the real predicate: an entry of the plain image is signed, nothing else is
    Fn8 reverse = (Fn8)viaBindAt;
    const uint64_t args[] = { P + 0x1040, P + 0x1044, A + 0x1000, C + 0x1000, 0, 0x1234 };
    for (uint64_t a : args) { reverse(a, 1, 2, 3, 4, 5, 6, 7); CHECK(gSeen[0] == (a == P + 0x1040 ? oracleSign(a, 0) : a), "argument %llx came out as %llx", (unsigned long long)a, (unsigned long long)gSeen[0]); }

    // hook 3
    void* callerArm64e = (void*)0x1500; void* callerPlain = (void*)0x2500;
    // the two results below are compared against their signatures; move them off their PAC fixed points inside the image
    // ranges the test needs, and assert the choices
    const uint64_t arm64eFunction = notAFixedPoint(0x5500, 0x6000, 0x40);
    const uint64_t outsideImage = notAFixedPoint(0x7500, 0x8000, 0x40);
    CHECK((arm64eFunction != 0) && (outsideImage != 0), "no value free of PAC fixed points for the dlsym checks");
    uint64_t signedThunk = (uint64_t)darlingDlsymSignForCaller((void*)raw, callerArm64e, "_atexit");
    CHECK(signedThunk == oracleSign(thunk, 0), "dlsym for an arm64e caller did not return the signed thunk");
    CHECK(darlingDlsymSignForCaller((void*)raw, callerPlain, "_atexit") == (void*)raw, "dlsym for a plain caller was changed");
    CHECK(darlingDlsymSignForCaller((void*)raw, (void*)0x7000, "_atexit") == (void*)raw, "dlsym for a caller in no image was changed");
    CHECK(darlingDlsymSignForCaller((void*)arm64eFunction, callerArm64e, "_atexit") == (void*)oracleSign(arm64eFunction, 0), "dlsym of an arm64e function was thunked or not signed");
    CHECK(darlingDlsymSignForCaller((void*)raw, callerArm64e, "_not_a_row") == (void*)oracleSign(raw, 0), "dlsym of a symbol with no row was changed beyond signing");
    CHECK(darlingDlsymSignForCaller((void*)outsideImage, callerArm64e, "_atexit") == (void*)oracleSign(outsideImage, 0), "dlsym of an address in no image was thunked");

    // the switch: honoured when the process may use it, ignored when it is restricted
    environment("DYLD_DARLING_ARM64E_ADAPTERS", "off");
    CHECK(adaptedTarget("_atexit", raw, false) == raw, "off did not turn the adapters off");
    CHECK(reverseAdaptedTarget(setT, callee, true, nullptr) == callee, "off did not turn the opposite direction off");
    environment("DYLD_DARLING_ARM64E_ADAPTERS", "on");
    CHECK(adaptedTarget("_atexit", raw, false) != raw, "on did not turn them back on");
    CHECK(reverseAdaptedTarget(setT, callee, true, nullptr) != callee, "on did not turn the opposite direction back on");
    environment("DYLD_DARLING_ARM64E_ADAPTERS", "something else");
    CHECK(adaptedTarget("_atexit", raw, false) != raw, "an unknown value turned the adapters off");
    const bool gates[3][2] = { { false, true }, { true, false }, { false, false } };
    for (const auto& g : gates) {
      gLinkContext.allowEnvVarsPath = g[0]; gLinkContext.allowEnvVarsSharedCache = g[1];
      environment("DYLD_DARLING_ARM64E_ADAPTERS", "off");
      CHECK(adaptedTarget("_atexit", raw, false) != raw, "a restricted process (path %d, shared cache %d) turned the adapters off", g[0], g[1]);
      CHECK(reverseAdaptedTarget(setT, callee, true, nullptr) != callee, "a restricted process (path %d, shared cache %d) turned the opposite direction off", g[0], g[1]);
    }
    gLinkContext.allowEnvVarsPath = gLinkContext.allowEnvVarsSharedCache = true;
    environment("DYLD_DARLING_ARM64E_ADAPTERS", "off");
    environment("DYLD_SOMETHING_ELSE", "off");
    CHECK(adaptedTarget("_atexit", raw, false) == raw, "another variable undid the switch");
    printf("%s %d checks, %d failures\n", gFailures ? "FAIL" : "PASS", gChecks, gFailures);
    return gFailures ? 1 : 0;
  }
CPP

def replay_source(src)
  s = snippets(src)
  missing = s.select { |_, v| v.nil? }.keys
  return [nil, missing] unless missing.empty?
  text = REPLAY.dup
  text.sub!('@GOT@') { s[:got] }
  text.sub!('@FIXUPS@') { s[:fixups] }
  text.sub!('@SIGN_DEFINE@') { s[:sign_define].strip }
  text.sub!('@SIGN_FUNCTION@') { s[:sign_function] }
  text.sub!('@ENV@') { s[:env] }
  text.sub!('@PLAIN_ENTRY@') { s[:plain_entry] }
  text.sub!('@PLAIN_IMPORT@') { s[:plain_import] }
  text.sub!('@BIND_AT@') { s[:bind_at] }
  [text, []]
end

Dir.mktmpdir('darling-arm64e-adapters-hooks-') do |dir|
  src = SOURCES.to_h { |k, path| [k, File.read(File.join(root, path))] }
  text, missing = replay_source(src)
  check 'every hook is found in its source file', missing.empty?, missing.inspect
  abort "#{$failures} failures" unless text

  # the dlsym call sites all pass the underscored name, which is what the rows are keyed by
  check 'all five dlsym call sites pass the underscored symbol name', src[:api].scan('DARLING_DLSYM_SIGN_FOR_CALLER(result, callerAddress, underscoredName)').size == 5 &&
                                                                  src[:api].scan('DARLING_DLSYM_SIGN_FOR_CALLER(').size == 7, src[:api].scan('DARLING_DLSYM_SIGN_FOR_CALLER(').size
  SOURCES.each_value do |path|
    body = File.read(File.join(root, path))
    check "#{path} includes the adapter header only for DARLING", body.include?("#ifdef DARLING\n#include \"DarlingArm64eAdapters.h\"\n#endif")
  end

  driver = File.join(dir, 'replay.cpp')
  File.write(driver, text)
  exe, err = AdapterSupport.build(root, dir, 'real', driver)
  check 'the replay compiles', !exe.nil?, err[0, 800]
  abort "#{$failures} failures" unless exe
  out, st = AdapterSupport.run(exe)
  out.lines.grep(/^FAIL/).first(10).each { |l| puts l }
  summary = out.lines.grep(/^(PASS|FAIL) \d+ checks/).last.to_s.strip
  check "the replay of the hooks: #{summary}", st.success? && summary.start_with?('PASS')

  mutants = {
    'the GOT override thunks an arm64e exporter' => [:dyld2, 'dyld3::darling::cpusubtypeIsArm64e(foundIn->machHeader()->cpusubtype)', 'false'],
    'the GOT override passes the wrong symbol' => [:dyld2, 'adaptedTarget(symbol, found,', 'adaptedTarget("_unrelated", found,'],
    'the fixups thunk for a plain importer' => [:loader, ' && dyld3::darling::cpusubtypeIsArm64e(this->machHeader()->cpusubtype) )', ' )'],
    'the fixups thunk a bind with an addend' => [:loader, '(addend == 0) && ', ''],
    'the fixups do not look at the target image' => [:loader, '(targetImage != NULL) && ', ''],
    'the fixups thunk an interposed address' => [:loader, ' && targetImage->containsAddress((void*)symbolAddress)', ''],
    'the fixups thunk an arm64e target' => [:loader, 'dyld3::darling::cpusubtypeIsArm64e(targetImage->machHeader()->cpusubtype));', 'false);'],
    # the caller test is one condition, or an assignment once the cache region's callers are handled too
    'dlsym thunks for a plain caller' => src[:api].include?('callerIsArm64e = dyld3::darling::cpusubtypeIsArm64e(') ?
      [:api, 'callerIsArm64e = dyld3::darling::cpusubtypeIsArm64e(callerImage->machHeader()->cpusubtype);', 'callerIsArm64e = true;'] :
      [:api, '|| !dyld3::darling::cpusubtypeIsArm64e(callerImage->machHeader()->cpusubtype) )', ')'],
    'dlsym never thunks' => [:api, "\t\tif ( resultImage != NULL )\n\t\t\tresult = (void*)dyld3::darling::adaptedTarget(", "\t\tif ( false )\n\t\t\tresult = (void*)dyld3::darling::adaptedTarget("],
    'dlsym thunks an arm64e function' => [:api, 'dyld3::darling::cpusubtypeIsArm64e(resultImage->machHeader()->cpusubtype));', 'false);'],
    'dlsym passes no symbol name' => [:api, 'adaptedTarget(machoName,', 'adaptedTarget("_x",'],
    'one dlsym site passes the plain name' => [:api, "result = DARLING_DLSYM_SIGN_FOR_CALLER(result, callerAddress, underscoredName);\n\t\t\t}\n#endif\n\t\t\tif ( dyld::gLogAPIs )\n\t\t\t\tdyld::log(\"  %s(RTLD_DEFAULT", "result = DARLING_DLSYM_SIGN_FOR_CALLER(result, callerAddress, symbolName);\n\t\t\t}\n#endif\n\t\t\tif ( dyld::gLogAPIs )\n\t\t\t\tdyld::log(\"  %s(RTLD_DEFAULT"],
    'the switch ignores the shared cache gate' => [:dyld2, '"DYLD_DARLING_ARM64E_ADAPTERS") == 0) && gLinkContext.allowEnvVarsSharedCache && gLinkContext.allowEnvVarsPath', '"DYLD_DARLING_ARM64E_ADAPTERS") == 0) && gLinkContext.allowEnvVarsPath'],
    'the switch ignores the path gate' => [:dyld2, '"DYLD_DARLING_ARM64E_ADAPTERS") == 0) && gLinkContext.allowEnvVarsSharedCache && gLinkContext.allowEnvVarsPath', '"DYLD_DARLING_ARM64E_ADAPTERS") == 0) && gLinkContext.allowEnvVarsSharedCache'],
    'the switch has no gate at all' => [:dyld2, '"DYLD_DARLING_ARM64E_ADAPTERS") == 0) && gLinkContext.allowEnvVarsSharedCache && gLinkContext.allowEnvVarsPath', '"DYLD_DARLING_ARM64E_ADAPTERS") == 0)'],
    'a plain importer of an arm64e export gets no thunk from the chained fixups' => [:loader, 'symbolAddress = darlingPlainImportTarget(this, symbolName, symbolAddress, addend, targetImage);', ';'],
    'a plain importer of an arm64e export gets no thunk from the dyld-info binds' => [:loader, 'symbolAddress = darlingPlainImportTarget(image, symbolName, symbolAddress, addend, targetImage);', ';'],
    'an arm64e importer is adapted in the reverse direction' => [:loader, "\tif ( dyld3::darling::cpusubtypeIsArm64e(importer->machHeader()->cpusubtype) )\n\t\treturn symbolAddress;\n", ''],
    'the reverse hook thunks a bind with an addend' => [:loader, '(addend != 0) || ', ''],
    'the reverse hook thunks an importer in the shared cache' => [:loader, '(exporter == NULL) || importer->inSharedCache() || ', '(exporter == NULL) || '],
    'the reverse hook does not look at the exporter' => [:loader, '(exporter == NULL) || ', ''],
    'the reverse hook thunks an interposed address' => [:loader, ' || !exporter->containsAddress((void*)symbolAddress)', ''],
    'the reverse hook ignores the exporter\'s cpu subtype' => [:loader, 'dyld3::darling::cpusubtypeIsArm64e(exporter->machHeader()->cpusubtype), &darling', 'true, &darling'],
    'the reverse hook passes no predicate' => [:loader, ', &darlingAddressIsPlainFunctionEntry)', ', nullptr)'],
    'the entry predicate accepts an image of the cache' => [:loader, '(image == NULL) || image->inSharedCache()', '(image == NULL)'],
    'the entry predicate accepts an arm64e image' => [:loader, "\tif ( dyld3::darling::cpusubtypeIsArm64e(image->machHeader()->cpusubtype) )\n\t\treturn false;\n", ''],
    'the entry predicate accepts an address outside the executable segments' => [:loader, "\tif ( !inExecutableSegment )\n\t\treturn false;\n", ''],
    'the entry predicate ignores a load-command error' => [:loader, 'diag.hasError() || ', ''],
    'the entry predicate accepts an image with no function starts' => [:loader, ' || (leInfo.functionStarts == NULL) )', ' )'],
    'the entry predicate reads a table outside the LINKEDIT' => [:loader, "\t\treturn false;\n\tconst uint8_t* blob", "\t\t;\n\tconst uint8_t* blob"],
    'the entry predicate forgets the slide' => [:loader, '(layout.linkeditUnslidVMAddr + layout.slide)', '(layout.linkeditUnslidVMAddr)'],
    'the entry predicate measures the offset from zero' => [:loader, 'address - (uint64_t)(uintptr_t)ml)', 'address)'],
    'off means on' => [:dyld2, 'strcmp(value, "off") == 0 ? dyld3::darling::AdapterMode::Off', 'strcmp(value, "off") == 0 ? dyld3::darling::AdapterMode::On'],
  }
  killed = 0
  mutants.each_with_index do |(desc, (file, from, to)), i|
    unless src[file].scan(from).size == 1
      check "mutant applies: #{desc}", false, "#{src[file].scan(from).size} matches"
      next
    end
    msrc = src.merge(file => src[file].sub(from) { to })
    mtext, mmissing = replay_source(msrc)
    dead = !mmissing.empty?
    unless dead
      mdriver = File.join(dir, "mutant#{i}.cpp")
      File.write(mdriver, mtext)
      mexe, = AdapterSupport.build(root, dir, "mutant#{i}", mdriver)
      dead = mexe.nil? || begin
        mout, mst = AdapterSupport.run(mexe)
        !mst.success? || mout =~ /^FAIL/
      end
    end
    # the call site mutant is caught by the source count, not by the replay
    dead ||= msrc[:api].scan('DARLING_DLSYM_SIGN_FOR_CALLER(result, callerAddress, underscoredName)').size != 5
    killed += 1 if dead
    check "mutation probe killed: #{desc}", dead
  end
  puts "probes killed #{killed}/#{mutants.size}"
end

puts($failures.zero? ? 'ALL PASS' : "#{$failures} FAILURES")
exit($failures.zero? ? 0 : 1)
