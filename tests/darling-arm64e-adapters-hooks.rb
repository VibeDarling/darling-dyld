# The three bind hooks and the environment switch of the arm64e adapters, replayed: the exact text of each hook is cut out
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
    const MachHeader* machHeader() const { return &mh; }
    bool containsAddress(const void* a) const { return (uint64_t)a >= lo && (uint64_t)a < hi; }
  };
  static ImageLoader gArm64eCaller = { { 2 }, 0x1000, 0x2000 };
  static ImageLoader gPlainCaller = { { 0 }, 0x2000, 0x3000 };
  static ImageLoader gPlainTarget = { { 0 }, 0x3000, 0x4000 };
  static ImageLoader gArm64eTarget = { { 2 }, 0x5000, 0x6000 };
  namespace dyld {
    ImageLoader* findImageContainingAddress(const void* a) {
      ImageLoader* all[] = { &gArm64eCaller, &gPlainCaller, &gPlainTarget, &gArm64eTarget };
      for (ImageLoader* i : all) if (i->containsAddress(a)) return i;
      return nullptr;
    }
  }
  __attribute__((target("arch=armv8.3-a"))) static uint64_t oracleSign(uint64_t p, uint64_t m) { asm("pacia %0, %1" : "+r"(p) : "r"(m)); return p; }

  static int gFailures, gChecks;
  #define CHECK(cond, ...) do { ++gChecks; if (!(cond)) { ++gFailures; printf("FAIL %d %s: ", __LINE__, #cond); printf(__VA_ARGS__); printf("\n"); } } while (0)

  // hook 1: the split cache's GOT override
  static uint64_t hook1(const char* symbol, uintptr_t found, const ImageLoader* foundIn) {
    uint64_t value = 0; uint64_t* address = &value;
    @GOT@
    return value;
  }

  // hook 2: the chained fixups of an arm64e image loaded from disk
  struct Importer {
    MachHeader mh;
    const MachHeader* machHeader() const { return &mh; }
    uint64_t bind(const char* symbolName, uint64_t addend, uintptr_t resolved, const ImageLoader* resolvedImage) {
      const ImageLoader* targetImage = resolvedImage;
      uintptr_t symbolAddress = resolved;
  @FIXUPS@
      return symbolAddress + addend;
    }
  };

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
    const uint64_t raw = 0x3500;
    // hook 1
    CHECK(hook1("_atexit", raw, &gPlainTarget) != raw, "a plain exporter's callback-taking function was not thunked");
    CHECK(hook1("_atexit", raw, &gArm64eTarget) == raw, "an arm64e exporter was thunked");
    CHECK(hook1("_not_a_row", raw, &gPlainTarget) == raw, "a symbol with no row was changed");
    CHECK(hook1("_atexit_b", raw, &gPlainTarget) == raw, "an unsupported row changed the binding");
    CHECK(hook1("_atexit", raw, &gPlainTarget) == hook1("_atexit", raw, &gPlainTarget), "the same target got two thunks");

    // hook 2
    Importer arm64e = { { 2 } }, plain = { { 0 } };
    uint64_t thunk = arm64e.bind("_atexit", 0, raw, &gPlainTarget);
    CHECK(thunk != raw, "an arm64e importer of a plain export got no thunk");
    CHECK(thunk == hook1("_atexit", raw, &gPlainTarget), "the fixups and the GOT override made different thunks for one target");
    CHECK(plain.bind("_atexit", 0, raw, &gPlainTarget) == raw, "a plain importer got a thunk");
    CHECK(arm64e.bind("_atexit", 8, raw, &gPlainTarget) == raw + 8, "a bind with an addend was thunked");
    CHECK(arm64e.bind("_atexit", 0, 0x5500, &gArm64eTarget) == 0x5500, "an arm64e target was thunked");
    const ImageLoader* volatile noImage = nullptr;
    CHECK(arm64e.bind("_atexit", 0, raw, noImage) == raw, "a bind with no target image was changed");
    CHECK(arm64e.bind("_atexit", 0, 0, &gPlainTarget) == 0, "a missing weak import was changed");
    CHECK(arm64e.bind("_atexit", 0, 0x9000, &gPlainTarget) == 0x9000, "an interposed address, outside the target image, was thunked");
    CHECK(arm64e.bind("_not_a_row", 0, raw, &gPlainTarget) == raw, "a symbol with no row was changed by the fixups");

    // hook 3
    void* callerArm64e = (void*)0x1500; void* callerPlain = (void*)0x2500;
    uint64_t signedThunk = (uint64_t)darlingDlsymSignForCaller((void*)raw, callerArm64e, "_atexit");
    CHECK(signedThunk == oracleSign(thunk, 0), "dlsym for an arm64e caller did not return the signed thunk");
    CHECK(darlingDlsymSignForCaller((void*)raw, callerPlain, "_atexit") == (void*)raw, "dlsym for a plain caller was changed");
    CHECK(darlingDlsymSignForCaller((void*)raw, (void*)0x7000, "_atexit") == (void*)raw, "dlsym for a caller in no image was changed");
    CHECK(darlingDlsymSignForCaller((void*)0x5500, callerArm64e, "_atexit") == (void*)oracleSign(0x5500, 0), "dlsym of an arm64e function was thunked or not signed");
    CHECK(darlingDlsymSignForCaller((void*)raw, callerArm64e, "_not_a_row") == (void*)oracleSign(raw, 0), "dlsym of a symbol with no row was changed beyond signing");
    CHECK(darlingDlsymSignForCaller((void*)0x7500, callerArm64e, "_atexit") == (void*)oracleSign(0x7500, 0), "dlsym of an address in no image was thunked");

    // the switch: honoured when the process may use it, ignored when it is restricted
    environment("DYLD_DARLING_ARM64E_ADAPTERS", "off");
    CHECK(adaptedTarget("_atexit", raw, false) == raw, "off did not turn the adapters off");
    environment("DYLD_DARLING_ARM64E_ADAPTERS", "on");
    CHECK(adaptedTarget("_atexit", raw, false) != raw, "on did not turn them back on");
    environment("DYLD_DARLING_ARM64E_ADAPTERS", "something else");
    CHECK(adaptedTarget("_atexit", raw, false) != raw, "an unknown value turned the adapters off");
    const bool gates[3][2] = { { false, true }, { true, false }, { false, false } };
    for (const auto& g : gates) {
      gLinkContext.allowEnvVarsPath = g[0]; gLinkContext.allowEnvVarsSharedCache = g[1];
      environment("DYLD_DARLING_ARM64E_ADAPTERS", "off");
      CHECK(adaptedTarget("_atexit", raw, false) != raw, "a restricted process (path %d, shared cache %d) turned the adapters off", g[0], g[1]);
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
    'dlsym thunks for a plain caller' => [:api, '|| !dyld3::darling::cpusubtypeIsArm64e(callerImage->machHeader()->cpusubtype) )', ')'],
    'dlsym never thunks' => [:api, "\t\tif ( resultImage != NULL )\n\t\t\tresult = (void*)dyld3::darling::adaptedTarget(", "\t\tif ( false )\n\t\t\tresult = (void*)dyld3::darling::adaptedTarget("],
    'dlsym thunks an arm64e function' => [:api, 'dyld3::darling::cpusubtypeIsArm64e(resultImage->machHeader()->cpusubtype));', 'false);'],
    'dlsym passes no symbol name' => [:api, 'adaptedTarget(machoName,', 'adaptedTarget("_x",'],
    'one dlsym site passes the plain name' => [:api, "result = DARLING_DLSYM_SIGN_FOR_CALLER(result, callerAddress, underscoredName);\n\t\t\t}\n#endif\n\t\t\tif ( dyld::gLogAPIs )\n\t\t\t\tdyld::log(\"  %s(RTLD_DEFAULT", "result = DARLING_DLSYM_SIGN_FOR_CALLER(result, callerAddress, symbolName);\n\t\t\t}\n#endif\n\t\t\tif ( dyld::gLogAPIs )\n\t\t\t\tdyld::log(\"  %s(RTLD_DEFAULT"],
    'the switch ignores the shared cache gate' => [:dyld2, '"DYLD_DARLING_ARM64E_ADAPTERS") == 0) && gLinkContext.allowEnvVarsSharedCache && gLinkContext.allowEnvVarsPath', '"DYLD_DARLING_ARM64E_ADAPTERS") == 0) && gLinkContext.allowEnvVarsPath'],
    'the switch ignores the path gate' => [:dyld2, '"DYLD_DARLING_ARM64E_ADAPTERS") == 0) && gLinkContext.allowEnvVarsSharedCache && gLinkContext.allowEnvVarsPath', '"DYLD_DARLING_ARM64E_ADAPTERS") == 0) && gLinkContext.allowEnvVarsSharedCache'],
    'the switch has no gate at all' => [:dyld2, '"DYLD_DARLING_ARM64E_ADAPTERS") == 0) && gLinkContext.allowEnvVarsSharedCache && gLinkContext.allowEnvVarsPath', '"DYLD_DARLING_ARM64E_ADAPTERS") == 0)'],
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
