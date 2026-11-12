# overridePatchGotSlots of DyldSharedCache on the synthetic patch cache (tests/gen-split-cache-fixture.py --variant
# patch): the coalesced GOT slots of an exporter are overwritten with the stub resolver's addresses, signed as the
# slot's flags say. Every written slot is checked with the PAC instructions themselves (autia/autda with the
# process's own keys, a modifier decoded here from the manifest, not by the reader), every other word of the GOT
# mapping must be byte-identical, and the DATA_CONST mapping must be read-only before, writable only between the
# first write and the return, and read-only again afterwards. Needs an arm64 Linux host with pointer
# authentication (SKIP otherwise). No Apple cache content is used.
# Usage: ruby tests/patch-info-v4-override.rb [checkout] [base-address]
require 'tmpdir'
require 'open3'
require 'rbconfig'
root = File.realpath(ARGV.fetch(0, File.expand_path('..', __dir__)))
base = ARGV.fetch(1, '0x180000000')
require_relative 'split-cache-harness'
require_relative 'patch-fixture-program'

HWCAP_PACA = 1 << 30
host_hwcap = File.binread('/proc/self/auxv').unpack('Q*').each_slice(2).find { |type, _| type == 16 }&.last.to_i
unless RbConfig::CONFIG['host_cpu'] =~ /aarch64|arm64/ && (host_hwcap & HWCAP_PACA) != 0
  puts 'SKIP patch-info-v4-override: this host has no pointer authentication (arm64 Linux with PAC is required)'
  exit 0
end

OVERRIDE_MAIN = <<~CPP
  __attribute__((target("arch=armv8.3-a"))) static uint64_t authenticate(int isData, uint64_t value, uint64_t modifier) {
    if (isData) asm("autda %0, %1" : "+r"(value) : "r"(modifier)); else asm("autia %0, %1" : "+r"(value) : "r"(modifier));
    return value;
  }
  // A hardware that traps on a failed authentication (FPAC) kills the child, which counts as a failed authentication.
  static bool authenticates(int isData, uint64_t value, uint64_t modifier, uint64_t target) {
    fflush(stdout);
    pid_t pid = fork(); assert(pid >= 0);
    if (pid == 0) _exit(authenticate(isData, value, modifier) == target ? 0 : 1);
    int status = 0; assert(waitpid(pid, &status, 0) == pid);
    return WIFEXITED(status) && WEXITSTATUS(status) == 0;
  }
  static std::string permissions(uint64_t address) {
    FILE *maps = fopen("/proc/self/maps", "r"); assert(maps);
    char line[512]; std::string perms = "unmapped";
    while (fgets(line, sizeof line, maps)) {
      unsigned long long start, end; char p[8];
      if (sscanf(line, "%llx-%llx %7s", &start, &end, p) == 3 && address >= start && address < end) { perms = p; break; }
    }
    fclose(maps); return perms;
  }
  static uint64_t stubAddress(const std::string &symbol) {
    static const std::map<std::string, uint64_t> stubs = {{"_alpha", 0x111100001000ull}, {"_gamma", 0x111100002000ull}, {"_delta_data", 0x111100003000ull},
      {"_bravo", 0x111100004000ull}, {"_unexplained", 0x111100006000ull}, {"_beta", 0x111100005000ull}};   // _charlie has none: missing; _beta is of an export kind that is not understood (7), or kind 8 in mainKind
    auto it = stubs.find(symbol); return it == stubs.end() ? 0 : it->second;
  }
  struct Snapshot { std::vector<uint64_t> words; };
  static Snapshot snapshot(const Fixture &f) {
    Snapshot s; const uint64_t *p = (const uint64_t *)f.gotMapAddr;
    for (uint64_t i = 0; i < f.gotMapSize / 8; ++i) s.words.push_back(p[i]);
    return s;
  }
  static uint64_t word(const Snapshot &s, const Fixture &f, uint64_t slot) { return s.words[(slot - f.gotMapAddr) / 8]; }
  static uint64_t *slotPtr(uint64_t slot) { return (uint64_t *)slot; }

  struct Rejections { unsigned trials = 0, rejected = 0; void add(bool ok) { ++trials; if (!ok) ++rejected; } };

  static void poke(uint64_t address, unsigned bytes, uint64_t value) {
    const uint64_t page = (uint64_t)sysconf(_SC_PAGESIZE);
    assert(mprotect((void *)(address & ~(page - 1)), 2 * page, PROT_READ | PROT_WRITE) == 0);
    memcpy((void *)address, &value, bytes);
  }
  static int mainOverride(const std::string &dir) {
    const Fixture f = loadManifest(dir);
    const DyldSharedCache *cache = mapFixture(dir);
    CHECK(permissions(f.gotMapAddr) == "r--p");                 // the mapper left the DATA_CONST mapping read-only
    // a second DATA_CONST mapping that no slot is written into: it must never be made writable
    const uint64_t otherData = 0x180000000ull + 0x10000;
    poke(otherData + 0x280 + 40, 8, 5);                          // the .02 header: its mapping's flags AUTH_DATA | CONST_DATA
    assert(mprotect((void *)otherData, 4 * 0x4000, PROT_READ) == 0);
    CHECK(permissions(otherData) == "r--p");
    const Snapshot before = snapshot(f);

    // --- exporter 1 (libexpa): _beta has an export kind that is not understood, everything else is provided ---
    __block unsigned calls = 0; __block std::vector<std::string> seenSymbols; __block std::vector<std::string> permsAtResolve, otherAtResolve;
    auto resolver = ^bool(const char *symbol, bool, uint64_t *address) {
      ++calls; seenSymbols.push_back(symbol); permsAtResolve.push_back(permissions(f.gotMapAddr)); otherAtResolve.push_back(permissions(otherData));
      *address = stubAddress(symbol); return *address != 0;
    };
    DyldSharedCache::PatchOverrideStats stats;
    CHECK(cache->overridePatchGotSlots(1, resolver, nullptr, &stats) == nullptr);
    CHECK(stats.exports == 4 && stats.slots == 7 && stats.patched == 6 && stats.unexplained == 1 && stats.missingExports == 0 && stats.missingSlots == 0);
    CHECK(stats.patched + stats.unexplained + stats.missingSlots == stats.slots && !stats.alreadyApplied);
    CHECK(seenSymbols == (std::vector<std::string>{"_alpha", "_gamma", "_delta_data"}));     // _beta is not even looked up
    // writable only once the first write is about to happen: the first lookup still sees read-only, a later one sees writable
    CHECK(permsAtResolve[0] == "r--p" && permsAtResolve[2] == "rw-p");
    CHECK(permissions(f.gotMapAddr) == "r--p");                 // restored on return
    CHECK(otherAtResolve == (std::vector<std::string>{"r--p", "r--p", "r--p"}) && permissions(otherData) == "r--p");

    // --- exporter 2 (libexpb): _charlie is not provided, _unexplained has an encoding nobody can explain ---
    DyldSharedCache::PatchOverrideStats stats2;
    permsAtResolve.clear();
    CHECK(cache->overridePatchGotSlots(2, resolver, nullptr, &stats2) == nullptr);
    CHECK(stats2.exports == 3 && stats2.slots == 3 && stats2.patched == 1 && stats2.unexplained == 1 && stats2.missingExports == 1 && stats2.missingSlots == 1);
    CHECK(stats2.patched + stats2.unexplained + stats2.missingSlots == stats2.slots);
    CHECK(permissions(f.gotMapAddr) == "r--p");

    // --- an independent walk of the whole GOT mapping ---
    const Snapshot after = snapshot(f);
    std::map<uint64_t, const Got *> listed; for (const Got &g : f.got) listed[g.slot] = &g;
    Rejections wrongModifier;
    unsigned patchedSeen = 0, untouchedSeen = 0;
    for (uint64_t slot = f.gotMapAddr; slot < f.gotMapAddr + f.gotMapSize; slot += 8) {
      const uint64_t was = word(before, f, slot), now = word(after, f, slot);
      auto it = listed.find(slot);
      const bool shouldPatch = it != listed.end() && it->second->explained && it->second->symbol != "_beta" && it->second->symbol != "_charlie";
      if (!shouldPatch) { CHECK(now == was); ++untouchedSeen; continue; }
      const Got &g = *it->second; const uint64_t target = stubAddress(g.symbol) + g.addend; ++patchedSeen;
      if (g.auth) {
        const uint64_t modifier = g.addrDiv ? ((slot & 0x0000ffffffffffffull) | ((uint64_t)g.disc << 48)) : g.disc;
        CHECK(authenticates(g.keyData, now, modifier, target));
        wrongModifier.add(authenticates(g.keyData, now, modifier ^ 1, target));
      } else {
        CHECK(now == (target | ((uint64_t)g.high7 << 57)));
      }
    }
    CHECK(patchedSeen == 7);
    printf("rejected with a wrong modifier: %u of %u\\n", wrongModifier.rejected, wrongModifier.trials);
    CHECK(wrongModifier.trials >= 4 && wrongModifier.rejected * 2 > wrongModifier.trials);
    // the missing and the unexplained slot keep the cache's own pointer, and so do the client (plain table) slots and the control slots
    for (const Got &g : f.got) if (g.symbol == "_beta" || g.symbol == "_charlie" || !g.explained) CHECK(word(after, f, g.slot) == word(before, f, g.slot));
    for (const Plain &p : f.plain) CHECK(word(after, f, p.slot) == word(before, f, p.slot));
    for (uint64_t c : f.control) CHECK(word(after, f, c) == word(before, f, c));

    // --- idempotence: a second pass over a patched exporter does not even look the symbols up ---
    const unsigned callsBefore = calls;
    DyldSharedCache::PatchOverrideStats again;
    CHECK(cache->overridePatchGotSlots(1, resolver, nullptr, &again) == nullptr);
    CHECK(again.alreadyApplied && again.patched == 0 && again.slots == 0 && calls == callsBefore);
    const Snapshot afterAgain = snapshot(f);
    CHECK(afterAgain.words == after.words);

    // --- the exporters with nothing in the GOT table are fine and write nothing ---
    for (unsigned image : {0u, 3u}) {
      DyldSharedCache::PatchOverrideStats none;
      CHECK(cache->overridePatchGotSlots(image, resolver, nullptr, &none) == nullptr && none.exports == 0 && none.patched == 0);
    }
    CHECK(snapshot(f).words == after.words && permissions(f.gotMapAddr) == "r--p");
    CHECK_ERR(cache->overridePatchGotSlots(77, resolver, nullptr, &stats), "image index");
    printf(failures ? "RESULT failed (%d)\\n" : "RESULT ok\\n", failures);
    return failures != 0;
  }

  // Export kind 8 (objc class and similar exports) is a plain address, another nonzero kind is not understood: the fixture's _beta
  // (kind 7, authenticated data-key slot) gets the kind in the mode ("kind8", ...) written into the mapped export table before exporter 1
  // is patched. The reader tells the resolver which exports are classes; a "refuse" mode makes the resolver refuse them as dyld2 does for
  // a plain image, and the slot must then keep the cache's own pointer and count as missing.
  static unsigned gLogged; static std::string gLoggedLine;
  static void captureLog(const char *format, ...) { va_list ap; va_start(ap, format); char buf[256]; vsnprintf(buf, sizeof buf, format, ap); va_end(ap); ++gLogged; gLoggedLine = buf; }
  static int mainKind(const std::string &dir, unsigned kind, bool refuseClass) {
    const Fixture f = loadManifest(dir);
    const DyldSharedCache *cache = mapFixture(dir);
    size_t beta = 0; while (f.exports[beta].name != "_beta") ++beta;
    const uint64_t nameWord = f.arrays.at("imageExports").first + 8 * beta + 4;
    uint32_t nameKind; memcpy(&nameKind, (void *)nameWord, 4);
    CHECK((nameKind >> 28) == 7);
    poke(nameWord, 4, (nameKind & 0x0fffffffu) | ((uint64_t)kind << 28));
    const Snapshot before = snapshot(f);
    __block std::vector<std::string> seenSymbols, classSymbols;
    auto resolver = ^bool(const char *symbol, bool classExport, uint64_t *address) {
      seenSymbols.push_back(symbol); if (classExport) classSymbols.push_back(symbol);
      if (classExport && refuseClass) return false;
      *address = stubAddress(symbol); return *address != 0;
    };
    DyldSharedCache::PatchOverrideStats stats;
    CHECK(cache->overridePatchGotSlots(1, resolver, captureLog, &stats) == nullptr);
    const bool understood = kind == 0 || kind == 8;
    const bool refused = kind == 8 && refuseClass;                // looked up, refused, counted as missing, the cache's own class stays
    const bool plainAddress = understood && !refused;
    CHECK(stats.exports == 4 && stats.slots == 7 && stats.patched == (plainAddress ? 7u : 6u) && stats.unexplained == (understood ? 0u : 1u));
    CHECK(stats.missingExports == (refused ? 1u : 0u) && stats.missingSlots == (refused ? 1u : 0u));
    CHECK(gLogged == (understood ? 0u : 1u));
    if ( !understood ) CHECK(gLoggedLine.find("'_beta'") != std::string::npos && gLoggedLine.find("not understood") != std::string::npos);
    CHECK(classSymbols == (kind == 8 ? std::vector<std::string>{"_beta"} : std::vector<std::string>{}));
    CHECK(seenSymbols == (understood ? std::vector<std::string>{"_alpha", "_beta", "_gamma", "_delta_data"} : std::vector<std::string>{"_alpha", "_gamma", "_delta_data"}));
    const Snapshot after = snapshot(f);
    for (const Got &g : f.got) {
      if ( g.symbol != "_beta" ) continue;
      if ( !plainAddress ) { CHECK(word(after, f, g.slot) == word(before, f, g.slot)); continue; }
      // the slot is the stub's address signed as the slot's flags say (data key, no address diversity, discriminator 1)
      CHECK(g.auth && g.keyData && !g.addrDiv && authenticates(1, word(after, f, g.slot), g.disc, stubAddress("_beta") + g.addend));
    }
    printf(failures ? "RESULT failed (%d)\\n" : "RESULT ok\\n", failures);
    return failures != 0;
  }

  // Refusals that stop the override before it writes: each must leave the GOT mapping read-only and untouched.
  static int mainErrors(const std::string &dir) {
    const Fixture f = loadManifest(dir);
    const DyldSharedCache *cache = mapFixture(dir);
    const Snapshot before = snapshot(f);
    DyldSharedCache::PatchOverrideStats stats;
    auto good = ^bool(const char *symbol, bool, uint64_t *address) { *address = stubAddress(symbol); return *address != 0; };
    // an address that does not fit the 48-bit pointer field of an authenticated pointer, however high its first stray bit is
    for (uint64_t stray : {1ull << 48, 1ull << 50, 1ull << 55, 1ull << 60}) {
      CHECK_ERR(cache->overridePatchGotSlots(2, ^bool(const char *, bool, uint64_t *address) { *address = stray; return true; }, nullptr, &stats), "does not fit");
    }
    CHECK(snapshot(f).words == before.words && permissions(f.gotMapAddr) == "r--p");
    // a GOT slot that is misaligned (the table check accepts it: it only needs the 8 bytes inside a mapping)
    const uint64_t gotLocations = f.arrays.at("gotLocations").first, bravo = gotLocations + 16 * 7;
    uint32_t savedLo; memcpy(&savedLo, (void *)bravo, 4);
    poke(bravo, 4, savedLo + 4);
    CHECK_ERR(cache->overridePatchGotSlots(2, good, nullptr, &stats), "misaligned");
    poke(bravo, 4, savedLo);
    CHECK(snapshot(f).words == before.words && permissions(f.gotMapAddr) == "r--p");
    // a slot in a mapping that is neither DATA_CONST nor writable: refused, not a fault
    const uint64_t flagsField = f.gotMapAddr - 0x10000 + 0x280 + 56 + 40;      // the .03 sub-cache header: mapping 1's flags
    uint64_t savedFlags; memcpy(&savedFlags, (void *)flagsField, 8);
    poke(flagsField, 8, 1);
    CHECK_ERR(cache->overridePatchGotSlots(2, good, nullptr, &stats), "cannot be made writable");
    poke(flagsField, 8, savedFlags);
    CHECK(snapshot(f).words == before.words && permissions(f.gotMapAddr) == "r--p");
    // a failure to make the mapping writable is an error, before anything is written
    gFailProtect = 1;
    CHECK_ERR(cache->overridePatchGotSlots(2, good, nullptr, &stats), "could not make a DATA_CONST mapping writable");
    gFailProtect = 0;
    CHECK(snapshot(f).words == before.words && permissions(f.gotMapAddr) == "r--p");
    // a mapping that is writable already (DATA_CONST by flag, but writable by protection) must stay writable
    const uint64_t protField = flagsField + 12;                                  // initProt follows flags (8), maxProt (4)
    uint32_t savedProt; memcpy(&savedProt, (void *)protField, 4);
    poke(protField, 4, 3);
    assert(mprotect((void *)f.gotMapAddr, f.gotMapSize, PROT_READ | PROT_WRITE) == 0);
    CHECK(cache->overridePatchGotSlots(2, good, nullptr, &stats) == nullptr && stats.patched == 1);
    CHECK(permissions(f.gotMapAddr) == "rw-p");
    poke(protField, 4, savedProt);
    assert(mprotect((void *)f.gotMapAddr, f.gotMapSize, PROT_READ) == 0);
    // a failure to put the mapping back is an error too (the exporter is not marked done)
    gFailProtect = 2;
    CHECK_ERR(cache->overridePatchGotSlots(1, good, nullptr, &stats), "could not make a DATA_CONST mapping read-only again");
    gFailProtect = 0;
    // a process that keeps DATA_CONST writable (gEnableSharedCacheDataConst false) is not toggled either way
    assert(mprotect((void *)f.gotMapAddr, f.gotMapSize, PROT_READ | PROT_WRITE) == 0);
    gEnableSharedCacheDataConst = false;
    CHECK(cache->overridePatchGotSlots(1, good, nullptr, &stats) == nullptr && stats.patched == 6 && stats.unexplained == 1);
    CHECK(permissions(f.gotMapAddr) == "rw-p");
    printf(failures ? "RESULT failed (%d)\\n" : "RESULT ok\\n", failures);
    return failures != 0;
  }
  // A cache without patch info: the override is refused and not one word of any mapping changes.
  static int mainNoPatchInfo(const std::string &dir) {
    const DyldSharedCache *cache = mapFixture(dir);
    const uint64_t data = 0x180000000ull + 0x10000, size = 4 * 0x4000;
    std::vector<uint64_t> before((uint64_t *)data, (uint64_t *)(data + size));
    DyldSharedCache::PatchOverrideStats stats;
    CHECK(!cache->hasPatchInfoV4());
    CHECK_ERR(cache->overridePatchGotSlots(0, ^bool(const char *, bool, uint64_t *) { CHECK(false); return false; }, nullptr, &stats), "outside the cache mappings");
    CHECK(std::vector<uint64_t>((uint64_t *)data, (uint64_t *)(data + size)) == before && stats.patched == 0);
    printf(failures ? "RESULT failed (%d)\\n" : "RESULT ok\\n", failures);
    return failures != 0;
  }
  int main(int argc, char **argv) {
    assert(argc >= 3);
    const std::string mode = argv[2];
    if ( mode.rfind("kind", 0) == 0 ) return mainKind(argv[1], (unsigned)atoi(mode.c_str() + 4), mode.find("refuse") != std::string::npos);
    return mode == "errors" ? mainErrors(argv[1]) : mode == "nopatch" ? mainNoPatchInfo(argv[1]) : mainOverride(argv[1]);
  }
CPP

Dir.mktmpdir('patch-info-v4-override-') do |dir|
  File.write("#{dir}/test.cpp", "#{SplitCacheHarness.prefix(root)}\n#{PatchFixtureProgram::PREFIX}\n#{OVERRIDE_MAIN}")
  failed_build = SplitCacheHarness.compile(root, dir)
  abort failed_build if failed_build
  out, st = Open3.capture2e('python3', '-I', "#{root}/tests/gen-split-cache-fixture.py", "#{dir}/fx", '--variant', 'patch', '--base', base)
  abort out unless st.success?
  # patch_high puts the GOT 4 GiB above the cache base, so the high word of every GOT offset is used
  out, st = Open3.capture2e('python3', '-I', "#{root}/tests/gen-split-cache-fixture.py", "#{dir}/fxh", '--variant', 'patch_high', '--base', base)
  abort out unless st.success?
  # kind 8 is patched like kind 0 unless the resolver refuses a class export; the nonzero kinds around it (and the unused 15) are not understood
  [%w[fx override], %w[fx errors], %w[fxh override], %w[fx kind8], %w[fx kind8refuse], %w[fx kind0refuse], %w[fx kind0], %w[fx kind1], %w[fx kind7], %w[fx kind9], %w[fx kind15]].each do |fixture, mode|
    out, st = Open3.capture2e("#{dir}/test", "#{dir}/#{fixture}", mode)
    puts out
    abort "patch info v4 override test (#{fixture} #{mode}) failed" unless st.success? && out.include?('RESULT ok')
  end
  out, st = Open3.capture2e('python3', '-I', "#{root}/tests/gen-split-cache-fixture.py", "#{dir}/fx0", '--base', base)
  abort out unless st.success?
  out, st = Open3.capture2e("#{dir}/test", "#{dir}/fx0", 'nopatch')
  puts out
  abort 'patch info v4 override test (no patch info) failed' unless st.success? && out.include?('RESULT ok')
  puts 'PASS patch info v4 override: signed slots authenticate, missing and unexplained slots keep the cache pointer, idempotent, DATA_CONST writable only around the writes'
end
