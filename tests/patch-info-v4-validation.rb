# Refusals of the version-4 patch info reader: one corrupted word per check (version, array bounds and overflow,
# overlap, alignment, image count, every tiling relation, client image, export index, export name, location
# address, GOT location address, reserved word), each with its specific error string. The words are overwritten
# in the mapped synthetic cache (private pages), the whole-table check and the lazy per-exporter check must
# answer as stated, the enumeration must not call its handler, and restoring the word makes the table valid again.
# The record offsets below are written independently of dyld_cache_format.h.
# Usage: ruby tests/patch-info-v4-validation.rb [checkout] [base-address]
require 'tmpdir'
require 'open3'
root = File.realpath(ARGV.fetch(0, File.expand_path('..', __dir__)))
base = ARGV.fetch(1, '0x180000000')
require_relative 'split-cache-harness'
require_relative 'patch-fixture-program'

VALIDATION_MAIN = <<~CPP
  static void writable(uint64_t address, size_t size) {
    const uint64_t page = (uint64_t)sysconf(_SC_PAGESIZE);
    assert(mprotect((void *)(address & ~(page - 1)), ((address + size + page - 1) & ~(page - 1)) - (address & ~(page - 1)), PROT_READ | PROT_WRITE) == 0);
  }
  static uint64_t peek(uint64_t address, unsigned bytes) { uint64_t v = 0; memcpy(&v, (void *)address, bytes); return v; }
  static void poke(uint64_t address, unsigned bytes, uint64_t value) { writable(address, bytes); memcpy((void *)address, &value, bytes); }

  static const DyldSharedCache *gCache;
  static Fixture gFixture;
  static const char *const SAME = "same";    // the lazy check must give the whole-table answer
  static const char *const CLEAN = nullptr;  // the lazy check does not look at that relation

  // Overwrites `bytes` at address with value; the whole-table check must say `text`; the check of exporter
  // `lazyImage` must say `lazy` (SAME: the same text) or nothing (CLEAN); then the word is restored.
  static void refuse(const char *label, uint64_t address, unsigned bytes, uint64_t value, const char *text, unsigned lazyImage, const char *lazy) {
    const uint64_t saved = peek(address, bytes);
    poke(address, bytes, value);
    DyldSharedCache::PatchInfoV4Counts counts;
    const char *whole = gCache->checkPatchInfoV4(&counts);
    if (!whole || !strstr(whole, text)) { printf("FAIL %s: whole-table check gave '%s', wanted '%s'\\n", label, whole ? whole : "(null)", text); ++failures; }
    const char *lazyWant = lazy == SAME ? text : lazy;
    const char *got = gCache->checkPatchInfoV4Exporter(lazyImage);
    if (lazyWant ? (!got || !strstr(got, lazyWant)) : (got != nullptr)) { printf("FAIL %s: exporter check gave '%s', wanted '%s'\\n", label, got ? got : "(null)", lazyWant ? lazyWant : "(null)"); ++failures; }
    __block unsigned calls = 0;
    const char *enumerated = gCache->forEachPatchGotLocation(lazyImage, ^(const DyldSharedCache::PatchLocationV4 &) { ++calls; });
    if (got) { CHECK(enumerated != nullptr && !strcmp(enumerated, got) && calls == 0); }
    poke(address, bytes, saved);
    CHECK(gCache->checkPatchInfoV4(&counts) == nullptr && gCache->checkPatchInfoV4Exporter(lazyImage) == nullptr);
    printf("refused %s\\n", label);
  }

  int main(int argc, char **argv) {
    assert(argc >= 2);
    gFixture = loadManifest(argv[1]); gCache = mapFixture(argv[1]);
    const Fixture &f = gFixture;
    DyldSharedCache::PatchInfoV4Counts counts;
    CHECK(gCache->checkPatchInfoV4(&counts) == nullptr);
    const uint64_t H = f.blobAddr;
    auto A = [&](const char *name) { return f.arrays.at(name).first; };
    static const char *const names[9] = {"patchTable", "imageExports", "clients", "clientExports", "locations", "exportNames", "gotClients", "gotClientExports", "gotLocations"};

    // header words: version, location version, then (address, count) of the nine arrays at 8 + 16 * n
    refuse("version 5", H, 4, 5, "not version 4", 1, SAME);
    refuse("location version 1", H + 4, 4, 1, "not version 4", 1, SAME);
    for (unsigned n = 0; n < 9; ++n) {
      char label[64], text[64]; snprintf(label, sizeof label, "%s array past the patch info", names[n]); snprintf(text, sizeof text, "%s ", names[n]);
      refuse(label, H + 8 + 16 * n + 8, 8, 0x100000, text, 1, SAME);
      snprintf(label, sizeof label, "%s array before the arrays area", names[n]);
      refuse(label, H + 8 + 16 * n, 8, H, text, 1, SAME);
    }
    refuse("patchTable count overflows its size", H + 16, 8, 0x4000000000000000ull, "patchTable array lies outside", 1, SAME);
    refuse("patchTable address wraps", H + 8, 8, UINT64_MAX - 3, "patchTable array lies outside", 1, SAME);
    refuse("arrays overlap", H + 8 + 16, 8, A("patchTable"), "arrays overlap", 1, SAME);
    refuse("array not 4-byte aligned", H + 8 + 16 * 4, 8, A("locations") + 2, "not 4-byte aligned", 1, SAME);
    refuse("patchTable count differs from the images", H + 16, 8, 3, "image count", 1, SAME);
    refuse("gotClients count differs from the images", H + 8 + 16 * 6 + 8, 8, 3, "image count", 1, SAME);

    // the per-image slices: patchTable (16 B: clients start/count, exports start/count), clients (12 B), clientExports (12 B)
    const uint64_t PT = A("patchTable"), EX = A("imageExports"), CL = A("clients"), CE = A("clientExports"), LO = A("locations"),
                   GC = A("gotClients"), GE = A("gotClientExports"), GL = A("gotLocations"), NM = A("exportNames");
    // a count one too high leaves the last slice short of the end of its array (the arrays have slack after them)
    refuse("exports array one record too long", H + 8 + 16 * 1 + 8, 8, f.arrays.at("imageExports").second + 1, "export slices", 1, CLEAN);
    refuse("clients array one record too long", H + 8 + 16 * 2 + 8, 8, f.arrays.at("clients").second + 1, "client slices", 1, CLEAN);
    refuse("clientExports array one record too long", H + 8 + 16 * 3 + 8, 8, f.arrays.at("clientExports").second + 1, "client export slices", 1, CLEAN);
    refuse("locations array one record too long", H + 8 + 16 * 4 + 8, 8, f.arrays.at("locations").second + 1, "location slices", 1, CLEAN);
    refuse("gotClientExports array one record too long", H + 8 + 16 * 7 + 8, 8, f.arrays.at("gotClientExports").second + 1, "GOT client slices", 1, CLEAN);
    refuse("gotLocations array one record too long", H + 8 + 16 * 8 + 8, 8, f.arrays.at("gotLocations").second + 1, "GOT location slices", 1, CLEAN);
    refuse("client slices do not tile", PT + 16, 4, 1, "client slices", 1, CLEAN);
    refuse("client slice outside the clients array", PT + 16 + 4, 4, 50, "client slices", 1, SAME);
    refuse("export slices do not tile", PT + 32 + 8, 4, 4, "export slices", 2, "GOT export lies outside");
    refuse("export slice outside the exports array", PT + 32 + 12, 4, 50, "export slices", 2, SAME);
    refuse("client names an image outside the cache", CL, 4, 99, "image outside the cache", 1, CLEAN);
    refuse("client export slices do not tile", CL + 12 + 4, 4, 5, "client export slices", 1, CLEAN);
    refuse("client export outside its exporter", CE, 4, 7, "client export lies outside its exporter", 1, CLEAN);
    refuse("location slices do not tile", CE + 12 + 4, 4, 2, "location slices", 1, CLEAN);
    refuse("location outside the slide-info mappings", LO, 4, 0, "location lies outside the mappings that carry slide info", 1, CLEAN);
    refuse("location offset wraps", LO, 4, 0xffffffffu, "location lies outside the mappings that carry slide info", 1, CLEAN);
    // the export names: nameKind (8-byte export record, name word at +4), and the terminator of the last name
    refuse("export name offset outside the names", EX + 4, 4, 0x0fffffff, "export name", 1, SAME);
    refuse("last export name not terminated", NM + f.arrays.at("exportNames").second - 1, 1, 'x', "export name", 2, SAME);
    // the GOT tables: gotClients (8 B), gotClientExports (12 B), gotLocations (16 B)
    refuse("GOT client slices do not tile", GC + 16, 4, 3, "GOT client slices", 2, "GOT export lies outside");
    refuse("GOT client slice outside its array", GC + 16 + 4, 4, 50, "GOT client slices", 2, SAME);
    refuse("GOT export outside its exporter", GE, 4, 7, "GOT export lies outside its exporter", 1, SAME);
    refuse("GOT location slices do not tile", GE + 12 + 4, 4, 0, "GOT location slices", 1, SAME);
    refuse("GOT location in a mapping without slide info", GL, 4, 0x1000, "GOT location lies outside the mappings", 1, SAME);
    refuse("GOT location offset high word", GL + 4, 4, 7, "GOT location lies outside the mappings", 1, SAME);
    refuse("GOT location reserved word", GL + 12, 4, 1, "reserved word", 1, SAME);

    // the main header: patch info that is absent, too small or outside every mapping is simply not there
    const uint64_t hdr = (uint64_t)gCache;
    const uint64_t ADDR = hdr + 0x98, SIZE = hdr + 0xa0;
    const uint64_t savedAddr = peek(ADDR, 8), savedSize = peek(SIZE, 8);
    struct Case { const char *label; uint64_t addr, size; } cases[] = {
      {"patch info in an unmapped gap", f.gotMapAddr + 0x20000, f.blobSize}, {"patch info too small for its header", savedAddr, 100},
      {"patch info past its mapping", savedAddr, 0x100000}, {"patch info size wraps", savedAddr, UINT64_MAX - 8}, {"no patch info", 0, 0},
    };
    for (const Case &c : cases) {
      poke(ADDR, 8, c.addr); poke(SIZE, 8, c.size);
      CHECK(!gCache->hasPatchInfoV4());
      CHECK_ERR(gCache->checkPatchInfoV4Headers(), "outside the cache mappings");
      printf("absent: %s\\n", c.label);
    }
    poke(ADDR, 8, savedAddr); poke(SIZE, 8, savedSize);
    CHECK(gCache->hasPatchInfoV4() && gCache->checkPatchInfoV4(&counts) == nullptr);
    printf(failures ? "RESULT failed (%d)\\n" : "RESULT ok\\n", failures);
    return failures != 0;
  }
CPP

Dir.mktmpdir('patch-info-v4-validation-') do |dir|
  File.write("#{dir}/test.cpp", "#{SplitCacheHarness.prefix(root)}\n#{PatchFixtureProgram::PREFIX}\n#{VALIDATION_MAIN}")
  failed_build = SplitCacheHarness.compile(root, dir)
  abort failed_build if failed_build
  out, st = Open3.capture2e('python3', '-I', "#{root}/tests/gen-split-cache-fixture.py", "#{dir}/fx", '--variant', 'patch', '--base', base)
  abort out unless st.success?
  out, st = Open3.capture2e("#{dir}/test", "#{dir}/fx")
  puts out
  abort 'patch info v4 validation test failed' unless st.success? && out.include?('RESULT ok')
  puts 'PASS patch info v4 validation: every check refuses its corrupted word with its own message'
end
