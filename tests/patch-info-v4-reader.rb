# The version-4 patch info reader of DyldSharedCache (hasPatchInfoV4, checkPatchInfoV4*, forEachPatch*Location),
# run on a synthetic split cache whose fourth file (tests/gen-split-cache-fixture.py --variant patch) carries
# three more images, a coalesced GOT mapping and a patch info written independently of the C header. The
# expectations come from the generator's manifest, not from the reader. No Apple cache content is used.
# Requires Linux (MAP_FIXED, /proc/self/maps), Ruby, python3 and clang++, and the base address free.
# Usage: ruby tests/patch-info-v4-reader.rb [checkout] [base-address]
require 'tmpdir'
require 'open3'
root = File.realpath(ARGV.fetch(0, File.expand_path('..', __dir__)))
base = ARGV.fetch(1, '0x180000000')
require_relative 'split-cache-harness'
require_relative 'patch-fixture-program'

READER_MAIN = <<~CPP
  int main(int argc, char **argv) {
    assert(argc >= 2);
    const std::string dir = argv[1];
    const Fixture f = loadManifest(dir);
    const DyldSharedCache *cache = mapFixture(dir);

    // --- present, and the cheap check of the headers passes ---
    CHECK(cache->hasPatchInfoV4());
    CHECK(cache->checkPatchInfoV4Headers() == nullptr);
    CHECK(cache->header.patchInfoAddr == f.blobAddr && cache->header.patchInfoSize == f.blobSize);

    // --- the whole table, with the counts the generator wrote ---
    DyldSharedCache::PatchInfoV4Counts counts;
    CHECK(cache->checkPatchInfoV4(&counts) == nullptr);
    CHECK(counts.images == f.images.size() && counts.exports == f.exports.size() && counts.clients == 2 && counts.plainLocations == f.plain.size());
    CHECK(counts.gotExports == 7 && counts.gotLocations == f.got.size());

    // --- exporters by install name: the image index of the existing image helpers ---
    uint32_t index[4];
    for (unsigned i = 0; i < f.images.size(); ++i) {
      CHECK(cache->hasImagePath(f.images[i].second.c_str(), index[i]));
      CHECK(index[i] == i);
      uint64_t mTime, inode; CHECK((uint64_t)cache->getIndexedImageEntry(index[i], mTime, inode) == f.images[i].first);
    }
    CHECK(!cache->hasImagePath("/usr/lib/system/libnothere.dylib", index[0]));

    // --- the exporter-level check, and GOT enumeration matches the manifest slot by slot ---
    for (unsigned image = 0; image < f.images.size(); ++image) {
      CHECK(cache->checkPatchInfoV4Exporter(image) == nullptr);
      __block std::vector<DyldSharedCache::PatchLocationV4> seen;
      CHECK(cache->forEachPatchGotLocation(image, ^(const DyldSharedCache::PatchLocationV4 &l) { seen.push_back(l); }) == nullptr);
      std::vector<const Got *> want; for (const Got &g : f.got) if (g.exporter == image) want.push_back(&g);
      CHECK(seen.size() == want.size());
      for (size_t i = 0; i < seen.size() && i < want.size(); ++i) {
        const Got &g = *want[i]; const DyldSharedCache::PatchLocationV4 &l = seen[i]; const Export *e = findExport(f, image, g.symbol);
        CHECK(g.symbol == l.symbol && (uint64_t)l.slot == g.slot && l.flags == g.flags && l.explained == g.explained);
        CHECK(e && l.implOffset == e->impl && l.kind == e->kind);
        CHECK(l.encoding.authenticated == g.auth && l.encoding.bit8 == g.bit8);
        if (g.explained) {
          CHECK(l.encoding.usesAddressDiversity == g.addrDiv && l.encoding.keyIsData == g.keyData && l.encoding.discriminator == g.disc);
          CHECK(l.encoding.addend == g.addend && l.encoding.high7 == g.high7);
        }
      }
      __block std::vector<std::pair<DyldSharedCache::PatchLocationV4, unsigned>> plain;
      CHECK(cache->forEachPatchPlainLocation(image, ^(const DyldSharedCache::PatchLocationV4 &l, uint32_t client) { plain.push_back({l, client}); }) == nullptr);
      std::vector<const Plain *> wantPlain; for (const Plain &p : f.plain) if (p.exporter == image) wantPlain.push_back(&p);
      CHECK(plain.size() == wantPlain.size());
      for (size_t i = 0; i < plain.size() && i < wantPlain.size(); ++i) {
        const Plain &p = *wantPlain[i];
        CHECK(plain[i].first.symbol == p.symbol && (uint64_t)plain[i].first.slot == p.slot && plain[i].first.flags == p.flags && plain[i].second == p.client);
      }
    }
    CHECK(cache->checkPatchInfoV4Exporter(4) != nullptr && strstr(cache->checkPatchInfoV4Exporter(4), "image index"));
    CHECK(cache->forEachPatchGotLocation(99, ^(const DyldSharedCache::PatchLocationV4 &) { CHECK(false); }) != nullptr);

    // --- the enumerated slots are exactly the GOT slots the mapper rebased: nothing else is listed ---
    __block unsigned listed = 0;
    for (unsigned image = 0; image < f.images.size(); ++image) cache->forEachPatchGotLocation(image, ^(const DyldSharedCache::PatchLocationV4 &) { ++listed; });
    CHECK(listed == f.got.size() && listed == 10);
    for (uint64_t c : f.control) for (const Got &g : f.got) CHECK(g.slot != c);
    printf(failures ? "RESULT failed (%d)\\n" : "RESULT ok\\n", failures);
    return failures != 0;
  }
CPP

Dir.mktmpdir('patch-info-v4-reader-') do |dir|
  File.write("#{dir}/test.cpp", "#{SplitCacheHarness.prefix(root)}\n#{PatchFixtureProgram::PREFIX}\n#{READER_MAIN}")
  failed_build = SplitCacheHarness.compile(root, dir)
  abort failed_build if failed_build
  out, st = Open3.capture2e('python3', '-I', "#{root}/tests/gen-split-cache-fixture.py", "#{dir}/fx", '--variant', 'patch', '--base', base)
  abort out unless st.success?
  out, st = Open3.capture2e("#{dir}/test", "#{dir}/fx")
  puts out
  abort 'patch info v4 reader test failed' unless st.success? && out.include?('RESULT ok')

  # a cache without patch info: nothing is present, nothing is read
  File.write("#{dir}/test.cpp", "#{SplitCacheHarness.prefix(root)}\n#{PatchFixtureProgram::PREFIX}\n" + <<~CPP)
    int main(int argc, char **argv) {
      const DyldSharedCache *cache = mapFixture(argv[1]);
      CHECK(cache->header.patchInfoAddr == 0 && !cache->hasPatchInfoV4());
      CHECK_ERR(cache->checkPatchInfoV4Headers(), "outside the cache mappings");
      CHECK_ERR(cache->forEachPatchGotLocation(0, ^(const DyldSharedCache::PatchLocationV4 &) { CHECK(false); }), "outside the cache mappings");
      printf(failures ? "RESULT failed\\n" : "RESULT ok\\n"); return failures != 0;
    }
  CPP
  failed_build = SplitCacheHarness.compile(root, dir)
  abort failed_build if failed_build
  out, st = Open3.capture2e('python3', '-I', "#{root}/tests/gen-split-cache-fixture.py", "#{dir}/fx0", '--base', base)
  abort out unless st.success?
  out, st = Open3.capture2e("#{dir}/test", "#{dir}/fx0")
  puts out
  abort 'patch info v4 reader test without patch info failed' unless st.success? && out.include?('RESULT ok')
  puts 'PASS patch info v4 reader: presence, whole-table check, exporter lookup by install name, GOT and plain enumeration with decoded flags'
end
