# Maps a real split dyld shared cache with the actual mapSplitCachePrivate and checks the result against an
# independent walk of the slide info (pread of the files, no mapping code shared with the mapper), then
# exercises the DyldSharedCache image helpers on the mapped cache. Authenticated slots are checked with the
# PAC instructions (autia/autda with the process's own keys, so this needs a PAC-capable arm64 Linux host)
# against the independently decoded key, modifier and target. Opt-in: it reads the cache you point it at
# and the process peaks at several GB of memory, so it is skipped unless DYLD_REAL_CACHE_DIR is set.
#
#   DYLD_REAL_CACHE_DIR   directory holding dyld_shared_cache_arm64e and its sub-cache files
#   DYLD_REAL_CACHE_IMAGE install name to look up (optional; without it only the image count is checked)
#   DYLD_REAL_CACHE_OVERRIDE_IMAGES comma-separated install names of the exporters whose coalesced GOT slots the version 4
#                         patch info override is applied to, with a stub resolver that gives every symbol a fake address
#                         (optional; default: the five libSystem exporters under /usr/lib/system/)
#
# The patch info part prints counts only, never cache values: the whole-table check (every tiling relation, name and
# location), then per exporter the GOT symbols and slots, how many the override patched, left unexplained or missed,
# and an independent walk of the raw tables that checks every patched slot with autia/autda and every other slot of the
# whole GOT for being byte-identical to before.
#
# Usage: DYLD_REAL_CACHE_DIR=... [DYLD_REAL_CACHE_IMAGE=...] ruby tests/real-cache-check.rb [checkout]
# The cache is mapped at its own preferred address (0x180000000 for an arm64e macOS cache), which must be free.
require 'tmpdir'
require 'open3'
root = File.realpath(ARGV.fetch(0, File.expand_path('..', __dir__)))
dir_env = ENV['DYLD_REAL_CACHE_DIR']
main_file = dir_env && File.join(dir_env, 'dyld_shared_cache_arm64e')
unless main_file && File.file?(main_file)
  puts 'SKIP real-cache-check: set DYLD_REAL_CACHE_DIR to a directory containing dyld_shared_cache_arm64e'
  exit 0
end
require_relative 'split-cache-harness'

# The patch info part of the check, a block of main(): see the header comment. The raw walker below reads the mapped
# tables through its own offsets and decoder, sharing nothing with DyldSharedCache::forEachPatchGotLocation.
PATCH_CHECK = <<~'CPP'
  if (!cache->hasPatchInfoV4()) {
    printf("patch info v4: absent in this cache, nothing to check\n");
  } else {
    DyldSharedCache::PatchInfoV4Counts counts;
    const char *tableError = cache->checkPatchInfoV4(&counts);
    printf("patch info v4 whole-table check: %s images=%llu exports=%llu clients=%llu plain-locations=%llu got-exports=%llu got-locations=%llu\n",
           tableError ? tableError : "ok", (unsigned long long)counts.images, (unsigned long long)counts.exports, (unsigned long long)counts.clients,
           (unsigned long long)counts.plainLocations, (unsigned long long)counts.gotExports, (unsigned long long)counts.gotLocations);
    assert(tableError == nullptr);

    // --- raw walker: header words at 8 + 16 * n (address, count); strides 16, 8, 12, 12, 8, 1, 8, 12, 16 ---
    const uint64_t slide = (uint64_t)cache - regionStart, info = cache->header.patchInfoAddr + slide;
    auto arrayAt = [&](unsigned n) { return le64((const uint8_t *)(info + 8 + 16 * n)) + slide; };
    auto arrayCount = [&](unsigned n) { return le64((const uint8_t *)(info + 8 + 16 * n + 8)); };
    const uint64_t exportsArray = arrayAt(1), namesArray = arrayAt(5), gotClientsArray = arrayAt(6), gotExportsArray = arrayAt(7), gotLocsArray = arrayAt(8);
    struct RawSlot { uint64_t address, was; uint32_t flags, exporter, exportIndex; };
    std::vector<RawSlot> allSlots; allSlots.reserve(arrayCount(8));
    std::map<uint32_t, std::vector<size_t>> slotsOf;
    uint64_t rawUnexplained = 0, rawBit8 = 0, rawKinds = 0;
    for (uint32_t image = 0; image < arrayCount(6); ++image) {
      const uint8_t *g = (const uint8_t *)(gotClientsArray + 8ull * image);
      for (uint64_t k = le32(g); k < (uint64_t)le32(g) + le32(g + 4); ++k) {
        const uint8_t *e = (const uint8_t *)(gotExportsArray + 12 * k);
        for (uint64_t l = le32(e + 4); l < (uint64_t)le32(e + 4) + le32(e + 8); ++l) {
          const uint8_t *loc = (const uint8_t *)(gotLocsArray + 16 * l);
          const uint64_t address = regionStart + slide + ((uint64_t)le32(loc + 4) << 32 | le32(loc)); const uint32_t flags = le32(loc + 8);
          const bool authentic = flags & 1;
          rawUnexplained += authentic ? (((flags >> 1) & 0x7f) != 0) : ((flags >> 16) != 0);
          rawBit8 += (flags >> 8) & 1;
          rawKinds += (le32((const uint8_t *)(exportsArray + 8ull * le32(e)) + 4) >> 28) != 0;   // refused as well: the kind is not understood
          slotsOf[image].push_back(allSlots.size());
          allSlots.push_back({address, *(const uint64_t *)address, flags, image, le32(e)});
        }
      }
    }
    printf("patch info v4 raw walk of the whole GOT: slots=%zu exporters-with-slots=%zu unexplained-encodings=%llu bit8-set=%llu slots-of-nonzero-kind=%llu\n",
           allSlots.size(), slotsOf.size(), (unsigned long long)rawUnexplained, (unsigned long long)rawBit8, (unsigned long long)rawKinds);
    assert(allSlots.size() == counts.gotLocations);

    // --- the override, with a stub resolver: a fake, deterministic address for every symbol ---
    auto stub = [](const char *symbol) { uint64_t h = 1469598103934665603ull; for (const char *c = symbol; *c; ++c) h = (h ^ (uint8_t)*c) * 1099511628211ull; return 0x0000600000000000ull | (h & 0x00000000fffffff0ull); };
    std::vector<std::string> exporterNames;
    const char *listEnv = getenv("DYLD_REAL_CACHE_OVERRIDE_IMAGES");
    std::string list = (listEnv && *listEnv) ? listEnv : "/usr/lib/system/libsystem_c.dylib,/usr/lib/system/libsystem_kernel.dylib,/usr/lib/system/libsystem_malloc.dylib,/usr/lib/system/libsystem_platform.dylib,/usr/lib/system/libsystem_pthread.dylib";
    for (size_t at = 0; at <= list.size();) { size_t comma = list.find(',', at); if (comma == std::string::npos) comma = list.size(); if (comma > at) exporterNames.push_back(list.substr(at, comma - at)); at = comma + 1; }
    // --- raw walker of the plain table, before the override: header words 0 (patchTable: clients and exports slices per exporter), 2 (clients),
    // 3 (clientExports), 4 (locations: client-relative offset, flags). The images' addresses come from the image table of the header. The slots of
    // the exporters that are about to be overridden are recorded with their value; every other plain slot is only hashed, to prove it is not touched.
    struct RawPlain { uint64_t address, was; uint32_t flags, exporter, exportIndex, client; };
    std::set<uint32_t> overridden;
    for (const std::string &name : exporterNames) { uint32_t index; if (cache->hasImagePath(name.c_str(), index)) overridden.insert(index); }
    const uint64_t patchTableArray = arrayAt(0), clientsArray = arrayAt(2), clientExportsArray = arrayAt(3), locationsArray = arrayAt(4);
    const uint8_t *imageInfos = (const uint8_t *)cache + le32(hdr + 0x1c0);
    auto imageAddress = [&](uint32_t i) { return le64(imageInfos + 32ull * i) + slide; };
    auto walkPlain = [&](void (^visit)(uint64_t address, uint32_t flags, uint32_t exporter, uint32_t exportIndex, uint32_t client)) {
      for (uint32_t image = 0; image < arrayCount(0); ++image) {
        const uint8_t *pt = (const uint8_t *)(patchTableArray + 16ull * image);
        for (uint64_t c = le32(pt); c < (uint64_t)le32(pt) + le32(pt + 4); ++c) {
          const uint8_t *client = (const uint8_t *)(clientsArray + 12 * c);
          const uint64_t clientBase = imageAddress(le32(client));
          for (uint64_t x = le32(client + 4); x < (uint64_t)le32(client + 4) + le32(client + 8); ++x) {
            const uint8_t *ce = (const uint8_t *)(clientExportsArray + 12 * x);
            for (uint64_t l = le32(ce + 4); l < (uint64_t)le32(ce + 4) + le32(ce + 8); ++l) {
              const uint8_t *loc = (const uint8_t *)(locationsArray + 8 * l);
              visit(clientBase + le32(loc), le32(loc + 4), image, le32(ce), le32(client));
            }
          }
        }
      }
    };
    __block std::vector<RawPlain> overriddenPlain; __block uint64_t plainTotal = 0, othersBefore = 14695981039346656037ull;
    walkPlain(^(uint64_t address, uint32_t flags, uint32_t exporter, uint32_t exportIndex, uint32_t client) {
      ++plainTotal;
      const uint64_t value = *(const uint64_t *)address;
      if (overridden.count(exporter)) overriddenPlain.push_back({address, value, flags, exporter, exportIndex, client});
      else othersBefore = (othersBefore ^ (address * 0x9E3779B97F4A7C15ull) ^ value) * 1099511628211ull;
    });
    printf("patch info v4 raw walk of the whole plain table: locations=%llu of the overridden exporters=%zu\n", (unsigned long long)plainTotal, overriddenPlain.size());
    assert(plainTotal == counts.plainLocations);
    // What the cache holds before the override must decode as the table says: exporter header + implementation offset + the location's own
    // addend, signed with the location's own key, discriminator and address diversity (an unauthenticated one carries its high7). This is
    // the proof that the encoding of a plain location is the one of a GOT slot and that the override may reuse it.
    uint64_t preChecked = 0, preWrong = 0, preShown = 0; std::map<std::string, uint64_t> mismatchSymbols; uint64_t preTlvDelta = 0;
    for (const RawPlain &r : overriddenPlain) {
      const uint32_t kind = le32((const uint8_t *)(exportsArray + 8ull * r.exportIndex) + 4) >> 28, f = r.flags; const bool authentic = f & 1;
      if ((kind != 0 && kind != 8) || (authentic ? (((f >> 1) & 0x7f) != 0) : ((f >> 16) != 0))) continue;
      const uint64_t addend = authentic ? (f >> 9) & 0x1f : (f >> 9) & 0x7f;
      const uint64_t want = imageAddress(r.exporter) + le32((const uint8_t *)(exportsArray + 8ull * r.exportIndex)) + addend;
      bool ok;
      if (authentic) { const uint64_t disc = f >> 16, modifier = ((f >> 14) & 1) ? ((r.address & 0x0000ffffffffffffull) | (disc << 48)) : disc; ok = authenticate((f >> 15) & 1, r.was, modifier) == want; }
      else ok = r.was == (want | ((uint64_t)((f >> 1) & 0x7f) << 57));
      ++preChecked;
      // Known exception: the TLV descriptors' thunk slots point 8 bytes past the table's `__tlv_bootstrap` (flags say addend 0). libdyld
      // replaces that thunk when it initializes the descriptors, so the override writes what the table says like everywhere else.
      if (!ok && !strcmp((const char *)(namesArray + (le32((const uint8_t *)(exportsArray + 8ull * r.exportIndex) + 4) & 0x0fffffffu)), "__tlv_bootstrap") && (r.was & 0x0000ffffffffffffull) == want + 8) { ++preTlvDelta; continue; }
      if (!ok) { ++preWrong; ++mismatchSymbols[std::string((const char *)(namesArray + (le32((const uint8_t *)(exportsArray + 8ull * r.exportIndex) + 4) & 0x0fffffffu))) + " delta " + std::to_string((long long)((r.was & 0x0000ffffffffffffull) - want))]; if (preShown++ < 5) printf("PLAIN PRE-STATE MISMATCH at region offset %#llx flags %#x exporter %u kind %u symbol %s value %#llx want %#llx\n", (unsigned long long)(r.address - regionStart - slide), f, r.exporter, kind, (const char *)(namesArray + (le32((const uint8_t *)(exportsArray + 8ull * r.exportIndex) + 4) & 0x0fffffffu)), (unsigned long long)r.was, (unsigned long long)want); }
    }
    printf("plain locations of the overridden exporters, before the override: checked=%llu decode-mismatches=%llu (plus %llu __tlv_bootstrap thunk slots that are 8 past the table's address)\n", (unsigned long long)preChecked, (unsigned long long)preWrong, (unsigned long long)preTlvDelta);
    for (const auto &m : mismatchSymbols) printf("  pre-state mismatch %s: %llu\n", m.first.c_str(), (unsigned long long)m.second);
    assert(preChecked > 0 && preWrong == 0);
    // Which clients are "in the process": two thirds of the cache's images, by index. The override must patch the plain locations of those and leave every
    // other client's pages alone, which the verification below checks against the raw walk.
    auto loadedClient = [](uint32_t client) { return client % 3 != 0; };
    int (^clientAction)(uint32_t) = ^int(uint32_t client) { return loadedClient(client) ? DyldSharedCache::kPlainClientPatch : DyldSharedCache::kPlainClientIgnore; };
    std::set<uint32_t> patched; uint64_t totalSlots = 0, totalPatched = 0, totalUnexplained = 0, totalMissing = 0;
    std::map<uint32_t, uint64_t> plainOfExporter, plainUnexplainedOfExporter; uint64_t totalPlainPatched = 0, totalPlainUnexplained = 0, totalPlainMissing = 0;
    for (const RawPlain &r : overriddenPlain) {
      if (!loadedClient(r.client)) continue;
      const uint32_t kind = le32((const uint8_t *)(exportsArray + 8ull * r.exportIndex) + 4) >> 28, f = r.flags; const bool authentic = f & 1;
      ++plainOfExporter[r.exporter];
      plainUnexplainedOfExporter[r.exporter] += (kind != 0 && kind != 8) || (authentic ? (((f >> 1) & 0x7f) != 0) : ((f >> 16) != 0));
    }
    for (const std::string &name : exporterNames) {
      uint32_t index;
      if (!cache->hasImagePath(name.c_str(), index)) { printf("override %s: not in the cache\n", name.c_str()); assert(false); }
      DyldSharedCache::PatchOverrideStats stats;
      const char *error = cache->overridePatchGotSlots(index, ^bool(const char *symbol, bool, uint64_t *address) { *address = stub(symbol); return true; }, clientAction, nullptr, &stats);
      if (error) { printf("override %s: error: %s\n", name.c_str(), error); assert(false); }
      std::set<uint32_t> symbols; for (size_t i : slotsOf[index]) symbols.insert(allSlots[i].exportIndex);
      __block uint64_t plainLocations = 0;
      assert(cache->forEachPatchPlainLocation(index, ^(const DyldSharedCache::PatchLocationV4 &, uint32_t client) { plainLocations += loadedClient(client); }) == nullptr);
      // the kind bits of the export name word are not interpreted: show how the GOT slots spread over them
      __block std::map<uint32_t, uint64_t> kinds;
      assert(cache->forEachPatchGotLocation(index, ^(const DyldSharedCache::PatchLocationV4 &l) { ++kinds[l.kind]; }) == nullptr);
      std::string kindText; for (const auto &k : kinds) kindText += " kind" + std::to_string(k.first) + "=" + std::to_string(k.second);
      printf("override %s: image=%u got-exports=%zu export-entries=%llu got-slots=%llu patched=%llu unexplained=%llu missing-symbols=%llu missing-slots=%llu (plain-table locations of the loaded clients: %llu, patched=%llu unexplained=%llu missing=%llu; got slots by kind:%s)\n",
             name.c_str(), index, symbols.size(), (unsigned long long)stats.exports, (unsigned long long)stats.slots, (unsigned long long)stats.patched, (unsigned long long)stats.unexplained,
             (unsigned long long)stats.missingExports, (unsigned long long)stats.missingSlots, (unsigned long long)plainLocations,
             (unsigned long long)stats.plainPatched, (unsigned long long)stats.plainUnexplained, (unsigned long long)stats.plainMissing, kindText.c_str());
      assert(stats.exports >= symbols.size() && stats.slots == slotsOf[index].size() && stats.missingExports == 0 && stats.missingSlots == 0);
      assert(stats.patched + stats.unexplained == stats.slots);
      // the plain locations are applied too: every one is accounted for, and the raw walk agrees on how many the override must refuse
      assert(stats.plainSlots == plainLocations && stats.plainSlots == plainOfExporter[index] && stats.plainMissing == 0);
      assert(stats.plainPatched + stats.plainUnexplained == stats.plainSlots && stats.plainUnexplained == plainUnexplainedOfExporter[index]);
      totalPlainPatched += stats.plainPatched; totalPlainUnexplained += stats.plainUnexplained; totalPlainMissing += stats.plainMissing;
      DyldSharedCache::PatchOverrideStats again;
      assert(cache->overridePatchGotSlots(index, ^bool(const char *, bool, uint64_t *) { assert(false); return false; }, nullptr, nullptr, &again) == nullptr && again.alreadyApplied);
      patched.insert(index); totalSlots += stats.slots; totalPatched += stats.patched; totalUnexplained += stats.unexplained; totalMissing += stats.missingSlots;
    }

    // --- independent verification of the whole GOT: patched slots authenticate to their stub, every other slot is unchanged ---
    uint64_t authOk = 0, plainOk = 0, unchanged = 0, wrong = 0, shown = 0;
    for (const RawSlot &s : allSlots) {
      const uint64_t now = *(const uint64_t *)s.address; const uint32_t f = s.flags; const bool authentic = f & 1;
      const uint32_t slotKind = le32((const uint8_t *)(exportsArray + 8ull * s.exportIndex) + 4) >> 28;
      const bool kindZero = slotKind == 0 || slotKind == 8;     // kind 8 (classes) is patched like kind 0 unless the resolver refuses it, and this one never does
      const bool explained = kindZero && (authentic ? (((f >> 1) & 0x7f) == 0) : ((f >> 16) == 0));
      bool ok;
      if (!patched.count(s.exporter) || !explained) { ok = (now == s.was); unchanged += ok; }
      else {
        const char *symbol = (const char *)(namesArray + (le32((const uint8_t *)(exportsArray + 8ull * s.exportIndex) + 4) & 0x0fffffffu));
        const uint64_t addend = authentic ? (f >> 9) & 0x1f : (f >> 9) & 0x7f, target = stub(symbol) + addend;
        if (authentic) {
          const uint64_t disc = f >> 16, modifier = ((f >> 14) & 1) ? ((s.address & 0x0000ffffffffffffull) | (disc << 48)) : disc;
          ok = authenticate((f >> 15) & 1, now, modifier) == target; authOk += ok;
        } else { ok = now == (target | ((uint64_t)((f >> 1) & 0x7f) << 57)); plainOk += ok; }
      }
      if (!ok) { ++wrong; if (shown++ < 5) printf("PATCH MISMATCH at region offset %#llx flags %#x\n", (unsigned long long)(s.address - regionStart - slide), f); }
    }
    printf("patch override verified: slots=%llu patched=%llu unexplained=%llu missing=%llu | independent: authenticate-ok=%llu plain-ok=%llu unchanged=%llu wrong=%llu\n",
           (unsigned long long)totalSlots, (unsigned long long)totalPatched, (unsigned long long)totalUnexplained, (unsigned long long)totalMissing,
           (unsigned long long)authOk, (unsigned long long)plainOk, (unsigned long long)unchanged, (unsigned long long)wrong);
    assert(wrong == 0 && authOk + plainOk == totalPatched && authOk + plainOk + unchanged == allSlots.size());

    // --- independent verification of every plain location of the overridden exporters: it authenticates to the stub's address plus ITS OWN addend
    // with ITS OWN key, discriminator and address diversity (the pre-state decode above proved those are the cache's own parameters); a refused one is
    // unchanged; every plain slot of every other exporter is byte-identical to before ---
    uint64_t plainAuthOk = 0, plainRawOk = 0, plainRefusedKept = 0, plainNotLoadedKept = 0, plainWrong = 0, plainShown = 0;
    std::map<uint32_t, uint64_t> plainVerifiedOf;
    for (const RawPlain &r : overriddenPlain) {
      const uint64_t now = *(const uint64_t *)r.address; const uint32_t f = r.flags; const bool authentic = f & 1;
      const uint32_t kind = le32((const uint8_t *)(exportsArray + 8ull * r.exportIndex) + 4) >> 28;
      const bool explained = (kind == 0 || kind == 8) && (authentic ? (((f >> 1) & 0x7f) == 0) : ((f >> 16) == 0));
      bool ok;
      if (!loadedClient(r.client)) { ok = now == r.was; plainNotLoadedKept += ok; }
      else if (!explained) { ok = now == r.was; plainRefusedKept += ok; }
      else {
        const char *symbol = (const char *)(namesArray + (le32((const uint8_t *)(exportsArray + 8ull * r.exportIndex) + 4) & 0x0fffffffu));
        const uint64_t addend = authentic ? (f >> 9) & 0x1f : (f >> 9) & 0x7f, target = stub(symbol) + addend;
        if (authentic) {
          const uint64_t disc = f >> 16, modifier = ((f >> 14) & 1) ? ((r.address & 0x0000ffffffffffffull) | (disc << 48)) : disc;
          ok = authenticate((f >> 15) & 1, now, modifier) == target; plainAuthOk += ok;
        } else { ok = now == (target | ((uint64_t)((f >> 1) & 0x7f) << 57)); plainRawOk += ok; }
        plainVerifiedOf[r.exporter] += ok;
      }
      if (!ok) { ++plainWrong; if (plainShown++ < 5) printf("PLAIN PATCH MISMATCH at region offset %#llx flags %#x\n", (unsigned long long)(r.address - regionStart - slide), f); }
    }
    __block uint64_t othersAfter = 14695981039346656037ull;
    walkPlain(^(uint64_t address, uint32_t, uint32_t exporter, uint32_t, uint32_t) {
      if (!overridden.count(exporter)) othersAfter = (othersAfter ^ (address * 0x9E3779B97F4A7C15ull) ^ *(const uint64_t *)address) * 1099511628211ull;
    });
    for (const std::string &name : exporterNames) {
      uint32_t index; assert(cache->hasImagePath(name.c_str(), index));
      printf("plain locations of %s: %llu, authenticate or compare ok after the override: %llu\n", name.c_str(), (unsigned long long)plainOfExporter[index], (unsigned long long)plainVerifiedOf[index]);
      // libsystem_malloc is the exporter whose plain pointers (CoreFoundation's static allocator) crash the guest when left on the cache's copy
      if (name.find("libsystem_malloc") != std::string::npos) assert(plainOfExporter[index] > 0 && plainVerifiedOf[index] == plainOfExporter[index] - plainUnexplainedOfExporter[index]);
    }
    printf("plain override verified: locations=%zu patched=%llu unexplained=%llu missing=%llu | independent: authenticate-ok=%llu plain-ok=%llu refused-kept=%llu not-loaded-clients-kept=%llu wrong=%llu | other exporters' plain slots unchanged=%s\n",
           overriddenPlain.size(), (unsigned long long)totalPlainPatched, (unsigned long long)totalPlainUnexplained, (unsigned long long)totalPlainMissing,
           (unsigned long long)plainAuthOk, (unsigned long long)plainRawOk, (unsigned long long)plainRefusedKept, (unsigned long long)plainNotLoadedKept, (unsigned long long)plainWrong, othersAfter == othersBefore ? "yes" : "NO");
    assert(plainWrong == 0 && plainAuthOk + plainRawOk == totalPlainPatched && plainAuthOk + plainRawOk + plainRefusedKept + plainNotLoadedKept == overriddenPlain.size() && othersAfter == othersBefore);
  }
CPP

Dir.mktmpdir('real-cache-check-') do |dir|
  File.write("#{dir}/test.cpp", <<~CPP)
    #{SplitCacheHarness.prefix(root, real_trie: true)}
    #include <unordered_map>
    #include <map>

    // Standard export-trie walk (the tests stub the dyld one): the terminal info of symbol, or null.
    const uint8_t *dyld3::MachOLoaded::trieWalk(Diagnostics&, const uint8_t *start, const uint8_t *end, const char *symbol) {
      Diagnostics d; const uint8_t *p = start; const char *s = symbol;
      while (p < end) {
        const uint8_t *q = p; uint64_t termSize = dyld3::MachOFile::read_uleb128(d, q, end);
        if (*s == 0) return termSize ? q : nullptr;
        const uint8_t *c = q + termSize; if (c >= end) return nullptr;
        unsigned count = *c++; const uint8_t *next = nullptr;
        for (unsigned i = 0; i < count && c < end; ++i) {
          const char *t = s; const char *l = (const char *)c;
          while (*l && *t == *l) { ++l; ++t; }
          const uint8_t *e = c; while (*e) ++e; ++e;
          uint64_t off = dyld3::MachOFile::read_uleb128(d, e, end);
          if (*l == 0) { next = start + off; s = t; break; }
          c = e;
        }
        if (!next) return nullptr;
        p = next;
      }
      return nullptr;
    }

    // Independent of the mapper: authenticate a signed slot, 0 = IA key, 1 = DA key; returns the stripped pointer or garbage.
    // On hardware with FPAC a failed authentication faults here and kills the process before the counts below are
    // printed, which is still a loud failure of the check.
    __attribute__((target("arch=armv8.3-a"))) static uint64_t authenticate(int isData, uint64_t value, uint64_t modifier) {
      if (isData) asm("autda %0, %1" : "+r"(value) : "r"(modifier)); else asm("autia %0, %1" : "+r"(value) : "r"(modifier));
      return value;
    }

    struct StubSlot { uint64_t raw = 0, valueAdd = 0; bool found = false; };

    static unsigned gImages, gRegions;
    static uint64_t le64(const uint8_t *p) { uint64_t v; memcpy(&v, p, 8); return v; }
    static uint32_t le32(const uint8_t *p) { uint32_t v; memcpy(&v, p, 4); return v; }
    static void preadall(int fd, void *buf, size_t n, uint64_t off) {
      size_t d = 0; while (d < n) { ssize_t r = pread(fd, (char *)buf + d, n - d, off + d); assert(r > 0); d += (size_t)r; }
    }

    int main(int argc, char **argv) {
      setvbuf(stdout, NULL, _IONBF, 0);
      assert(argc >= 2);
      std::string mainPath = argv[1];
      const char *image = argc > 2 ? argv[2] : nullptr;
      SharedCacheLoadInfo result = {}; SplitCacheMapStats stats = {};
      if (!mapSplitCachePrivate(mainPath.c_str(), true, &result, &stats)) {
        printf("RESULT error: %s\\n", result.errorMessage ? result.errorMessage : "(none)");
        return 1;
      }
      printf("mapped: load=%p files=%u mappings=%u pagesWithChains=%llu plainRebased=%llu authSigned=%llu authLeftAlone=%llu\\n",
             (const void *)result.loadAddress, stats.files, stats.mappings, (unsigned long long)stats.pagesWithChains,
             (unsigned long long)stats.plainRebased, (unsigned long long)stats.authSigned, (unsigned long long)stats.authLeftAlone);

      // independent walk of every slide-info chain straight from the files, compared with the mapped memory
      std::vector<std::string> paths; paths.push_back(mainPath);
      int mfd = ::open(mainPath.c_str(), O_RDONLY); assert(mfd >= 0);
      uint8_t hdr[0x400]; preadall(mfd, hdr, sizeof hdr, 0);
      uint32_t subOffset = le32(hdr + 0x188), subCount = le32(hdr + 0x18c);
      for (uint32_t i = 0; i < subCount; ++i) {
        uint8_t e[56]; preadall(mfd, e, 56, subOffset + (uint64_t)i * 56);
        char suffix[33] = {0}; memcpy(suffix, e + 24, 32); paths.push_back(mainPath + suffix);
      }
      close(mfd);
      uint64_t regionStart = le64(hdr + 0xe0), regionSize = le64(hdr + 0xe8);
      uint64_t pages = 0, plain = 0, auth = 0, bad = 0, outside = 0, shown = 0, authBad = 0, authOutside = 0;

      // Consumer cross-check of the key and diversity bits: every arm64e auth stub (adrp x17; add x17, x17, #lo12;
      // ldr x16, [x17]; braa x16, x17) authenticates its GOT slot with the IA key and the slot address as modifier, so
      // that slot's chain entry must say IA, address diversity and diversity 0. The images are found through the
      // image table and their Mach-O headers parsed here, not through the mapper's helpers.
      std::unordered_map<uint64_t, StubSlot> stubSlots; uint64_t stubs = 0;
      {
        int ifd = ::open(mainPath.c_str(), O_RDONLY); assert(ifd >= 0);
        uint32_t imagesOffset = le32(hdr + 0x1c0), imagesCount = le32(hdr + 0x1c4);
        const uint64_t regionEnd = regionStart + regionSize;
        for (uint32_t i = 0; i < imagesCount; ++i) {
          uint8_t info[32]; preadall(ifd, info, sizeof info, imagesOffset + (uint64_t)i * 32);
          uint64_t imageAddress = le64(info); assert(imageAddress >= regionStart && imageAddress + 32 < regionEnd);
          const uint8_t *header = (const uint8_t *)imageAddress; assert(le32(header) == 0xFEEDFACF);
          uint32_t ncmds = le32(header + 16), sizeofcmds = le32(header + 20);
          assert(sizeofcmds <= 0x100000 && imageAddress + 32 + sizeofcmds <= regionEnd);
          const uint8_t *cmd = header + 32, *cmdsEnd = cmd + sizeofcmds;
          for (uint32_t c = 0; c < ncmds; ++c) {
            assert(cmd + 8 <= cmdsEnd); uint32_t id = le32(cmd), size = le32(cmd + 4); assert(size >= 8 && cmd + size <= cmdsEnd);
            if (id == 0x19 && size >= 72) {
              uint32_t nsects = le32(cmd + 64); assert(72 + 80ULL * nsects <= size);
              for (uint32_t k = 0; k < nsects; ++k) {
                const uint8_t *sect = cmd + 72 + 80 * k;
                if (strncmp((const char *)sect, "__auth_stubs", 16) != 0) continue;
                uint64_t sectAddress = le64(sect + 32), sectSize = le64(sect + 40);
                assert(sectAddress >= regionStart && sectAddress + sectSize <= regionEnd);
                for (uint64_t off = 0; off + 16 <= sectSize; off += 16) {
                  const uint8_t *stub = (const uint8_t *)(sectAddress + off);
                  uint32_t adrp = le32(stub), add = le32(stub + 4);
                  if ((adrp & 0x9F00001F) != 0x90000011 || (add & 0xFF8003FF) != 0x91000231 || le32(stub + 8) != 0xF9400230 || le32(stub + 12) != 0xD71F0A11) continue;
                  int64_t pageDelta = (int64_t)(((adrp >> 5) & 0x7FFFF) << 2 | ((adrp >> 29) & 3));
                  if (pageDelta & 0x100000) pageDelta -= 0x200000;
                  uint64_t imm12 = (add >> 10) & 0xFFF; if ((add >> 22) & 1) imm12 <<= 12;
                  uint64_t slot = (((sectAddress + off) & ~0xFFFULL) + (uint64_t)(pageDelta * 4096)) + imm12;
                  stubSlots.emplace(slot, StubSlot()); ++stubs;
                }
              }
            }
            cmd += size;
          }
        }
        close(ifd);
      }
      for (const std::string &p : paths) {
        int fd = ::open(p.c_str(), O_RDONLY); assert(fd >= 0);
        uint8_t h[0x200]; preadall(fd, h, sizeof h, 0);
        uint32_t tableOffset = le32(h + 0x138), tableCount = le32(h + 0x13c);
        for (uint32_t m = 0; m < tableCount; ++m) {
          uint8_t e[56]; preadall(fd, e, 56, tableOffset + (uint64_t)m * 56);
          uint64_t addr = le64(e), size = le64(e + 8), fileOffset = le64(e + 16), slideOffset = le64(e + 24), slideSize = le64(e + 32);
          if (!slideSize) continue;
          std::vector<uint8_t> si(slideSize); preadall(fd, si.data(), slideSize, slideOffset);
          assert(le32(si.data()) == 5);
          uint32_t pageSize = le32(si.data() + 4), pageCount = le32(si.data() + 8); uint64_t valueAdd = le64(si.data() + 16);
          std::vector<uint8_t> page(pageSize);
          for (uint32_t i = 0; i < pageCount; ++i) {
            uint16_t start; memcpy(&start, si.data() + 24 + 2 * i, 2);
            if (start == 0xFFFF) continue;
            ++pages;
            uint64_t pageAddr = addr + (uint64_t)i * pageSize; assert(pageAddr + pageSize <= addr + size);
            preadall(fd, page.data(), pageSize, fileOffset + (pageAddr - addr));
            uint32_t off = start;
            for (;;) {
              assert(off + 8 <= pageSize);
              uint64_t raw = le64(page.data() + off), loc = pageAddr + off, mapped = *(const uint64_t *)loc, expect;
              auto stubSlot = stubSlots.find(loc);
              if (stubSlot != stubSlots.end()) stubSlot->second = {raw, valueAdd, true};
              if (raw >> 63) {
                // signed in place: the key, modifier and target are decoded here from the on-disk entry
                ++auth;
                uint64_t target = valueAdd + (raw & 0x3ffffffffULL), diversity = (raw >> 34) & 0xffff;
                uint64_t modifier = ((raw >> 50) & 1) ? ((loc & 0x0000ffffffffffffULL) | (diversity << 48)) : diversity;
                if (target < regionStart || target >= regionStart + regionSize) ++authOutside;
                if (authenticate((raw >> 51) & 1, mapped, modifier) != target) ++authBad;
                expect = mapped;   // the signed value itself is not predictable, authentication is its check
              }
              else {
                ++plain;
                expect = (valueAdd + (raw & 0x3ffffffffULL)) | (((raw >> 34) & 0xff) << 56);
                uint64_t target = expect & 0x00ffffffffffffffULL;
                if (target < regionStart || target >= regionStart + regionSize) ++outside;
              }
              if (mapped != expect) {
                ++bad;
                if (shown++ < 5) printf("MISMATCH at region offset %#llx (%s)\\n", (unsigned long long)(loc - regionStart), (raw >> 63) ? "auth" : "plain");
              }
              unsigned next = (raw >> 52) & 0x7ff; if (!next) break; off += next * 8;
            }
          }
        }
        close(fd);
      }
      printf("independent walk: pages=%llu plain=%llu auth=%llu plain-targets-outside-region=%llu mismatches=%llu auth-targets-outside-region=%llu auth-failures=%llu\\n",
             (unsigned long long)pages, (unsigned long long)plain, (unsigned long long)auth, (unsigned long long)outside, (unsigned long long)bad,
             (unsigned long long)authOutside, (unsigned long long)authBad);
      assert(pages == stats.pagesWithChains && plain == stats.plainRebased && auth == stats.authSigned && stats.authLeftAlone == 0);
      assert(bad == 0 && outside == 0 && authOutside == 0 && authBad == 0);

      uint64_t checked = 0, notChain = 0, notAuth = 0, wrongKey = 0, wrongAddrDiv = 0, wrongDiversity = 0, stubAuthBad = 0;
      for (const auto &entry : stubSlots) {
        const StubSlot &s = entry.second;
        if (!s.found) { ++notChain; continue; }
        ++checked;
        if (!(s.raw >> 63)) { ++notAuth; continue; }
        wrongKey += (s.raw >> 51) & 1;
        wrongAddrDiv += !((s.raw >> 50) & 1);
        wrongDiversity += ((s.raw >> 34) & 0xffff) != 0;
        if (authenticate(0, *(const uint64_t *)entry.first, entry.first & 0x0000ffffffffffffULL) != s.valueAdd + (s.raw & 0x3ffffffffULL)) ++stubAuthBad;
      }
      uint64_t violations = notAuth + wrongKey + wrongAddrDiv + wrongDiversity + stubAuthBad;
      printf("auth stubs: stubs=%llu slots=%zu checked=%llu not-chain-entries=%llu violations=%llu (not-auth=%llu wrong-key=%llu no-addr-div=%llu diversity-not-0=%llu autia-failures=%llu)\\n",
             (unsigned long long)stubs, stubSlots.size(), (unsigned long long)checked, (unsigned long long)notChain, (unsigned long long)violations,
             (unsigned long long)notAuth, (unsigned long long)wrongKey, (unsigned long long)wrongAddrDiv, (unsigned long long)wrongDiversity, (unsigned long long)stubAuthBad);
      assert(checked > 0 && violations == 0);

      const DyldSharedCache *cache = result.loadAddress;
      if (image) {
        uint32_t index = 0; assert(cache->hasImagePath(image, index));
        uint64_t mTime, inode; const mach_header *mh = cache->getIndexedImageEntry(index, mTime, inode);
        printf("hasImagePath(%s) index %u, header magic %#x\\n", image, index, mh->magic);
        assert(mh->magic == 0xFEEDFACF && strcmp(cache->getIndexedImagePath(index), image) == 0);
      }
      #{PATCH_CHECK}
      cache->forEachImage(^(const mach_header *, const char *) { ++gImages; });
      cache->forEachRegion(^(const void *, uint64_t, uint64_t, uint32_t, uint32_t, uint64_t) { ++gRegions; });
      uint32_t tableImages = 0; cache->imageTable(tableImages);
      printf("forEachImage=%u imageTable=%u forEachRegion=%u mappings=%u mappedSize=%#llx\\n", gImages, tableImages, gRegions,
             stats.mappings, (unsigned long long)cache->mappedSize());
      assert(gImages == tableImages && gRegions == stats.mappings && cache->mappedSize() == regionSize);
      printf("RESULT ok\\n");
      return 0;
    }
  CPP
  failed_build = SplitCacheHarness.compile(root, dir)
  abort failed_build if failed_build
  args = [main_file]
  args << ENV['DYLD_REAL_CACHE_IMAGE'] if ENV['DYLD_REAL_CACHE_IMAGE'] && !ENV['DYLD_REAL_CACHE_IMAGE'].empty?
  out, st = Open3.capture2e("#{dir}/test", *args)
  puts out
  abort 'real-cache check failed' unless st.success? && out.include?('RESULT ok')
  puts 'PASS real cache mapped, plain slots match an independent walk, every authenticated slot authenticates to its target, auth stubs agree with the key and diversity bits, the patch info validates and its GOT override (stub resolver) authenticates, image helpers agree'
end
