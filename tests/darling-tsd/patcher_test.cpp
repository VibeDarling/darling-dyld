// Placement and application of the TSD translation against a model of memory.
#include "test_support.h"

#include <algorithm>

extern "C" {
    extern uint32_t oracle_veneer[5], oracle_return;
}

static const uintptr_t kBase = 0x180000000ULL;
static const unsigned long kSlot = 0x170;
static const uint32_t kNop = 0xD503201FU;

// Memory made of regions, so that sites and gaps can be hundreds of megabytes apart.
struct ModelMemory {
    struct Region { uintptr_t start; std::vector<uint8_t> bytes; };
    struct Write { uintptr_t address; size_t length; };
    std::vector<Region> regions;
    std::vector<Write> writes;
    int syncs = 0;
    int failWrite = -1;     // number of the write that fails
    Region* find(uintptr_t address, size_t length) {
        for (Region& r : regions) {
            if ( address >= r.start && address + length <= r.start + r.bytes.size() )
                return &r;
        }
        return nullptr;
    }
    void addRegion(uintptr_t start, size_t length, uint32_t fill) {
        Region r = { start, std::vector<uint8_t>(length) };
        for (size_t i = 0; i + 4 <= length; i += 4) memcpy(&r.bytes[i], &fill, 4);
        regions.push_back(r);
    }
    uint32_t word(uintptr_t address) { Region* r = find(address, 4); uint32_t w = 0; if ( r ) memcpy(&w, &r->bytes[address - r->start], 4); return w; }
    void setWord(uintptr_t address, uint32_t w) { Region* r = find(address, 4); memcpy(&r->bytes[address - r->start], &w, 4); }
    static bool doRead(void* c, uintptr_t a, void* out, size_t n) {
        ModelMemory* m = (ModelMemory*)c; Region* r = m->find(a, n);
        if ( !r ) return false;
        memcpy(out, &r->bytes[a - r->start], n);
        return true;
    }
    static bool doWrite(void* c, uintptr_t a, const void* data, size_t n) {
        ModelMemory* m = (ModelMemory*)c; Region* r = m->find(a, n);
        if ( !r || (int)m->writes.size() == m->failWrite ) return false;
        memcpy(&r->bytes[a - r->start], data, n);
        m->writes.push_back({ a, n });
        return true;
    }
    static void doSync(void* c, uintptr_t, size_t) { ++((ModelMemory*)c)->syncs; }
    Memory memory() { return { this, doRead, doWrite, doSync }; }
};

static bool decodeBranch(uint32_t w, uintptr_t at, uintptr_t* target) {
    if ( (w & 0xFC000000U) != 0x14000000U ) return false;
    int64_t imm = (int64_t)(w & 0x03FFFFFFU);
    if ( imm & 0x02000000 ) imm -= 0x04000000;
    *target = at + imm * 4;
    return true;
}

// One image at cache offset 0 holding the given sites, plus gaps. Every site word is installed in the model.
struct Scenario {
    TableBuilder builder;
    ModelMemory memory;
    std::vector<uintptr_t> siteAddresses;
    Scenario() {
        memory.addRegion(kBase, 0x1000, kNop);
        builder.images.push_back({ 0, {} });
    }
    void addSite(uint32_t offset, SiteKind kind, uint32_t reg) {
        builder.images[0].sites.push_back(encodeSite(offset, kind, reg));
        memory.setWord(kBase + offset, kMRSTPIDRRO | reg);
        if ( kind == kCPUIndexRead ) memory.setWord(kBase + offset + 4, 0xD34CFC00U | (reg << 5) | reg);
    }
    void addGap(uint32_t start, uint32_t size) {
        builder.gaps.push_back({ start, size });
        if ( memory.find(kBase + start, size) != nullptr ) {
            for (uint32_t i = 0; i != size; i += 4) memory.setWord(kBase + start + i, 0);
        }
        else {
            memory.addRegion(kBase + start, size, 0);
        }
    }
};

static std::vector<ExecutableRange> rangesOf(const ModelMemory& m) {
    std::vector<ExecutableRange> r;
    for (const ModelMemory::Region& region : m.regions) r.push_back({ region.start, region.bytes.size() });
    return r;
}

struct Run {
    SiteTable table;
    Patcher* patcher = nullptr;
    PatchStats stats = {};
    const char* error = nullptr;
    ~Run() { delete patcher; }
    void run(Scenario& s, uintptr_t image = kBase) {
        const char* parseError = s.builder.parse(table);
        if ( parseError ) { fprintf(stderr, "scenario table refused: %s\n", parseError); ++failures; }
        patcher = new Patcher(table, kBase, kSlot);
        std::vector<ExecutableRange> ranges = rangesOf(s.memory);
        const char* initError = patcher->init(ranges.data(), (uint32_t)ranges.size());
        if ( initError ) { fprintf(stderr, "init: %s\n", initError); ++failures; }
        error = patcher->patchImage(image, s.memory.memory(), &stats);
    }
};

static void testBasic() {
    Scenario s;
    s.addSite(0x100, kTSDRead, 9);
    s.addSite(0x200, kTSDRead, 30);
    s.addSite(0x300, kTSDRead, 31);
    s.addSite(0x400, kCPUIndexRead, 0);
    s.addGap(0x800, 0x100);
    Run r;
    r.run(s);
    CHECK(r.error == nullptr);
    CHECK(r.stats.sites == 4 && r.stats.veneers == 2 && r.stats.nops == 1 && r.stats.cpuZeroed == 1 && r.stats.trapped == 0);
    uintptr_t target = 0;
    CHECK(decodeBranch(s.memory.word(kBase + 0x100), kBase + 0x100, &target) && target == kBase + 0x800);
    CHECK(decodeBranch(s.memory.word(kBase + 0x200), kBase + 0x200, &target) && target == kBase + 0x814);
    CHECK(s.memory.word(kBase + 0x300) == kNop);
    CHECK(s.memory.word(kBase + 0x400) == (0xAA1F03E0U | 0));
    CHECK(s.memory.word(kBase + 0x404) == (0xD34CFC00U | 0));     // the shift stays and shifts zero
    CHECK(s.memory.word(kBase + 0x104) == kNop);                    // neighbours untouched
    // the veneer of the x9 read is the assembler's, up to its return branch
    for (int i = 0; i != 4; ++i) CHECK(s.memory.word(kBase + 0x800 + 4 * i) == oracle_veneer[i]);
    CHECK(decodeBranch(s.memory.word(kBase + 0x810), kBase + 0x810, &target) && target == kBase + 0x104);
    CHECK(s.memory.word(kBase + 0x814) == (0xD53BD040U | 30) && s.memory.word(kBase + 0x81C) == (0xB5000040U | 30));
    CHECK(decodeBranch(s.memory.word(kBase + 0x824), kBase + 0x824, &target) && target == kBase + 0x204);
    CHECK(r.patcher->bytesUsed(0) == 40);
    // veneers are written, and made visible, before the first site
    size_t firstSite = s.memory.writes.size();
    for (size_t i = 0; i != s.memory.writes.size(); ++i) if ( s.memory.writes[i].address < kBase + 0x800 ) { firstSite = i; break; }
    CHECK(firstSite == 2 && s.memory.writes.size() == 2 + 4 && s.memory.syncs == 6);
    for (size_t i = firstSite; i != s.memory.writes.size(); ++i) CHECK(s.memory.writes[i].address < kBase + 0x800);
    // a second call changes nothing
    const size_t writes = s.memory.writes.size();
    PatchStats again;
    CHECK(r.patcher->patchImage(kBase, s.memory.memory(), &again) == nullptr && s.memory.writes.size() == writes);
}

static void testRefusals() {
    {   Scenario s; s.addSite(0x100, kTSDRead, 9); s.addSite(0x200, kTSDRead, 10); s.addGap(0x800, 0x100);
        s.memory.setWord(kBase + 0x200, kMRSTPIDRRO | 11);        // wrong register: the table is stale
        Run r; r.run(s); CHECK(r.error && strstr(r.error, "stale") && s.memory.writes.empty()); }
    {   Scenario s; s.addSite(0x100, kCPUIndexRead, 9); s.addGap(0x800, 0x100);
        s.memory.setWord(kBase + 0x104, kNop);
        Run r; r.run(s); CHECK(r.error && strstr(r.error, "lsr") && s.memory.writes.empty()); }
    {   Scenario s; s.addSite(0x100, kTSDRead, 9); s.addGap(0x800, 0x100);
        s.memory.setWord(kBase + 0x800, 0x12345678);                // the gap is not zero
        Run r; r.run(s); CHECK(r.error && strstr(r.error, "not zero") && s.memory.writes.empty()); }
    {   Scenario s; s.addSite(0x100, kTSDRead, 9); s.addGap(0x800, 0x100);
        s.memory.setWord(kBase + 0x810, 0x12345678);                // zero check covers the whole veneer
        Run r; r.run(s); CHECK(r.error && strstr(r.error, "not zero")); }
    {   Scenario s; s.addSite(0x100, kTSDRead, 9); s.addGap(0x800, 0x100);
        Run r; r.run(s, kBase + 0x40); CHECK(r.error && strstr(r.error, "does not describe")); }
    {   Scenario s; s.addSite(0x100, kTSDRead, 9); s.addGap(0x800, 0x100);
        Run r; r.run(s, kBase - 0x1000); CHECK(r.error && strstr(r.error, "outside the cache")); }
    {   Scenario s; s.addSite(0x100, kTSDRead, 9); s.addGap(0x800, 0x100);
        s.memory.failWrite = 0;                                      // the veneer write fails: no site may be touched
        Run r; r.run(s); CHECK(r.error && strstr(r.error, "veneer") && s.memory.word(kBase + 0x100) == (kMRSTPIDRRO | 9)); }
    {   Scenario s; s.addSite(0x100, kTSDRead, 9); s.addGap(0x800, 0x100);
        s.memory.failWrite = 1;
        Run r; r.run(s); CHECK(r.error && strstr(r.error, "site")); }
    {   Scenario s; s.addSite(0x100, kTSDRead, 9);                  // no gap at all: the trap stays
        Run r; r.run(s); CHECK(r.error == nullptr && r.stats.trapped == 1 && s.memory.word(kBase + 0x100) == 0xDA09U); }
    {   Scenario s; s.addGap(0x800, 0x100);
        SiteTable table; s.builder.parse(table); Patcher bad(table, kBase, 0x171); ExecutableRange any = { kBase, 0x1000 }; CHECK(bad.init(&any, 1) != nullptr); }
}

static void testPlacement() {
    // the gap's last 16 bytes cannot hold a veneer: exactly one fits in 36 bytes, two in 40
    {   Scenario s; s.addSite(0x100, kTSDRead, 9); s.addSite(0x104, kTSDRead, 9); s.addGap(0x800, 36);
        Run r; r.run(s); CHECK(r.stats.veneers == 1 && r.stats.trapped == 1 && r.patcher->bytesUsed(0) == 20); }
    {   Scenario s; s.addSite(0x100, kTSDRead, 9); s.addSite(0x104, kTSDRead, 9); s.addGap(0x800, 40);
        Run r; r.run(s); CHECK(r.stats.veneers == 2 && r.patcher->bytesUsed(0) == 40); }
    {   Scenario s; s.addSite(0x100, kTSDRead, 9); s.addSite(0x104, kTSDRead, 9); s.addGap(0x800, 20);
        Run r; r.run(s); CHECK(r.stats.veneers == 1 && r.stats.trapped == 1); }
    // a full gap spills into the next one, on either side
    {   Scenario s; for (uint32_t i = 0; i != 5; ++i) s.addSite(0x100 + 4 * i, kTSDRead, 9);
        s.addGap(0x200, 40); s.addGap(0x800, 100);
        Run r; r.run(s); CHECK(r.stats.veneers == 5 && r.stats.trapped == 0 && r.patcher->bytesUsed(0) == 40 && r.patcher->bytesUsed(1) == 60); }
    {   Scenario s; for (uint32_t i = 0; i != 5; ++i) s.addSite(0x900 + 4 * i, kTSDRead, 9);
        s.addGap(0x100, 100); s.addGap(0x800, 20);
        Run r; r.run(s); CHECK(r.stats.veneers == 5 && r.patcher->bytesUsed(1) == 20 && r.patcher->bytesUsed(0) == 80); }
    // the nearer gap wins; on a tie the lower one
    {   Scenario s; s.addSite(0x400, kTSDRead, 9); s.addGap(0x100, 0x40); s.addGap(0x600, 0x40);
        Run r; r.run(s); CHECK(r.patcher->bytesUsed(1) == 20 && r.patcher->bytesUsed(0) == 0); }
    {   Scenario s; s.addSite(0x400, kTSDRead, 9); s.addGap(0x200, 0x40); s.addGap(0x600, 0x40);
        Run r; r.run(s); CHECK(r.patcher->bytesUsed(0) == 20 && r.patcher->bytesUsed(1) == 0); }
    {   Scenario s; s.addSite(0x400, kTSDRead, 9); s.addGap(0x100, 0x40); s.addGap(0x500, 0x40);
        Run r; r.run(s); CHECK(r.patcher->bytesUsed(1) == 20 && r.patcher->bytesUsed(0) == 0); }
}

// A `b` reaches 128 MiB: the last gap that works and the first that does not, on both sides.
static void testReach() {
    const uint32_t site = 0x100;
    const uint32_t limit = 1U << 27;
    struct Case { uint32_t gapStart; bool above; bool reachable; };
    const Case cases[] = {
        { site + limit - 12, true, true },      // the veneer's own return branch is the binding one above
        { site + limit - 8, true, false },
        { site + limit + 0x1000, true, false },
    };
    for (const Case& c : cases) {
        Scenario s; s.addSite(site, kTSDRead, 9);
        s.memory.regions.clear(); s.memory.addRegion(kBase, 0x1000, kNop); s.memory.setWord(kBase + site, kMRSTPIDRRO | 9);
        s.addGap(c.gapStart, 0x40);
        Run r; r.run(s);
        CHECK(r.error == nullptr && (r.stats.veneers == 1) == c.reachable && (r.stats.trapped == 1) == !c.reachable);
    }
    // a site out of reach does not stop later, nearer sites from using the gap
    {   Scenario s; s.addSite(site, kTSDRead, 9); s.addSite(site + 0x20, kTSDRead, 10);
        s.memory.regions.clear(); s.memory.addRegion(kBase, 0x1000, kNop);
        s.memory.setWord(kBase + site, kMRSTPIDRRO | 9); s.memory.setWord(kBase + site + 0x20, kMRSTPIDRRO | 10);
        s.addGap(site + limit - 8, 0x40);
        Run r; r.run(s); CHECK(r.error == nullptr && r.stats.trapped == 1 && r.stats.veneers == 1 && s.memory.word(kBase + site) == 0xDA09U); }
    // below the site: the gap sits in an image placed above 128 MiB, the site in a second image
    const uint32_t imageB = 0x20000000;         // 512 MiB
    const uint32_t siteB = 0x100;
    const uint32_t below[] = { imageB + siteB - limit, imageB + siteB - limit - 4 };
    const bool reaches[] = { true, false };
    for (int i = 0; i != 2; ++i) {
        TableBuilder b;
        b.images = { { 0, {} }, { imageB, { encodeSite(siteB, kTSDRead, 9) } } };
        b.gaps = { { below[i], 0x40 } };
        ModelMemory m;
        m.addRegion(kBase + imageB, 0x1000, kNop);
        m.setWord(kBase + imageB + siteB, kMRSTPIDRRO | 9);
        m.addRegion(kBase + below[i], 0x40, 0);
        SiteTable table; CHECK(b.parse(table) == nullptr);
        Patcher p(table, kBase, kSlot); std::vector<ExecutableRange> ranges = rangesOf(m); CHECK(p.init(ranges.data(), (uint32_t)ranges.size()) == nullptr);
        PatchStats st;
        CHECK(p.patchImage(kBase + imageB, m.memory(), &st) == nullptr && (st.veneers == 1) == reaches[i]);
    }
}

// Many images with heavy ones among them, as in the real cache: every veneer must land in a gap, in reach, once.
static void testMany() {
    const uint32_t images = 3000, stride = 0x3000, textBytes = 0x2800;
    TableBuilder b;
    ModelMemory m;
    m.addRegion(kBase, (size_t)images * stride, kNop);
    uint64_t seed = 12345;
    auto next = [&seed](uint32_t bound) { seed = seed * 6364136223846793005ULL + 1442695040888963407ULL; return (uint32_t)((seed >> 33) % bound); };
    size_t total = 0;
    for (uint32_t i = 0; i != images; ++i) {
        const uint32_t base = i * stride;
        b.gaps.push_back({ base + textBytes, stride - textBytes });
        for (uint32_t w = textBytes; w != stride; w += 4) m.setWord(kBase + base + w, 0);
        ImageSpec spec = { base, {} };
        const uint32_t count = (i % 300 == 7) ? 400 : next(13);
        uint32_t offset = 0x40;
        for (uint32_t k = 0; k != count; ++k) {
            offset += 8 + 4 * next(3);
            if ( offset + 8 >= textBytes ) break;
            const uint32_t reg = next(31);
            const SiteKind kind = (next(50) == 0) ? kCPUIndexRead : kTSDRead;
            spec.sites.push_back(encodeSite(offset, kind, reg));
            m.setWord(kBase + base + offset, kMRSTPIDRRO | reg);
            m.setWord(kBase + base + offset + 4, 0xD34CFC00U | (reg << 5) | reg);
        }
        total += spec.sites.size();
        b.images.push_back(spec);
    }
    SiteTable table;
    CHECK(b.parse(table) == nullptr);
    Patcher patcher(table, kBase, kSlot);
    std::vector<ExecutableRange> ranges = rangesOf(m);
    CHECK(patcher.init(ranges.data(), (uint32_t)ranges.size()) == nullptr);
    uint32_t veneers = 0, trapped = 0;
    for (uint32_t i = 0; i != images; ++i) {
        PatchStats st;
        CHECK(patcher.patchImage(kBase + (uintptr_t)i * stride, m.memory(), &st) == nullptr);
        veneers += st.veneers;
        trapped += st.trapped;
    }
    CHECK(total > 20000 && trapped == 0 && veneers > 20000);
    uint32_t checked = 0;
    std::vector<uintptr_t> seen;
    for (uint32_t i = 0; i != images; ++i) {
        const ImageRecord* r = table.findImage(i * stride, nullptr);
        for (uint32_t k = 0; k != r->siteCount; ++k) {
            const uint32_t site = table.sites(*r)[k];
            const uintptr_t at = kBase + i * stride + siteOffset(site);
            if ( siteKind(site) == kCPUIndexRead && siteRegister(site) != 31 ) CHECK(m.word(at) == (0xAA1F03E0U | siteRegister(site)));
            if ( siteKind(site) != kTSDRead || siteRegister(site) == 31 ) continue;
            uintptr_t veneer = 0, back = 0;
            CHECK(decodeBranch(m.word(at), at, &veneer));
            CHECK(decodeBranch(m.word(veneer + 16), veneer + 16, &back) && back == at + 4);
            const uint32_t gapIndex = (uint32_t)((veneer - kBase) / stride);
            const Gap& g = table.gap(gapIndex);
            CHECK(veneer >= kBase + g.start && veneer + 20 <= kBase + g.start + g.size);
            seen.push_back(veneer);
            ++checked;
        }
    }
    std::sort(seen.begin(), seen.end());
    bool disjoint = true;
    for (size_t i = 1; i < seen.size(); ++i) disjoint = disjoint && (seen[i] - seen[i-1] >= 20);
    CHECK(disjoint && checked == veneers);
}

// The reach of a veneer differs by side (it returns to site + 4 from its fifth word): when the nearer gap is just out of
// reach on its side, the farther one on the other side may still fit.
static void testAsymmetricReach() {
    const uint32_t limit = 1U << 27;
    const uint32_t imageB = 0x20000000;
    const uint32_t siteB = 0x100;
    struct Case { uint32_t left, right; int usedLeft, usedRight; };
    const Case cases[] = {
        { imageB + siteB - limit + 4, imageB + siteB + limit - 8, 20, 0 },      // right is nearer but 4 bytes too far
        { imageB + siteB - limit + 4, imageB + siteB + limit - 12, 0, 20 },     // both reach, right is nearer
        { imageB + siteB - limit - 4, imageB + siteB + limit - 8, 0, 0 },       // neither reaches
    };
    for (const Case& c : cases) {
        TableBuilder b;
        b.images = { { 0, {} }, { imageB, { encodeSite(siteB, kTSDRead, 9) } } };
        b.gaps = { { c.left, 0x40 }, { c.right, 0x40 } };
        ModelMemory m;
        m.addRegion(kBase + imageB, 0x1000, kNop);
        m.setWord(kBase + imageB + siteB, kMRSTPIDRRO | 9);
        m.addRegion(kBase + c.left, 0x40, 0);
        m.addRegion(kBase + c.right, 0x40, 0);
        SiteTable table; CHECK(b.parse(table) == nullptr);
        Patcher p(table, kBase, kSlot);
        std::vector<ExecutableRange> ranges = rangesOf(m);
        CHECK(p.init(ranges.data(), (uint32_t)ranges.size()) == nullptr);
        PatchStats st;
        CHECK(p.patchImage(kBase + imageB, m.memory(), &st) == nullptr);
        CHECK((int)p.bytesUsed(0) == c.usedLeft && (int)p.bytesUsed(1) == c.usedRight);
    }
}

// Writes go through /proc/self/mem, which ignores protections: a table must not name memory outside the executable
// mappings of the cache.
static void testExecutableRanges() {
    {   Scenario s; s.addSite(0x100, kTSDRead, 9); s.addGap(0x800, 0x100);
        SiteTable table; CHECK(s.builder.parse(table) == nullptr);
        Patcher p(table, kBase, kSlot);
        ExecutableRange gapMissing = { kBase, 0x800 };
        const char* e = p.init(&gapMissing, 1); CHECK(e && strstr(e, "gap")); }
    {   Scenario s; s.addSite(0x100, kTSDRead, 9); s.addGap(0x800, 0x100);
        SiteTable table; CHECK(s.builder.parse(table) == nullptr);
        Patcher p(table, kBase, kSlot);
        ExecutableRange gapPartly = { kBase + 0x800, 0xFC };                    // one word short
        const char* e = p.init(&gapPartly, 1); CHECK(e && strstr(e, "gap")); }
    {   Scenario s; s.addSite(0x100, kTSDRead, 9); s.addGap(0x800, 0x100);
        SiteTable table; CHECK(s.builder.parse(table) == nullptr);
        Patcher p(table, kBase, kSlot);
        const char* e = p.init(nullptr, 0); CHECK(e && strstr(e, "no executable")); }
    {   Scenario s; s.addSite(0x100, kTSDRead, 9); s.addGap(0x800, 0x100);     // the site is outside: nothing is written
        SiteTable table; CHECK(s.builder.parse(table) == nullptr);
        Patcher p(table, kBase, kSlot);
        ExecutableRange ranges[2] = { { kBase, 0x100 }, { kBase + 0x800, 0x100 } };   // ends one word before the site's end
        CHECK(p.init(ranges, 2) == nullptr);
        PatchStats st;
        const char* e = p.patchImage(kBase, s.memory.memory(), &st); CHECK(e && strstr(e, "site outside") && s.memory.writes.empty()); }
    {   Scenario s; s.addSite(0x100, kTSDRead, 9); s.addGap(0x800, 0x100);     // the site's last word is the range's last word
        SiteTable table; CHECK(s.builder.parse(table) == nullptr);
        Patcher p(table, kBase, kSlot);
        ExecutableRange ranges[2] = { { kBase, 0x104 }, { kBase + 0x800, 0x100 } };
        CHECK(p.init(ranges, 2) == nullptr);
        PatchStats st;
        CHECK(p.patchImage(kBase, s.memory.memory(), &st) == nullptr && st.veneers == 1); }
    {   Scenario s; s.addSite(0x100, kTSDRead, 9); s.addGap(0x800, 0x100);     // the image header is outside
        SiteTable table; CHECK(s.builder.parse(table) == nullptr);
        Patcher p(table, kBase, kSlot);
        ExecutableRange ranges[2] = { { kBase + 0x100, 0x100 }, { kBase + 0x800, 0x100 } };
        CHECK(p.init(ranges, 2) == nullptr);
        PatchStats st;
        const char* e = p.patchImage(kBase, s.memory.memory(), &st); CHECK(e && strstr(e, "outside") && s.memory.writes.empty()); }
    {   Scenario s; s.addSite(0x100, kCPUIndexRead, 9); s.addGap(0x800, 0x100);   // a CPU-index read needs its second word inside too
        SiteTable table; CHECK(s.builder.parse(table) == nullptr);
        Patcher p(table, kBase, kSlot);
        ExecutableRange ranges[2] = { { kBase, 0x104 }, { kBase + 0x800, 0x100 } };
        CHECK(p.init(ranges, 2) == nullptr);
        PatchStats st;
        const char* e = p.patchImage(kBase, s.memory.memory(), &st); CHECK(e && strstr(e, "site outside") && s.memory.writes.empty()); }
}

void testPatcher() {
    testBasic();
    testRefusals();
    testPlacement();
    testReach();
    testMany();
    testAsymmetricReach();
    testExecutableRanges();
}
