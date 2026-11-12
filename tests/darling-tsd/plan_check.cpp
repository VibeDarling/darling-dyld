// Runs the production placement over a whole site table without a cache: memory is a model that answers a read of a
// site with the mrs the table promises and a read of a gap with zeros, and every write is checked.
// usage: plan_check TABLE CACHE_BASE_HEX [MIN_SITES]
#include "DarlingTSDIslands.h"

#include <algorithm>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <vector>

using namespace dyld3::darling_tsd;

struct Model {
    const SiteTable* table;
    uintptr_t base;
    std::vector<uintptr_t> siteAddress;     // sorted
    std::vector<uint32_t> siteWord;         // what the cache holds there (mrs, or lsr after a CPU-index mrs)
    std::vector<uintptr_t> written;         // word addresses written so far
    uint64_t errors = 0;
    int64_t farthest = 0;                   // longest branch from a translated site to its veneer
    bool inGap(uintptr_t a, size_t n) const {
        for (uint32_t lo = 0, hi = table->gapCount(); lo < hi; ) {
            const uint32_t mid = lo + (hi - lo) / 2;
            const Gap& g = table->gap(mid);
            if ( a < base + g.start ) hi = mid;
            else if ( a >= base + g.start + g.size ) lo = mid + 1;
            else return a + n <= base + g.start + g.size;
        }
        return false;
    }
    static bool read(void* c, uintptr_t a, void* out, size_t n) {
        Model* m = (Model*)c;
        if ( m->inGap(a, n) ) { memset(out, 0, n); return true; }
        for (size_t i = 0; i < n; i += 4) {
            auto it = std::lower_bound(m->siteAddress.begin(), m->siteAddress.end(), a + i);
            if ( it == m->siteAddress.end() || *it != a + i ) return false;
            memcpy((char*)out + i, &m->siteWord[it - m->siteAddress.begin()], 4);
        }
        return true;
    }
    static bool write(void* c, uintptr_t a, const void* data, size_t n) {
        Model* m = (Model*)c;
        const bool veneer = m->inGap(a, n);
        const bool site = std::binary_search(m->siteAddress.begin(), m->siteAddress.end(), a) && n == 4;
        if ( !veneer && !site ) { ++m->errors; fprintf(stderr, "write outside gaps and sites at 0x%lx\n", (unsigned long)a); return false; }
        for (size_t i = 0; i < n; i += 4) m->written.push_back(a + i);
        uint32_t word;
        memcpy(&word, data, 4);
        if ( site && (word & 0xFC000000U) == 0x14000000U ) {
            int64_t imm = word & 0x03FFFFFF;
            if ( imm & 0x02000000 ) imm -= 0x04000000;
            m->farthest = std::max(m->farthest, imm < 0 ? -imm * 4 : imm * 4);
        }
        return true;
    }
    static void sync(void*, uintptr_t, size_t) {}
};

int main(int argc, char** argv) {
    if ( argc < 3 ) { fprintf(stderr, "usage: plan_check TABLE CACHE_BASE_HEX [MIN_SITES]\n"); return 2; }
    FILE* f = fopen(argv[1], "rb");
    if ( !f ) { perror("open"); return 2; }
    fseek(f, 0, SEEK_END);
    const size_t length = (size_t)ftell(f);
    rewind(f);
    void* bytes = aligned_alloc(8, (length + 7) & ~(size_t)7);
    if ( fread(bytes, 1, length, f) != length ) { perror("read"); return 2; }
    fclose(f);
    SiteTable table;
    if ( const char* error = table.parse(bytes, length) ) { printf("table refused: %s\n", error); return 1; }

    const uintptr_t base = (uintptr_t)strtoull(argv[2], nullptr, 16);
    Model model;
    model.table = &table;
    model.base = base;
    std::vector<std::pair<uintptr_t, uint32_t>> words;
    uint64_t total = 0;
    std::vector<uint64_t> imageOffsets;
    for (uint32_t i = 0; i != table.imageCount(); ++i) imageOffsets.push_back(table.image(i).imageOffset);
    for (uint64_t offset : imageOffsets) {
        const ImageRecord* r = table.findImage(offset, nullptr);
        for (uint32_t k = 0; k != r->siteCount; ++k) {
            const uint32_t s = table.sites(*r)[k];
            const uintptr_t at = base + offset + siteOffset(s);
            words.push_back({ at, kMRSTPIDRRO | siteRegister(s) });
            if ( siteKind(s) == kCPUIndexRead && siteRegister(s) != 31 )
                words.push_back({ at + 4, 0xD34CFC00U | (siteRegister(s) << 5) | siteRegister(s) });
            ++total;
        }
    }
    std::sort(words.begin(), words.end());
    for (auto& w : words) { model.siteAddress.push_back(w.first); model.siteWord.push_back(w.second); }

    Patcher patcher(table, base, 0x170);
    const ExecutableRange everything = { base, (uintptr_t)1 << 40 };     // the model has no mappings to bound it
    if ( const char* error = patcher.init(&everything, 1) ) { printf("init: %s\n", error); return 1; }
    Memory memory = { &model, Model::read, Model::write, Model::sync };
    PatchStats sum = {};
    for (uint64_t offset : imageOffsets) {
        PatchStats st;
        if ( const char* error = patcher.patchImage(base + offset, memory, &st) ) { printf("patch 0x%llx: %s\n", (unsigned long long)offset, error); return 1; }
        sum.sites += st.sites; sum.veneers += st.veneers; sum.cpuZeroed += st.cpuZeroed; sum.nops += st.nops; sum.trapped += st.trapped;
    }
    std::sort(model.written.begin(), model.written.end());
    const bool unique = std::adjacent_find(model.written.begin(), model.written.end()) == model.written.end();
    uint64_t bytesUsed = 0;
    for (uint32_t g = 0; g != table.gapCount(); ++g) {
        if ( patcher.bytesUsed(g) > table.gap(g).size ) ++model.errors;
        bytesUsed += patcher.bytesUsed(g);
    }
    printf("images %u, sites %llu, veneers %u, cpu %u, nops %u, trapped %u, gaps %u, veneer bytes %llu, farthest %lld bytes, errors %llu, writes unique %d\n",
           table.imageCount(), (unsigned long long)total, sum.veneers, sum.cpuZeroed, sum.nops, sum.trapped, table.gapCount(),
           (unsigned long long)bytesUsed, (long long)model.farthest, (unsigned long long)model.errors, unique);
    const uint64_t minimum = (argc > 3) ? strtoull(argv[3], nullptr, 10) : 0;
    return (sum.trapped == 0 && model.errors == 0 && unique && sum.sites == total && total >= minimum && bytesUsed == (uint64_t)sum.veneers * kVeneerBytes) ? 0 : 1;
}
