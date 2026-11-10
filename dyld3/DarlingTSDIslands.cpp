#include "DarlingTSDIslands.h"

#include <stdlib.h>
#include <string.h>

namespace dyld3 {
namespace darling_tsd {

static const char kMagic[8] = { 'D', 'T', 'S', 'D', 'S', 'I', 'T', '1' };

const char* SiteTable::parse(const void* bytes, size_t length)
{
    if ( (bytes == nullptr) || (((uintptr_t)bytes & 3) != 0) )
        return "TSD site table is missing or misaligned";
    if ( length < sizeof(TableHeader) )
        return "TSD site table is shorter than its header";
    const TableHeader* h = (const TableHeader*)bytes;
    if ( memcmp(h->magic, kMagic, sizeof(kMagic)) != 0 )
        return "TSD site table has the wrong magic";
    if ( h->reserved != 0 )
        return "TSD site table reserved word is not zero";
    const uint64_t expected = sizeof(TableHeader) + (uint64_t)h->gapCount * sizeof(Gap)
                            + (uint64_t)h->imageCount * sizeof(ImageRecord) + (uint64_t)h->siteCount * sizeof(uint32_t);
    if ( expected != length )
        return "TSD site table length does not match its counts";
    const uint8_t* base = (const uint8_t*)bytes;
    const Gap* g = (const Gap*)(base + sizeof(TableHeader));
    const ImageRecord* images = (const ImageRecord*)(g + h->gapCount);
    const uint32_t* sites = (const uint32_t*)(images + h->imageCount);

    for (uint32_t i = 0; i != h->gapCount; ++i) {
        if ( ((g[i].start & 3) != 0) || ((g[i].size & 3) != 0) || (g[i].size < kVeneerBytes) )
            return "TSD site table gap is misaligned or too small";
        if ( (uint64_t)g[i].start + g[i].size > UINT32_MAX )
            return "TSD site table gap wraps";
        if ( (i != 0) && ((uint64_t)g[i-1].start + g[i-1].size > g[i].start) )
            return "TSD site table gaps are not sorted and disjoint";
    }
    uint32_t nextSite = 0;
    uint32_t gapIndex = 0;
    for (uint32_t i = 0; i != h->imageCount; ++i) {
        const ImageRecord& r = images[i];
        if ( (i != 0) && (images[i-1].imageOffset >= r.imageOffset) )
            return "TSD site table images are not sorted";
        if ( r.firstSite != nextSite )
            return "TSD site table site ranges do not tile the site array";
        if ( r.siteCount > h->siteCount - nextSite )
            return "TSD site table image has more sites than the table";
        nextSite += r.siteCount;
        const uint64_t limit = (i + 1 == h->imageCount) ? (uint64_t)1 << 32 : images[i+1].imageOffset;
        uint64_t previous = 0;
        for (uint32_t k = 0; k != r.siteCount; ++k) {
            const uint32_t s = sites[r.firstSite + k];
            const uint64_t address = (uint64_t)r.imageOffset + siteOffset(s);
            if ( (address >= limit) || ((k != 0) && (siteOffset(s) <= previous)) )
                return "TSD site table sites are not ascending inside their image";
            previous = siteOffset(s);
            // A gap that holds a site would let a veneer overwrite code that is rewritten as well.
            while ( (gapIndex != h->gapCount) && ((uint64_t)g[gapIndex].start + g[gapIndex].size <= address) )
                ++gapIndex;
            if ( (gapIndex != h->gapCount) && (g[gapIndex].start <= address) )
                return "TSD site table has a site inside a gap";
        }
    }
    if ( nextSite != h->siteCount )
        return "TSD site table site array is longer than its images";
    header = h;
    gaps = g;
    this->images = images;
    sitesArray = sites;
    return nullptr;
}

const ImageRecord* SiteTable::findImage(uint32_t imageOffset, uint32_t* index) const
{
    uint32_t low = 0;
    uint32_t high = header->imageCount;
    while ( low < high ) {
        const uint32_t middle = low + (high - low) / 2;
        if ( images[middle].imageOffset < imageOffset )
            low = middle + 1;
        else
            high = middle;
    }
    if ( (low == header->imageCount) || (images[low].imageOffset != imageOffset) )
        return nullptr;
    if ( index != nullptr )
        *index = low;
    return &images[low];
}

uint32_t encodeBranch(uintptr_t from, uintptr_t to, bool* ok)
{
    const int64_t delta = (int64_t)to - (int64_t)from;
    if ( ((delta & 3) != 0) || (delta < -(1LL << 27)) || (delta >= (1LL << 27)) ) {
        *ok = false;
        return 0;
    }
    return 0x14000000U | ((uint32_t)(delta >> 2) & 0x03FFFFFFU);
}

bool isValidSlotOffset(unsigned long slotOffset)
{
    return (slotOffset >= 16) && (slotOffset <= 32760) && ((slotOffset & 7) == 0);
}

void encodeVeneer(uint32_t reg, unsigned long slotOffset, uintptr_t veneer, uintptr_t site, uint32_t out[5], bool* ok)
{
    out[0] = 0xD53BD040U | reg;                                                     // mrs Xd, TPIDR_EL0
    out[1] = 0xF9400000U | ((uint32_t)(slotOffset / 8) << 10) | (reg << 5) | reg;   // ldr Xd, [Xd, #slot]
    out[2] = 0xB5000040U | reg;                                                     // cbnz Xd, +8: the flags stay intact
    out[3] = 0x0000DA00U | reg;                                                     // slot still empty: the kernel trap emulator
    out[4] = encodeBranch(veneer + 16, site + 4, ok);                               // b back
}

Patcher::Patcher(const SiteTable& t, uintptr_t base, unsigned long slotOffset)
    : table(t), cacheBase(base), slot(slotOffset)
{
}

Patcher::~Patcher()
{
    free(used);
    free(done);
}

const char* Patcher::init()
{
    if ( !isValidSlotOffset(slot) )
        return "the native TSD slot offset is not usable";
    used = (uint32_t*)calloc(table.gapCount() + 1, sizeof(uint32_t));
    done = (uint8_t*)calloc(table.imageCount() + 1, 1);
    if ( (used == nullptr) || (done == nullptr) )
        return "out of memory for the TSD translation state";
    return nullptr;
}

static bool veneerReaches(uintptr_t site, uintptr_t veneer)
{
    bool ok = true;
    encodeBranch(site, veneer, &ok);
    encodeBranch(veneer + 16, site + 4, &ok);
    return ok;
}

// The first gap from `*index` in direction `step` with room for a veneer; false when the table has no more.
bool Patcher::nextWithRoom(int64_t* index, int step, uintptr_t* address) const
{
    for (; (*index >= 0) && (*index < (int64_t)table.gapCount()); *index += step) {
        const Gap& g = table.gap((uint32_t)*index);
        if ( g.size - used[*index] >= kVeneerBytes ) {
            *address = cacheBase + g.start + used[*index];
            return true;
        }
    }
    return false;
}

// The nearest gap with room whose veneer the site can branch to and return from, or -1. Gaps are sorted, so the
// nearer of the two nearest candidates is the nearest overall, and if it is out of reach so is every other.
int Patcher::placeVeneer(uintptr_t site) const
{
    uint32_t low = 0;
    uint32_t high = table.gapCount();
    while ( low < high ) {          // first gap that starts above the site
        const uint32_t middle = low + (high - low) / 2;
        if ( cacheBase + table.gap(middle).start <= site )
            low = middle + 1;
        else
            high = middle;
    }
    int64_t left = (int64_t)low - 1;
    int64_t right = (int64_t)low;
    uintptr_t leftAddress = 0;
    uintptr_t rightAddress = 0;
    const bool haveLeft = nextWithRoom(&left, -1, &leftAddress);
    const bool haveRight = nextWithRoom(&right, +1, &rightAddress);
    if ( haveLeft && (!haveRight || (site - leftAddress <= rightAddress - site)) )
        return veneerReaches(site, leftAddress) ? (int)left : -1;
    if ( haveRight )
        return veneerReaches(site, rightAddress) ? (int)right : -1;
    return -1;
}

static bool isAllZero(const uint8_t* bytes, size_t length)
{
    for (size_t i = 0; i != length; ++i) {
        if ( bytes[i] != 0 )
            return false;
    }
    return true;
}

const char* Patcher::patchImage(uintptr_t machHeader, const Memory& memory, PatchStats* statsOut)
{
    PatchStats stats = {};
    if ( statsOut != nullptr )
        *statsOut = stats;
    if ( (machHeader < cacheBase) || (machHeader - cacheBase > UINT32_MAX) )
        return "TSD translation: image lies outside the cache";
    uint32_t index = 0;
    const ImageRecord* image = table.findImage((uint32_t)(machHeader - cacheBase), &index);
    if ( image == nullptr )
        return "TSD site table does not describe this image (made from another cache?)";
    if ( done[index] )
        return nullptr;
    const uint32_t* sites = table.sites(*image);
    const uint32_t count = image->siteCount;
    stats.sites = count;

    // Nothing is written before every site has been seen to hold what the table says.
    for (uint32_t k = 0; k != count; ++k) {
        const uintptr_t address = machHeader + siteOffset(sites[k]);
        uint32_t word[2] = { 0, 0 };
        if ( !memory.read(memory.context, address, word, (siteKind(sites[k]) == kCPUIndexRead) ? 8 : 4) )
            return "TSD translation: could not read a site";
        if ( word[0] != (kMRSTPIDRRO | siteRegister(sites[k])) )
            return "TSD site table is stale: a site does not hold mrs TPIDRRO_EL0";
        const uint32_t reg = siteRegister(sites[k]);
        if ( (siteKind(sites[k]) == kCPUIndexRead) && (reg != 31) && (word[1] != (0xD34CFC00U | (reg << 5) | reg)) )
            return "TSD site table is stale: a CPU-index read is not followed by lsr #12";
    }

    uintptr_t* veneerAt = (count != 0) ? (uintptr_t*)calloc(count, sizeof(uintptr_t)) : nullptr;
    if ( (count != 0) && (veneerAt == nullptr) )
        return "out of memory for the TSD translation plan";
    const char* error = nullptr;
    for (uint32_t k = 0; (k != count) && (error == nullptr); ++k) {
        if ( (siteKind(sites[k]) != kTSDRead) || (siteRegister(sites[k]) == 31) )
            continue;
        const uintptr_t site = machHeader + siteOffset(sites[k]);
        const int gap = placeVeneer(site);
        if ( gap < 0 )
            continue;
        const uintptr_t address = cacheBase + table.gap((uint32_t)gap).start + used[gap];
        uint8_t current[kVeneerBytes];
        if ( !memory.read(memory.context, address, current, sizeof(current)) )
            error = "TSD translation: could not read a gap";
        else if ( !isAllZero(current, sizeof(current)) )
            error = "TSD translation: a gap that the site table calls free is not zero";
        used[gap] += kVeneerBytes;
        veneerAt[k] = address;
    }

    // Veneers first, so that no site ever branches to a veneer that is not there yet.
    for (uint32_t k = 0; (k != count) && (error == nullptr); ++k) {
        if ( veneerAt[k] == 0 )
            continue;
        uint32_t words[5];
        bool ok = true;
        encodeVeneer(siteRegister(sites[k]), slot, veneerAt[k], machHeader + siteOffset(sites[k]), words, &ok);
        if ( !ok )
            error = "TSD translation: veneer cannot branch back";
        else if ( !memory.write(memory.context, veneerAt[k], words, sizeof(words)) )
            error = "TSD translation: could not write a veneer";
        else
            memory.sync(memory.context, veneerAt[k], sizeof(words));
    }
    for (uint32_t k = 0; (k != count) && (error == nullptr); ++k) {
        const uint32_t reg = siteRegister(sites[k]);
        const uintptr_t site = machHeader + siteOffset(sites[k]);
        uint32_t word;
        bool ok = true;
        if ( reg == 31 ) {
            word = 0xD503201FU;
            ++stats.nops;
        }
        else if ( siteKind(sites[k]) == kCPUIndexRead ) {
            word = 0xAA1F03E0U | reg;
            ++stats.cpuZeroed;
        }
        else if ( veneerAt[k] != 0 ) {
            word = encodeBranch(site, veneerAt[k], &ok);
            ++stats.veneers;
        }
        else {
            word = 0x0000DA00U | reg;
            ++stats.trapped;
        }
        if ( !ok )
            error = "TSD translation: site cannot branch to its veneer";
        else if ( !memory.write(memory.context, site, &word, sizeof(word)) )
            error = "TSD translation: could not write a site";
        else
            memory.sync(memory.context, site, sizeof(word));
    }
    free(veneerAt);
    if ( error != nullptr )
        return error;
    done[index] = 1;
    if ( statsOut != nullptr )
        *statsOut = stats;
    return nullptr;
}

}
}
