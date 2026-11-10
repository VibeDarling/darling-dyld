#include "DarlingTSDIslands.h"

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

}
}
