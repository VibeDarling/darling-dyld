// Darling: translation of `mrs Xt, TPIDRRO_EL0` in macOS dyld shared-cache code.
//
// macOS code reads its thread-specific-data (TSD) base from TPIDRRO_EL0. Linux reads 0 there, and Darling keeps the
// base in a dedicated slot of the native thread (sys_thread_get_native_tsd_slot_offset). Each read in cache text is
// replaced by a `b` to a 20 byte veneer that loads the slot. The cache text is 3.7 GB and a `b` reaches 128 MB, so
// veneers live in the zero padding between images (`gaps`). Which words to rewrite, and which gaps are free, comes
// from a sidecar table made from the cache by tests/darling-tsd/emit_tsd_sites.py.
//
// Nothing here depends on dyld: the host tests compile this file on their own.
#ifndef DarlingTSDIslands_h
#define DarlingTSDIslands_h

#include <stddef.h>
#include <stdint.h>

namespace dyld3 {
namespace darling_tsd {

enum : uint32_t {
    kMRSTPIDRRO = 0xD53BD060U,      // mrs Xt, TPIDRRO_EL0 (Xt in bits 0-4)
    kVeneerBytes = 20,
};

// What a site is. Both are an `mrs Xd, TPIDRRO_EL0` in the cache.
enum SiteKind : uint32_t {
    kTSDRead = 0,       // the TSD base: becomes a branch to a veneer
    kCPUIndexRead = 1,  // followed by `lsr Xd, Xd, #12`: the CPU number in the low bits, becomes `mov Xd, xzr`
};

// Sidecar file, little endian. Offsets are from the cache base (the main file's mapping address).
//   TableHeader | Gap[gapCount] | ImageRecord[imageCount] | uint32_t site[siteCount]
// site = (offset from the image's mach header >> 2) << 6 | kind << 5 | register
struct TableHeader {
    char     magic[8];      // "DTSDSIT1"
    uint8_t  uuid[16];      // UUID of the main cache file
    uint32_t gapCount;
    uint32_t imageCount;
    uint32_t siteCount;
    uint32_t reserved;      // zero
};
struct Gap { uint32_t start; uint32_t size; };
struct ImageRecord { uint32_t imageOffset; uint32_t firstSite; uint32_t siteCount; };

inline uint32_t encodeSite(uint32_t offsetFromImage, SiteKind kind, uint32_t reg) { return ((offsetFromImage >> 2) << 6) | ((uint32_t)kind << 5) | reg; }
inline uint32_t siteOffset(uint32_t site) { return (site >> 6) << 2; }
inline SiteKind siteKind(uint32_t site) { return (SiteKind)((site >> 5) & 1); }
inline uint32_t siteRegister(uint32_t site) { return site & 31; }

// A validated, borrowed view of a sidecar. The bytes must be 4-byte aligned and outlive the view.
class SiteTable {
public:
    // Returns null when the table is well formed, otherwise a static message. Checks the counts against the
    // length, that gaps and images are sorted, aligned and disjoint, that site words are ascending inside their
    // image and below the next image, and that no gap contains a site.
    const char*        parse(const void* bytes, size_t length);
    const uint8_t*     uuid() const { return header->uuid; }
    uint32_t           gapCount() const { return header->gapCount; }
    const Gap&         gap(uint32_t i) const { return gaps[i]; }
    uint32_t           imageCount() const { return header->imageCount; }
    // The record for the image whose mach header is at `imageOffset`, or null.
    const ImageRecord* findImage(uint32_t imageOffset, uint32_t* index) const;
    const uint32_t*    sites(const ImageRecord& image) const { return sitesArray + image.firstSite; }
private:
    const TableHeader*  header = nullptr;
    const Gap*          gaps = nullptr;
    const ImageRecord*  images = nullptr;
    const uint32_t*     sitesArray = nullptr;
};

// Instruction encoders (exposed for the tests).
uint32_t encodeBranch(uintptr_t from, uintptr_t to, bool* ok);                        // b
void     encodeVeneer(uint32_t reg, unsigned long slotOffset, uintptr_t veneer, uintptr_t site, uint32_t out[5], bool* ok);
bool     isValidSlotOffset(unsigned long slotOffset);

}
}

#endif
