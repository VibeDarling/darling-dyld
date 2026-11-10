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

// Sidecar file, little endian, 8-byte aligned. Offsets are from the cache base (the main file's mapping address); the
// cache is more than 4 GiB from its first to its last text page, so they are 64 bits.
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
struct Gap { uint64_t start; uint64_t size; };
struct ImageRecord { uint64_t imageOffset; uint32_t firstSite; uint32_t siteCount; };

inline uint32_t encodeSite(uint32_t offsetFromImage, SiteKind kind, uint32_t reg) { return ((offsetFromImage >> 2) << 6) | ((uint32_t)kind << 5) | reg; }
inline uint32_t siteOffset(uint32_t site) { return (site >> 6) << 2; }
inline SiteKind siteKind(uint32_t site) { return (SiteKind)((site >> 5) & 1); }
inline uint32_t siteRegister(uint32_t site) { return site & 31; }

// A validated, borrowed view of a sidecar. The bytes must be 8-byte aligned and outlive the view.
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
    const ImageRecord& image(uint32_t i) const { return images[i]; }
    // The record for the image whose mach header is at `imageOffset`, or null.
    const ImageRecord* findImage(uint64_t imageOffset, uint32_t* index) const;
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

// How the patcher touches memory. All addresses are in the process; `write` must not change page protections.
struct Memory {
    void* context;
    bool (*read)(void* context, uintptr_t address, void* out, size_t length);
    bool (*write)(void* context, uintptr_t address, const void* data, size_t length);
    void (*sync)(void* context, uintptr_t address, size_t length);    // make written code visible to instruction fetch
};

struct PatchStats {
    uint32_t sites;         // sites in the image
    uint32_t veneers;       // sites that now branch to a veneer
    uint32_t cpuZeroed;     // CPU-index reads replaced by `mov Xd, xzr`
    uint32_t nops;          // reads into xzr replaced by nop
    uint32_t trapped;       // no gap in reach: left as `udf #0xDA00|reg`, handled by the kernel trap emulator
};

// An address range of the cache that is mapped executable. The patcher writes only inside these.
struct ExecutableRange { uintptr_t start; uintptr_t size; };

class Patcher {
public:
    Patcher(const SiteTable& table, uintptr_t cacheBase, unsigned long slotOffset);
    ~Patcher();
    Patcher(const Patcher&) = delete;
    Patcher& operator=(const Patcher&) = delete;
    // Null when usable, otherwise a static message. `ranges` are the cache's executable mappings: every gap of the
    // table must lie inside one, and so must every image and site later, because writes through /proc/self/mem
    // ignore page protections and a stale table must not be able to write anywhere else.
    const char* init(const ExecutableRange* ranges, uint32_t rangeCount);
    // Translates every site of the image whose mach header is at `machHeader`. Every site is checked against
    // the table before anything is written; an image the table does not list, a site that does not hold the
    // expected instruction and a gap that is not zero are errors. Safe to call twice for one image. An error
    // after the first write leaves the image half translated: the caller must treat it as fatal.
    // The caller serialises calls (dyld holds its lock).
    const char* patchImage(uintptr_t machHeader, const Memory& memory, PatchStats* stats);
    uint32_t    bytesUsed(uint32_t gapIndex) const { return used[gapIndex]; }
private:
    bool        inExecutable(uintptr_t address, size_t length) const;
    bool        nextWithRoom(int64_t* index, int step, uintptr_t* address) const;
    int         placeVeneer(uintptr_t site) const;
    const SiteTable& table;
    uintptr_t   cacheBase;
    unsigned long slot;
    uint32_t*   used = nullptr;
    uint8_t*    done = nullptr;
    ExecutableRange* executable = nullptr;
    uint32_t    executableCount = 0;
};

// Memory that reads in place and writes through /proc/self/mem, so a page that holds a neighbour's running code is
// never unprotected. Writing a private file mapping this way copies the page, never the file.
class ProcSelfMemory {
public:
    ProcSelfMemory();
    ~ProcSelfMemory();
    ProcSelfMemory(const ProcSelfMemory&) = delete;
    ProcSelfMemory& operator=(const ProcSelfMemory&) = delete;
    bool   ok() const { return fd >= 0; }
    Memory memory();
private:
    int fd;
};

// Disk images (plain arm64, text mapped writable): `mrs Xt, TPIDRRO_EL0; and Xt, Xt, #imm` (the pthread_self shape)
// becomes `mrs Xt, TPIDR_EL0; ldr Xt, [Xt, #slotOffset]`. A lone mrs becomes `mrs Xt, TPIDR_EL0` as before, which
// reads the Linux thread pointer, not the TSD base, and reports nothing (known issue, not changed here).
// Returns false, after rewriting everything else, when a read needs the slot and `slotOffset` is not usable.
bool rewriteDiskTSDReads(uint32_t* instructions, size_t count, unsigned long slotOffset, size_t* rewritten);

}
}

#endif
