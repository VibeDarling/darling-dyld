// Host tests for dyld3/DarlingTSDIslands.cpp. Built and run by tests/darling-tsd-islands.rb.
#include "DarlingTSDIslands.h"

#include <stdio.h>
#include <string.h>
#include <vector>

using namespace dyld3::darling_tsd;

extern "C" {
    extern uint32_t oracle_mrs_x9, oracle_mrs_xzr, oracle_lsr_x9, oracle_mov_x9, oracle_nop, oracle_trap_x9;
    extern uint32_t oracle_veneer[5], oracle_veneer_x30[5], oracle_return, oracle_branch_forward;
}

static int checks, failures;
#define CHECK(condition) do { ++checks; if ( !(condition) ) { ++failures; fprintf(stderr, "FAIL %s:%d: %s\n", __FILE__, __LINE__, #condition); } } while (0)

struct ImageSpec { uint32_t imageOffset; std::vector<uint32_t> sites; };

// Builds the sidecar bytes in 4-byte aligned storage.
struct TableBuilder {
    std::vector<Gap> gaps;
    std::vector<ImageSpec> images;
    uint8_t uuid[16] = { 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16 };
    std::vector<uint32_t> storage;
    size_t length = 0;
    void build() {
        std::vector<uint32_t> sites;
        std::vector<ImageRecord> records;
        for (const ImageSpec& image : images) {
            records.push_back({ image.imageOffset, (uint32_t)sites.size(), (uint32_t)image.sites.size() });
            sites.insert(sites.end(), image.sites.begin(), image.sites.end());
        }
        TableHeader header = {};
        memcpy(header.magic, "DTSDSIT1", 8);
        memcpy(header.uuid, uuid, 16);
        header.gapCount = (uint32_t)gaps.size();
        header.imageCount = (uint32_t)records.size();
        header.siteCount = (uint32_t)sites.size();
        length = sizeof(header) + gaps.size() * sizeof(Gap) + records.size() * sizeof(ImageRecord) + sites.size() * 4;
        storage.assign(length / 4, 0);
        uint8_t* out = (uint8_t*)storage.data();
        memcpy(out, &header, sizeof(header));
        out += sizeof(header);
        if ( !gaps.empty() ) memcpy(out, gaps.data(), gaps.size() * sizeof(Gap));
        out += gaps.size() * sizeof(Gap);
        if ( !records.empty() ) memcpy(out, records.data(), records.size() * sizeof(ImageRecord));
        out += records.size() * sizeof(ImageRecord);
        if ( !sites.empty() ) memcpy(out, sites.data(), sites.size() * 4);
    }
    const char* parse(SiteTable& table) { build(); return table.parse(storage.data(), length); }
};

static TableBuilder sample() {
    TableBuilder b;
    b.gaps = { { 0x1000, 0x40 }, { 0x3ff0, 0x10010 } };
    b.images = {
        { 0x0, { encodeSite(0x100, kTSDRead, 9), encodeSite(0x104, kCPUIndexRead, 0) } },
        { 0x2000, {} },
        { 0x20000, { encodeSite(0x40, kTSDRead, 31) } },
    };
    return b;
}

static void testParse() {
    SiteTable table;
    TableBuilder b = sample();
    CHECK(b.parse(table) == nullptr);
    CHECK(table.gapCount() == 2 && table.imageCount() == 3);
    CHECK(table.gap(1).start == 0x3ff0 && table.gap(1).size == 0x10010);
    CHECK(memcmp(table.uuid(), b.uuid, 16) == 0);
    uint32_t index = 99;
    const ImageRecord* r = table.findImage(0x20000, &index);
    CHECK(r != nullptr && index == 2 && r->siteCount == 1);
    CHECK(siteOffset(table.sites(*r)[0]) == 0x40 && siteRegister(table.sites(*r)[0]) == 31 && siteKind(table.sites(*r)[0]) == kTSDRead);
    r = table.findImage(0x0, &index);
    CHECK(r != nullptr && index == 0 && r->siteCount == 2);
    const uint32_t cpu = table.sites(*r)[1];
    CHECK(siteKind(cpu) == kCPUIndexRead && siteRegister(cpu) == 0 && siteOffset(cpu) == 0x104);
    CHECK(table.findImage(0x2000, nullptr) != nullptr);
    CHECK(table.findImage(0x2004, nullptr) == nullptr);
    CHECK(table.findImage(0x30000, nullptr) == nullptr);
    // largest offset a site can carry: 26 bits of words
    CHECK(siteOffset(encodeSite(0x0FFFFFFC, kTSDRead, 1)) == 0x0FFFFFFC);

    TableBuilder empty;
    CHECK(empty.parse(table) == nullptr && table.imageCount() == 0 && table.findImage(0, nullptr) == nullptr);
}

// Each case corrupts one aspect of a valid table and expects a refusal.
static void testRefusals() {
    SiteTable table;
    { TableBuilder b = sample(); b.build(); CHECK(table.parse(b.storage.data(), b.length - 4) != nullptr); }
    { TableBuilder b = sample(); b.build(); CHECK(table.parse(b.storage.data(), 8) != nullptr); }
    { TableBuilder b = sample(); b.build(); CHECK(table.parse(nullptr, b.length) != nullptr); }
    { TableBuilder b = sample(); b.build(); CHECK(table.parse((const uint8_t*)b.storage.data() + 2, b.length - 4) != nullptr); }
    { TableBuilder b = sample(); b.build(); ((char*)b.storage.data())[0] = 'X'; CHECK(table.parse(b.storage.data(), b.length) != nullptr); }
    { TableBuilder b = sample(); b.build(); b.storage[9] = 1; CHECK(table.parse(b.storage.data(), b.length) != nullptr); }        // reserved
    { TableBuilder b = sample(); b.build(); b.storage[8] += 1; CHECK(table.parse(b.storage.data(), b.length) != nullptr); }       // siteCount
    { TableBuilder b = sample(); b.gaps[0].start = 0x1002; CHECK(b.parse(table) != nullptr); }
    { TableBuilder b = sample(); b.gaps[0].size = 0x42; CHECK(b.parse(table) != nullptr); }
    { TableBuilder b = sample(); b.gaps[0].size = 16; CHECK(b.parse(table) != nullptr); }                                         // below one veneer
    { TableBuilder b = sample(); b.gaps[1].start = 0x1020; CHECK(b.parse(table) != nullptr); }                                   // overlaps gap 0
    { TableBuilder b = sample(); std::swap(b.gaps[0], b.gaps[1]); CHECK(b.parse(table) != nullptr); }                            // unsorted
    { TableBuilder b = sample(); b.gaps[1] = { 0xFFFFFFF0, 0x20 }; CHECK(b.parse(table) != nullptr); }                           // wraps
    { TableBuilder b = sample(); b.images[1].imageOffset = 0x20000; CHECK(b.parse(table) != nullptr); }                          // duplicate
    { TableBuilder b = sample(); std::swap(b.images[0], b.images[2]); CHECK(b.parse(table) != nullptr); }                        // unsorted
    { TableBuilder b = sample(); b.images[0].sites = { encodeSite(0x104, kTSDRead, 9), encodeSite(0x100, kTSDRead, 9) }; CHECK(b.parse(table) != nullptr); }
    { TableBuilder b = sample(); b.images[0].sites = { encodeSite(0x100, kTSDRead, 9), encodeSite(0x100, kTSDRead, 10) }; CHECK(b.parse(table) != nullptr); }
    { TableBuilder b = sample(); b.images[0].sites.push_back(encodeSite(0x2000, kTSDRead, 9)); CHECK(b.parse(table) != nullptr); } // reaches the next image
    { TableBuilder b = sample(); b.images[0].sites = { encodeSite(0x1000, kTSDRead, 9) }; CHECK(b.parse(table) != nullptr); }     // inside gap 0
    { TableBuilder b = sample(); b.images[0].sites = { encodeSite(0x103C, kTSDRead, 9) }; CHECK(b.parse(table) != nullptr); }     // last word of gap 0
    { TableBuilder b = sample(); b.images[0].sites = { encodeSite(0x1040, kTSDRead, 9) }; CHECK(b.parse(table) == nullptr); }     // first word after it
    // header is 10 words, then 2 gaps of 2 words, then image records of 3 words: {imageOffset, firstSite, siteCount}
    { TableBuilder b = sample(); b.build(); b.storage[10 + 4 + 1] = 1; CHECK(table.parse(b.storage.data(), b.length) != nullptr); }   // firstSite of image 0
    { TableBuilder b = sample(); b.build(); b.storage[10 + 4 + 3 + 1] = 1; CHECK(table.parse(b.storage.data(), b.length) != nullptr); } // image 1 starts inside image 0's sites
    { TableBuilder b = sample(); b.build(); b.storage.push_back(0); CHECK(table.parse(b.storage.data(), b.length + 4) != nullptr); }  // trailing bytes
    { TableBuilder b = sample(); b.gaps[1].start = 0x103C; CHECK(b.parse(table) != nullptr); }                                   // overlaps gap 0 by one word
}

static void testEncoders() {
    bool ok = true;
    CHECK(kMRSTPIDRRO == (oracle_mrs_x9 & ~31U) && (kMRSTPIDRRO | 31) == oracle_mrs_xzr);
    CHECK((0xD34CFC00U | (9 << 5) | 9) == oracle_lsr_x9);
    CHECK((0xAA1F03E0U | 9) == oracle_mov_x9 && oracle_nop == 0xD503201FU && (0x0000DA00U | 9) == oracle_trap_x9);

    uint32_t veneer[5];
    encodeVeneer(9, 0x170, (uintptr_t)oracle_veneer, (uintptr_t)&oracle_return - 4, veneer, &ok);
    CHECK(ok && memcmp(veneer, oracle_veneer, 20) == 0);
    ok = true;
    encodeVeneer(30, 0x7ff8, (uintptr_t)oracle_veneer_x30, (uintptr_t)&oracle_return - 4, veneer, &ok);
    CHECK(ok && memcmp(veneer, oracle_veneer_x30, 20) == 0);

    ok = true;
    CHECK(encodeBranch((uintptr_t)&oracle_branch_forward, (uintptr_t)&oracle_return, &ok) == oracle_branch_forward && ok);
    // reach: +128 MiB - 4 and -128 MiB encode, +128 MiB and anything unaligned do not
    const uintptr_t base = 0x400000000ULL;
    ok = true; encodeBranch(base, base + (1U << 27) - 4, &ok); CHECK(ok);
    ok = true; encodeBranch(base, base - (1U << 27), &ok); CHECK(ok);
    ok = true; encodeBranch(base, base + (1U << 27), &ok); CHECK(!ok);
    ok = true; encodeBranch(base, base - (1U << 27) - 4, &ok); CHECK(!ok);
    ok = true; encodeBranch(base, base + 2, &ok); CHECK(!ok);
    // a veneer too far from the site refuses
    ok = true; encodeVeneer(9, 0x170, base, base + (1U << 27) + 16, veneer, &ok); CHECK(!ok);

    CHECK(isValidSlotOffset(16) && isValidSlotOffset(0x170) && isValidSlotOffset(32760));
    CHECK(!isValidSlotOffset(8) && !isValidSlotOffset(0x171) && !isValidSlotOffset(32768) && !isValidSlotOffset(~0UL));
}

int main() {
    testParse();
    testRefusals();
    testEncoders();
    printf("%d checks, %d failures\n", checks, failures);
    return failures == 0 ? 0 : 1;
}
