// Shared by the host tests of dyld3/DarlingTSDIslands.cpp.
#ifndef DarlingTSDTestSupport_h
#define DarlingTSDTestSupport_h

#include "DarlingTSDIslands.h"

#include <stdio.h>
#include <string.h>
#include <vector>

using namespace dyld3::darling_tsd;

inline int checks, failures;
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

#endif
