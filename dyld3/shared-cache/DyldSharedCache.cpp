/* -*- mode: C++; c-basic-offset: 4; indent-tabs-mode: nil -*-
 *
 * Copyright (c) 2014 Apple Inc. All rights reserved.
 *
 * @APPLE_LICENSE_HEADER_START@
 *
 * This file contains Original Code and/or Modifications of Original Code
 * as defined in and that are subject to the Apple Public Source License
 * Version 2.0 (the 'License'). You may not use this file except in
 * compliance with the License. Please obtain a copy of the License at
 * http://www.opensource.apple.com/apsl/ and read it before using this
 * file.
 *
 * The Original Code and all software distributed under the License are
 * distributed on an 'AS IS' basis, WITHOUT WARRANTY OF ANY KIND, EITHER
 * EXPRESS OR IMPLIED, AND APPLE HEREBY DISCLAIMS ALL SUCH WARRANTIES,
 * INCLUDING WITHOUT LIMITATION, ANY WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE, QUIET ENJOYMENT OR NON-INFRINGEMENT.
 * Please see the License for the specific language governing rights and
 * limitations under the License.
 *
 * @APPLE_LICENSE_HEADER_END@
 */


#include <dirent.h>
#include <sys/errno.h>
#include <sys/fcntl.h>
#include <sys/param.h>
#include <mach/mach.h>
#include <mach-o/loader.h>
#include <mach-o/fat.h>
#include <mach-o/dyld_priv.h>
#include <assert.h>
#include <unistd.h>
#include <dlfcn.h>

#if BUILDING_CACHE_BUILDER
#include <set>
#include <string>
#include <vector>
#include <unordered_map>
#include <unordered_set>
#include "SharedCacheBuilder.h"
#include "FileUtils.h"
#endif

#define NO_ULEB
#include "MachOLoaded.h"
#include "ClosureFileSystemPhysical.h"
#include "DyldSharedCache.h"
#include "Trie.hpp"
#include "StringUtils.h"

#include "objc-shared-cache.h"

#if !(BUILDING_LIBDYLD || BUILDING_DYLD)
#include "JSONWriter.h"
#include <sstream>
#endif

#if (BUILDING_LIBDYLD || BUILDING_DYLD)
VIS_HIDDEN bool gEnableSharedCacheDataConst = false;
#endif


#if BUILDING_CACHE_BUILDER
DyldSharedCache::CreateResults DyldSharedCache::create(const CreateOptions&               options,
                                                       const dyld3::closure::FileSystem&  fileSystem,
                                                       const std::vector<MappedMachO>&    dylibsToCache,
                                                       const std::vector<MappedMachO>&    otherOsDylibs,
                                                       const std::vector<MappedMachO>&    osExecutables)
{
    CreateResults       results;
    SharedCacheBuilder  cache(options, fileSystem);
    if (!cache.errorMessage().empty()) {
        results.errorMessage = cache.errorMessage();
        return results;
    }

    std::vector<FileAlias> aliases;
    switch ( options.platform ) {
        case dyld3::Platform::iOS:
        case dyld3::Platform::watchOS:
        case dyld3::Platform::tvOS:
            // FIXME: embedded cache builds should be getting aliases from manifest
            aliases.push_back({"/System/Library/Frameworks/IOKit.framework/Versions/A/IOKit", "/System/Library/Frameworks/IOKit.framework/IOKit"});
            aliases.push_back({"/usr/lib/libstdc++.6.dylib",                                  "/usr/lib/libstdc++.dylib"});
            aliases.push_back({"/usr/lib/libstdc++.6.dylib",                                  "/usr/lib/libstdc++.6.0.9.dylib"});
            aliases.push_back({"/usr/lib/libz.1.dylib",                                       "/usr/lib/libz.dylib"});
            aliases.push_back({"/usr/lib/libSystem.B.dylib",                                  "/usr/lib/libSystem.dylib"});
            aliases.push_back({"/System/Library/Frameworks/Foundation.framework/Foundation",  "/usr/lib/libextension.dylib"}); // <rdar://44315703>
            break;
        default:
            break;
    }

    cache.build(dylibsToCache, otherOsDylibs, osExecutables, aliases);

    results.agileSignature = cache.agileSignature();
    results.cdHashFirst    = cache.cdHashFirst();
    results.cdHashSecond   = cache.cdHashSecond();
    results.warnings       = cache.warnings();
    results.evictions      = cache.evictions();
    if ( cache.errorMessage().empty() ) {
        if ( !options.outputFilePath.empty() )  {
            // write cache file, if path non-empty
            cache.writeFile(options.outputFilePath);
        }
        if ( !options.outputMapFilePath.empty() ) {
            // write map file, if path non-empty
            cache.writeMapFile(options.outputMapFilePath);
        }
    }
    results.errorMessage = cache.errorMessage();
    cache.deleteBuffer();
    return results;
}

bool DyldSharedCache::verifySelfContained(std::vector<MappedMachO>& dylibsToCache,
                                          std::unordered_set<std::string>& badZippered,
                                          MappedMachO (^loader)(const std::string& runtimePath, Diagnostics& diag),
                                          std::vector<std::pair<DyldSharedCache::MappedMachO, std::set<std::string>>>& rejected)
{
    // build map of dylibs
    __block std::map<std::string, std::set<std::string>> badDylibs;
    __block std::set<std::string> knownDylibs;
    for (const DyldSharedCache::MappedMachO& dylib : dylibsToCache) {
        std::set<std::string> reasons;
        if ( dylib.mh->canBePlacedInDyldCache(dylib.runtimePath.c_str(), ^(const char* msg) { badDylibs[dylib.runtimePath].insert(msg);}) ) {
            knownDylibs.insert(dylib.runtimePath);
            knownDylibs.insert(dylib.mh->installName());
        } else {
            badDylibs[dylib.runtimePath].insert("");
        }
    }

    // check all dependencies to assure every dylib in cache only depends on other dylibs in cache
    __block std::set<std::string> missingWeakDylibs;
    __block bool doAgain = true;
    while ( doAgain ) {
        __block std::vector<DyldSharedCache::MappedMachO> foundMappings;
        doAgain = false;
        // scan dylib list making sure all dependents are in dylib list
        for (const DyldSharedCache::MappedMachO& dylib : dylibsToCache) {
            if ( badDylibs.count(dylib.runtimePath) != 0 )
                continue;
            dylib.mh->forEachDependentDylib(^(const char* loadPath, bool isWeak, bool isReExport, bool isUpward, uint32_t compatVersion, uint32_t curVersion, bool& stop) {
                if ( isWeak && (missingWeakDylibs.count(loadPath) != 0) )
                    return;
                if ( knownDylibs.count(loadPath) == 0 ) {
                    doAgain = true;
                    if ( badZippered.count(loadPath) != 0 ) {
                        badDylibs[dylib.runtimePath].insert("");
                        knownDylibs.erase(dylib.runtimePath);
                        knownDylibs.erase(dylib.mh->installName());
                        badZippered.insert(dylib.runtimePath);
                        badZippered.insert(dylib.mh->installName());
                        return;
                    }
                    Diagnostics diag;
                    MappedMachO foundMapping;
                    if ( badDylibs.count(loadPath) == 0 )
                        foundMapping = loader(loadPath, diag);
                    if ( foundMapping.length == 0 ) {
                        // We allow weakly linked dylibs to be missing only if they are not present on disk
                        // The shared cache doesn't contain enough information to patch them in later if they are
                        // found on disk, so we don't want to pull something in to cache and cut it off from a dylib it
                        // could have used.
                        if ( isWeak ) {
                            missingWeakDylibs.insert(loadPath);
                            return;
                        }

                        if (diag.hasError())
                            badDylibs[dylib.runtimePath].insert(diag.errorMessage());
                        else
                            badDylibs[dylib.runtimePath].insert(std::string("Could not find dependency '") + loadPath +"'");
                        knownDylibs.erase(dylib.runtimePath);
                        knownDylibs.erase(dylib.mh->installName());
                    }
                    else {
                        std::set<std::string> reasons;
                        if ( foundMapping.mh->canBePlacedInDyldCache(foundMapping.runtimePath.c_str(), ^(const char* msg) { badDylibs[foundMapping.runtimePath].insert(msg);})) {
                            // see if existing mapping was returned
                            bool alreadyInVector = false;
                            for (const MappedMachO& existing : dylibsToCache) {
                                if ( existing.mh == foundMapping.mh ) {
                                    alreadyInVector = true;
                                    break;
                                }
                            }
                            if ( !alreadyInVector )
                                foundMappings.push_back(foundMapping);
                            knownDylibs.insert(loadPath);
                            knownDylibs.insert(foundMapping.runtimePath);
                            knownDylibs.insert(foundMapping.mh->installName());
                        } else {
                            badDylibs[dylib.runtimePath].insert("");
                        }
                   }
                }
            });
        }
        dylibsToCache.insert(dylibsToCache.end(), foundMappings.begin(), foundMappings.end());
        // remove bad dylibs
        const auto badDylibsCopy = badDylibs;
        dylibsToCache.erase(std::remove_if(dylibsToCache.begin(), dylibsToCache.end(), [&](const DyldSharedCache::MappedMachO& dylib) {
            auto i = badDylibsCopy.find(dylib.runtimePath);
            if ( i !=  badDylibsCopy.end()) {
                // Only add the warning if we are not a bad zippered dylib
                if ( badZippered.count(dylib.runtimePath) == 0 )
                    rejected.push_back(std::make_pair(dylib, i->second));
                return true;
             }
             else {
                return false;
             }
        }), dylibsToCache.end());
    }

    return badDylibs.empty();
}
#endif

template<typename T>
const T DyldSharedCache::getAddrField(uint64_t addr) const {
    uint64_t slide = (uint64_t)this - unslidLoadAddress();
    return (const T)(addr + slide);
}

uint64_t DyldSharedCache::getCodeSignAddress() const
{
    // The main file lists only its own mappings; the address after the last sub-cache is the end of the region.
    if ( dyld_cache_header_is_split(header) )
        return header.sharedRegionStart + header.sharedRegionSize;
    auto mappings = (const dyld_cache_mapping_info*)((uint8_t*)this + header.mappingOffset);
    return mappings[header.mappingCount-1].address + mappings[header.mappingCount-1].size;
}

// The mapping tables of the main file and every sub-cache file of a split cache, read where the mapper put
// the files' headers (the main header at the cache address, a sub-cache's at its cacheVMOffset). Every table
// has to lie inside its header's first mapping, which has to start at the header: if any does not, there is
// no usable answer and false is returned.
static const uint32_t kMaxSplitSubCaches = 32;       // as in the mapper
static const uint32_t kMaxSplitFileMappings = 20;
static const uint64_t kMinMappingSize = 0x1000;      // a header's first table entry is read before its size is known

static bool splitFileMappingTable(const dyld_cache_header* header, uint64_t firstAddress,
                                  const dyld_cache_mapping_and_slide_info** table, uint32_t* count)
{
    const uint64_t offset = header->mappingWithSlideOffset;
    *count = header->mappingWithSlideCount;
    if ( (*count == 0) || (*count > kMaxSplitFileMappings) || (offset % alignof(dyld_cache_mapping_and_slide_info) != 0)
      || !dyld_cache_range_contains(0, kMinMappingSize, offset, sizeof(dyld_cache_mapping_and_slide_info)) )
        return false;
    *table = (const dyld_cache_mapping_and_slide_info*)((const char*)header + offset);
    return ((*table)[0].address == firstAddress) && ((*table)[0].fileOffset == 0)
        && dyld_cache_range_contains(0, (*table)[0].size, offset, uint64_t(*count) * sizeof(dyld_cache_mapping_and_slide_info));
}

static bool splitCacheTables(const DyldSharedCache* cache, const dyld_cache_mapping_and_slide_info* tables[],
                             uint32_t counts[], uint32_t* files)
{
    const dyld_cache_header& main = cache->header;
    const uint32_t subCaches = main.subCacheArrayCount;
    if ( !splitFileMappingTable(&main, main.sharedRegionStart, &tables[0], &counts[0]) || (subCaches > kMaxSplitSubCaches)
      || (main.subCacheArrayOffset % alignof(dyld_subcache_entry) != 0)
      || !dyld_cache_range_contains(0, tables[0][0].size, main.subCacheArrayOffset, uint64_t(subCaches) * sizeof(dyld_subcache_entry)) )
        return false;
    const dyld_subcache_entry* entries = (const dyld_subcache_entry*)((const char*)cache + main.subCacheArrayOffset);
    for (uint32_t i = 0; i != subCaches; ++i) {
        if ( !dyld_cache_range_contains(0, main.sharedRegionSize, entries[i].cacheVMOffset, kMinMappingSize) )
            return false;
        const dyld_cache_header* header = (const dyld_cache_header*)((const char*)cache + entries[i].cacheVMOffset);
        if ( !splitFileMappingTable(header, main.sharedRegionStart + entries[i].cacheVMOffset, &tables[i + 1], &counts[i + 1]) )
            return false;
    }
    *files = subCaches + 1;
    return true;
}

// A split cache lists its images in the main file at imagesOffsetSplit; the legacy table is empty then.
static const dyld_cache_image_info* cacheImageTable(const dyld_cache_header& header, const void* cacheBase, uint32_t& count)
{
    if ( dyld_cache_header_is_split(header) ) {
        count = header.imagesCountSplit;
        return (const dyld_cache_image_info*)((const char*)cacheBase + header.imagesOffsetSplit);
    }
    count = header.imagesCount;
    return (const dyld_cache_image_info*)((const char*)cacheBase + header.imagesOffset);
}

const dyld_cache_image_info* DyldSharedCache::imageTable(uint32_t& count) const
{
    return cacheImageTable(header, this, count);
}

bool DyldSharedCache::isSplitCache() const
{
    return dyld_cache_header_is_split(header);
}

void DyldSharedCache::forEachRegion(void (^handler)(const void* content, uint64_t vmAddr, uint64_t size,
                                                    uint32_t initProt, uint32_t maxProt, uint64_t flags)) const
{
    // <rdar://problem/49875993> sanity check cache header
    if ( strncmp(header.magic, "dyld_v1", 7) != 0 )
        return;
    if ( header.mappingOffset > 1024 )
        return;
    if ( header.mappingCount > 20 )
        return;
    if ( header.mappingOffset <= __offsetof(dyld_cache_header, mappingWithSlideOffset) ) {
        const dyld_cache_mapping_info* mappings = (dyld_cache_mapping_info*)((char*)this + header.mappingOffset);
        const dyld_cache_mapping_info* mappingsEnd = &mappings[header.mappingCount];
        for (const dyld_cache_mapping_info* m=mappings; m < mappingsEnd; ++m) {
            handler((char*)this + m->fileOffset, m->address, m->size, m->initProt, m->maxProt, 0);
        }
    } else {
        if ( dyld_cache_header_is_split(header) ) {
            // Sub-cache files are mapped at their VM address, so their content is found there, not at a file offset.
            const dyld_cache_mapping_and_slide_info* tables[kMaxSplitSubCaches + 1];
            uint32_t counts[kMaxSplitSubCaches + 1];
            uint32_t files;
            if ( !splitCacheTables(this, tables, counts, &files) )
                return;
            for (uint32_t f = 0; f != files; ++f) {
                for (uint32_t i = 0; i != counts[f]; ++i) {
                    const dyld_cache_mapping_and_slide_info* m = &tables[f][i];
                    handler((const char*)this + (m->address - tables[0][0].address), m->address, m->size, m->initProt, m->maxProt, m->flags);
                }
            }
            return;
        }
        const dyld_cache_mapping_and_slide_info* mappings = (const dyld_cache_mapping_and_slide_info*)((char*)this + header.mappingWithSlideOffset);
        const dyld_cache_mapping_and_slide_info* mappingsEnd = &mappings[header.mappingCount];
        for (const dyld_cache_mapping_and_slide_info* m=mappings; m < mappingsEnd; ++m) {
            handler((char*)this + m->fileOffset, m->address, m->size, m->initProt, m->maxProt, m->flags);
        }
    }
}

bool DyldSharedCache::inCache(const void* addr, size_t length, bool& readOnly) const
{
    // quick out if before start of cache
    if ( addr < this )
        return false;

    const dyld_cache_mapping_info* mappings = (dyld_cache_mapping_info*)((char*)this + header.mappingOffset);
    uintptr_t slide = (uintptr_t)this - (uintptr_t)(mappings[0].address);
    uintptr_t unslidStart = (uintptr_t)addr - slide;

    // quick out if after end of cache
    const dyld_cache_mapping_info* lastMapping = &mappings[header.mappingCount - 1];
    if ( unslidStart > (lastMapping->address + lastMapping->size) )
        return false;

    // walk cache regions
    const dyld_cache_mapping_info* mappingsEnd = &mappings[header.mappingCount];
    uintptr_t unslidEnd = unslidStart + length;
    for (const dyld_cache_mapping_info* m=mappings; m < mappingsEnd; ++m) {
        if ( (unslidStart >= m->address) && (unslidEnd < (m->address+m->size)) ) {
            readOnly = ((m->initProt & VM_PROT_WRITE) == 0);
            return true;
        }
    }

    return false;
}

bool DyldSharedCache::isAlias(const char* path) const {
    const dyld_cache_mapping_info* mappings = (dyld_cache_mapping_info*)((char*)this + header.mappingOffset);
    uintptr_t slide = (uintptr_t)this - (uintptr_t)(mappings[0].address);
    // paths for aliases are store between cache header and first segment
    return path < ((char*)mappings[0].address + slide);
}

void DyldSharedCache::forEachImage(void (^handler)(const mach_header* mh, const char* installName)) const
{
    uint32_t imagesCount;
    const dyld_cache_image_info*   dylibs   = cacheImageTable(header, this, imagesCount);
    const dyld_cache_mapping_info* mappings = (dyld_cache_mapping_info*)((char*)this + header.mappingOffset);
    if ( mappings[0].fileOffset != 0 )
        return;
    uint64_t firstImageOffset = 0;
    uint64_t firstRegionAddress = mappings[0].address;
    for (uint32_t i=0; i < imagesCount; ++i) {
        const char* dylibPath  = (char*)this + dylibs[i].pathFileOffset;
        uint64_t offset = dylibs[i].address - firstRegionAddress;
        if ( firstImageOffset == 0 )
            firstImageOffset = offset;
        // skip over aliases (a split cache's table has none, and all its paths are in the main file's header area)
        if ( !dyld_cache_header_is_split(header) && (dylibs[i].pathFileOffset < firstImageOffset) )
            continue;
        const mach_header* mh = (mach_header*)((char*)this + offset);
        handler(mh, dylibPath);
    }
}

void DyldSharedCache::forEachImageEntry(void (^handler)(const char* path, uint64_t mTime, uint64_t inode)) const
{
    uint32_t imagesCount;
    const dyld_cache_image_info*   dylibs   = cacheImageTable(header, this, imagesCount);
    const dyld_cache_mapping_info* mappings = (dyld_cache_mapping_info*)((char*)this + header.mappingOffset);
    if ( mappings[0].fileOffset != 0 )
        return;
    uint64_t firstImageOffset = 0;
    uint64_t firstRegionAddress = mappings[0].address;
    for (uint32_t i=0; i < imagesCount; ++i) {
        const char* dylibPath  = (char*)this + dylibs[i].pathFileOffset;
        uint64_t offset = dylibs[i].address - firstRegionAddress;
        if ( firstImageOffset == 0 )
            firstImageOffset = offset;
        // skip over aliases (a split cache's table has none, and all its paths are in the main file's header area)
        if ( !dyld_cache_header_is_split(header) && (dylibs[i].pathFileOffset < firstImageOffset) )
            continue;
        handler(dylibPath, dylibs[i].modTime, dylibs[i].inode);
    }
}

const bool DyldSharedCache::hasLocalSymbolsInfo() const
{
    return (header.localSymbolsOffset != 0 && header.mappingOffset > offsetof(dyld_cache_header,localSymbolsSize));
}

const void* DyldSharedCache::getLocalNlistEntries() const
{
    // check for cache without local symbols info
    if (!this->hasLocalSymbolsInfo())
        return nullptr;
    const auto localInfo = (dyld_cache_local_symbols_info*)((uint8_t*)this + header.localSymbolsOffset);
    return (uint8_t*)localInfo + localInfo->nlistOffset;
}

const uint32_t DyldSharedCache::getLocalNlistCount() const
{
    // check for cache without local symbols info
     if (!this->hasLocalSymbolsInfo())
        return 0;
    const auto localInfo = (dyld_cache_local_symbols_info*)((uint8_t*)this + header.localSymbolsOffset);
    return localInfo->nlistCount;
}

const char* DyldSharedCache::getLocalStrings() const
{
    // check for cache without local symbols info
     if (!this->hasLocalSymbolsInfo())
        return nullptr;
    const auto localInfo = (dyld_cache_local_symbols_info*)((uint8_t*)this + header.localSymbolsOffset);
    return (char*)localInfo + localInfo->stringsOffset;
}

const uint32_t DyldSharedCache::getLocalStringsSize() const
{
    // check for cache without local symbols info
     if (!this->hasLocalSymbolsInfo())
        return 0;
    const auto localInfo = (dyld_cache_local_symbols_info*)((uint8_t*)this + header.localSymbolsOffset);
    return localInfo->stringsSize;
}

 void DyldSharedCache::forEachLocalSymbolEntry(void (^handler)(uint32_t dylibOffset, uint32_t nlistStartIndex, uint32_t nlistCount, bool& stop)) const
{
    // check for cache without local symbols info
     if (!this->hasLocalSymbolsInfo())
        return;
    const auto localInfo = (dyld_cache_local_symbols_info*)((uint8_t*)this + header.localSymbolsOffset);
    const auto localEntries = (dyld_cache_local_symbols_entry*)((uint8_t*)localInfo + localInfo->entriesOffset);
    bool stop = false;
    for (uint32_t i = 0; i < localInfo->entriesCount; i++) {
        dyld_cache_local_symbols_entry localEntry = localEntries[i];
        handler(localEntry.dylibOffset, localEntry.nlistStartIndex, localEntry.nlistCount, stop);
    }
}


const mach_header* DyldSharedCache::getIndexedImageEntry(uint32_t index, uint64_t& mTime, uint64_t& inode) const
{
    uint32_t imagesCount;
    const dyld_cache_image_info*   dylibs   = cacheImageTable(header, this, imagesCount);
    const dyld_cache_mapping_info* mappings = (dyld_cache_mapping_info*)((char*)this + header.mappingOffset);
    mTime = dylibs[index].modTime;
    inode = dylibs[index].inode;
    return (mach_header*)((uint8_t*)this + dylibs[index].address - mappings[0].address);
}


 const char* DyldSharedCache::getIndexedImagePath(uint32_t index) const
{
    uint32_t imagesCount;
    auto dylibs = cacheImageTable(header, this, imagesCount);
    return (char*)this + dylibs[index].pathFileOffset;
}

void DyldSharedCache::forEachImageTextSegment(void (^handler)(uint64_t loadAddressUnslid, uint64_t textSegmentSize, const uuid_t dylibUUID, const char* installName, bool& stop)) const
{
    // check for old cache without imagesText array
    if ( (header.mappingOffset <= __offsetof(dyld_cache_header, imagesTextOffset)) || (header.imagesTextCount == 0) )
        return;

    // walk imageText table and call callback for each entry
    const dyld_cache_image_text_info* imagesText = (dyld_cache_image_text_info*)((char*)this + header.imagesTextOffset);
    const dyld_cache_image_text_info* imagesTextEnd = &imagesText[header.imagesTextCount];
    bool stop = false;
    for (const dyld_cache_image_text_info* p=imagesText; p < imagesTextEnd && !stop; ++p) {
        handler(p->loadAddress, p->textSegmentSize, p->uuid, (char*)this + p->pathOffset, stop);
    }
}

bool DyldSharedCache::addressInText(uint32_t cacheOffset, uint32_t* imageIndex) const
{
    const dyld_cache_mapping_info* mappings = (dyld_cache_mapping_info*)((char*)this + header.mappingOffset);
    if ( cacheOffset > mappings[0].size )
        return false;
    uint64_t targetAddr = mappings[0].address + cacheOffset;
    // walk imageText table and call callback for each entry
    const dyld_cache_image_text_info* imagesText = (dyld_cache_image_text_info*)((char*)this + header.imagesTextOffset);
    const dyld_cache_image_text_info* imagesTextEnd = &imagesText[header.imagesTextCount];
    for (const dyld_cache_image_text_info* p=imagesText; p < imagesTextEnd; ++p) {
        if ( (p->loadAddress <= targetAddr) && (targetAddr < p->loadAddress+p->textSegmentSize) ) {
            *imageIndex = (uint32_t)(p-imagesText);
            return true;
        }
    }
    return false;
}

const char* DyldSharedCache::archName() const
{
    const char* archSubString = ((char*)this) + 7;
    while (*archSubString == ' ')
        ++archSubString;
    return archSubString;
}


dyld3::Platform DyldSharedCache::platform() const
{
    return (dyld3::Platform)header.platform;
}

#if BUILDING_CACHE_BUILDER
std::string DyldSharedCache::mapFile() const
{
    __block std::string             result;
    __block std::vector<uint64_t>   regionStartAddresses;
    __block std::vector<uint64_t>   regionSizes;
    __block std::vector<uint64_t>   regionFileOffsets;

    result.reserve(256*1024);
    forEachRegion(^(const void* content, uint64_t vmAddr, uint64_t size,
                    uint32_t initProt, uint32_t maxProt, uint64_t flags) {
        regionStartAddresses.push_back(vmAddr);
        regionSizes.push_back(size);
        regionFileOffsets.push_back((uint8_t*)content - (uint8_t*)this);
        char lineBuffer[256];
        const char* prot = "RW";
        if ( maxProt == (VM_PROT_EXECUTE|VM_PROT_READ) )
            prot = "EX";
        else if ( maxProt == VM_PROT_READ )
            prot = "RO";
        if ( size > 1024*1024 )
            sprintf(lineBuffer, "mapping  %s %4lluMB 0x%0llX -> 0x%0llX\n", prot, size/(1024*1024), vmAddr, vmAddr+size);
        else
            sprintf(lineBuffer, "mapping  %s %4lluKB 0x%0llX -> 0x%0llX\n", prot, size/1024,        vmAddr, vmAddr+size);
        result += lineBuffer;
    });

    // TODO:  add linkedit breakdown
    result += "\n\n";

    forEachImage(^(const mach_header* mh, const char* installName) {
        result += std::string(installName) + "\n";
        const dyld3::MachOFile* mf = (dyld3::MachOFile*)mh;
        mf->forEachSegment(^(const dyld3::MachOFile::SegmentInfo& info, bool& stop) {
            char lineBuffer[256];
            sprintf(lineBuffer, "\t%16s 0x%08llX -> 0x%08llX\n", info.segName, info.vmAddr, info.vmAddr+info.vmSize);
            result += lineBuffer;
        });
        result += "\n";
    });

    return result;
}
#endif


uint64_t DyldSharedCache::unslidLoadAddress() const
{
    const dyld_cache_mapping_info* mappings = (dyld_cache_mapping_info*)((char*)this + header.mappingOffset);
    return mappings[0].address;
}

void DyldSharedCache::getUUID(uuid_t uuid) const
{
    memcpy(uuid, header.uuid, sizeof(uuid_t));
}

uint64_t DyldSharedCache::mappedSize() const
{
    // The main file lists only its own mappings, but the sub-cache files fill the rest of the region.
    if ( dyld_cache_header_is_split(header) )
        return header.sharedRegionSize;
    __block uint64_t startAddr = 0;
    __block uint64_t endAddr = 0;
    forEachRegion(^(const void* content, uint64_t vmAddr, uint64_t size,
                    uint32_t initProt, uint32_t maxProt, uint64_t flags) {
        if ( startAddr == 0 )
            startAddr = vmAddr;
        uint64_t end = vmAddr+size;
        if ( end > endAddr )
            endAddr = end;
    });
    return (endAddr - startAddr);
}

bool DyldSharedCache::findMachHeaderImageIndex(const mach_header* mh, uint32_t& imageIndex) const
{
    const dyld_cache_mapping_info* mappings = (dyld_cache_mapping_info*)((char*)this + header.mappingOffset);
    uintptr_t slide = (uintptr_t)this - (uintptr_t)(mappings[0].address);
    uint64_t unslidMh = (uintptr_t)mh - slide;
    uint32_t imagesCount;
    const dyld_cache_image_info* dylibs = cacheImageTable(header, this, imagesCount);
    for (uint32_t i=0; i < imagesCount; ++i) {
        if ( dylibs[i].address == unslidMh ) {
            imageIndex = i;
            return true;
        }
    }
    return false;
}

bool DyldSharedCache::hasImagePath(const char* dylibPath, uint32_t& imageIndex) const
{
    const dyld_cache_mapping_info* mappings = (dyld_cache_mapping_info*)((char*)this + header.mappingOffset);
    if ( mappings[0].fileOffset != 0 )
        return false;
    if ( (header.mappingOffset >= 0x118) && !(dyld_cache_header_is_split(header) && (header.dylibsTrieSize == 0)) ) {
        uintptr_t      slide           = (uintptr_t)this - (uintptr_t)(mappings[0].address);
        const uint8_t* dylibTrieStart  = (uint8_t*)(this->header.dylibsTrieAddr + slide);
        const uint8_t* dylibTrieEnd    = dylibTrieStart + this->header.dylibsTrieSize;

        Diagnostics diag;
        const uint8_t* imageNode = dyld3::MachOLoaded::trieWalk(diag, dylibTrieStart, dylibTrieEnd, dylibPath);
        if ( imageNode != NULL ) {
            imageIndex = (uint32_t)dyld3::MachOFile::read_uleb128(diag, imageNode, dylibTrieEnd);
            return true;
        }
    }
    else {
        uint32_t imagesCount;
        const dyld_cache_image_info* dylibs = cacheImageTable(header, this, imagesCount);
        uint64_t firstImageOffset = 0;
        uint64_t firstRegionAddress = mappings[0].address;
        for (uint32_t i=0; i < imagesCount; ++i) {
            const char* aPath  = (char*)this + dylibs[i].pathFileOffset;
            if ( strcmp(aPath, dylibPath) == 0 ) {
                imageIndex = i;
                return true;
            }
            uint64_t offset = dylibs[i].address - firstRegionAddress;
            if ( firstImageOffset == 0 )
                firstImageOffset = offset;
            // skip over aliases
            if ( dylibs[i].pathFileOffset < firstImageOffset)
                continue;
        }
    }

    return false;
}

bool DyldSharedCache::isOverridablePath(const char* dylibPath) const
{
    // all dylibs in customer dyld cache cannot be overridden except libdispatch.dylib
    if ( header.cacheType == kDyldSharedCacheTypeProduction ) {
        return (strcmp(dylibPath, "/usr/lib/system/libdispatch.dylib") == 0);
    }
    // in dev caches we can override all paths
    return true;
}

bool DyldSharedCache::hasNonOverridablePath(const char* dylibPath) const
{
    // all dylibs in customer dyld cache cannot be overridden except libdispatch.dylib
    bool pathIsInDyldCacheWhichCannotBeOverridden = false;
    if ( header.cacheType == kDyldSharedCacheTypeProduction ) {
        uint32_t imageIndex;
        pathIsInDyldCacheWhichCannotBeOverridden = this->hasImagePath(dylibPath, imageIndex);
        if ( pathIsInDyldCacheWhichCannotBeOverridden && isOverridablePath(dylibPath) )
            pathIsInDyldCacheWhichCannotBeOverridden = false;
    }
    return pathIsInDyldCacheWhichCannotBeOverridden;
}

#if !BUILDING_LIBDSC
const dyld3::closure::Image* DyldSharedCache::findDlopenOtherImage(const char* path) const
{
    const dyld_cache_mapping_info* mappings = (dyld_cache_mapping_info*)((char*)this + header.mappingOffset);
    if ( mappings[0].fileOffset != 0 )
        return nullptr;
    if ( header.mappingOffset < __offsetof(dyld_cache_header, otherImageArrayAddr) )
        return nullptr;
    if ( header.otherImageArrayAddr == 0 )
        return nullptr;
    uintptr_t      slide           = (uintptr_t)this - (uintptr_t)(mappings[0].address);
    const uint8_t* dylibTrieStart  = (uint8_t*)(this->header.otherTrieAddr + slide);
    const uint8_t* dylibTrieEnd    = dylibTrieStart + this->header.otherTrieSize;

    Diagnostics diag;
    const uint8_t* imageNode = dyld3::MachOLoaded::trieWalk(diag, dylibTrieStart, dylibTrieEnd, path);
    if ( imageNode != NULL ) {
        dyld3::closure::ImageNum imageNum = (uint32_t)dyld3::MachOFile::read_uleb128(diag, imageNode, dylibTrieEnd);
        uint64_t arrayAddrOffset = header.otherImageArrayAddr - mappings[0].address;
        const dyld3::closure::ImageArray* otherImageArray = (dyld3::closure::ImageArray*)((char*)this + arrayAddrOffset);
        return otherImageArray->imageForNum(imageNum);
    }

    return nullptr;
}

const dyld3::closure::LaunchClosure* DyldSharedCache::findClosure(const char* executablePath) const
{
    const dyld_cache_mapping_info* mappings = (dyld_cache_mapping_info*)((char*)this + header.mappingOffset);
    uintptr_t      slide                = (uintptr_t)this - (uintptr_t)(mappings[0].address);
    const uint8_t* executableTrieStart  = (uint8_t*)(this->header.progClosuresTrieAddr + slide);
    const uint8_t* executableTrieEnd    = executableTrieStart + this->header.progClosuresTrieSize;
    const uint8_t* closuresStart        = (uint8_t*)(this->header.progClosuresAddr + slide);

    Diagnostics diag;
    const uint8_t* imageNode = dyld3::MachOLoaded::trieWalk(diag, executableTrieStart, executableTrieEnd, executablePath);
    if ( (imageNode == NULL) && (strncmp(executablePath, "/System/", 8) == 0) ) {
        // anything in /System/ should have a closure.  Perhaps it was launched via symlink path
        char realPath[PATH_MAX];
        if ( realpath(executablePath, realPath) != NULL )
            imageNode = dyld3::MachOLoaded::trieWalk(diag, executableTrieStart, executableTrieEnd, realPath);
    }
    if ( imageNode != NULL ) {
        uint32_t closureOffset = (uint32_t)dyld3::MachOFile::read_uleb128(diag, imageNode, executableTrieEnd);
        if ( closureOffset < this->header.progClosuresSize )
            return (dyld3::closure::LaunchClosure*)((uint8_t*)closuresStart + closureOffset);
    }

    return nullptr;
}

#if !BUILDING_LIBDYLD && !BUILDING_DYLD
void DyldSharedCache::forEachLaunchClosure(void (^handler)(const char* executableRuntimePath, const dyld3::closure::LaunchClosure* closure)) const
{
    const dyld_cache_mapping_info* mappings = (dyld_cache_mapping_info*)((char*)this + header.mappingOffset);
    uintptr_t      slide                = (uintptr_t)this - (uintptr_t)(mappings[0].address);
    const uint8_t* executableTrieStart  = (uint8_t*)(this->header.progClosuresTrieAddr + slide);
    const uint8_t* executableTrieEnd    = executableTrieStart + this->header.progClosuresTrieSize;
    const uint8_t* closuresStart        = (uint8_t*)(this->header.progClosuresAddr + slide);

    std::vector<DylibIndexTrie::Entry> closureEntries;
    if ( Trie<DylibIndex>::parseTrie(executableTrieStart, executableTrieEnd, closureEntries) ) {
        for (DylibIndexTrie::Entry& entry : closureEntries ) {
            uint32_t offset = entry.info.index;
            if ( offset < this->header.progClosuresSize )
                handler(entry.name.c_str(), (const dyld3::closure::LaunchClosure*)(closuresStart+offset));
        }
    }
}

void DyldSharedCache::forEachDlopenImage(void (^handler)(const char* runtimePath, const dyld3::closure::Image* image)) const
{
    const dyld_cache_mapping_info* mappings = (dyld_cache_mapping_info*)((char*)this + header.mappingOffset);
    uintptr_t      slide           = (uintptr_t)this - (uintptr_t)(mappings[0].address);
    const uint8_t* otherTrieStart  = (uint8_t*)(this->header.otherTrieAddr + slide);
    const uint8_t* otherTrieEnd    = otherTrieStart + this->header.otherTrieSize;

    std::vector<DylibIndexTrie::Entry> otherEntries;
    if ( Trie<DylibIndex>::parseTrie(otherTrieStart, otherTrieEnd, otherEntries) ) {
        for (const DylibIndexTrie::Entry& entry : otherEntries ) {
            dyld3::closure::ImageNum imageNum = entry.info.index;
            uint64_t arrayAddrOffset = header.otherImageArrayAddr - mappings[0].address;
            const dyld3::closure::ImageArray* otherImageArray = (dyld3::closure::ImageArray*)((char*)this + arrayAddrOffset);
            handler(entry.name.c_str(), otherImageArray->imageForNum(imageNum));
        }
    }
}

void DyldSharedCache::forEachDylibPath(void (^handler)(const char* dylibPath, uint32_t index)) const
{
    const dyld_cache_mapping_info* mappings = (dyld_cache_mapping_info*)((char*)this + header.mappingOffset);
    uintptr_t      slide                = (uintptr_t)this - (uintptr_t)(mappings[0].address);
    const uint8_t* dylibTrieStart       = (uint8_t*)(this->header.dylibsTrieAddr + slide);
    const uint8_t* dylibTrieEnd         = dylibTrieStart + this->header.dylibsTrieSize;

   std::vector<DylibIndexTrie::Entry> dylibEntries;
    if ( Trie<DylibIndex>::parseTrie(dylibTrieStart, dylibTrieEnd, dylibEntries) ) {
        for (DylibIndexTrie::Entry& entry : dylibEntries ) {
            handler(entry.name.c_str(), entry.info.index);
        }
    }
}
#endif // !BUILDING_LIBDYLD && !BUILDING_DYLD
#endif // !BUILDING_LIBDSC

const dyld3::closure::ImageArray* DyldSharedCache::cachedDylibsImageArray() const
{
    // check for old cache without imagesArray
    if ( header.mappingOffset < 0x100 )
        return nullptr;

    if ( header.dylibsImageArrayAddr == 0 )
        return nullptr;
        
    const dyld_cache_mapping_info* mappings = (dyld_cache_mapping_info*)((char*)this + header.mappingOffset);
    uint64_t arrayAddrOffset = header.dylibsImageArrayAddr - mappings[0].address;
    return (dyld3::closure::ImageArray*)((char*)this + arrayAddrOffset);
}

const dyld3::closure::ImageArray* DyldSharedCache::otherOSImageArray() const
{
    // check for old cache without imagesArray
    if ( header.mappingOffset < __offsetof(dyld_cache_header, otherImageArrayAddr) )
        return nullptr;

    if ( header.otherImageArrayAddr == 0 )
        return nullptr;

    const dyld_cache_mapping_info* mappings = (dyld_cache_mapping_info*)((char*)this + header.mappingOffset);
    uint64_t arrayAddrOffset = header.otherImageArrayAddr - mappings[0].address;
    return (dyld3::closure::ImageArray*)((char*)this + arrayAddrOffset);
}


uint32_t DyldSharedCache::patchableExportCount(uint32_t imageIndex) const {
    if ( header.patchInfoAddr == 0 )
        return 0;

    const dyld_cache_patch_info* patchInfo = getAddrField<dyld_cache_patch_info*>(header.patchInfoAddr);
    const dyld_cache_image_patches* patchArray = getAddrField<dyld_cache_image_patches*>(patchInfo->patchTableArrayAddr);
    if (imageIndex > patchInfo->patchTableArrayCount)
        return 0;
    return patchArray[imageIndex].patchExportsCount;
}

void DyldSharedCache::forEachPatchableExport(uint32_t imageIndex, void (^handler)(uint32_t cacheOffsetOfImpl, const char* exportName)) const {
    if ( header.patchInfoAddr == 0 )
        return;

    const dyld_cache_patch_info* patchInfo = getAddrField<dyld_cache_patch_info*>(header.patchInfoAddr);
    const dyld_cache_image_patches* patchArray = getAddrField<dyld_cache_image_patches*>(patchInfo->patchTableArrayAddr);
    if (imageIndex > patchInfo->patchTableArrayCount)
        return;
    const dyld_cache_image_patches& patch = patchArray[imageIndex];
    if ( (patch.patchExportsStartIndex + patch.patchExportsCount) > patchInfo->patchExportArrayCount )
        return;
    const dyld_cache_patchable_export* patchExports = getAddrField<dyld_cache_patchable_export*>(patchInfo->patchExportArrayAddr);
    const char* exportNames = getAddrField<char*>(patchInfo->patchExportNamesAddr);
    for (uint64_t exportIndex = 0; exportIndex != patch.patchExportsCount; ++exportIndex) {
        const dyld_cache_patchable_export& patchExport = patchExports[patch.patchExportsStartIndex + exportIndex];
        const char* exportName = ( patchExport.exportNameOffset < patchInfo->patchExportNamesSize ) ? &exportNames[patchExport.exportNameOffset] : "";
        handler(patchExport.cacheOffsetOfImpl, exportName);
    }
}

void DyldSharedCache::forEachPatchableUseOfExport(uint32_t imageIndex, uint32_t cacheOffsetOfImpl,
                                                  void (^handler)(dyld_cache_patchable_location patchLocation)) const {
    if ( header.patchInfoAddr == 0 )
        return;

    // Loading a new cache so get the data from the cache header
    const dyld_cache_patch_info* patchInfo = getAddrField<dyld_cache_patch_info*>(header.patchInfoAddr);
    const dyld_cache_image_patches* patchArray = getAddrField<dyld_cache_image_patches*>(patchInfo->patchTableArrayAddr);
    if (imageIndex > patchInfo->patchTableArrayCount)
        return;
    const dyld_cache_image_patches& patch = patchArray[imageIndex];
    if ( (patch.patchExportsStartIndex + patch.patchExportsCount) > patchInfo->patchExportArrayCount )
        return;
    const dyld_cache_patchable_export* patchExports = getAddrField<dyld_cache_patchable_export*>(patchInfo->patchExportArrayAddr);
    const dyld_cache_patchable_location* patchLocations = getAddrField<dyld_cache_patchable_location*>(patchInfo->patchLocationArrayAddr);
    for (uint64_t exportIndex = 0; exportIndex != patch.patchExportsCount; ++exportIndex) {
        const dyld_cache_patchable_export& patchExport = patchExports[patch.patchExportsStartIndex + exportIndex];
        if ( patchExport.cacheOffsetOfImpl != cacheOffsetOfImpl )
            continue;
        if ( (patchExport.patchLocationsStartIndex + patchExport.patchLocationsCount) > patchInfo->patchLocationArrayCount )
            return;
        for (uint64_t locationIndex = 0; locationIndex != patchExport.patchLocationsCount; ++locationIndex) {
            const dyld_cache_patchable_location& patchLocation = patchLocations[patchExport.patchLocationsStartIndex + locationIndex];
            handler(patchLocation);
        }
    }
}

#if (BUILDING_LIBDYLD || BUILDING_DYLD)
void DyldSharedCache::changeDataConstPermissions(mach_port_t machTask, uint32_t permissions,
                                                 DataConstLogFunc logFunc) const {

    const dyld_cache_mapping_info* mappings = (dyld_cache_mapping_info*)((char*)this + header.mappingOffset);
    uintptr_t slide = (uintptr_t)this - (uintptr_t)(mappings[0].address);

    if ( (permissions & VM_PROT_WRITE) != 0 )
        permissions |= VM_PROT_COPY;

    forEachRegion(^(const void *, uint64_t vmAddr, uint64_t size,
                    uint32_t initProt, uint32_t maxProt, uint64_t flags) {
        void* content = (void*)(vmAddr + slide);
        if ( ( flags & DYLD_CACHE_MAPPING_CONST_DATA) == 0 )
            return;
        if ( logFunc != nullptr ) {
            logFunc("dyld: marking shared cache range 0x%x permissions: 0x%09lX -> 0x%09lX\n",
                    permissions, (long)content, (long)content + size);
        }
        kern_return_t result = vm_protect(machTask, (vm_address_t)content, (vm_size_t)size, false, permissions);
        if ( result != KERN_SUCCESS ) {
            if ( logFunc != nullptr )
                logFunc("dyld: failed to mprotect shared cache due to: %d\n", result);
        }
    });
}

DyldSharedCache::DataConstLazyScopedWriter::DataConstLazyScopedWriter(const DyldSharedCache* cache, mach_port_t machTask, DataConstLogFunc logFunc)
    : cache(cache), machTask(machTask), logFunc(logFunc) {
}

DyldSharedCache::DataConstLazyScopedWriter::~DataConstLazyScopedWriter() {
    if ( wasMadeWritable )
        cache->changeDataConstPermissions(machTask, VM_PROT_READ, logFunc);
}

void DyldSharedCache::DataConstLazyScopedWriter::makeWriteable() {
    if ( wasMadeWritable )
        return;
    if ( !gEnableSharedCacheDataConst )
        return;
    if ( cache == nullptr )
        return;
    wasMadeWritable = true;
    cache->changeDataConstPermissions(machTask, VM_PROT_READ | VM_PROT_WRITE, logFunc);
}

DyldSharedCache::DataConstScopedWriter::DataConstScopedWriter(const DyldSharedCache* cache, mach_port_t machTask, DataConstLogFunc logFunc)
    : writer(cache, machTask, logFunc) {
    writer.makeWriteable();
}

// ---- version 4 patch info of a split cache (reader) ----
// A real cache has an 88 MB patch info that comes from a file, so nothing is read before its extent is checked.
// The header and the array extents are checked on every use (nine comparisons), the slices of one exporter when
// that exporter is used, and the whole table only by checkPatchInfoV4(), which is for tools and tests.
namespace {

struct PatchMapping {
    uint64_t    address;
    uint64_t    size;
    uint64_t    flags;
    uint32_t    initProt;
    bool        hasSlideInfo;
};

struct PatchMappings {
    PatchMapping    all[(kMaxSplitSubCaches + 1) * kMaxSplitFileMappings];
    uint32_t        count = 0;
};

struct PatchTablesV4 {
    dyld_cache_patch_info_v4                    info;
    const dyld_cache_image_patches_v4*          patches;
    const dyld_cache_patchable_export_v4*       exports;
    const dyld_cache_patch_client_v4*           clients;
    const dyld_cache_patch_client_export_v4*    clientExports;
    const dyld_cache_patchable_location_v4*     locations;
    const dyld_cache_image_got_clients_v4*      gotClients;
    const dyld_cache_got_client_export_v4*      gotExports;
    const dyld_cache_patchable_got_location_v4* gotLocations;
    const char*                                 names;
    const dyld_cache_image_info*                images;
    uint32_t                                    imageCount;
    uint64_t                                    unslidBase;     // the cache offsets of the GOT table are relative to this
    uint64_t                                    slide;
};

// Where the slices of one image start, so that the slices of successive images can be checked to tile their arrays.
// UINT64_MAX means "adopt the first slice's start" (a lazily checked exporter has no predecessor to compare with).
struct PatchCursors {
    uint64_t    clients, exports, clientExports, locations, gotExports, gotLocations;
    explicit PatchCursors(uint64_t start) : clients(start), exports(start), clientExports(start), locations(start), gotExports(start), gotLocations(start) {}
};

}

static const char* const kPatchErrNotMapped      = "patch info lies outside the cache mappings";
static const char* const kPatchErrVersion        = "patch info is not version 4 with patch location version 0";
static const char* const kPatchErrBounds[9]      = {
    "patch info patchTable array lies outside the patch info", "patch info imageExports array lies outside the patch info",
    "patch info clients array lies outside the patch info", "patch info clientExports array lies outside the patch info",
    "patch info locations array lies outside the patch info", "patch info exportNames lies outside the patch info",
    "patch info gotClients array lies outside the patch info", "patch info gotClientExports array lies outside the patch info",
    "patch info gotLocations array lies outside the patch info" };
static const char* const kPatchErrOverlap        = "patch info arrays overlap";
static const char* const kPatchErrAlign          = "patch info array is not 4-byte aligned";
static const char* const kPatchErrTableCount     = "patch info per-image tables do not match the image count";
static const char* const kPatchErrImage          = "patch info image index lies outside the cache";
static const char* const kPatchErrClientsTile    = "patch info client slices do not tile the clients array";
static const char* const kPatchErrExportsTile    = "patch info export slices do not tile the exports array";
static const char* const kPatchErrClientImage    = "patch info client names an image outside the cache";
static const char* const kPatchErrCExportsTile   = "patch info client export slices do not tile the clientExports array";
static const char* const kPatchErrExportIndex    = "patch info client export lies outside its exporter's exports";
static const char* const kPatchErrLocationsTile  = "patch info location slices do not tile the locations array";
static const char* const kPatchErrExportName     = "patch info export name lies outside the names or is not terminated";
static const char* const kPatchErrLocation       = "patch info location lies outside the mappings that carry slide info";
static const char* const kPatchErrGotTile        = "patch info GOT client slices do not tile the gotClientExports array";
static const char* const kPatchErrGotExportIndex = "patch info GOT export lies outside its exporter's exports";
static const char* const kPatchErrGotLocsTile    = "patch info GOT location slices do not tile the gotLocations array";
static const char* const kPatchErrGotLocation    = "patch info GOT location lies outside the mappings that carry slide info";
static const char* const kPatchErrGotReserved    = "patch info GOT location has a nonzero reserved word";

static bool patchMappings(const DyldSharedCache* cache, PatchMappings* maps)
{
    const dyld_cache_mapping_and_slide_info* tables[kMaxSplitSubCaches + 1];
    uint32_t counts[kMaxSplitSubCaches + 1];
    uint32_t files;
    if ( !splitCacheTables(cache, tables, counts, &files) )
        return false;
    maps->count = 0;
    for (uint32_t f = 0; f != files; ++f) {
        for (uint32_t i = 0; i != counts[f]; ++i) {
            const dyld_cache_mapping_and_slide_info& m = tables[f][i];
            maps->all[maps->count++] = { m.address, m.size, m.flags, m.initProt, m.slideInfoFileSize != 0 };
        }
    }
    return true;
}

// [address, address + size) lies inside one mapping; with needSlideInfo, inside one that carries slide info
static const PatchMapping* patchMappingContaining(const PatchMappings& maps, uint64_t address, uint64_t size, bool needSlideInfo)
{
    for (uint32_t i = 0; i != maps.count; ++i) {
        if ( (!needSlideInfo || maps.all[i].hasSlideInfo) && dyld_cache_range_contains(maps.all[i].address, maps.all[i].size, address, size) )
            return &maps.all[i];
    }
    return nullptr;
}

static bool patchSliceInside(uint64_t start, uint64_t count, uint64_t total)
{
    return start <= total && count <= total - start;
}

// The next slice has to begin where the previous one ended, and has to lie inside its array.
static bool patchTile(uint64_t* cursor, uint64_t start, uint64_t count, uint64_t total)
{
    if ( *cursor == UINT64_MAX )
        *cursor = start;
    if ( (start != *cursor) || !patchSliceInside(start, count, total) )
        return false;
    *cursor = start + count;
    return true;
}

static bool patchNameOk(const PatchTablesV4& t, uint32_t nameKind)
{
    const uint64_t offset = nameKind & 0x0fffffffu;
    return offset < t.info.exportNamesSize && memchr(t.names + offset, 0, t.info.exportNamesSize - offset) != nullptr;
}

static const char* openPatchTablesV4(const DyldSharedCache* cache, const PatchMappings& maps, PatchTablesV4* t)
{
    const dyld_cache_header& h = cache->header;
    if ( !cache->isSplitCache() || (h.patchInfoAddr == 0) || (h.patchInfoSize < sizeof(dyld_cache_patch_info_v4))
      || (patchMappingContaining(maps, h.patchInfoAddr, h.patchInfoSize, false) == nullptr) )
        return kPatchErrNotMapped;
    t->unslidBase = cache->unslidLoadAddress();
    t->slide = (uint64_t)(uintptr_t)cache - t->unslidBase;
    memcpy(&t->info, (const void*)(uintptr_t)(h.patchInfoAddr + t->slide), sizeof(t->info));
    const dyld_cache_patch_info_v4& info = t->info;
    if ( (info.patchTableVersion != 4) || (info.patchLocationVersion != 0) )
        return kPatchErrVersion;

    struct Array { uint64_t address, count, stride; };
    const Array arrays[9] = {
        { info.patchTableArrayAddr, info.patchTableArrayCount, sizeof(dyld_cache_image_patches_v4) },
        { info.imageExportsArrayAddr, info.imageExportsArrayCount, sizeof(dyld_cache_patchable_export_v4) },
        { info.clientsArrayAddr, info.clientsArrayCount, sizeof(dyld_cache_patch_client_v4) },
        { info.clientExportsArrayAddr, info.clientExportsArrayCount, sizeof(dyld_cache_patch_client_export_v4) },
        { info.locationArrayAddr, info.locationArrayCount, sizeof(dyld_cache_patchable_location_v4) },
        { info.exportNamesAddr, info.exportNamesSize, 1 },
        { info.gotClientsArrayAddr, info.gotClientsArrayCount, sizeof(dyld_cache_image_got_clients_v4) },
        { info.gotClientExportsArrayAddr, info.gotClientExportsArrayCount, sizeof(dyld_cache_got_client_export_v4) },
        { info.gotLocationArrayAddr, info.gotLocationArrayCount, sizeof(dyld_cache_patchable_got_location_v4) },
    };
    uint64_t lengths[9];
    for (unsigned i = 0; i != 9; ++i) {
        if ( arrays[i].count > UINT64_MAX / arrays[i].stride )
            return kPatchErrBounds[i];
        lengths[i] = arrays[i].count * arrays[i].stride;
        // arrays follow the header inside the patch info
        if ( !dyld_cache_range_contains(h.patchInfoAddr + sizeof(info), h.patchInfoSize - sizeof(info), arrays[i].address, lengths[i]) )
            return kPatchErrBounds[i];
        if ( arrays[i].address % 4 != 0 )
            return kPatchErrAlign;
    }
    for (unsigned i = 0; i != 9; ++i) {
        for (unsigned j = i + 1; j != 9; ++j) {
            if ( (lengths[i] != 0) && (lengths[j] != 0)
              && (arrays[i].address < arrays[j].address + lengths[j]) && (arrays[j].address < arrays[i].address + lengths[i]) )
                return kPatchErrOverlap;
        }
    }
    const uint64_t slide = t->slide;
    t->patches       = (const dyld_cache_image_patches_v4*)(uintptr_t)(info.patchTableArrayAddr + slide);
    t->exports       = (const dyld_cache_patchable_export_v4*)(uintptr_t)(info.imageExportsArrayAddr + slide);
    t->clients       = (const dyld_cache_patch_client_v4*)(uintptr_t)(info.clientsArrayAddr + slide);
    t->clientExports = (const dyld_cache_patch_client_export_v4*)(uintptr_t)(info.clientExportsArrayAddr + slide);
    t->locations     = (const dyld_cache_patchable_location_v4*)(uintptr_t)(info.locationArrayAddr + slide);
    t->names         = (const char*)(uintptr_t)(info.exportNamesAddr + slide);
    t->gotClients    = (const dyld_cache_image_got_clients_v4*)(uintptr_t)(info.gotClientsArrayAddr + slide);
    t->gotExports    = (const dyld_cache_got_client_export_v4*)(uintptr_t)(info.gotClientExportsArrayAddr + slide);
    t->gotLocations  = (const dyld_cache_patchable_got_location_v4*)(uintptr_t)(info.gotLocationArrayAddr + slide);
    t->images        = cache->imageTable(t->imageCount);
    if ( (info.patchTableArrayCount != t->imageCount) || (info.gotClientsArrayCount != t->imageCount) )
        return kPatchErrTableCount;
    return nullptr;
}

// One exporter's slices. The GOT part and the exports are always checked; the plain (client) part only when asked,
// because libobjc alone has 765,442 plain locations. With cursors that start at UINT64_MAX the slices are only
// checked to be contiguous among themselves; the whole-table pass starts them at 0 and so checks the tiling too.
static const char* checkPatchExporterV4(const PatchTablesV4& t, const PatchMappings& maps, uint32_t image, bool includePlain,
                                        PatchCursors* c)
{
    if ( image >= t.imageCount )
        return kPatchErrImage;
    const dyld_cache_image_patches_v4& p = t.patches[image];
    if ( !patchTile(&c->exports, p.exportsStartIndex, p.exportsCount, t.info.imageExportsArrayCount) )
        return kPatchErrExportsTile;
    if ( !patchTile(&c->clients, p.clientsStartIndex, p.clientsCount, t.info.clientsArrayCount) )
        return kPatchErrClientsTile;
    for (uint64_t i = p.exportsStartIndex; i != (uint64_t)p.exportsStartIndex + p.exportsCount; ++i) {
        if ( !patchNameOk(t, t.exports[i].nameKind) )
            return kPatchErrExportName;
    }
    if ( includePlain ) {
        for (uint64_t i = p.clientsStartIndex; i != (uint64_t)p.clientsStartIndex + p.clientsCount; ++i) {
            const dyld_cache_patch_client_v4& client = t.clients[i];
            if ( client.clientDylibIndex >= t.imageCount )
                return kPatchErrClientImage;
            if ( !patchTile(&c->clientExports, client.exportsStartIndex, client.exportsCount, t.info.clientExportsArrayCount) )
                return kPatchErrCExportsTile;
            for (uint64_t j = client.exportsStartIndex; j != (uint64_t)client.exportsStartIndex + client.exportsCount; ++j) {
                const dyld_cache_patch_client_export_v4& e = t.clientExports[j];
                if ( (e.imageExportIndex < p.exportsStartIndex) || (e.imageExportIndex - p.exportsStartIndex >= p.exportsCount) )
                    return kPatchErrExportIndex;
                if ( !patchTile(&c->locations, e.locationsStartIndex, e.locationsCount, t.info.locationArrayCount) )
                    return kPatchErrLocationsTile;
                const uint64_t imageAddress = t.images[client.clientDylibIndex].address;
                for (uint64_t k = e.locationsStartIndex; k != (uint64_t)e.locationsStartIndex + e.locationsCount; ++k) {
                    const uint32_t offset = t.locations[k].dylibOffsetOfUse;
                    if ( (offset > UINT64_MAX - imageAddress) || (patchMappingContaining(maps, imageAddress + offset, sizeof(uint64_t), true) == nullptr) )
                        return kPatchErrLocation;
                }
            }
        }
    }
    const dyld_cache_image_got_clients_v4& g = t.gotClients[image];
    if ( !patchTile(&c->gotExports, g.exportsStartIndex, g.exportsCount, t.info.gotClientExportsArrayCount) )
        return kPatchErrGotTile;
    for (uint64_t i = g.exportsStartIndex; i != (uint64_t)g.exportsStartIndex + g.exportsCount; ++i) {
        const dyld_cache_got_client_export_v4& e = t.gotExports[i];
        if ( (e.imageExportIndex < p.exportsStartIndex) || (e.imageExportIndex - p.exportsStartIndex >= p.exportsCount) )
            return kPatchErrGotExportIndex;
        if ( !patchTile(&c->gotLocations, e.locationsStartIndex, e.locationsCount, t.info.gotLocationArrayCount) )
            return kPatchErrGotLocsTile;
        for (uint64_t k = e.locationsStartIndex; k != (uint64_t)e.locationsStartIndex + e.locationsCount; ++k) {
            const dyld_cache_patchable_got_location_v4& l = t.gotLocations[k];
            const uint64_t offset = ((uint64_t)l.cacheOffsetHi << 32) | l.cacheOffsetLo;
            if ( (offset > UINT64_MAX - t.unslidBase) || (patchMappingContaining(maps, t.unslidBase + offset, sizeof(uint64_t), true) == nullptr) )
                return kPatchErrGotLocation;
            if ( l.reserved != 0 )
                return kPatchErrGotReserved;
        }
    }
    return nullptr;
}

bool DyldSharedCache::hasPatchInfoV4() const
{
    if ( !isSplitCache() || (header.patchInfoAddr == 0) || (header.patchInfoSize < sizeof(dyld_cache_patch_info_v4)) )
        return false;
    PatchMappings maps;
    if ( !patchMappings(this, &maps) || (patchMappingContaining(maps, header.patchInfoAddr, header.patchInfoSize, false) == nullptr) )
        return false;
    uint32_t version;
    memcpy(&version, (const void*)(uintptr_t)(header.patchInfoAddr + ((uint64_t)(uintptr_t)this - unslidLoadAddress())), sizeof(version));
    return version == 4;
}

#if !BUILDING_DYLD
// Checks and enumeration for tools and tests: dyld itself only needs hasPatchInfoV4() and the override.
const char* DyldSharedCache::checkPatchInfoV4Headers() const
{
    PatchMappings maps;
    PatchTablesV4 t;
    if ( !patchMappings(this, &maps) )
        return kPatchErrNotMapped;
    return openPatchTablesV4(this, maps, &t);
}

const char* DyldSharedCache::checkPatchInfoV4Exporter(uint32_t imageIndex) const
{
    PatchMappings maps;
    PatchTablesV4 t;
    if ( !patchMappings(this, &maps) )
        return kPatchErrNotMapped;
    if ( const char* error = openPatchTablesV4(this, maps, &t) )
        return error;
    PatchCursors cursors(UINT64_MAX);
    return checkPatchExporterV4(t, maps, imageIndex, false, &cursors);
}

const char* DyldSharedCache::checkPatchInfoV4(PatchInfoV4Counts* counts) const
{
    memset(counts, 0, sizeof(*counts));
    PatchMappings maps;
    PatchTablesV4 t;
    if ( !patchMappings(this, &maps) )
        return kPatchErrNotMapped;
    if ( const char* error = openPatchTablesV4(this, maps, &t) )
        return error;
    PatchCursors cursors(0);
    for (uint32_t i = 0; i != t.imageCount; ++i) {
        if ( const char* error = checkPatchExporterV4(t, maps, i, true, &cursors) )
            return error;
    }
    const dyld_cache_patch_info_v4& info = t.info;
    if ( cursors.exports != info.imageExportsArrayCount )
        return kPatchErrExportsTile;
    if ( cursors.clients != info.clientsArrayCount )
        return kPatchErrClientsTile;
    if ( cursors.clientExports != info.clientExportsArrayCount )
        return kPatchErrCExportsTile;
    if ( cursors.locations != info.locationArrayCount )
        return kPatchErrLocationsTile;
    if ( cursors.gotExports != info.gotClientExportsArrayCount )
        return kPatchErrGotTile;
    if ( cursors.gotLocations != info.gotLocationArrayCount )
        return kPatchErrGotLocsTile;
    counts->images = t.imageCount;
    counts->exports = info.imageExportsArrayCount;
    counts->clients = info.clientsArrayCount;
    counts->plainLocations = info.locationArrayCount;
    counts->gotExports = info.gotClientExportsArrayCount;
    counts->gotLocations = info.gotLocationArrayCount;
    return nullptr;
}

#endif

static DyldSharedCache::PatchLocationV4 patchLocation(const PatchTablesV4& t, uint32_t exportIndex, uint64_t slotUnslid, uint32_t flags)
{
    DyldSharedCache::PatchLocationV4 loc;
    loc.symbol      = t.names + (t.exports[exportIndex].nameKind & 0x0fffffffu);
    loc.exportIndex = exportIndex;
    loc.kind        = t.exports[exportIndex].nameKind >> 28;
    loc.implOffset  = t.exports[exportIndex].dylibOffsetOfImpl;
    loc.slot        = (uint64_t*)(uintptr_t)(slotUnslid + t.slide);
    loc.flags       = flags;
    loc.explained   = decodeCachePatchFlagsV4(flags, &loc.encoding);
    return loc;
}

#if !BUILDING_DYLD
// Checks and enumeration for tools and tests: dyld itself only needs hasPatchInfoV4() and the override.
const char* DyldSharedCache::forEachPatchGotLocation(uint32_t imageIndex, void (^handler)(const PatchLocationV4& location)) const
{
    PatchMappings maps;
    PatchTablesV4 t;
    if ( !patchMappings(this, &maps) )
        return kPatchErrNotMapped;
    if ( const char* error = openPatchTablesV4(this, maps, &t) )
        return error;
    PatchCursors cursors(UINT64_MAX);
    if ( const char* error = checkPatchExporterV4(t, maps, imageIndex, false, &cursors) )
        return error;
    const dyld_cache_image_got_clients_v4& g = t.gotClients[imageIndex];
    for (uint64_t i = g.exportsStartIndex; i != (uint64_t)g.exportsStartIndex + g.exportsCount; ++i) {
        const dyld_cache_got_client_export_v4& e = t.gotExports[i];
        for (uint64_t k = e.locationsStartIndex; k != (uint64_t)e.locationsStartIndex + e.locationsCount; ++k) {
            const dyld_cache_patchable_got_location_v4& l = t.gotLocations[k];
            handler(patchLocation(t, e.imageExportIndex, t.unslidBase + (((uint64_t)l.cacheOffsetHi << 32) | l.cacheOffsetLo), l.flags));
        }
    }
    return nullptr;
}

const char* DyldSharedCache::forEachPatchPlainLocation(uint32_t imageIndex,
                                                       void (^handler)(const PatchLocationV4& location, uint32_t clientIndex)) const
{
    PatchMappings maps;
    PatchTablesV4 t;
    if ( !patchMappings(this, &maps) )
        return kPatchErrNotMapped;
    if ( const char* error = openPatchTablesV4(this, maps, &t) )
        return error;
    // the plain part is only checked for this exporter, which for libobjc is most of the table
    PatchCursors cursors(UINT64_MAX);
    if ( const char* error = checkPatchExporterV4(t, maps, imageIndex, true, &cursors) )
        return error;
    const dyld_cache_image_patches_v4& p = t.patches[imageIndex];
    for (uint64_t i = p.clientsStartIndex; i != (uint64_t)p.clientsStartIndex + p.clientsCount; ++i) {
        const dyld_cache_patch_client_v4& client = t.clients[i];
        for (uint64_t j = client.exportsStartIndex; j != (uint64_t)client.exportsStartIndex + client.exportsCount; ++j) {
            const dyld_cache_patch_client_export_v4& e = t.clientExports[j];
            for (uint64_t k = e.locationsStartIndex; k != (uint64_t)e.locationsStartIndex + e.locationsCount; ++k) {
                handler(patchLocation(t, e.imageExportIndex, t.images[client.clientDylibIndex].address + t.locations[k].dylibOffsetOfUse,
                                      t.locations[k].flags), client.clientDylibIndex);
            }
        }
    }
    return nullptr;
}

#endif

// ---- override of the coalesced GOT slots of an exporter that the process provides itself ----
static const char* const kPatchErrSign     = "patch override: the address of an exported symbol does not fit a pointer of the slot's kind";
static const char* const kPatchErrSlot     = "patch override: a GOT slot is misaligned or lies in a mapping that cannot be made writable";
static const char* const kPatchErrProtect  = "patch override: could not make a DATA_CONST mapping writable";
static const char* const kPatchErrRestore  = "patch override: could not make a DATA_CONST mapping read-only again";

namespace {
// Makes the read-only DATA_CONST mappings that a slot is written into writable, each on its first write, and puts them
// back with restore() (the destructor does it too, for the early exits). A mapping that is already writable is never
// touched, so it cannot come back read-only; mappings without a write are never touched either.
struct PatchWriter {
    const PatchMappings&                maps;
    uint64_t                            slide;
    DyldSharedCache::DataConstLogFunc   logFunc;
    bool                                writable[(kMaxSplitSubCaches + 1) * kMaxSplitFileMappings] = {};

    PatchWriter(const PatchMappings& m, uint64_t s, DyldSharedCache::DataConstLogFunc log) : maps(m), slide(s), logFunc(log) { }
    ~PatchWriter() { restore(); }
    // false when a mapping could not be made read-only again
    bool restore() {
        bool ok = true;
        for (uint32_t i = 0; i != maps.count; ++i) {
            if ( !writable[i] )
                continue;
            writable[i] = false;
            if ( vm_protect(mach_task_self(), (vm_address_t)(maps.all[i].address + slide), (vm_size_t)maps.all[i].size, false, VM_PROT_READ) != KERN_SUCCESS ) {
                ok = false;
                if ( logFunc != nullptr )
                    logFunc("dyld: failed to make the shared cache GOT read-only again\n");
            }
        }
        return ok;
    }
    // A mapping that is not DATA_CONST, is writable already, or that this process keeps writable (gEnableSharedCacheDataConst is false), needs nothing.
    bool prepare(const PatchMapping* m) {
        const uint32_t index = (uint32_t)(m - maps.all);
        if ( writable[index] || ((m->flags & DYLD_CACHE_MAPPING_CONST_DATA) == 0) || ((m->initProt & VM_PROT_WRITE) != 0) || !gEnableSharedCacheDataConst )
            return true;
        if ( vm_protect(mach_task_self(), (vm_address_t)(m->address + slide), (vm_size_t)m->size, false, VM_PROT_READ | VM_PROT_WRITE | VM_PROT_COPY) != KERN_SUCCESS )
            return false;
        writable[index] = true;
        return true;
    }
};
}

// This file is also built into libdyld, which has no C++ library: a bitmap of the exporters done, for the one cache of the process.
static const uint32_t kMaxPatchableImages = 8192;
static uint64_t sPatchedExporters[kMaxPatchableImages / 64];
static const DyldSharedCache* sPatchedCache;

const char* DyldSharedCache::overridePatchGotSlots(uint32_t imageIndex, bool (^resolve)(const char* symbol, bool classExport, uint64_t* address),
                                                    DataConstLogFunc logFunc, PatchOverrideStats* stats) const
{
    memset(stats, 0, sizeof(*stats));
    if ( imageIndex >= kMaxPatchableImages )
        return kPatchErrImage;
    if ( sPatchedCache != this ) {
        memset(sPatchedExporters, 0, sizeof(sPatchedExporters));
        sPatchedCache = this;
    }
    if ( (sPatchedExporters[imageIndex / 64] & (1ULL << (imageIndex % 64))) != 0 ) {
        stats->alreadyApplied = true;
        return nullptr;
    }
    PatchMappings maps;
    PatchTablesV4 t;
    if ( !patchMappings(this, &maps) )
        return kPatchErrNotMapped;
    if ( const char* error = openPatchTablesV4(this, maps, &t) )
        return error;
    PatchCursors cursors(UINT64_MAX);
    if ( const char* error = checkPatchExporterV4(t, maps, imageIndex, false, &cursors) )
        return error;

    PatchWriter writer(maps, t.slide, logFunc);
    const dyld_cache_image_got_clients_v4& g = t.gotClients[imageIndex];
    for (uint64_t i = g.exportsStartIndex; i != (uint64_t)g.exportsStartIndex + g.exportsCount; ++i) {
        const dyld_cache_got_client_export_v4& e = t.gotExports[i];
        const char* symbol = t.names + (t.exports[e.imageExportIndex].nameKind & 0x0fffffffu);
        uint64_t address = 0;
        ++stats->exports;
        stats->slots += e.locationsCount;
        // kind 8 is inferred from observed exports (objc classes, Swift class metadata, concrete block classes, xpc type objects; not
        // defined in the open-source headers), other kinds are left alone. The resolver decides whether a kind 8 export may be
        // overridden: a plain libsystem_blocks or libxpc substitute leaves the __NSConcrete*Block and __xpc_type_* slots on the cache copy
        const uint32_t kind = t.exports[e.imageExportIndex].nameKind >> 28;
        if ( (kind != 0) && (kind != 8) ) {
            stats->unexplained += e.locationsCount;
            if ( logFunc != nullptr )
                logFunc("dyld: GOT slots of '%s' have an export kind that is not understood, left as the cache's pointers\n", symbol);
            continue;
        }
        if ( !resolve(symbol, kind == 8, &address) ) {
            ++stats->missingExports;
            stats->missingSlots += e.locationsCount;
            continue;
        }
        for (uint64_t k = e.locationsStartIndex; k != (uint64_t)e.locationsStartIndex + e.locationsCount; ++k) {
            const dyld_cache_patchable_got_location_v4& l = t.gotLocations[k];
            const uint64_t slotUnslid = t.unslidBase + (((uint64_t)l.cacheOffsetHi << 32) | l.cacheOffsetLo);
            const PatchLocationV4 loc = patchLocation(t, e.imageExportIndex, slotUnslid, l.flags);
            if ( !loc.explained ) {
                ++stats->unexplained;
                if ( logFunc != nullptr )
                    logFunc("dyld: GOT slot of '%s' has an encoding that cannot be explained (flags 0x%x), left as the cache's pointer\n", symbol, l.flags);
                continue;
            }
            // the signer only has the 48-bit pointer field of an authenticated pointer, and an unauthenticated one keeps its top byte for high7
            if ( (address >> (loc.encoding.authenticated ? 48 : 56)) != 0 )
                return kPatchErrSign;
            const uint64_t target = address + loc.encoding.addend;
            const PatchMapping* mapping = patchMappingContaining(maps, slotUnslid, sizeof(uint64_t), true);
            if ( (slotUnslid % sizeof(uint64_t) != 0) || (mapping == nullptr)
              || (((mapping->flags & DYLD_CACHE_MAPPING_CONST_DATA) == 0) && ((mapping->initProt & VM_PROT_WRITE) == 0)) )
                return kPatchErrSlot;
            if ( !writer.prepare(mapping) )
                return kPatchErrProtect;
            if ( loc.encoding.authenticated ) {
                // signPointer() numbers the keys IA, IB, DA, DB
                *loc.slot = dyld3::MachOLoaded::ChainedFixupPointerOnDisk::Arm64e::signPointer(target, loc.slot, loc.encoding.usesAddressDiversity,
                                loc.encoding.discriminator, loc.encoding.keyIsData ? 2 : 0);
            }
            else {
                *loc.slot = target | ((uint64_t)loc.encoding.high7 << 57);
            }
            ++stats->patched;
        }
    }
    if ( !writer.restore() )
        return kPatchErrRestore;
    sPatchedExporters[imageIndex / 64] |= 1ULL << (imageIndex % 64);
    return nullptr;
}
// ---- end of the patch info reader and override ----
#endif

#if !(BUILDING_LIBDYLD || BUILDING_DYLD)
// MRM map file generator
std::string DyldSharedCache::generateJSONMap(const char* disposition) const {
    dyld3::json::Node cacheNode;

    cacheNode.map["version"].value = "1";
    cacheNode.map["disposition"].value = disposition;
    cacheNode.map["base-address"].value = dyld3::json::hex(unslidLoadAddress());
    uuid_t cache_uuid;
    getUUID(cache_uuid);
    uuid_string_t cache_uuidStr;
    uuid_unparse(cache_uuid, cache_uuidStr);
    cacheNode.map["uuid"].value = cache_uuidStr;

    __block dyld3::json::Node imagesNode;
    forEachImage(^(const mach_header *mh, const char *installName) {
        dyld3::json::Node imageNode;
        imageNode.map["path"].value = installName;
        dyld3::MachOAnalyzer* ma = (dyld3::MachOAnalyzer*)mh;
        uuid_t uuid;
        if (ma->getUuid(uuid)) {
            uuid_string_t uuidStr;
            uuid_unparse(uuid, uuidStr);
            imageNode.map["uuid"].value = uuidStr;
        }

        __block dyld3::json::Node segmentsNode;
        ma->forEachSegment(^(const dyld3::MachOAnalyzer::SegmentInfo &info, bool &stop) {
            dyld3::json::Node segmentNode;
            segmentNode.map["name"].value = info.segName;
            segmentNode.map["start-vmaddr"].value = dyld3::json::hex(info.vmAddr);
            segmentNode.map["end-vmaddr"].value = dyld3::json::hex(info.vmAddr + info.vmSize);
            segmentsNode.array.push_back(segmentNode);
        });
        imageNode.map["segments"] = segmentsNode;
        imagesNode.array.push_back(imageNode);
    });

    cacheNode.map["images"] = imagesNode;

    std::stringstream stream;
    printJSON(cacheNode, 0, stream);

    return stream.str();
}

std::string DyldSharedCache::generateJSONDependents() const {
    std::unordered_map<std::string, std::set<std::string>> dependents;
    computeTransitiveDependents(dependents);

    std::stringstream stream;

    stream << "{";
    bool first = true;
    for (auto p : dependents) {
        if (!first) stream << "," << std::endl;
        first = false;

        stream << "\"" << p.first << "\" : [" << std::endl;
        bool firstDependent = true;
        for (const std::string & dependent : p.second) {
            if (!firstDependent) stream << "," << std::endl;
            firstDependent = false;
            stream << "  \"" << dependent << "\"";
        }
        stream << "]" <<  std::endl;
    }
    stream << "}" << std::endl;
    return stream.str();
}

#endif

#if !(BUILDING_LIBDYLD || BUILDING_DYLD)
dyld3::MachOAnalyzer::VMAddrConverter DyldSharedCache::makeVMAddrConverter(bool contentRebased) const {
    typedef dyld3::MachOAnalyzer::VMAddrConverter VMAddrConverter;

    __block VMAddrConverter::SharedCacheFormat pointerFormat = VMAddrConverter::SharedCacheFormat::none;
    __block uint64_t pointerValueAdd = 0;;
    forEachSlideInfo(^(uint64_t mappingStartAddress, uint64_t mappingSize, const uint8_t *mappingPagesStart, uint64_t slideInfoOffset, uint64_t slideInfoSize, const dyld_cache_slide_info *slideInfoHeader) {
        assert(slideInfoHeader->version >= 2);
        if ( slideInfoHeader->version == 2 ) {
            const dyld_cache_slide_info2* slideInfo = (dyld_cache_slide_info2*)(slideInfoHeader);
            assert(slideInfo->delta_mask == 0x00FFFF0000000000);
            pointerFormat   = VMAddrConverter::SharedCacheFormat::v2_x86_64_tbi;
            pointerValueAdd = slideInfo->value_add;
        } else if ( slideInfoHeader->version == 3 ) {
            pointerFormat   = VMAddrConverter::SharedCacheFormat::v3;
            pointerValueAdd = unslidLoadAddress();
        } else {
            assert(false);
        }
    });

    const dyld_cache_mapping_info* mappings = (dyld_cache_mapping_info*)((char*)this + header.mappingOffset);
    uintptr_t slide = (uintptr_t)this - (uintptr_t)(mappings[0].address);

    VMAddrConverter vmAddrConverter;
    vmAddrConverter.preferredLoadAddress            = pointerValueAdd;
    vmAddrConverter.slide                           = slide;
    vmAddrConverter.chainedPointerFormat            = 0;
    vmAddrConverter.sharedCacheChainedPointerFormat = pointerFormat;
    vmAddrConverter.contentRebased                  = contentRebased;

    return vmAddrConverter;
}
#endif

const dyld_cache_slide_info* DyldSharedCache::legacyCacheSlideInfo() const
{
    assert(header.mappingOffset <= __offsetof(dyld_cache_header, mappingWithSlideOffset));
    const dyld_cache_mapping_info* mappings = (dyld_cache_mapping_info*)((char*)this + header.mappingOffset);
    uintptr_t slide = (uintptr_t)this - (uintptr_t)(mappings[0].address);

    uint64_t offsetInLinkEditRegion = (header.slideInfoOffsetUnused - mappings[2].fileOffset);
    return (dyld_cache_slide_info*)((uint8_t*)(mappings[2].address) + slide + offsetInLinkEditRegion);
}

const dyld_cache_mapping_info* DyldSharedCache::legacyCacheDataRegionMapping() const
{
    assert(header.mappingOffset <= __offsetof(dyld_cache_header, mappingWithSlideOffset));
    const dyld_cache_mapping_info* mappings = (dyld_cache_mapping_info*)((char*)this + header.mappingOffset);
    return &mappings[1];
}

const uint8_t* DyldSharedCache::legacyCacheDataRegionBuffer() const
{
    assert(header.mappingOffset <= __offsetof(dyld_cache_header, mappingWithSlideOffset));
    const dyld_cache_mapping_info* mappings = (dyld_cache_mapping_info*)((char*)this + header.mappingOffset);
    uintptr_t slide = (uintptr_t)this - (uintptr_t)(mappings[0].address);
    
    return (uint8_t*)(legacyCacheDataRegionMapping()->address) + slide;
}

#if !BUILDING_LIBDSC
const objc_opt::objc_opt_t* DyldSharedCache::objcOpt() const {
    // Find the objc image. A split cache has no dyld3 image array, so libobjc is located through
    // its image table and the array is never read.
    const dyld3::MachOAnalyzer* objcMA = nullptr;

    uint32_t imageIndex;
    if ( !hasImagePath("/usr/lib/libobjc.A.dylib", imageIndex) )
        return nullptr;
    if ( isSplitCache() ) {
        // hasImagePath decodes the index from the dylibs trie, which is untrusted cache content
        uint32_t imagesCount;
        imageTable(imagesCount);
        if ( imageIndex >= imagesCount )
            return nullptr;
        uint64_t mTime, inode;
        objcMA = (const dyld3::MachOAnalyzer*)getIndexedImageEntry(imageIndex, mTime, inode);
    } else {
        const dyld3::closure::ImageArray* images = cachedDylibsImageArray();
        if ( images == nullptr )
            return nullptr;
        const dyld3::closure::Image* image = images->imageForNum(imageIndex+1);
        if ( image == nullptr )
            return nullptr;
        objcMA = (const dyld3::MachOAnalyzer*)((uintptr_t)this + image->cacheOffset());
    }
    if ( objcMA == nullptr )
        return nullptr;

    // If we found the objc image, then try to find the read-only data inside.
    __block const uint8_t* objcROContent = nullptr;
    int64_t slide = objcMA->getSlide();
    objcMA->forEachSection(^(const dyld3::MachOAnalyzer::SectionInfo& info, bool malformedSectionRange, bool& stop) {
        if (strcmp(info.segInfo.segName, "__TEXT") != 0)
            return;
        if (strcmp(info.sectName, "__objc_opt_ro") != 0)
            return;
        if ( malformedSectionRange ) {
            stop = true;
            return;
        }
        // the section must hold the whole version-16 objc_opt_t the caller will read
        if ( info.sectSize < sizeof(objc_opt::objc_opt_t) ) {
            stop = true;
            return;
        }
        objcROContent = (uint8_t*)(info.sectAddr + slide);
    });

    if (objcROContent == nullptr)
        return nullptr;

    const objc_opt::objc_opt_t* optObjCHeader = (const objc_opt::objc_opt_t*)objcROContent;
    return optObjCHeader->version == objc_opt::VERSION ? optObjCHeader : nullptr;
}

const void* DyldSharedCache::objcOptPtrs() const {
    // Find the objc image. A split cache has no dyld3 image array, so libobjc is located through
    // its image table and the array is never read.
    const dyld3::MachOAnalyzer* objcMA = nullptr;

    uint32_t imageIndex;
    if ( !hasImagePath("/usr/lib/libobjc.A.dylib", imageIndex) )
        return nullptr;
    if ( isSplitCache() ) {
        // hasImagePath decodes the index from the dylibs trie, which is untrusted cache content
        uint32_t imagesCount;
        imageTable(imagesCount);
        if ( imageIndex >= imagesCount )
            return nullptr;
        uint64_t mTime, inode;
        objcMA = (const dyld3::MachOAnalyzer*)getIndexedImageEntry(imageIndex, mTime, inode);
    } else {
        const dyld3::closure::ImageArray* images = cachedDylibsImageArray();
        if ( images == nullptr )
            return nullptr;
        const dyld3::closure::Image* image = images->imageForNum(imageIndex+1);
        if ( image == nullptr )
            return nullptr;
        objcMA = (const dyld3::MachOAnalyzer*)((uintptr_t)this + image->cacheOffset());
    }
    if ( objcMA == nullptr )
        return nullptr;

    // If we found the objc image, then try to find the read-only data inside.
    __block const void* objcPointersContent = nullptr;
    int64_t slide = objcMA->getSlide();
    uint32_t pointerSize = objcMA->pointerSize();
    objcMA->forEachSection(^(const dyld3::MachOAnalyzer::SectionInfo& info, bool malformedSectionRange, bool& stop) {
        if ( (strncmp(info.segInfo.segName, "__DATA", 6) != 0) && (strncmp(info.segInfo.segName, "__AUTH", 6) != 0) )
            return;
        if (strcmp(info.sectName, "__objc_opt_ptrs") != 0)
            return;
        if ( info.sectSize != pointerSize ) {
            stop = true;
            return;
        }
        if ( malformedSectionRange ) {
            stop = true;
            return;
        }
        objcPointersContent = (uint8_t*)(info.sectAddr + slide);
    });

    return objcPointersContent;
}
#endif

std::pair<const void*, uint64_t> DyldSharedCache::getObjCConstantRange() const {
    if ( isSplitCache() )
        return { nullptr, 0 };

    const dyld3::MachOAnalyzer* libDyldMA = nullptr;
    uint32_t imageIndex;
    if ( hasImagePath("/usr/lib/system/libdyld.dylib", imageIndex) ) {
        const dyld3::closure::ImageArray* images = cachedDylibsImageArray();
        const dyld3::closure::Image* image = images->imageForNum(imageIndex+1);
        libDyldMA = (const dyld3::MachOAnalyzer*)((uintptr_t)this + image->cacheOffset());

        std::pair<const void*, uint64_t> ranges = { nullptr, 0 };
#if TARGET_OS_OSX
        ranges.first = libDyldMA->findSectionContent("__DATA", "__objc_ranges", ranges.second);
#else
        ranges.first = libDyldMA->findSectionContent("__DATA_CONST", "__objc_ranges", ranges.second);
#endif
        return ranges;
    }

    return { nullptr, 0 };
}

bool DyldSharedCache::hasSlideInfo() const {
    if ( header.mappingOffset <= __offsetof(dyld_cache_header, mappingWithSlideOffset) ) {
        return header.slideInfoSizeUnused != 0;
    } else {
        const dyld_cache_mapping_and_slide_info* slidableMappings = (const dyld_cache_mapping_and_slide_info*)((char*)this + header.mappingWithSlideOffset);
        for (uint32_t i = 0; i != header.mappingWithSlideCount; ++i) {
            if ( slidableMappings[i].slideInfoFileSize != 0 ) {
                return true;
            }
        }
    }
    return false;
}

void DyldSharedCache::forEachSlideInfo(void (^handler)(uint64_t mappingStartAddress, uint64_t mappingSize,
                                                       const uint8_t* mappingPagesStart,
                                                       uint64_t slideInfoOffset, uint64_t slideInfoSize,
                                                       const dyld_cache_slide_info* slideInfoHeader)) const {
    if ( header.mappingOffset <= __offsetof(dyld_cache_header, mappingWithSlideOffset) ) {
        // Old caches should get the slide info from the cache header and assume a single data region.
        const dyld_cache_mapping_info* dataMapping = legacyCacheDataRegionMapping();
        uint64_t dataStartAddress = dataMapping->address;
        uint64_t dataSize = dataMapping->size;
        const uint8_t* dataPagesStart = legacyCacheDataRegionBuffer();
        const dyld_cache_slide_info* slideInfoHeader = legacyCacheSlideInfo();

        handler(dataStartAddress, dataSize, dataPagesStart,
                header.slideInfoOffsetUnused, header.slideInfoSizeUnused, slideInfoHeader);
    } else {
        const dyld_cache_mapping_and_slide_info* slidableMappings = (const dyld_cache_mapping_and_slide_info*)((char*)this + header.mappingWithSlideOffset);
        const dyld_cache_mapping_and_slide_info* linkeditMapping = &slidableMappings[header.mappingWithSlideCount - 1];
        uint64_t sharedCacheSlide = (uint64_t)this - unslidLoadAddress();

        for (uint32_t i = 0; i != header.mappingWithSlideCount; ++i) {
            if ( slidableMappings[i].slideInfoFileOffset != 0 ) {
                // Get the data pages
                uint64_t dataStartAddress = slidableMappings[i].address;
                uint64_t dataSize = slidableMappings[i].size;
                const uint8_t* dataPagesStart = (uint8_t*)dataStartAddress + sharedCacheSlide;

                // Get the slide info
                uint64_t offsetInLinkEditRegion = (slidableMappings[i].slideInfoFileOffset - linkeditMapping->fileOffset);
                const dyld_cache_slide_info* slideInfoHeader = (dyld_cache_slide_info*)((uint8_t*)(linkeditMapping->address) + sharedCacheSlide + offsetInLinkEditRegion);
                handler(dataStartAddress, dataSize, dataPagesStart,
                        slidableMappings[i].slideInfoFileOffset, slidableMappings[i].slideInfoFileSize, slideInfoHeader);
            }
        }
    }
}

#if BUILDING_LIBDYLD
const char* DyldSharedCache::getCanonicalPath(const char *path) const {
    uint32_t dyldCacheImageIndex;
    if ( hasImagePath(path, dyldCacheImageIndex) )
        return getIndexedImagePath(dyldCacheImageIndex);
#if TARGET_OS_OSX
    // on macOS support "Foo.framework/Foo" symlink
    char resolvedPath[PATH_MAX];
    realpath(path, resolvedPath);
    int realpathErrno = errno;
    // If realpath() resolves to a path which does not exist on disk, errno is set to ENOENT
    if ( (realpathErrno == ENOENT) || (realpathErrno == 0) ) {
        if ( hasImagePath(resolvedPath, dyldCacheImageIndex) )
            return getIndexedImagePath(dyldCacheImageIndex);
    }
#endif
    return nullptr;
}
#endif

#if !(BUILDING_LIBDYLD || BUILDING_DYLD)
void DyldSharedCache::fillMachOAnalyzersMap(std::unordered_map<std::string,dyld3::MachOAnalyzer*> & dylibAnalyzers) const {
    forEachImage(^(const mach_header *mh, const char *iteratedInstallName) {
        dylibAnalyzers[std::string(iteratedInstallName)] = (dyld3::MachOAnalyzer*)mh;
    });
}

void DyldSharedCache::computeReverseDependencyMapForDylib(std::unordered_map<std::string, std::set<std::string>> &reverseDependencyMap, const std::unordered_map<std::string,dyld3::MachOAnalyzer*> & dylibAnalyzers, const std::string &loadPath) const {
    dyld3::MachOAnalyzer *ma = dylibAnalyzers.at(loadPath);
    if (reverseDependencyMap.find(loadPath) != reverseDependencyMap.end()) return;
    reverseDependencyMap[loadPath] = std::set<std::string>();

    ma->forEachDependentDylib(^(const char *dependencyLoadPath, bool isWeak, bool isReExport, bool isUpward, uint32_t compatVersion, uint32_t curVersion, bool &stop) {
        if (isUpward) return;
        std::string dependencyLoadPathString = std::string(dependencyLoadPath);
        computeReverseDependencyMapForDylib(reverseDependencyMap, dylibAnalyzers, dependencyLoadPathString);
        reverseDependencyMap[dependencyLoadPathString].insert(loadPath);
    });
}

// Walks the shared cache and construct the reverse dependency graph (if dylib A depends on B,
// constructs the graph with B -> A edges)
void DyldSharedCache::computeReverseDependencyMap(std::unordered_map<std::string, std::set<std::string>> &reverseDependencyMap) const {
    std::unordered_map<std::string,dyld3::MachOAnalyzer*> dylibAnalyzers;

    fillMachOAnalyzersMap(dylibAnalyzers);
    forEachImage(^(const mach_header *mh, const char *installName) {
        computeReverseDependencyMapForDylib(reverseDependencyMap, dylibAnalyzers, std::string(installName));
    });
}

// uses the reverse dependency graph constructed above to find the recursive set of dependents for each dylib
void DyldSharedCache::findDependentsRecursively(std::unordered_map<std::string, std::set<std::string>> &transitiveDependents, const std::unordered_map<std::string, std::set<std::string>> &reverseDependencyMap, std::set<std::string> & visited, const std::string &loadPath) const {

    if (transitiveDependents.find(loadPath) != transitiveDependents.end()) {
        return;
    }

    if (visited.find(loadPath) != visited.end()) {
        return;
    }

    visited.insert(loadPath);

    std::set<std::string> dependents;

    for (const std::string & dependent : reverseDependencyMap.at(loadPath)) {
        findDependentsRecursively(transitiveDependents, reverseDependencyMap, visited, dependent);
        if (transitiveDependents.find(dependent) != transitiveDependents.end()) {
            std::set<std::string> & theseTransitiveDependents = transitiveDependents.at(dependent);
            dependents.insert(theseTransitiveDependents.begin(), theseTransitiveDependents.end());
        }
        dependents.insert(dependent);
    }

    transitiveDependents[loadPath] = dependents;
}

// Fills a map from each install name N to the set of install names depending on N
void DyldSharedCache::computeTransitiveDependents(std::unordered_map<std::string, std::set<std::string>> & transitiveDependents) const {
    std::unordered_map<std::string, std::set<std::string>> reverseDependencyMap;
    computeReverseDependencyMap(reverseDependencyMap);
    forEachImage(^(const mach_header *mh, const char *installName) {
        std::set<std::string> visited;
        findDependentsRecursively(transitiveDependents, reverseDependencyMap, visited, std::string(installName));
    });
}
#endif
