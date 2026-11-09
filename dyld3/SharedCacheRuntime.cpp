/*
 * Copyright (c) 2017 Apple Inc. All rights reserved.
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



#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/param.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/syslog.h>
#include <sys/sysctl.h>
#include <sys/mman.h>
#include <libkern/OSCacheControl.h>
#include <mach/mach.h>
#include <mach-o/fat.h>
#include <mach-o/loader.h>
#include <mach-o/ldsyms.h>
#include <mach/shared_region.h>
#include <mach/mach.h>
#include <Availability.h>
#include <TargetConditionals.h>

#include "dyld_cache_format.h"
#include "SharedCacheRuntime.h"
#include "Loading.h"
#include "BootArgs.h"

#define ENABLE_DYLIBS_TO_OVERRIDE_CACHE_SIZE 1024

// should be in mach/shared_region.h
extern "C" int __shared_region_check_np(uint64_t* startaddress);
extern "C" int __shared_region_map_and_slide_np(int fd, uint32_t count, const shared_file_mapping_np mappings[], long slide, const dyld_cache_slide_info2* slideInfo, size_t slideInfoSize);
extern "C" int __shared_region_map_and_slide_2_np(uint32_t files_count, const shared_file_np files[], uint32_t mappings_count, const shared_file_mapping_slide_np mappings[]);

#ifndef VM_PROT_NOAUTH
#define VM_PROT_NOAUTH  0x40  /* must not interfere with normal prot assignments */
#endif

extern bool gEnableSharedCacheDataConst;

namespace dyld {
    extern void log(const char*, ...);
    extern void logToConsole(const char* format, ...);
#if defined(__x86_64__) && !TARGET_OS_SIMULATOR
    bool isTranslated();
#endif
}


namespace dyld3 {


struct CacheInfo
{
    shared_file_mapping_slide_np            mappings[DyldSharedCache::MaxMappings];
    uint32_t                                mappingsCount;
    // All mappings come from the same file
    int                                     fd               = 0;
    uint64_t                                sharedRegionStart;
    uint64_t                                sharedRegionSize;
    uint64_t                                maxSlide;
};




#if __i386__
    #define ARCH_NAME            "i386"
    #define ARCH_CACHE_MAGIC     "dyld_v1    i386"
#elif __x86_64__
    #define ARCH_NAME            "x86_64"
    #define ARCH_CACHE_MAGIC     "dyld_v1  x86_64"
    #define ARCH_NAME_H          "x86_64h"
    #define ARCH_CACHE_MAGIC_H   "dyld_v1 x86_64h"
#elif __ARM_ARCH_7K__
    #define ARCH_NAME            "armv7k"
    #define ARCH_CACHE_MAGIC     "dyld_v1  armv7k"
#elif __ARM_ARCH_7A__
    #define ARCH_NAME            "armv7"
    #define ARCH_CACHE_MAGIC     "dyld_v1   armv7"
#elif __ARM_ARCH_7S__
    #define ARCH_NAME            "armv7s"
    #define ARCH_CACHE_MAGIC     "dyld_v1  armv7s"
#elif __arm64e__
    #define ARCH_NAME            "arm64e"
    #define ARCH_CACHE_MAGIC     "dyld_v1  arm64e"
#elif __arm64__
    #if __LP64__
        #define ARCH_NAME            "arm64"
        #define ARCH_CACHE_MAGIC     "dyld_v1   arm64"
    #else
        #define ARCH_NAME            "arm64_32"
        #define ARCH_CACHE_MAGIC     "dyld_v1arm64_32"
    #endif
#endif


#if !TARGET_OS_SIMULATOR
static void rebaseChainV2(uint8_t* pageContent, uint16_t startOffset, uintptr_t slideAmount, const dyld_cache_slide_info2* slideInfo)
{
    const uintptr_t   deltaMask    = (uintptr_t)(slideInfo->delta_mask);
    const uintptr_t   valueMask    = ~deltaMask;
    const uintptr_t   valueAdd     = (uintptr_t)(slideInfo->value_add);
    const unsigned    deltaShift   = __builtin_ctzll(deltaMask) - 2;

    uint32_t pageOffset = startOffset;
    uint32_t delta = 1;
    while ( delta != 0 ) {
        uint8_t* loc = pageContent + pageOffset;
        uintptr_t rawValue = *((uintptr_t*)loc);
        delta = (uint32_t)((rawValue & deltaMask) >> deltaShift);
        uintptr_t value = (rawValue & valueMask);
        if ( value != 0 ) {
            value += valueAdd;
            value += slideAmount;
        }
        *((uintptr_t*)loc) = value;
        //dyld::log("         pageOffset=0x%03X, loc=%p, org value=0x%08llX, new value=0x%08llX, delta=0x%X\n", pageOffset, loc, (uint64_t)rawValue, (uint64_t)value, delta);
        pageOffset += delta;
    }
}
#endif

#if !__LP64__ && !TARGET_OS_SIMULATOR
static void rebaseChainV4(uint8_t* pageContent, uint16_t startOffset, uintptr_t slideAmount, const dyld_cache_slide_info4* slideInfo)
{
    const uintptr_t   deltaMask    = (uintptr_t)(slideInfo->delta_mask);
    const uintptr_t   valueMask    = ~deltaMask;
    const uintptr_t   valueAdd     = (uintptr_t)(slideInfo->value_add);
    const unsigned    deltaShift   = __builtin_ctzll(deltaMask) - 2;

    uint32_t pageOffset = startOffset;
    uint32_t delta = 1;
    while ( delta != 0 ) {
        uint8_t* loc = pageContent + pageOffset;
        uintptr_t rawValue = *((uintptr_t*)loc);
        delta = (uint32_t)((rawValue & deltaMask) >> deltaShift);
        uintptr_t value = (rawValue & valueMask);
        if ( (value & 0xFFFF8000) == 0 ) {
           // small positive non-pointer, use as-is
        }
        else if ( (value & 0x3FFF8000) == 0x3FFF8000 ) {
           // small negative non-pointer
           value |= 0xC0000000;
        }
        else {
            value += valueAdd;
            value += slideAmount;
        }
        *((uintptr_t*)loc) = value;
        //dyld::log("         pageOffset=0x%03X, loc=%p, org value=0x%08llX, new value=0x%08llX, delta=0x%X\n", pageOffset, loc, (uint64_t)rawValue, (uint64_t)value, delta);
        pageOffset += delta;
    }
}
#endif

#if TARGET_OS_OSX
bool getMacOSCachePath(char pathBuffer[], size_t pathBufferSize,
                       const char* cacheDir, bool useHaswell) {
    // Clear old attempts at finding a cache, if any
    pathBuffer[0] = '\0';

    // set cache dir
    strlcpy(pathBuffer, cacheDir, pathBufferSize);

    // append file component of cache file
    if ( pathBuffer[strlen(pathBuffer)-1] != '/' )
        strlcat(pathBuffer, "/", pathBufferSize);

#if __x86_64__
    if ( useHaswell ) {
        size_t len = strlen(pathBuffer);
        struct stat haswellStatBuf;
        strlcat(pathBuffer, DYLD_SHARED_CACHE_BASE_NAME ARCH_NAME_H, pathBufferSize);
        if ( dyld3::stat(pathBuffer, &haswellStatBuf) == 0 )
            return true;
        // no haswell cache file, use regular x86_64 cache
        pathBuffer[len] = '\0';
    }
#endif

    struct stat statBuf;
    strlcat(pathBuffer, DYLD_SHARED_CACHE_BASE_NAME ARCH_NAME, pathBufferSize);
    if ( dyld3::stat(pathBuffer, &statBuf) == 0 )
        return true;

    return false;
}
#endif // TARGET_OS_OSX

static void getCachePath(const SharedCacheOptions& options, size_t pathBufferSize, char pathBuffer[])
{
#if TARGET_OS_OSX

    if ( options.cacheDirOverride != nullptr ) {
        getMacOSCachePath(pathBuffer, pathBufferSize, options.cacheDirOverride, options.useHaswell);
    } else {
        getMacOSCachePath(pathBuffer, pathBufferSize, MACOSX_MRM_DYLD_SHARED_CACHE_DIR, options.useHaswell);
    }

#else // TARGET_OS_OSX

    // Non-macOS path
    if ( options.cacheDirOverride != nullptr ) {
        strlcpy(pathBuffer, options.cacheDirOverride, pathBufferSize);
    } else {
        strlcpy(pathBuffer, IPHONE_DYLD_SHARED_CACHE_DIR, sizeof(IPHONE_DYLD_SHARED_CACHE_DIR));
    }

    // append file component of cache file
    if ( pathBuffer[strlen(pathBuffer)-1] != '/' )
        strlcat(pathBuffer, "/", pathBufferSize);

    strlcat(pathBuffer, DYLD_SHARED_CACHE_BASE_NAME ARCH_NAME, pathBufferSize);

#if TARGET_OS_IPHONE && !TARGET_OS_SIMULATOR
    // use .development cache if it exists
    if ( BootArgs::forceCustomerCache() ) {
        // The boot-arg always wins.  Use the customer cache if we are told to
        return;
    }
    if ( !dyld3::internalInstall() ) {
        // We can't use the development cache on customer installs
        return;
    }
    if ( BootArgs::forceDevelopmentCache() ) {
        // The boot-arg always wins.  Use the development cache if we are told to
        strlcat(pathBuffer, DYLD_SHARED_CACHE_DEVELOPMENT_EXT, pathBufferSize);
        return;
    }

    // If only one or the other caches exists, then use the one we have
    struct stat devCacheStatBuf;
    struct stat optCacheStatBuf;
    bool devCacheExists = (dyld3::stat(IPHONE_DYLD_SHARED_CACHE_DIR DYLD_SHARED_CACHE_BASE_NAME ARCH_NAME DYLD_SHARED_CACHE_DEVELOPMENT_EXT, &devCacheStatBuf) == 0);
    bool optCacheExists = (dyld3::stat(IPHONE_DYLD_SHARED_CACHE_DIR DYLD_SHARED_CACHE_BASE_NAME ARCH_NAME, &optCacheStatBuf) == 0);
    if ( !devCacheExists ) {
        // If the dev cache doesn't exist, then use the customer cache
        return;
    }
    if ( !optCacheExists ) {
        // If the customer cache doesn't exist, then use the development cache
        strlcat(pathBuffer, DYLD_SHARED_CACHE_DEVELOPMENT_EXT, pathBufferSize);
        return;
    }

    // Finally, check for the sentinels
    struct stat enableStatBuf;
    //struct stat sentinelStatBuf;
    bool enableFileExists = (dyld3::stat(IPHONE_DYLD_SHARED_CACHE_DIR "enable-dylibs-to-override-cache", &enableStatBuf) == 0);
    // FIXME: rdar://problem/59813537 Re-enable once automation is updated to use boot-arg
    bool sentinelFileExists = false;
    //bool sentinelFileExists = (dyld3::stat(MACOSX_MRM_DYLD_SHARED_CACHE_DIR "enable_development_mode", &sentinelStatBuf) == 0);
    if ( enableFileExists && (enableStatBuf.st_size < ENABLE_DYLIBS_TO_OVERRIDE_CACHE_SIZE) ) {
        // if the old enable file exists, use the development cache
        strlcat(pathBuffer, DYLD_SHARED_CACHE_DEVELOPMENT_EXT, pathBufferSize);
        return;
    }
    if ( sentinelFileExists ) {
        // If the new sentinel exists, then use the development cache
        strlcat(pathBuffer, DYLD_SHARED_CACHE_DEVELOPMENT_EXT, pathBufferSize);
        return;
    }
#endif

#endif //!TARGET_OS_OSX
}


int openSharedCacheFile(const SharedCacheOptions& options, SharedCacheLoadInfo* results)
{
    getCachePath(options, sizeof(results->path), results->path);
    return dyld3::open(results->path, O_RDONLY, 0);
}

static bool validMagic(const SharedCacheOptions& options, const DyldSharedCache* cache)
{
    if ( strcmp(cache->header.magic, ARCH_CACHE_MAGIC) == 0 )
        return true;

#if __x86_64__
    if ( options.useHaswell ) {
        if ( strcmp(cache->header.magic, ARCH_CACHE_MAGIC_H) == 0 )
            return true;
    }
#endif
    return false;
}


static bool validPlatform(const SharedCacheOptions& options, const DyldSharedCache* cache)
{
    // grandfather in old cache that does not have platform in header
    if ( cache->header.mappingOffset < 0xE0 )
        return true;

    if ( cache->header.platform != (uint32_t)MachOFile::currentPlatform() )
        return false;

#if TARGET_OS_SIMULATOR
    if ( cache->header.simulator == 0 )
        return false;
#else
    if ( cache->header.simulator != 0 )
        return false;
#endif

    return true;
}

#if !TARGET_OS_SIMULATOR
static void verboseSharedCacheMappings(const shared_file_mapping_slide_np mappings[DyldSharedCache::MaxMappings],
                                       uint32_t mappingsCount)
{
    for (int i=0; i < mappingsCount; ++i) {
        const char* mappingName = "";
        if ( mappings[i].sms_max_prot & VM_PROT_WRITE ) {
            if ( mappings[i].sms_max_prot & VM_PROT_NOAUTH ) {
                // __DATA*
                mappingName = "data";
            } else {
                // __AUTH*
                mappingName = "auth";
            }
        }
        uint32_t init_prot = mappings[i].sms_init_prot & (VM_PROT_READ | VM_PROT_WRITE | VM_PROT_EXECUTE);
        uint32_t max_prot = mappings[i].sms_max_prot & (VM_PROT_READ | VM_PROT_WRITE | VM_PROT_EXECUTE);
        dyld::log("        0x%08llX->0x%08llX init=%x, max=%x %s%s%s%s\n",
            mappings[i].sms_address, mappings[i].sms_address+mappings[i].sms_size-1,
            init_prot, max_prot,
            ((mappings[i].sms_init_prot & VM_PROT_READ) ? "read " : ""),
            ((mappings[i].sms_init_prot & VM_PROT_WRITE) ? "write " : ""),
            ((mappings[i].sms_init_prot & VM_PROT_EXECUTE) ? "execute " : ""),
            mappingName);
    }
}


static void verboseSharedCacheMappingsToConsole(const shared_file_mapping_slide_np mappings[DyldSharedCache::MaxMappings],
                                                uint32_t mappingsCount)
{
    for (int i=0; i < mappingsCount; ++i) {
        const char* mappingName = "";
        if ( mappings[i].sms_max_prot & VM_PROT_WRITE ) {
            if ( mappings[i].sms_max_prot & VM_PROT_NOAUTH ) {
                // __DATA*
                mappingName = "data";
            } else {
                // __AUTH*
                mappingName = "auth";
            }
        }
        uint32_t init_prot = mappings[i].sms_init_prot & (VM_PROT_READ | VM_PROT_WRITE | VM_PROT_EXECUTE);
        uint32_t max_prot = mappings[i].sms_max_prot & (VM_PROT_READ | VM_PROT_WRITE | VM_PROT_EXECUTE);
        dyld::logToConsole("dyld: mapping 0x%08llX->0x%08llX init=%x, max=%x %s%s%s%s\n",
                           mappings[i].sms_address, mappings[i].sms_address+mappings[i].sms_size-1,
                           init_prot, max_prot,
                           ((mappings[i].sms_init_prot & VM_PROT_READ) ? "read " : ""),
                           ((mappings[i].sms_init_prot & VM_PROT_WRITE) ? "write " : ""),
                           ((mappings[i].sms_init_prot & VM_PROT_EXECUTE) ? "execute " : ""),
                           mappingName);
    }
}
#endif

static bool cacheRangeContains(uint64_t start, uint64_t length,
                               uint64_t address, uint64_t size)
{
    return dyld_cache_range_contains(start, length, address, size);
}

// A mapping protection must be non-empty, within read/write/execute and never writable and executable at once.
static bool cacheProtectionIsValid(uint32_t prot)
{
    return (prot != 0) && ((prot & ~(VM_PROT_READ|VM_PROT_WRITE|VM_PROT_EXECUTE)) == 0)
        && !((prot & VM_PROT_WRITE) && (prot & VM_PROT_EXECUTE));
}

static bool cacheMappingTableFits(const dyld_cache_header& header, uint64_t headerPageSize)
{
    if ( !dyld_cache_header_is_split(header) )
        return header.mappingOffset <= 0x168;
    return cacheRangeContains(0, headerPageSize, header.mappingOffset,
                              uint64_t(header.mappingCount) * sizeof(dyld_cache_mapping_info));
}

// Mappings of one file of a split cache must be sane and in ascending, non-overlapping VM order.
// Which one is text, data or linkedit is not known from its position there.
static bool splitFileMappingsAreValid(const dyld_cache_mapping_info* mappings, uint32_t count)
{
    for (uint32_t i = 0; i != count; ++i) {
        if ( !cacheProtectionIsValid(mappings[i].maxProt) )
            return false;
        if ( (i + 1 != count) && (mappings[i].address + mappings[i].size > mappings[i + 1].address) )
            return false;
    }
    return true;
}

// DyldSharedCache reads the header and its tables through the first mapping of the main file, so that
// mapping has to start the region at file offset 0 and hold every table the header points to.
static bool splitHeaderIsMapped(const dyld_cache_header& header, uint64_t address, uint64_t fileOffset, uint64_t size)
{
    return address == header.sharedRegionStart && fileOffset == 0
        && cacheRangeContains(0, size, header.mappingOffset, uint64_t(header.mappingCount) * sizeof(dyld_cache_mapping_info))
        && cacheRangeContains(0, size, header.mappingWithSlideOffset, uint64_t(header.mappingWithSlideCount) * sizeof(dyld_cache_mapping_and_slide_info))
        && cacheRangeContains(0, size, header.imagesOffsetSplit, uint64_t(header.imagesCountSplit) * sizeof(dyld_cache_image_info));
}

// The signature blob must end the file (an unsigned file has offset == length and size 0, and fails the
// registration that follows) and no mapping may reach into it, so every mapped byte is signed.
static bool splitSignatureCoversMappings(const dyld_cache_header& header, const dyld_cache_mapping_info* mappings,
                                         uint32_t count, uint64_t fileLength)
{
    if ( !cacheRangeContains(0, fileLength, header.codeSignatureOffset, header.codeSignatureSize)
      || (header.codeSignatureOffset + header.codeSignatureSize != fileLength) )
        return false;
    for (uint32_t i = 0; i != count; ++i) {
        if ( mappings[i].fileOffset + mappings[i].size > header.codeSignatureOffset )
            return false;
    }
    return true;
}

static bool preflightCacheFile(const SharedCacheOptions& options, SharedCacheLoadInfo* results, CacheInfo* info)
{
    
    // find and open shared cache file
    int fd = openSharedCacheFile(options, results);
    if ( fd == -1 ) {
        results->errorMessage = "shared cache file open() failed";
        return false;
    }

    struct stat cacheStatBuf;
    if ( dyld3::stat(results->path, &cacheStatBuf) != 0 ) {
        results->errorMessage = "shared cache file stat() failed";
        ::close(fd);
        return false;
    }
    size_t cacheFileLength = (size_t)(cacheStatBuf.st_size);

    // sanity check header and mappings
    uint8_t firstPage[0x4000];
    if ( ::pread(fd, firstPage, sizeof(firstPage), 0) != sizeof(firstPage) ) {
        results->errorMessage = "shared cache file pread() failed";
        ::close(fd);
        return false;
    }
    const DyldSharedCache* cache = (DyldSharedCache*)firstPage;
    if ( !validMagic(options, cache) ) {
        results->errorMessage = "shared cache file has wrong magic";
        ::close(fd);
        return false;
    }
    if ( !validPlatform(options, cache) ) {
        results->errorMessage = "shared cache file is for a different platform";
        ::close(fd);
        return false;
    }
    if ( (cache->header.mappingCount < (dyld_cache_header_is_split(cache->header) ? 1 : 3))
      || (cache->header.mappingCount > DyldSharedCache::MaxMappings)
      || !cacheMappingTableFits(cache->header, sizeof(firstPage)) ) {
        results->errorMessage = "shared cache file mappings are invalid";
        ::close(fd);
        return false;
    }
    const dyld_cache_mapping_info* const fileMappings = (dyld_cache_mapping_info*)&firstPage[cache->header.mappingOffset];
    const dyld_cache_mapping_info* textMapping = &fileMappings[0];
    const dyld_cache_mapping_info* firstDataMapping = &fileMappings[1];
    const dyld_cache_mapping_info* linkeditMapping = &fileMappings[cache->header.mappingCount - 1];
    // Validate extents before the ordering/adjacency checks below add sizes.
    // Both VM ranges and file ranges come from the cache, not the kernel.
    for (uint32_t i = 0; i != cache->header.mappingCount; ++i) {
        if ( !cacheRangeContains(cache->header.sharedRegionStart, cache->header.sharedRegionSize,
                                 fileMappings[i].address, fileMappings[i].size)
          || !cacheRangeContains(0, cacheFileLength, fileMappings[i].fileOffset, fileMappings[i].size) ) {
            results->errorMessage = "shared cache mapping range is invalid";
            ::close(fd);
            return false;
        }
    }
    if ( dyld_cache_header_is_split(cache->header) ) {
        // Extents were validated above, so the sums in the checks below cannot wrap.
        if ( !splitFileMappingsAreValid(fileMappings, cache->header.mappingCount) ) {
            results->errorMessage = "shared cache split mappings are invalid";
            ::close(fd);
            return false;
        }
        if ( !splitHeaderIsMapped(cache->header, fileMappings[0].address, fileMappings[0].fileOffset, fileMappings[0].size) ) {
            results->errorMessage = "shared cache split header is not mapped at the region start";
            ::close(fd);
            return false;
        }
        if ( !splitSignatureCoversMappings(cache->header, fileMappings, cache->header.mappingCount, cacheFileLength) ) {
            results->errorMessage = "shared cache split signature does not cover its mappings";
            ::close(fd);
            return false;
        }
    }
    else {
        if (  (textMapping->fileOffset != 0)
          || ((fileMappings[0].address + fileMappings[0].size) > firstDataMapping->address)
          || ((fileMappings[0].fileOffset + fileMappings[0].size) != firstDataMapping->fileOffset)
          || (cache->header.codeSignatureOffset > cacheFileLength)
          || (cache->header.codeSignatureSize != cacheFileLength - cache->header.codeSignatureOffset)
          || (textMapping->maxProt != (VM_PROT_READ|VM_PROT_EXECUTE))
          || (linkeditMapping->maxProt != VM_PROT_READ) ) {
            results->errorMessage = "shared cache text/linkedit mappings are invalid";
            ::close(fd);
            return false;
        }

        // Check the __DATA mappings
        for (unsigned i = 1; i != (cache->header.mappingCount - 1); ++i) {
            if ( ((fileMappings[i].address + fileMappings[i].size) > fileMappings[i + 1].address)
              || ((fileMappings[i].fileOffset + fileMappings[i].size) != fileMappings[i + 1].fileOffset)
              || (fileMappings[i].maxProt != (VM_PROT_READ|VM_PROT_WRITE)) ) {
                results->errorMessage = "shared cache data mappings are invalid";
                ::close(fd);
                return false;
            }
        }

        if ( (textMapping->address != cache->header.sharedRegionStart) || ((linkeditMapping->address + linkeditMapping->size) > (cache->header.sharedRegionStart+cache->header.sharedRegionSize)) ) {
            results->errorMessage = "shared cache file mapping addressses invalid";
            ::close(fd);
            return false;
        }
    }

    // Use the same format discriminator as the slide-table consumer below.
    // A modern header with zero entries must not bypass this validation.
    if ( cache->header.mappingOffset > __offsetof(dyld_cache_header, mappingWithSlideOffset) ) {
        if ( (cache->header.mappingWithSlideCount != cache->header.mappingCount)
          || (cache->header.mappingWithSlideOffset % alignof(dyld_cache_mapping_and_slide_info) != 0)
          || !cacheRangeContains(0, sizeof(firstPage), cache->header.mappingWithSlideOffset,
                                  uint64_t(cache->header.mappingWithSlideCount) * sizeof(dyld_cache_mapping_and_slide_info)) ) {
            results->errorMessage = "shared cache slide mappings are invalid";
            ::close(fd);
            return false;
        }
    }

    // register code signature of cache file
    fsignatures_t siginfo;
    siginfo.fs_file_start = 0;  // cache always starts at beginning of file
    siginfo.fs_blob_start = (void*)cache->header.codeSignatureOffset;
    siginfo.fs_blob_size  = (size_t)(cache->header.codeSignatureSize);
    int result = fcntl(fd, F_ADDFILESIGS_RETURN, &siginfo);
    if ( result == -1 ) {
        results->errorMessage = "code signature registration for shared cache failed";
        ::close(fd);
        return false;
    }

    // <rdar://problem/23188073> validate code signature covers entire shared cache
    uint64_t codeSignedLength = siginfo.fs_file_start;
    if ( codeSignedLength < cache->header.codeSignatureOffset ) {
        results->errorMessage = "code signature does not cover entire shared cache file";
        ::close(fd);
        return false;
    }
    void* mappedData = ::mmap(NULL, sizeof(firstPage), PROT_READ|PROT_EXEC, MAP_PRIVATE, fd, 0);
    if ( mappedData == MAP_FAILED ) {
        results->errorMessage = "first page of shared cache not mmap()able";
        ::close(fd);
        return false;
    }
    if ( memcmp(mappedData, firstPage, sizeof(firstPage)) != 0 ) {
        results->errorMessage = "first page of mmap()ed shared cache not valid";
        ::munmap(mappedData, sizeof(firstPage));
        ::close(fd);
        return false;
    }
    ::munmap(mappedData, sizeof(firstPage));

    // fill out results
    info->mappingsCount = cache->header.mappingCount;
    // We have to emit the mapping for the __LINKEDIT before the slid mappings
    // This is so that the kernel has already mapped __LINKEDIT in to its address space
    // for when it copies the slid info for each __DATA mapping
    for (int i=0; i < cache->header.mappingCount; ++i) {
        uint64_t    slideInfoFileOffset = 0;
        uint64_t    slideInfoFileSize   = 0;
        vm_prot_t   authProt            = 0;
        vm_prot_t   initProt            = fileMappings[i].initProt;
        if ( cache->header.mappingOffset <= __offsetof(dyld_cache_header, mappingWithSlideOffset) ) {
            // Old cache without the new slid mappings
            if ( i == 1 ) {
                // Add slide info to the __DATA mapping
                slideInfoFileOffset = cache->header.slideInfoOffsetUnused;
                slideInfoFileSize   = cache->header.slideInfoSizeUnused;
                // Don't set auth prot to anything interseting on the old mapppings
                authProt = 0;
            }
        } else {
            // New cache where each mapping has a corresponding slid mapping
            const dyld_cache_mapping_and_slide_info* slidableMappings = (const dyld_cache_mapping_and_slide_info*)&firstPage[cache->header.mappingWithSlideOffset];
            slideInfoFileOffset = slidableMappings[i].slideInfoFileOffset;
            slideInfoFileSize   = slidableMappings[i].slideInfoFileSize;
            if ( (slidableMappings[i].flags & DYLD_CACHE_MAPPING_AUTH_DATA) == 0 )
                authProt = VM_PROT_NOAUTH;
            if ( (slidableMappings[i].flags & DYLD_CACHE_MAPPING_CONST_DATA) != 0 ) {
                // The cache was built with __DATA_CONST being read-only.  We can override that
                // with a boot-arg
                if ( !gEnableSharedCacheDataConst )
                    initProt |= VM_PROT_WRITE;
            }
        }

        // Add a file for each mapping
        info->fd                        = fd;
        info->mappings[i].sms_address               = fileMappings[i].address;
        info->mappings[i].sms_size                  = fileMappings[i].size;
        info->mappings[i].sms_file_offset           = fileMappings[i].fileOffset;
        info->mappings[i].sms_slide_size            = 0;
        info->mappings[i].sms_slide_start           = 0;
        info->mappings[i].sms_max_prot              = fileMappings[i].maxProt;
        info->mappings[i].sms_init_prot             = initProt;
        if ( slideInfoFileSize != 0 ) {
            const dyld_cache_mapping_info* slideMapping = nullptr;
            for (uint32_t j = 0; j != cache->header.mappingCount; ++j) {
                if ( cacheRangeContains(fileMappings[j].fileOffset, fileMappings[j].size,
                                        slideInfoFileOffset, slideInfoFileSize) ) {
                    slideMapping = &fileMappings[j];
                    break;
                }
            }
            if ( slideMapping == nullptr ) {
                results->errorMessage = "shared cache slide info lies outside mappings";
                ::close(fd);
                return false;
            }
            uint64_t offsetInSlideRegion = slideInfoFileOffset - slideMapping->fileOffset;
            info->mappings[i].sms_slide_start   = (user_addr_t)(slideMapping->address + offsetInSlideRegion);
            info->mappings[i].sms_slide_size    = (user_addr_t)slideInfoFileSize;
            info->mappings[i].sms_init_prot    |= (VM_PROT_SLIDE | authProt);
            info->mappings[i].sms_max_prot     |= (VM_PROT_SLIDE | authProt);
        }
    }
    info->sharedRegionStart = cache->header.sharedRegionStart;
    info->sharedRegionSize  = cache->header.sharedRegionSize;
    info->maxSlide          = cache->header.maxSlide;
    return true;
}


#if !TARGET_OS_SIMULATOR

// update all __DATA pages with slide info
static bool rebaseDataPages(bool isVerbose, const dyld_cache_slide_info* slideInfo, const uint8_t *dataPagesStart,
                            uint64_t sharedRegionStart, SharedCacheLoadInfo* results)
{
    const dyld_cache_slide_info* slideInfoHeader = slideInfo;
    if ( slideInfoHeader != nullptr ) {
        if ( slideInfoHeader->version == 2 ) {
            const dyld_cache_slide_info2* slideHeader = (dyld_cache_slide_info2*)slideInfo;
            const uint32_t  page_size = slideHeader->page_size;
            const uint16_t* page_starts = (uint16_t*)((long)(slideInfo) + slideHeader->page_starts_offset);
            const uint16_t* page_extras = (uint16_t*)((long)(slideInfo) + slideHeader->page_extras_offset);
            for (int i=0; i < slideHeader->page_starts_count; ++i) {
                uint8_t* page = (uint8_t*)(long)(dataPagesStart + (page_size*i));
                uint16_t pageEntry = page_starts[i];
                //dyld::log("page[%d]: page_starts[i]=0x%04X\n", i, pageEntry);
                if ( pageEntry == DYLD_CACHE_SLIDE_PAGE_ATTR_NO_REBASE )
                    continue;
                if ( pageEntry & DYLD_CACHE_SLIDE_PAGE_ATTR_EXTRA ) {
                    uint16_t chainIndex = (pageEntry & 0x3FFF);
                    bool done = false;
                    while ( !done ) {
                        uint16_t pInfo = page_extras[chainIndex];
                        uint16_t pageStartOffset = (pInfo & 0x3FFF)*4;
                        //dyld::log("     chain[%d] pageOffset=0x%03X\n", chainIndex, pageStartOffset);
                        rebaseChainV2(page, pageStartOffset, results->slide, slideHeader);
                        done = (pInfo & DYLD_CACHE_SLIDE_PAGE_ATTR_END);
                        ++chainIndex;
                    }
                }
                else {
                    uint32_t pageOffset = pageEntry * 4;
                    //dyld::log("     start pageOffset=0x%03X\n", pageOffset);
                    rebaseChainV2(page, pageOffset, results->slide, slideHeader);
                }
            }
        }
#if __LP64__
        else if ( slideInfoHeader->version == 3 ) {
             const dyld_cache_slide_info3* slideHeader = (dyld_cache_slide_info3*)slideInfo;
             const uint32_t                pageSize    = slideHeader->page_size;
             for (int i=0; i < slideHeader->page_starts_count; ++i) {
                 uint8_t* page = (uint8_t*)(dataPagesStart + (pageSize*i));
                 uint64_t delta = slideHeader->page_starts[i];
                 //dyld::log("page[%d]: page_starts[i]=0x%04X\n", i, delta);
                 if ( delta == DYLD_CACHE_SLIDE_V3_PAGE_ATTR_NO_REBASE )
                     continue;
                 delta = delta/sizeof(uint64_t); // initial offset is byte based
                 dyld_cache_slide_pointer3* loc = (dyld_cache_slide_pointer3*)page;
                 do {
                     loc += delta;
                     delta = loc->plain.offsetToNextPointer;
                     if ( loc->auth.authenticated ) {
#if __has_feature(ptrauth_calls)
                        uint64_t target = sharedRegionStart + loc->auth.offsetFromSharedCacheBase + results->slide;
                        MachOLoaded::ChainedFixupPointerOnDisk ptr;
                        ptr.raw64 = *((uint64_t*)loc);
                        loc->raw = ptr.arm64e.signPointer(loc, target);
#else
                        results->errorMessage = "invalid pointer kind in cache file";
                        return false;
#endif
                     }
                     else {
                        MachOLoaded::ChainedFixupPointerOnDisk ptr;
                        ptr.raw64 = *((uint64_t*)loc);
                        loc->raw = ptr.arm64e.unpackTarget() + results->slide;
                     }
                } while (delta != 0);
            }
        }
#else
        else if ( slideInfoHeader->version == 4 ) {
            const dyld_cache_slide_info4* slideHeader = (dyld_cache_slide_info4*)slideInfo;
            const uint32_t  page_size = slideHeader->page_size;
            const uint16_t* page_starts = (uint16_t*)((long)(slideInfo) + slideHeader->page_starts_offset);
            const uint16_t* page_extras = (uint16_t*)((long)(slideInfo) + slideHeader->page_extras_offset);
            for (int i=0; i < slideHeader->page_starts_count; ++i) {
                uint8_t* page = (uint8_t*)(long)(dataPagesStart + (page_size*i));
                uint16_t pageEntry = page_starts[i];
                //dyld::log("page[%d]: page_starts[i]=0x%04X\n", i, pageEntry);
                if ( pageEntry == DYLD_CACHE_SLIDE4_PAGE_NO_REBASE )
                    continue;
                if ( pageEntry & DYLD_CACHE_SLIDE4_PAGE_USE_EXTRA ) {
                    uint16_t chainIndex = (pageEntry & DYLD_CACHE_SLIDE4_PAGE_INDEX);
                    bool done = false;
                    while ( !done ) {
                        uint16_t pInfo = page_extras[chainIndex];
                        uint16_t pageStartOffset = (pInfo & DYLD_CACHE_SLIDE4_PAGE_INDEX)*4;
                        //dyld::log("     chain[%d] pageOffset=0x%03X\n", chainIndex, pageStartOffset);
                        rebaseChainV4(page, pageStartOffset, results->slide, slideHeader);
                        done = (pInfo & DYLD_CACHE_SLIDE4_PAGE_EXTRA_END);
                        ++chainIndex;
                    }
                }
                else {
                    uint32_t pageOffset = pageEntry * 4;
                    //dyld::log("     start pageOffset=0x%03X\n", pageOffset);
                    rebaseChainV4(page, pageOffset, results->slide, slideHeader);
                }
            }
        }
#endif // LP64
        else {
            results->errorMessage = "invalid slide info in cache file";
            return false;
        }
    }
    return true;
}

static bool reuseExistingCache(const SharedCacheOptions& options, SharedCacheLoadInfo* results)
{
    uint64_t cacheBaseAddress;
#if __i386__
    if ( syscall(294, &cacheBaseAddress) == 0 ) {
#else
    if ( __shared_region_check_np(&cacheBaseAddress) == 0 ) {
#endif
        const DyldSharedCache* existingCache = (DyldSharedCache*)cacheBaseAddress;
        if ( validMagic(options, existingCache) ) {
            const dyld_cache_mapping_info* const fileMappings = (dyld_cache_mapping_info*)(cacheBaseAddress + existingCache->header.mappingOffset);
            results->loadAddress = existingCache;
            results->slide = (long)(cacheBaseAddress - fileMappings[0].address);
            // we don't know the path this cache was previously loaded from, assume default
            getCachePath(options, sizeof(results->path), results->path);
            if ( options.verbose ) {
                const dyld_cache_mapping_and_slide_info* const mappings = (const dyld_cache_mapping_and_slide_info*)(cacheBaseAddress + existingCache->header.mappingWithSlideOffset);
                dyld::log("re-using existing shared cache (%s):\n", results->path);
                shared_file_mapping_slide_np slidMappings[DyldSharedCache::MaxMappings];
                for (int i=0; i < DyldSharedCache::MaxMappings; ++i) {
                    slidMappings[i].sms_address = mappings[i].address;
                    slidMappings[i].sms_size = mappings[i].size;
                    slidMappings[i].sms_file_offset = mappings[i].fileOffset;
                    slidMappings[i].sms_max_prot = mappings[i].maxProt;
                    slidMappings[i].sms_init_prot = mappings[i].initProt;
                    slidMappings[i].sms_address += results->slide;
                    if ( existingCache->header.mappingOffset > __offsetof(dyld_cache_header, mappingWithSlideOffset) ) {
                        // New caches have slide info on each new mapping
                        const dyld_cache_mapping_and_slide_info* const slidableMappings = (dyld_cache_mapping_and_slide_info*)(cacheBaseAddress + existingCache->header.mappingWithSlideOffset);
                        assert(existingCache->header.mappingWithSlideCount <= DyldSharedCache::MaxMappings);
                        if ( !(slidableMappings[i].flags & DYLD_CACHE_MAPPING_AUTH_DATA) ) {
                            slidMappings[i].sms_max_prot  |= VM_PROT_NOAUTH;
                            slidMappings[i].sms_init_prot |= VM_PROT_NOAUTH;
                        }
                        if ( (slidableMappings[i].flags & DYLD_CACHE_MAPPING_CONST_DATA) != 0 ) {
                            // The cache was built with __DATA_CONST being read-only.  We can override that
                            // with a boot-arg
                            if ( !gEnableSharedCacheDataConst )
                                slidMappings[i].sms_init_prot |= VM_PROT_WRITE;
                        }
                    }
                }
                verboseSharedCacheMappings(slidMappings, existingCache->header.mappingCount);
            }
        }
        else {
            results->errorMessage = "existing shared cache in memory is not compatible";
        }

        return true;
    }
    return false;
}

static long pickCacheASLRSlide(CacheInfo& info)
{
    // choose new random slide
#if TARGET_OS_IPHONE || (TARGET_OS_OSX && TARGET_CPU_ARM64)
    // <rdar://problem/20848977> change shared cache slide for 32-bit arm to always be 16k aligned
    long slide;
    if (info.maxSlide == 0)
        slide = 0;
    else
        slide = ((arc4random() % info.maxSlide) & (-16384));
#else
    long slide;
    if (info.maxSlide == 0)
        slide = 0;
    else
        slide = ((arc4random() % info.maxSlide) & (-4096));
#if defined(__x86_64__) && !TARGET_OS_SIMULATOR
    if (dyld::isTranslated()) {
        slide &= (-16384);
    }
#endif
#endif
    
    return slide;
}

static bool mapCacheSystemWide(const SharedCacheOptions& options, SharedCacheLoadInfo* results)
{
    CacheInfo info;
    if ( !preflightCacheFile(options, results, &info) )
        return false;

    int result = 0;
    if ( info.mappingsCount != 3 ) {
        uint32_t maxSlide = options.disableASLR ? 0 : (uint32_t)info.maxSlide;

        shared_file_np file;
        file.sf_fd = info.fd;
        file.sf_mappings_count = info.mappingsCount;
        // For the new syscall, this is actually the max slide.  The kernel now owns the actual slide
        file.sf_slide = maxSlide;
        result = __shared_region_map_and_slide_2_np(1, &file, info.mappingsCount, info.mappings);
    } else {
        // With the old syscall, dyld has to choose the slide
        results->slide = options.disableASLR ? 0 : pickCacheASLRSlide(info);

        // update mappings based on the slide we choose
        for (uint32_t i=0; i < info.mappingsCount; ++i) {
            info.mappings[i].sms_address += results->slide;
            if ( info.mappings[i].sms_slide_size != 0 )
                info.mappings[i].sms_slide_start += (uint32_t)results->slide;
        }

        // If we get here then we don't have the new kernel function, so use the old one
        const dyld_cache_slide_info2*   slideInfo       = nullptr;
        size_t                          slideInfoSize   = 0;
        shared_file_mapping_np mappings[3];
        for (unsigned i = 0; i != 3; ++i) {
            mappings[i].sfm_address         = info.mappings[i].sms_address;
            mappings[i].sfm_size            = info.mappings[i].sms_size;
            mappings[i].sfm_file_offset     = info.mappings[i].sms_file_offset;
            mappings[i].sfm_max_prot        = info.mappings[i].sms_max_prot;
            mappings[i].sfm_init_prot       = info.mappings[i].sms_init_prot;
            if ( info.mappings[i].sms_slide_size != 0 ) {
                slideInfo       = (dyld_cache_slide_info2*)info.mappings[i].sms_slide_start;
                slideInfoSize   = (size_t)info.mappings[i].sms_slide_size;
            }
        }
        result = __shared_region_map_and_slide_np(info.fd, 3, mappings, results->slide, slideInfo, slideInfoSize);
    }

    ::close(info.fd);
    if ( result == 0 ) {
        results->loadAddress = (const DyldSharedCache*)(info.mappings[0].sms_address);
        if ( info.mappingsCount != 3 ) {
            // We don't know our own slide any more as the kernel owns it, so ask for it again now
            if ( reuseExistingCache(options, results) ) {

                // update mappings based on the slide the kernel chose
                for (uint32_t i=0; i < info.mappingsCount; ++i) {
                    info.mappings[i].sms_address += results->slide;
                    if ( info.mappings[i].sms_slide_size != 0 )
                        info.mappings[i].sms_slide_start += (uint32_t)results->slide;
                }

                if ( options.verbose )
                    verboseSharedCacheMappingsToConsole(info.mappings, info.mappingsCount);
                return true;
            }
            // Uh oh, we mapped the kernel, but we didn't find the slide
            if ( options.verbose )
                dyld::logToConsole("dyld: error finding shared cache slide for system wide mapping\n");
            return false;
        }
    }
    else {
        // could be another process beat us to it
        if ( reuseExistingCache(options, results) )
            return true;
        // if cache does not exist, then really is an error
        if ( results->errorMessage == nullptr )
            results->errorMessage = "syscall to map cache into shared region failed";
        return false;
    }

    if ( options.verbose ) {
        dyld::log("mapped dyld cache file system wide: %s\n", results->path);
        verboseSharedCacheMappings(info.mappings, info.mappingsCount);
    }
    return true;
}
#endif // TARGET_OS_SIMULATOR

static int mmapProtection(uint32_t vmProt)
{
    return ((vmProt & VM_PROT_READ) ? PROT_READ : 0) | ((vmProt & VM_PROT_WRITE) ? PROT_WRITE : 0)
         | ((vmProt & VM_PROT_EXECUTE) ? PROT_EXEC : 0);
}

#if defined(DARLING)
// Reserve with a hint, never MAP_FIXED: a collision must not replace live code.
// Once acquired, the file mappings may safely replace our own reservation.
class DarlingCacheReservation {
    void* address = MAP_FAILED;
    size_t size = 0;
public:
    bool acquire(uint64_t start, uint64_t length) {
        if ( start == 0 || length == 0 || start > UINTPTR_MAX
          || length > SIZE_MAX || length > UINTPTR_MAX - start )
            return false;
        void* requested = (void*)(uintptr_t)start;
        void* mapped = ::mmap(requested, (size_t)length, PROT_NONE,
                              MAP_PRIVATE | MAP_ANON, -1, 0);
        if ( mapped == MAP_FAILED )
            return false;
        if ( mapped != requested ) {
            ::munmap(mapped, (size_t)length);
            return false;
        }
        address = mapped;
        size = (size_t)length;
        return true;
    }
    void keep() { address = MAP_FAILED; }
    ~DarlingCacheReservation() {
        if ( address != MAP_FAILED )
            ::munmap(address, size);
    }
};
#endif

#if defined(DARLING) && defined(__arm64__)
extern "C" unsigned long sys_thread_get_native_tsd_slot_offset(void);

class DarlingTSDReadVeneers {
    uint32_t* memory = nullptr;
    size_t used = 0;
    unsigned long slot = 0;
    bool committed = false;
    static const size_t capacity = 1024 * 1024;
    static bool branch(uintptr_t from, uintptr_t to, uint32_t& encoded) {
        int64_t delta = (int64_t)to - (int64_t)from;
        if ((delta & 3) || delta < -(1LL << 27) || delta >= (1LL << 27))
            return false;
        encoded = 0x14000000U | ((uint32_t)(delta >> 2) & 0x03FFFFFFU);
        return true;
    }
public:
    DarlingTSDReadVeneers(uintptr_t cacheStart, unsigned long offset) : slot(offset) {
        if (offset < 16 || offset > 32760 || (offset & 7) || cacheStart <= capacity)
            return;
        void* desired = (void*)(cacheStart - capacity);
        void* mapped = ::mmap(desired, capacity, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANON, -1, 0);
        if (mapped != desired) {
            if (mapped != MAP_FAILED) ::munmap(mapped, capacity);
            return;
        }
        memory = (uint32_t*)mapped;
    }
    ~DarlingTSDReadVeneers() {
        if (memory && !committed) ::munmap(memory, capacity);
    }
    uint32_t translate(uint32_t reg, uintptr_t original) {
        if (reg == 31) return 0xD503201FU; // MRS XZR has no observable result
        uint32_t entryBranch, returnBranch;
        if (!memory || used + 20 > capacity
            || !branch(original, (uintptr_t)memory + used, entryBranch)
            || !branch((uintptr_t)memory + used + 16, original + 4, returnBranch))
            return 0x0000DA00U | reg;
        uint32_t* code = (uint32_t*)((uintptr_t)memory + used);
        code[0] = 0xD53BD040U | reg; // mrs Xd, TPIDR_EL0
        code[1] = 0xF9400000U | ((uint32_t)(slot / 8) << 10) | (reg << 5) | reg;
        code[2] = 0xB5000040U | reg; // cbnz Xd, +8 (preserves NZCV)
        code[3] = 0x0000DA00U | reg; // uninitialized slot: existing TSD trap
        code[4] = returnBranch;
        used += 20;
        return entryBranch;
    }
    size_t count() const { return used / 20; }
    bool finish() {
        if (memory) {
            sys_icache_invalidate(memory, used);
            if (::mprotect(memory, capacity, PROT_READ | PROT_EXEC) != 0)
                return false;
        }
        committed = true;
        return true;
    }
};

static bool translateDarlingCacheTSD(const CacheInfo& info, const char** errorMessage)
{
    DarlingTSDReadVeneers veneers(info.mappings[0].sms_address,
                                 sys_thread_get_native_tsd_slot_offset());
    for (uint32_t i = 0; i < info.mappingsCount; ++i) {
        const auto& mapping = info.mappings[i];
        if (!(mapping.sms_init_prot & VM_PROT_EXECUTE))
            continue;
        void* start = (void*)(uintptr_t)mapping.sms_address;
        size_t size = (size_t)mapping.sms_size;
        if (::mprotect(start, size, PROT_READ | PROT_WRITE) != 0) {
            *errorMessage = "could not make private cache text writable for TSD translation";
            return false;
        }
        uint32_t* instruction = (uint32_t*)start;
        uint32_t* end = instruction + size / sizeof(uint32_t);
        bool changed = false;
        for (; instruction != end; ++instruction) {
            if ((*instruction & 0xFFFFFFE0U) != 0xD53BD060U)
                continue;
            const uint32_t reg = *instruction & 0x1FU;
            const uint32_t cpuIndexShift = 0xD34CFC00U | (reg << 5) | reg;
            // Darwin's allocator CPU-index read is not a TSD pointer read.
            if ((instruction + 1 != end) && instruction[1] == cpuIndexShift)
                *instruction = 0xAA1F03E0U | reg; // mov Xd, XZR
            else
                *instruction = veneers.translate(reg, (uintptr_t)instruction);
            changed = true;
        }
        if (changed)
            sys_icache_invalidate(start, size);
        if (::mprotect(start, size, mmapProtection(mapping.sms_init_prot)) != 0) {
            *errorMessage = "could not restore private cache text protections";
            return false;
        }
    }
    if (!veneers.finish()) {
        *errorMessage = "could not protect private cache TSD veneers";
        return false;
    }
    return true;
}
#endif

static bool mapCachePrivate(const SharedCacheOptions& options, SharedCacheLoadInfo* results)
{
    // open and validate cache file
    CacheInfo info;
    if ( !preflightCacheFile(options, results, &info) )
        return false;

    // compute ALSR slide
    results->slide = 0;
#if !TARGET_OS_SIMULATOR
    results->slide = options.disableASLR ? 0 : pickCacheASLRSlide(info);
#endif

    // update mappings
    for (uint32_t i=0; i < info.mappingsCount; ++i) {
        info.mappings[i].sms_address += (uint32_t)results->slide;
        if ( info.mappings[i].sms_slide_size != 0 )
            info.mappings[i].sms_slide_start += (uint32_t)results->slide;
    }

    results->loadAddress = (const DyldSharedCache*)(info.mappings[0].sms_address);

#if defined(DARLING)
    // Linux-backed Darling has no replaceable system-wide shared region.
    // Validate the complete destination span before any destructive mappings.
    const uint64_t slide = (uint32_t)results->slide;
    const uint64_t start = info.sharedRegionStart;
    const uint64_t length = info.sharedRegionSize;
    bool valid = start <= UINT64_MAX - slide;
    const uint64_t destination = valid ? start + slide : 0;
    valid = valid && length != 0 && length <= UINT64_MAX - destination;
    for (uint32_t i = 0; valid && i < info.mappingsCount; ++i) {
        const uint64_t address = info.mappings[i].sms_address;
        const uint64_t size = info.mappings[i].sms_size;
        valid = address >= destination && address - destination <= length
             && size <= length - (address - destination);
    }
    DarlingCacheReservation reservation;
    if ( !valid || !reservation.acquire(destination, length) ) {
        results->loadAddress = nullptr;
        results->errorMessage = "could not reserve unoccupied private shared cache region";
        ::close(info.fd);
        return false;
    }
#else
    // deallocate any existing system wide shared cache
    deallocateExistingSharedCache();
#endif

#if TARGET_OS_SIMULATOR && TARGET_OS_WATCH && !defined(DARLING)
    // <rdar://problem/50887685> watchOS 32-bit cache does not overlap macOS dyld cache address range
    // mmap() of a file needs a vm_allocation behind it, so make one
    vm_address_t loadAddress = 0x40000000;
    ::vm_allocate(mach_task_self(), &loadAddress, 0x40000000, VM_FLAGS_FIXED);
#endif

    // map cache just for this process with mmap()
    for (int i=0; i < info.mappingsCount; ++i) {
        void* mmapAddress = (void*)(uintptr_t)(info.mappings[i].sms_address);
        size_t size = (size_t)(info.mappings[i].sms_size);
        //dyld::log("dyld: mapping address %p with size 0x%08lX\n", mmapAddress, size);
        int protection = mmapProtection(info.mappings[i].sms_init_prot);
        off_t offset = info.mappings[i].sms_file_offset;
        if ( ::mmap(mmapAddress, size, protection, MAP_FIXED | MAP_PRIVATE, info.fd, offset) != mmapAddress ) {
            // failed to map some chunk of this shared cache file
            // clear shared region
#if !defined(DARLING)
            ::mmap((void*)((long)SHARED_REGION_BASE), SHARED_REGION_SIZE, PROT_NONE, MAP_FIXED | MAP_PRIVATE| MAP_ANON, 0, 0);
#endif
            // return failure
            results->loadAddress        = nullptr;
            results->errorMessage       = "could not mmap() part of dyld cache";
            ::close(info.fd);
            return false;
        }
    }
    ::close(info.fd);

#if TARGET_OS_SIMULATOR // simulator caches do not support sliding
#if defined(DARLING) && defined(__arm64__)
    if (!translateDarlingCacheTSD(info, &results->errorMessage)) {
        results->loadAddress = nullptr;
        return false;
    }
#endif
#if defined(DARLING)
    reservation.keep();
#endif
    return true;
#else

    // Change __DATA_CONST to read-write for this block
    DyldSharedCache::DataConstScopedWriter patcher(results->loadAddress, mach_task_self(), options.verbose ? &dyld::log : nullptr);

    __block bool success = true;
    for (int i=0; i < info.mappingsCount; ++i) {
        if ( info.mappings[i].sms_slide_size == 0 )
            continue;
        const dyld_cache_slide_info* slideInfoHeader = (const dyld_cache_slide_info*)info.mappings[i].sms_slide_start;
        const uint8_t* mappingPagesStart = (const uint8_t*)info.mappings[i].sms_address;
        success &= rebaseDataPages(options.verbose, slideInfoHeader, mappingPagesStart, info.sharedRegionStart, results);
    }

    if ( options.verbose ) {
        dyld::log("mapped dyld cache file private to process (%s):\n", results->path);
        verboseSharedCacheMappings(info.mappings, info.mappingsCount);
    }
#if defined(DARLING) && defined(__arm64__)
    if (success)
        success = translateDarlingCacheTSD(info, &results->errorMessage);
#endif
#if defined(DARLING)
    if ( success )
        reservation.keep();
    else
        results->loadAddress = nullptr;
#endif
    return success;
#endif
}



#if defined(DARLING) && !TARGET_OS_SIMULATOR
// Split caches (a main file plus ".NN" sub-cache files) mapped privately at their preferred address.
// Plain slide-info-v5 entries are rebased; authenticated ones are signed with this process's keys.

static const uint32_t kSplitMaxFileMappings = 16;
static const uint32_t kSplitMaxMappings     = 64;
static const uint32_t kSplitMaxSubCaches    = 32;
static const uint64_t kSplitMaxSlideInfo    = 64ULL * 1024 * 1024;

struct SplitMapping {
    dyld_cache_mapping_and_slide_info   info;
    uint32_t                            file;
};

struct SplitCacheFiles {
    int         fds[kSplitMaxSubCaches + 1];
    uint32_t    count = 0;
    ~SplitCacheFiles() {
        for (uint32_t i = 0; i != count; ++i)
            ::close(fds[i]);
    }
};

static bool preadAll(int fd, uint64_t offset, void* buffer, size_t length)
{
    uint8_t* out = (uint8_t*)buffer;
    while ( length != 0 ) {
        ssize_t n = ::pread(fd, out, length, (off_t)offset);
        if ( n <= 0 )
            return false;
        out += n;
        offset += (uint64_t)n;
        length -= (size_t)n;
    }
    return true;
}

// Why signing is impossible on this host, or nullptr when it is possible. dyld is a Darwin binary and has no
// getauxval(), so AT_HWCAP is read from the auxiliary vector the host kernel exposes (arm64 HWCAP_PACA).
static const char* splitCachePointerAuthError()
{
#if defined(__aarch64__) || defined(__arm64__)
    static const uint64_t kAtNull = 0;
    static const uint64_t kAtHwcap = 16;
    static const uint64_t kHwcapPaca = 1ULL << 30;
    const int fd = dyld3::open("/proc/self/auxv", O_RDONLY, 0);
    if ( fd == -1 )
        return "split cache has authenticated pointers but the host auxiliary vector cannot be opened to check pointer authentication";
    const char* error = "split cache has authenticated pointers but the host auxiliary vector has no AT_HWCAP";
    for (uint64_t i = 0; i != 128; ++i) {
        uint64_t entry[2];
        if ( !preadAll(fd, i * sizeof(entry), entry, sizeof(entry)) ) {
            error = "split cache has authenticated pointers but the host auxiliary vector is unreadable";
            break;
        }
        if ( entry[0] == kAtNull )
            break;
        if ( entry[0] == kAtHwcap ) {
            error = ((entry[1] & kHwcapPaca) != 0) ? nullptr
                  : "split cache has authenticated pointers but the host has no pointer authentication (HWCAP_PACA is not set)";
            break;
        }
    }
    ::close(fd);
    return error;
#else
    return "split cache has authenticated pointers but pointer authentication needs an arm64 host";
#endif
}

struct SplitAuthPolicy {
    SplitCacheAuthMode  mode;
    bool                verified;   // the host check runs once, when the first authenticated entry is met
};

static bool splitTarget(const dyld_cache_slide_info5& header, uint64_t runtimeOffset, uint64_t sharedRegionStart,
                        uint64_t sharedRegionSize, uint64_t* target, const char** error)
{
    if ( header.value_add > UINT64_MAX - runtimeOffset ) {
        *error = "split cache slide info target overflows";
        return false;
    }
    *target = header.value_add + runtimeOffset;
    if ( !cacheRangeContains(sharedRegionStart, sharedRegionSize, *target, 0) ) {
        *error = "split cache slide info target lies outside the cache region";
        return false;
    }
    return true;
}

// Rebases the entries of one mapping's slide info in place (slide 0): plain ones become pointers, authenticated
// ones are signed (or left, per the policy). Any structural doubt is an error: nothing here is allowed to
// write outside the page its chain started in.
static bool rebaseSlideInfoV5(uint8_t* mappingContent, uint64_t mappingSize,
                              uint64_t sharedRegionStart, uint64_t sharedRegionSize,
                              const uint8_t* slideInfo, uint64_t slideInfoSize,
                              SplitAuthPolicy* policy, SplitCacheMapStats* stats, const char** error)
{
    if ( slideInfoSize < sizeof(dyld_cache_slide_info5) ) {
        *error = "split cache slide info is truncated";
        return false;
    }
    dyld_cache_slide_info5 header;
    memcpy(&header, slideInfo, sizeof(header));
    if ( header.version != 5 ) {
        *error = "split cache slide info has an unknown version";
        return false;
    }
    const uint64_t pageSize = header.page_size;
    if ( (pageSize < sizeof(uint64_t)) || ((pageSize & (pageSize - 1)) != 0) || (pageSize > UINT16_MAX + 1ULL) ) {
        *error = "split cache slide info has an invalid page size";
        return false;
    }
    if ( header.page_starts_count > (slideInfoSize - sizeof(header)) / sizeof(uint16_t) ) {
        *error = "split cache slide info page_starts exceed the slide info";
        return false;
    }
    if ( header.page_starts_count > mappingSize / pageSize ) {
        *error = "split cache slide info covers more pages than its mapping";
        return false;
    }
    const uint8_t* pageStarts = slideInfo + sizeof(header);
    for (uint32_t page = 0; page != header.page_starts_count; ++page) {
        uint16_t start;
        memcpy(&start, pageStarts + page * sizeof(uint16_t), sizeof(start));
        if ( start == DYLD_CACHE_SLIDE_V5_PAGE_ATTR_NO_REBASE )
            continue;
        if ( (start & 7) != 0 ) {
            *error = "split cache slide info chain start is misaligned";
            return false;
        }
        if ( start > pageSize - sizeof(uint64_t) ) {
            *error = "split cache slide info chain starts outside its page";
            return false;
        }
        uint8_t* pageContent = mappingContent + (uint64_t)page * pageSize;
        uint64_t offset = start;
        for (;;) {
            uint64_t* location = (uint64_t*)(pageContent + offset);
            dyld_cache_slide_pointer5 pointer;
            pointer.raw = *location;
            uint64_t target;
            if ( pointer.auth.auth ) {
                if ( policy->mode == kSplitCacheAuthLeaveAlone ) {
                    ++stats->authLeftAlone;
                }
                else {
                    if ( !policy->verified ) {
                        if ( (*error = splitCachePointerAuthError()) != nullptr )
                            return false;
                        policy->verified = true;
                    }
                    if ( !splitTarget(header, pointer.auth.runtimeOffset, sharedRegionStart, sharedRegionSize, &target, error) )
                        return false;
                    // Slide info key bit: 0 = IA, 1 = DA; signPointer() numbers the keys IA, IB, DA, DB.
                    *location = MachOLoaded::ChainedFixupPointerOnDisk::Arm64e::signPointer(target, location, pointer.auth.addrDiv,
                                    (uint16_t)pointer.auth.diversity, pointer.auth.keyIsData ? 2 : 0);
                    ++stats->authSigned;
                }
            }
            else {
                if ( !splitTarget(header, pointer.regular.runtimeOffset, sharedRegionStart, sharedRegionSize, &target, error) )
                    return false;
                *location = target | ((uint64_t)pointer.regular.high8 << 56);
                ++stats->plainRebased;
            }
            const uint64_t strides = pointer.regular.next;
            if ( strides == 0 )
                break;
            if ( strides * sizeof(uint64_t) > (pageSize - sizeof(uint64_t)) - offset ) {
                *error = "split cache slide info chain leaves its page";
                return false;
            }
            offset += strides * sizeof(uint64_t);
        }
        ++stats->pagesWithChains;
    }
    return true;
}

static bool splitMappingsOverlap(const dyld_cache_mapping_and_slide_info& a, const dyld_cache_mapping_and_slide_info& b)
{
    return a.address < b.address + b.size && b.address < a.address + a.size;
}

static const char* openSplitCacheFile(const char* path, SplitCacheFiles& files, int* fd, uint64_t* length,
                                      dyld_cache_header* header, const dyld_cache_header* mainHeader)
{
    if ( files.count > kSplitMaxSubCaches )
        return "split cache has too many files";
    *fd = dyld3::open(path, O_RDONLY, 0);
    if ( *fd == -1 )
        return "split cache file open() failed";
    files.fds[files.count++] = *fd;
    struct stat statBuf;
    if ( ::fstat(*fd, &statBuf) != 0 )
        return "split cache file fstat() failed";
    *length = (uint64_t)statBuf.st_size;
    if ( (*length < sizeof(*header)) || !preadAll(*fd, 0, header, sizeof(*header)) )
        return "split cache file header unreadable";
    if ( strncmp(header->magic, "dyld_v1", 7) != 0 )
        return "split cache file has wrong magic";
    // A sub-cache must be of the same architecture and platform as the main file.
    if ( (mainHeader != nullptr)
      && ((memcmp(header->magic, mainHeader->magic, sizeof(header->magic)) != 0) || (header->platform != mainHeader->platform)) )
        return "split cache sub-cache does not match the main file";
    return nullptr;
}

// Appends this file's mappings to all[] after checking each against the region, the file and the
// mappings of every file loaded before it.
static const char* loadSplitFileMappings(int fd, uint64_t fileLength, const dyld_cache_header& header, uint32_t fileIndex,
                                         uint64_t regionStart, uint64_t regionSize, SplitMapping* all, uint32_t* total)
{
    const uint32_t count = header.mappingWithSlideCount;
    const uint64_t pageSize = (uint64_t)getpagesize();
    if ( (count == 0) || (count > kSplitMaxFileMappings) || (*total + count > kSplitMaxMappings) )
        return "split cache file has an invalid mapping count";
    if ( (header.mappingWithSlideOffset % alignof(dyld_cache_mapping_and_slide_info) != 0)
      || !cacheRangeContains(0, fileLength, header.mappingWithSlideOffset, uint64_t(count) * sizeof(dyld_cache_mapping_and_slide_info)) )
        return "split cache mapping table lies outside its file";
    for (uint32_t i = 0; i != count; ++i) {
        SplitMapping& m = all[*total];
        if ( !preadAll(fd, header.mappingWithSlideOffset + uint64_t(i) * sizeof(m.info), &m.info, sizeof(m.info)) )
            return "split cache mapping table unreadable";
        m.file = fileIndex;
        // mmap rounds a size up to a page, which would expose bytes past the mapping.
        if ( (m.info.size == 0) || (m.info.size % pageSize != 0)
          || (m.info.address % pageSize != 0) || (m.info.fileOffset % pageSize != 0) )
            return "split cache mapping is empty or misaligned";
        // Each file's header is read through its first mapping (a sub-cache's at regionStart + cacheVMOffset).
        if ( (i == 0) && (m.info.fileOffset != 0) )
            return "split cache file does not start with its header";
        if ( !cacheRangeContains(regionStart, regionSize, m.info.address, m.info.size) )
            return "split cache mapping lies outside the shared region";
        if ( !cacheRangeContains(0, fileLength, m.info.fileOffset, m.info.size) )
            return "split cache mapping lies outside its file";
        if ( (m.info.slideInfoFileSize != 0)
          && (!cacheRangeContains(0, fileLength, m.info.slideInfoFileOffset, m.info.slideInfoFileSize)
              || (m.info.slideInfoFileSize > kSplitMaxSlideInfo)) )
            return "split cache slide info lies outside its file";
        if ( !cacheProtectionIsValid(m.info.maxProt) || !cacheProtectionIsValid(m.info.initProt) )
            return "split cache mapping protections are invalid";
        for (uint32_t j = 0; j != *total; ++j) {
            if ( splitMappingsOverlap(all[j].info, m.info) )
                return "split cache mappings overlap";
        }
        ++*total;
    }
    return nullptr;
}

// Deferred on purpose, not oversights:
// - No translateDarlingCacheTSD pass: the TSD rewrite and its veneer reach for a split cache is a separate design.
// - Protections: each mapping gets its raw initProt, whereas the legacy mapCachePrivate path adds VM_PROT_WRITE to a
//   DATA_CONST mapping unless gEnableSharedCacheDataConst is set. Revisit when dyld starts binding into the cache.
// - Authenticated pointers are signed with the running process's own keys; this never changes, resets or
//   disables a key, it only executes the PAC instructions.
// - authMode defaults to signing, the production behaviour; kSplitCacheAuthLeaveAlone (and authLeftAlone) exist for
//   host tests on machines without PAC and for no other caller.
bool mapSplitCachePrivate(const char* mainCachePath, bool verbose, SharedCacheLoadInfo* results, SplitCacheMapStats* stats,
                          SplitCacheAuthMode authMode)
{
    memset(stats, 0, sizeof(*stats));
    results->loadAddress = nullptr;
    results->slide = 0;
    results->errorMessage = nullptr;

    SplitAuthPolicy policy = { authMode, false };
    SplitCacheFiles files;
    SplitMapping mappings[kSplitMaxMappings];
    uint32_t mappingCount = 0;
    const char* error = nullptr;
    int mainFd;
    uint64_t mainLength;
    dyld_cache_header mainHeader;
    const size_t mainPathLength = strlen(mainCachePath);

    if ( mainPathLength >= sizeof(results->path) ) {
        results->errorMessage = "split cache path is too long";
        return false;
    }
    if ( (error = openSplitCacheFile(mainCachePath, files, &mainFd, &mainLength, &mainHeader, nullptr)) != nullptr ) {
        results->errorMessage = error;
        return false;
    }
    const uint64_t regionStart = mainHeader.sharedRegionStart;
    const uint64_t regionSize = mainHeader.sharedRegionSize;
    const uint32_t subCacheCount = mainHeader.subCacheArrayCount;
    if ( !dyld_cache_header_is_split(mainHeader) || (regionStart == 0) || (regionSize == 0) || (subCacheCount > kSplitMaxSubCaches)
      || !cacheRangeContains(0, mainLength, mainHeader.subCacheArrayOffset, uint64_t(subCacheCount) * sizeof(dyld_subcache_entry)) ) {
        results->errorMessage = "split cache main file header is invalid";
        return false;
    }
    if ( (error = loadSplitFileMappings(mainFd, mainLength, mainHeader, 0, regionStart, regionSize, mappings, &mappingCount)) != nullptr ) {
        results->errorMessage = error;
        return false;
    }
    if ( !splitHeaderIsMapped(mainHeader, mappings[0].info.address, mappings[0].info.fileOffset, mappings[0].info.size)
      || (mainHeader.mappingCount != mainHeader.mappingWithSlideCount) ) {
        results->errorMessage = "split cache main file does not map its header tables at the region start";
        return false;
    }
    // The legacy mapping array is what DyldSharedCache reads, so it must describe the same mappings.
    for (uint32_t i = 0; i != mainHeader.mappingCount; ++i) {
        dyld_cache_mapping_info legacy;
        if ( !preadAll(mainFd, mainHeader.mappingOffset + uint64_t(i) * sizeof(legacy), &legacy, sizeof(legacy))
          || (legacy.address != mappings[i].info.address) || (legacy.size != mappings[i].info.size)
          || (legacy.fileOffset != mappings[i].info.fileOffset) ) {
            results->errorMessage = "split cache main file mapping tables disagree";
            return false;
        }
    }

    for (uint32_t i = 0; i != subCacheCount; ++i) {
        dyld_subcache_entry entry;
        if ( !preadAll(mainFd, mainHeader.subCacheArrayOffset + uint64_t(i) * sizeof(entry), &entry, sizeof(entry)) ) {
            results->errorMessage = "split cache sub-cache table unreadable";
            return false;
        }
        const size_t suffixLength = strnlen(entry.fileSuffix, sizeof(entry.fileSuffix));
        if ( (suffixLength == 0) || (suffixLength == sizeof(entry.fileSuffix)) || (memchr(entry.fileSuffix, '/', suffixLength) != nullptr)
          || (mainPathLength + suffixLength >= sizeof(results->path)) ) {
            results->errorMessage = "split cache sub-cache file suffix is invalid";
            return false;
        }
        char path[sizeof(results->path)];
        memcpy(path, mainCachePath, mainPathLength);
        memcpy(path + mainPathLength, entry.fileSuffix, suffixLength);
        path[mainPathLength + suffixLength] = '\0';

        int fd;
        uint64_t length;
        dyld_cache_header header;
        if ( (error = openSplitCacheFile(path, files, &fd, &length, &header, &mainHeader)) != nullptr ) {
            results->errorMessage = error;
            return false;
        }
        // Placement comes from the main file's cacheVMOffset below: a sub-cache's own header names its
        // first mapping as sharedRegionStart and has no region size.
        if ( memcmp(header.uuid, entry.uuid, sizeof(entry.uuid)) != 0 ) {
            results->errorMessage = "split cache sub-cache does not match the main file";
            return false;
        }
        const uint32_t firstMapping = mappingCount;
        if ( (error = loadSplitFileMappings(fd, length, header, i + 1, regionStart, regionSize, mappings, &mappingCount)) != nullptr ) {
            results->errorMessage = error;
            return false;
        }
        if ( mappings[firstMapping].info.address - regionStart != entry.cacheVMOffset ) {
            results->errorMessage = "split cache sub-cache vm offset does not match its first mapping";
            return false;
        }
    }

    // Reserve the whole region first so that a collision fails before any live mapping is replaced.
    DarlingCacheReservation reservation;
    if ( !reservation.acquire(regionStart, regionSize) ) {
        results->errorMessage = "could not reserve unoccupied private shared cache region";
        return false;
    }
    for (uint32_t i = 0; i != mappingCount; ++i) {
        void* address = (void*)(uintptr_t)mappings[i].info.address;
        if ( ::mmap(address, (size_t)mappings[i].info.size, PROT_READ, MAP_FIXED | MAP_PRIVATE,
                    files.fds[mappings[i].file], (off_t)mappings[i].info.fileOffset) != address ) {
            results->errorMessage = "could not mmap() part of split dyld cache";
            return false;
        }
    }

    for (uint32_t i = 0; i != mappingCount; ++i) {
        const dyld_cache_mapping_and_slide_info& info = mappings[i].info;
        if ( info.slideInfoFileSize == 0 )
            continue;
        uint8_t* slideInfo = (uint8_t*)::malloc((size_t)info.slideInfoFileSize);
        bool ok = (slideInfo != nullptr) && preadAll(files.fds[mappings[i].file], info.slideInfoFileOffset, slideInfo, (size_t)info.slideInfoFileSize);
        if ( !ok ) {
            ::free(slideInfo);
            results->errorMessage = "split cache slide info unreadable";
            return false;
        }
        // The file mapping is private, so writing to it copies pages on demand and never touches the file.
        void* content = (void*)(uintptr_t)info.address;
        ok = (::mprotect(content, (size_t)info.size, PROT_READ | PROT_WRITE) == 0);
        if ( ok )
            ok = rebaseSlideInfoV5((uint8_t*)content, info.size, regionStart, regionSize, slideInfo, info.slideInfoFileSize, &policy, stats, &error);
        else
            error = "could not make split cache data writable for rebasing";
        ::free(slideInfo);
        if ( !ok ) {
            results->errorMessage = error;
            return false;
        }
    }

    for (uint32_t i = 0; i != mappingCount; ++i) {
        if ( ::mprotect((void*)(uintptr_t)mappings[i].info.address, (size_t)mappings[i].info.size,
                        mmapProtection(mappings[i].info.initProt)) != 0 ) {
            results->errorMessage = "could not apply split cache mapping protections";
            return false;
        }
    }

    stats->files = files.count;
    stats->mappings = mappingCount;
    results->loadAddress = (const DyldSharedCache*)(uintptr_t)regionStart;
    strlcpy(results->path, mainCachePath, sizeof(results->path));
    if ( verbose ) {
        dyld::log("mapped split dyld cache private to process (%s): %u mappings in %u files, %llu plain pointers rebased, %llu authenticated pointers signed, %llu authenticated pointers left in on-disk form\n",
                  results->path, mappingCount, files.count, (unsigned long long)stats->plainRebased,
                  (unsigned long long)stats->authSigned, (unsigned long long)stats->authLeftAlone);
    }
    reservation.keep();
    return true;
}
#endif // DARLING && !TARGET_OS_SIMULATOR


bool loadDyldCache(const SharedCacheOptions& options, SharedCacheLoadInfo* results)
{
    results->loadAddress        = 0;
    results->slide              = 0;
    results->errorMessage       = nullptr;

#if TARGET_OS_SIMULATOR
    // simulator only supports mmap()ing cache privately into process
    return mapCachePrivate(options, results);
#else
    if ( options.forcePrivate ) {
        // mmap cache into this process only
        return mapCachePrivate(options, results);
    }
    else {
        // fast path: when cache is already mapped into shared region
        bool hasError = false;
        if ( reuseExistingCache(options, results) ) {
            hasError = (results->errorMessage != nullptr);
        } else {
            // slow path: this is first process to load cache
            hasError = mapCacheSystemWide(options, results);
        }
        return hasError;
    }
#endif
}


bool findInSharedCacheImage(const SharedCacheLoadInfo& loadInfo, const char* dylibPathToFind, SharedCacheFindDylibResults* results)
{
    if ( loadInfo.loadAddress == nullptr )
        return false;

    if ( (loadInfo.loadAddress->header.formatVersion != dyld3::closure::kFormatVersion)
      || (loadInfo.loadAddress->header.dylibsImageArrayAddr == 0)
      || loadInfo.loadAddress->isSplitCache() ) {
        // support for older cache with a different Image* format
#if TARGET_OS_IPHONE
        uint64_t hash = 0;
        for (const char* s=dylibPathToFind; *s != '\0'; ++s)
                hash += hash*4 + *s;
#endif
        uint32_t imagesCount;
        const dyld_cache_image_info* const start = loadInfo.loadAddress->imageTable(imagesCount);
        const dyld_cache_image_info* const end = &start[imagesCount];
        // The path trie can outlive the dyld3 ImageArray format. Use recorded
        // aliases (including framework Current paths), not guessed versions.
        uint32_t aliasIndex = 0;
        if ( loadInfo.loadAddress->header.mappingOffset >= 0x118
          && loadInfo.loadAddress->header.dylibsTrieAddr != 0
          && loadInfo.loadAddress->header.dylibsTrieSize != 0
          && loadInfo.loadAddress->hasImagePath(dylibPathToFind, aliasIndex)
          && aliasIndex < imagesCount ) {
            const dyld_cache_image_info* p = &start[aliasIndex];
            results->mhInCache = (const mach_header*)(p->address + loadInfo.slide);
            results->pathInCache = (const char*)loadInfo.loadAddress + p->pathFileOffset;
            results->slideInCache = loadInfo.slide;
            results->image = nullptr;
            return true;
        }
        for (const dyld_cache_image_info* p = start; p != end; ++p) {
#if TARGET_OS_IPHONE
            // on iOS, inode is used to hold hash of path
            if ( (p->modTime == 0) && (p->inode != hash) )
                continue;
#endif
            const char* aPath = (char*)loadInfo.loadAddress + p->pathFileOffset;
            if ( strcmp(aPath, dylibPathToFind) == 0 ) {
                results->mhInCache    = (const mach_header*)(p->address+loadInfo.slide);
                results->pathInCache  = aPath;
                results->slideInCache = loadInfo.slide;
                results->image        = nullptr;
                return true;
            }
        }
        return false;
    }

    const dyld3::closure::ImageArray* images = loadInfo.loadAddress->cachedDylibsImageArray();
    results->image = nullptr;
    uint32_t imageIndex;
    if ( loadInfo.loadAddress->hasImagePath(dylibPathToFind, imageIndex) ) {
        results->image = images->imageForNum(imageIndex+1);
    }

    if ( results->image == nullptr )
        return false;

    results->mhInCache    = (const mach_header*)((uintptr_t)loadInfo.loadAddress + results->image->cacheOffset());
    results->pathInCache  = results->image->path();
    results->slideInCache = loadInfo.slide;
    return true;
}


bool pathIsInSharedCacheImage(const SharedCacheLoadInfo& loadInfo, const char* dylibPathToFind)
{
    if ( (loadInfo.loadAddress == nullptr) )
        return false;

    uint32_t imageIndex;
    return loadInfo.loadAddress->hasImagePath(dylibPathToFind, imageIndex);
}

void deallocateExistingSharedCache()
{
#if TARGET_OS_SIMULATOR
    // dyld deallocated macOS shared cache before jumping into dyld_sim
#else
    // <rdar://problem/50773474> remove the shared region sub-map
    uint64_t existingCacheAddress = 0;
    if ( __shared_region_check_np(&existingCacheAddress) == 0 ) {
        ::mmap((void*)((long)SHARED_REGION_BASE), SHARED_REGION_SIZE, PROT_NONE, MAP_FIXED | MAP_PRIVATE| MAP_ANON, 0, 0);
    }
#endif

}

} // namespace dyld3
