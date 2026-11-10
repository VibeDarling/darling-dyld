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



#ifndef __DYLD_SHARED_CACHE_RUNTIME_H__
#define __DYLD_SHARED_CACHE_RUNTIME_H__

#include <string.h>
#include <stdint.h>

#include "DyldSharedCache.h"
#include "PointerAuth.h"
#if defined(DARLING) && defined(__arm64__)
#include "DarlingTSDIslands.h"
#endif

namespace dyld3 {

struct SharedCacheOptions {
    const char*     cacheDirOverride;
    bool            forcePrivate;
    bool            useHaswell;
    bool            verbose;
    bool            disableASLR;
};

struct SharedCacheLoadInfo {
    typedef const DyldSharedCache* __ptrauth_dyld_address_auth DyldCachePtrType;
    DyldCachePtrType             loadAddress;
    long                         slide;
    const char*                  errorMessage;
    char                         path[256];
};

bool loadDyldCache(const SharedCacheOptions& options, SharedCacheLoadInfo* results);

#if defined(DARLING)
// What mapSplitCachePrivate() does with authenticated slide-info entries. Signing is the production behaviour and
// the default; kSplitCacheAuthLeaveAlone exists only for the host tests on machines without pointer
// authentication and has no other caller.
enum SplitCacheAuthMode {
    kSplitCacheAuthSign,        // sign them with this process's own keys; fails when the host has no pointer authentication
    kSplitCacheAuthLeaveAlone,  // keep them in their on-disk chain form (hosts without pointer authentication)
};

// Counts reported by mapSplitCachePrivate().
struct SplitCacheMapStats {
    uint32_t    files;
    uint32_t    mappings;
    uint64_t    pagesWithChains;
    uint64_t    plainRebased;
    uint64_t    authSigned;         // authenticated pointers, signed with this process's keys
    uint64_t    authLeftAlone;      // authenticated pointers, still in their on-disk form
};

// Maps a split cache (the main file at mainCachePath plus the sub-cache files its header lists, found by
// appending each suffix to that path) privately at its preferred address. dyld calls it only when
// DYLD_SHARED_CACHE_SPLIT_DIR is set.
bool mapSplitCachePrivate(const char* mainCachePath, bool verbose, SharedCacheLoadInfo* results, SplitCacheMapStats* stats,
                          SplitCacheAuthMode authMode = kSplitCacheAuthSign);

// The architecture part of the split cache's main file name for a main executable (dyld_shared_cache_<name>), or
// nullptr when no cache exists for it. Subtype flag bits are ignored. x86_64 has a name but no split mapper.
const char* splitCacheArchName(uint32_t cputype, uint32_t cpusubtype);

// nullptr when dir is usable as a cache directory (absolute, no control characters, short enough), else why not.
const char* splitCacheDirError(const char* dir);

// Writes the main cache file's path (dir, a separator unless dir ends in one, the cache name) into path.
// nullptr on success, else why it cannot be built: a bad dir, an architecture without a cache or
// without split mapper support, or a path longer than pathSize.
const char* splitCacheMainFilePath(const char* dir, uint32_t cputype, uint32_t cpusubtype, char* path, size_t pathSize);

#if defined(__arm64__)
// Rewrites the `mrs Xt, TPIDRRO_EL0` reads of one image of the mapped split cache to read Darling's TSD slot instead
// (see DarlingTSDIslands.h). The sites come from the sidecar table "<main cache file>.tsdsites", made by
// tests/darling-tsd/emit_tsd_sites.py from the same cache; it is loaded on the first call and must carry the main
// file's UUID. Call it once per cache image before any of its code runs; a second call for an image does nothing.
// nullptr on success, else why not (the caller halts: a half-translated cache image would read a null TSD base).
const char* translateSplitCacheTSD(const SharedCacheLoadInfo& cache, const mach_header* image, darling_tsd::PatchStats* stats);
#endif

// True only when dir is a directory and mainFilePath (the file splitCacheMainFilePath built) does not exist in it: the
// directory has no cache for this architecture. Every other failure to use the file is left to mapSplitCachePrivate.
bool splitCacheMainFileIsMissing(const char* dir, const char* mainFilePath);
#endif


static const uint32_t kNoCacheImageIndex = 0xFFFFFFFF;

struct SharedCacheFindDylibResults {
    const mach_header*          mhInCache;
    const char*                 pathInCache;    // the canonical path: aliases resolve to it
    long                        slideInCache;
    const closure::Image*       image;          // null for split and old caches
    uint32_t                    cacheImageIndex;// index in the cache's image table, kNoCacheImageIndex when not found
};

bool findInSharedCacheImage(const SharedCacheLoadInfo& loadInfo, const char* dylibPathToFind, SharedCacheFindDylibResults* results);

bool pathIsInSharedCacheImage(const SharedCacheLoadInfo& loadInfo, const char* dylibPathToFind);

// Which copy of a library dyld loads when the cache and/or a file on disk can serve its path.
enum SharedCacheLoadSource {
    kSharedCacheLoadFromDisk,
    kSharedCacheLoadFromCache,
};

// Canonical cache paths that a split cache serves even when a file exists at the same path on disk. Exact
// string matches only: no globs and no environment override.
struct SharedCacheAllowList {
    const char* const*          paths;
    size_t                      count;
};

const SharedCacheAllowList& sharedCacheAllowList();

bool sharedCachePathIsAllowListed(const char* canonicalPath, const SharedCacheAllowList& allowList);

// A split cache image is found with no closure Image, so dyld cannot ask the cache whether a disk copy may
// override it. Old caches keep the rule that a file on disk wins; a split cache serves an allow-listed path from
// the cache and otherwise lets the disk win. canonicalPath is the path of the cache image, not the path asked for.
SharedCacheLoadSource chooseSharedCacheLoadSource(bool isSplitCache, bool inCache, bool existsOnDisk,
                                                  const char* canonicalPath, const SharedCacheAllowList& allowList);

// True when path (or an alias of it) is an allow-listed image of a split cache, so no search-path override
// may replace it either.
bool pathIsPinnedToSharedCache(const SharedCacheLoadInfo& loadInfo, const char* path);

void deallocateExistingSharedCache();

} // namespace dyld3

#endif // __DYLD_SHARED_CACHE_RUNTIME_H__


