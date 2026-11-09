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
// appending each suffix to that path) privately at its preferred address. Not called by dyld yet.
bool mapSplitCachePrivate(const char* mainCachePath, bool verbose, SharedCacheLoadInfo* results, SplitCacheMapStats* stats,
                          SplitCacheAuthMode authMode = kSplitCacheAuthSign);
#endif


struct SharedCacheFindDylibResults {
    const mach_header*          mhInCache;
    const char*                 pathInCache;
    long                        slideInCache;
    const closure::Image*       image;
};

bool findInSharedCacheImage(const SharedCacheLoadInfo& loadInfo, const char* dylibPathToFind, SharedCacheFindDylibResults* results);

bool pathIsInSharedCacheImage(const SharedCacheLoadInfo& loadInfo, const char* dylibPathToFind);

void deallocateExistingSharedCache();

} // namespace dyld3

#endif // __DYLD_SHARED_CACHE_RUNTIME_H__


