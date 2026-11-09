# Shared C++ prefix for the host tests that run the real mapSplitCachePrivate and the DyldSharedCache
# image helpers: the functions are extracted from the dyld sources and compiled against small stubs.
require 'open3'

module SplitCacheHarness
  # The stubbed export trie finds nothing; the real-cache check declares trieWalk and defines it itself.
  SIGN_DECL = 'struct ChainedFixupPointerOnDisk { struct Arm64e { static uint64_t signPointer(uint64_t, void*, bool, uint16_t, uint8_t); }; };'
  NO_TRIE = <<~STUB.strip
    struct MachOLoaded { #{SIGN_DECL} static const uint8_t *trieWalk(Diagnostics&, const uint8_t*, const uint8_t*, const char*) { return nullptr; } };
          struct MachOFile { static uint64_t read_uleb128(Diagnostics&, const uint8_t*&, const uint8_t*) { return 0; } };
  STUB
  REAL_TRIE = <<~STUB.strip
    struct MachOLoaded { #{SIGN_DECL} static const uint8_t *trieWalk(Diagnostics&, const uint8_t*, const uint8_t*, const char*); };
          struct MachOFile { static uint64_t read_uleb128(Diagnostics&, const uint8_t*&p, const uint8_t*end) { uint64_t r = 0; int sh = 0; while (p < end) { uint8_t b = *p++; r |= (uint64_t)(b & 0x7f) << sh; sh += 7; if (!(b & 0x80)) break; } return r; } };
  STUB

  # C++ source up to and including "using namespace dyld3;".
  def self.prefix(root, real_trie: false)
    runtime = File.read("#{root}/dyld3/SharedCacheRuntime.cpp")
    loaded_src = File.read("#{root}/dyld3/MachOLoaded.cpp")
    cache_src = File.read("#{root}/dyld3/shared-cache/DyldSharedCache.cpp")
    runtime_h = File.read("#{root}/dyld3/SharedCacheRuntime.h")
    reservation = runtime[/static int mmapProtection\(.*?^\}/m].to_s + "\n" + (runtime[/class DarlingCacheReservation \{.*?^\};/m] or abort 'reservation missing')
    range_helper = runtime[/static bool cacheRangeContains\(.*?(?=^static bool preflightCacheFile)/m] or abort 'range helpers missing'
    # The one signing routine, taken from the dyld source rather than copied.
    sign_pointer = loaded_src[/^#if !__has_feature\(ptrauth_calls\) && \(defined\(__aarch64__\).*?^uint64_t MachOLoaded::ChainedFixupPointerOnDisk::Arm64e::signPointer\(uint64_t unsignedAddr.*?^\}/m] or abort 'signPointer missing'
    split_code = runtime[/^static const uint32_t kSplitMaxFileMappings.*?^bool mapSplitCachePrivate\(.*?^\}/m] or abort 'split mapper missing'
    stats_struct = (runtime_h[/enum SplitCacheAuthMode \{.*?^\};/m] or abort 'auth mode enum missing') + "\n" +
                   (runtime_h[/struct SplitCacheMapStats \{.*?^\};/m] or abort 'stats struct missing') + "\n" +
                   (runtime_h[/^bool mapSplitCachePrivate\(.*?;/m] or abort 'mapper declaration missing')
    image_funcs = %w[imageTable isSplitCache forEachRegion forEachImage getIndexedImageEntry getIndexedImagePath
                     findMachHeaderImageIndex hasImagePath mappedSize].map do |name|
      cache_src[/^[^\n]*\bDyldSharedCache::#{name}\(.*?^\}/m] or abort "#{name} missing"
    end
    image_helper = cache_src[/^static const uint32_t kMaxSplitSubCaches.*?^static bool splitCacheTables\(.*?^\}/m] or abort 'split region walk missing'
    image_helper += "\n" + (cache_src[/^static const dyld_cache_image_info\* cacheImageTable\(.*?^\}/m] or abort 'image table helper missing')
    <<~CPP
    #include <sys/mman.h>
    #include <sys/stat.h>
    #include <fcntl.h>
    #include <unistd.h>
    #include <stdint.h>
    #include <stddef.h>
    #include <stdio.h>
    #include <stdlib.h>
    #include <stdarg.h>
    #include <string.h>
    #include <assert.h>
    #include <errno.h>
    #include <string>
    #include <vector>
    #define DARLING 1
    #define TARGET_OS_SIMULATOR 0
    #define __offsetof offsetof
    enum { VM_PROT_READ=1, VM_PROT_WRITE=2, VM_PROT_EXECUTE=4 };
    #include "dyld_cache_format.h"
    #if !__GLIBC_PREREQ(2, 38)
    static size_t strlcpy(char *d, const char *s, size_t n) { size_t l=strlen(s); if (n) { size_t c=l<n-1?l:n-1; memcpy(d,s,c); d[c]=0; } return l; }
    #endif
    // The block runtime is not linked: these blocks are never copied or escaped.
    extern "C" { void *_NSConcreteStackBlock[32]; void *_NSConcreteGlobalBlock[32];
                 void _Block_object_assign(void*, const void*, const int) {}
                 void _Block_object_dispose(const void*, const int) {} }
    struct mach_header { uint32_t magic, cputype, cpusubtype, filetype, ncmds, sizeofcmds, flags; };
    struct Diagnostics {};
    namespace dyld3 {
      #{real_trie ? REAL_TRIE : NO_TRIE}
      #{sign_pointer}
    }
    struct DyldSharedCache {
      dyld_cache_header header;
      const dyld_cache_image_info *imageTable(uint32_t&) const;
      bool isSplitCache() const;
      void forEachRegion(void (^)(const void*, uint64_t, uint64_t, uint32_t, uint32_t, uint64_t)) const;
      void forEachImage(void (^)(const mach_header*, const char*)) const;
      const mach_header *getIndexedImageEntry(uint32_t, uint64_t&, uint64_t&) const;
      const char *getIndexedImagePath(uint32_t) const;
      bool findMachHeaderImageIndex(const mach_header*, uint32_t&) const;
      bool hasImagePath(const char*, uint32_t&) const;
      uint64_t mappedSize() const;
    };
    #{image_helper}
    #{image_funcs.join("\n")}
    namespace dyld { static void log(const char *format, ...) { va_list a; va_start(a, format); printf("LOG "); vprintf(format, a); va_end(a); } }
    namespace dyld3 {
      struct SharedCacheLoadInfo { const DyldSharedCache *loadAddress; long slide; const char *errorMessage; char path[256]; };
      #{stats_struct}
      // Tests point gAuxvPath at a fabricated auxiliary vector to simulate a host without pointer authentication.
      static const char *gAuxvPath = "/proc/self/auxv";
      static int open(const char *path, int flags, int mode) { return ::open(strcmp(path, "/proc/self/auxv") == 0 ? gAuxvPath : path, flags, mode); }
      #{reservation}
      #{range_helper}
      #{split_code}
    }
    using namespace dyld3;
    CPP
  end

  # Compiles dir/test.cpp; returns the output when it fails.
  def self.compile(root, dir, flags = [])
    out, st = Open3.capture2e('clang++', '-std=c++17', '-fblocks', '-Wno-unused-value', *flags,
                              "-I#{root}/dyld3/shared-cache", "#{dir}/test.cpp", '-o', "#{dir}/test")
    st.success? ? nil : out
  end
end
