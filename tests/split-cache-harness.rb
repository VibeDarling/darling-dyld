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

  # Optional support for the Objective-C cache accessors. The dyld3 Mach-O layer is not built for the
  # host, so the section walk reads the LC_SEGMENT_64 table the fixture writes and exposes the fields
  # forEachSection gives the accessor. cachedDylibsImageArray is null by construction: a split cache
  # has no image array and reaching it is a test failure.
  OBJC_TYPES = <<~'CPP'.strip
    struct mach_header_64 { uint32_t magic, cputype, cpusubtype, filetype, ncmds, sizeofcmds, flags, reserved; };
    struct load_command { uint32_t cmd, cmdsize; };
    struct segment_command_64 { uint32_t cmd, cmdsize; char segname[16]; uint64_t vmaddr, vmsize, fileoff, filesize; uint32_t maxprot, initprot, nsects, flags; };
    struct section_64 { char sectname[16], segname[16]; uint64_t addr, size; uint32_t offset, align, reloff, nreloc, flags, reserved1, reserved2, reserved3; };
    namespace dyld3 { namespace closure {
      struct Image { uint32_t cacheOffset() const { return 0; } };
      struct ImageArray { const Image *imageForNum(uint32_t) const { return nullptr; } };
    } }
    namespace dyld3 {
      struct MachOAnalyzer {
        struct SegmentInfo { const char *segName; };
        struct SectionInfo { SegmentInfo segInfo; const char *sectName; uint64_t sectAddr, sectSize; };
        int64_t getSlide() const {
          const mach_header_64 *mh = (const mach_header_64 *)this;
          const uint8_t *p = (const uint8_t *)this + sizeof(mach_header_64);
          for (uint32_t i = 0; i < mh->ncmds; ++i) {
            const load_command *cmd = (const load_command *)p;
            if ( cmd->cmd == 0x19 && !strcmp(((const segment_command_64 *)cmd)->segname, "__TEXT") )
              return (int64_t)((uintptr_t)this - ((const segment_command_64 *)cmd)->vmaddr);
            p += cmd->cmdsize;
          }
          return 0;
        }
        uint32_t pointerSize() const { return 8; }
        void forEachSection(void (^cb)(const SectionInfo&, bool, bool&)) const {
          const mach_header_64 *mh = (const mach_header_64 *)this;
          const uint8_t *p = (const uint8_t *)this + sizeof(mach_header_64);
          bool stop = false;
          for (uint32_t i = 0; i < mh->ncmds && !stop; ++i) {
            const load_command *cmd = (const load_command *)p;
            if ( cmd->cmd == 0x19 ) {
              const segment_command_64 *seg = (const segment_command_64 *)cmd;
              const section_64 *sects = (const section_64 *)(seg + 1);
              for (uint32_t j = 0; j < seg->nsects && !stop; ++j) {
                SectionInfo info = { { seg->segname }, sects[j].sectname, sects[j].addr, sects[j].size };
                bool malformed = (sects[j].addr < seg->vmaddr) || (sects[j].addr + sects[j].size > seg->vmaddr + seg->filesize);
                cb(info, malformed, stop);
              }
            }
            p += cmd->cmdsize;
          }
        }
      };
    }
  CPP
  OBJC_DECLS = <<~'CPP'.strip
      const dyld3::closure::ImageArray *cachedDylibsImageArray() const;
      const objc_opt::objc_opt_t *objcOpt() const;
      const void *objcOptPtrs() const;
  CPP
  OBJC_DEFS = <<~'CPP'.strip
    static unsigned gCachedDylibsImageArrayCalls = 0;
    const dyld3::closure::ImageArray *DyldSharedCache::cachedDylibsImageArray() const {
      ++gCachedDylibsImageArrayCalls;
      return nullptr;
    }
  CPP

  # C++ source up to and including "using namespace dyld3;".
  def self.prefix(root, real_trie: false, objc: false)
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
                     findMachHeaderImageIndex hasImagePath mappedSize unslidLoadAddress].map do |name|
      cache_src[/^[^\n]*\bDyldSharedCache::#{name}\(.*?^\}/m] or abort "#{name} missing"
    end
    image_helper = cache_src[/^static const uint32_t kMaxSplitSubCaches.*?^static bool splitCacheTables\(.*?^\}/m] or abort 'split region walk missing'
    image_helper += "\n" + (cache_src[/^static const dyld_cache_image_info\* cacheImageTable\(.*?^\}/m] or abort 'image table helper missing')
    cache_h = File.read("#{root}/dyld3/shared-cache/DyldSharedCache.h")
    # The version 4 patch info reader, taken from the sources.
    patch_decls = (cache_h[/^    \/\/ Version 4 patch info of a split macOS cache.*?(?=^#endif)/m] or abort 'patch info declarations missing')
    log_func = cache_h[/^    typedef void \(\*DataConstLogFunc\).*?;/m] or abort 'DataConstLogFunc missing'
    patch_reader = cache_src[/^\/\/ ---- version 4 patch info of a split cache \(reader\) ----.*?^\/\/ ---- end of the patch info reader[^\n]*/m] or abort 'patch info reader missing'
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
    #include <set>
    #{objc ? '#include "objc-shared-cache.h"' : ''}
    #define DARLING 1
    #define TARGET_OS_SIMULATOR 0
    #define __offsetof offsetof
    enum { VM_PROT_READ=1, VM_PROT_WRITE=2, VM_PROT_EXECUTE=4, VM_PROT_COPY=0x10 };
    // Mach calls of the DATA_CONST writer, on the host's mprotect (the whole cache is this process's own memory).
    typedef int mach_port_t; typedef int kern_return_t; typedef uintptr_t vm_address_t; typedef size_t vm_size_t;
    #define KERN_SUCCESS 0
    #define MACH_PORT_NULL 0
    static mach_port_t mach_task_self() { return 1; }
    #define VM_FLAGS_ANYWHERE 1
    static kern_return_t vm_allocate(mach_port_t, vm_address_t *address, vm_size_t size, int) {
      void *p = mmap(nullptr, size, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
      if ( p == MAP_FAILED ) return 1;
      *address = (vm_address_t)p; return 0;
    }
    static kern_return_t vm_deallocate(mach_port_t, vm_address_t address, vm_size_t size) { return munmap((void *)address, size) == 0 ? 0 : 1; }
    bool gEnableSharedCacheDataConst = true;
    // Tests inject a failure: 1 fails making a mapping writable, 2 fails putting it back read-only (nothing is changed then).
    int gFailProtect = 0;
    static kern_return_t vm_protect(mach_port_t, vm_address_t address, vm_size_t size, int, int prot) {
      if ( (gFailProtect == 1 && (prot & VM_PROT_WRITE)) || (gFailProtect == 2 && !(prot & VM_PROT_WRITE)) ) return 1;
      return mprotect((void *)address, size, prot & 7) == 0 ? 0 : 1;
    }
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
    #{objc ? OBJC_TYPES : ''}
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
      uint64_t unslidLoadAddress() const;
      #{log_func}
      #{patch_decls}
      #{objc ? OBJC_DECLS : ''}
    };
    #{objc ? OBJC_DEFS : ''}
    #{image_helper}
    #{image_funcs.join("\n")}
    #{patch_reader}
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
