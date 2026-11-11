# The dyld4 objc callback interface (dyld3/DarlingObjCCallbacks.h): libobjc's v2-v4 callback structs, translated
# to the old-shape notifiers. The struct text is cut out of the tracked dyld_priv.h and the real header is
# compiled against it, so this exercises the code the dyld build uses. A v4 callback signed the way libobjc
# signs it must authenticate at its own field address, a forged one must be refused, the mark-image-mutable
# block's invoke must be signed where libobjc reads it, and a call through the unauthenticated invoke must
# fault on a CPU with pointer authentication. _dyld_get_dlopen_image_header is replayed the same way: the
# loader's dispatch, the libdyld wrapper and the cache table's two functions are cut out of the tracked
# sources and driven with sentinel, forged-cache and invalid handles. Mutants of either replay must each
# fail (--probes).
# Usage: ruby tests/dyld-objc-callbacks.rb [checkout] [--probes]
require 'tmpdir'
require 'fileutils'
require 'open3'
require_relative 'darling-arm64e-adapters-support'

ROOT = File.realpath(ARGV.fetch(0, File.expand_path('..', __dir__)))
RUN_PROBES = ARGV.include?('--probes')
PAC_HOST = AdapterSupport.pac_host?

$failures = 0
def check(desc, ok, detail = nil)
  if ok
    puts "PASS #{desc}"
  else
    $failures += 1
    puts "FAIL #{desc}#{detail ? ": #{detail}" : ''}"
  end
end

DYLDPRIV = File.read("#{ROOT}/gen/usr/local/include/mach-o/dyld_priv.h")
D3APIS = File.read("#{ROOT}/dyld3/APIs.cpp")
D3HDR = File.read("#{ROOT}/dyld3/APIs.h")
APIS = File.read("#{ROOT}/src/dyldAPIs.cpp")
WRAPPERS = File.read("#{ROOT}/src/dyldAPIsInLibSystem.cpp")
CALLBACKS = File.read("#{ROOT}/dyld3/DarlingObjCCallbacks.h")
ADAPTERS = File.read("#{ROOT}/dyld3/DarlingArm64eAdapters.h")

# --- wiring: both translation units define the SPIs and register the shared thunks -----------------
table = APIS[/static const struct dyld_func dyld_funcs\[\] = \{(.*?)\n\};/m, 1]
abort 'dyld_funcs table not found' unless table
rows = table.scan(/^\s*\{"([^"]+)",\s*\(void\*\)([A-Za-z0-9_:]+)\s*\},?\s*$/).to_h
check('table row __dyld_objc_register_callbacks', rows['__dyld_objc_register_callbacks'] == '_dyld_objc_register_callbacks', rows['__dyld_objc_register_callbacks'].inspect)
check('table row __dyld_get_dlopen_image_header', rows['__dyld_get_dlopen_image_header'] == '_dyld_get_dlopen_image_header', rows['__dyld_get_dlopen_image_header'].inspect)
check('dyld_priv.h declares _dyld_objc_register_callbacks',
      DYLDPRIV.include?('extern void _dyld_objc_register_callbacks(const struct _dyld_objc_callbacks*);'))
check('dyld_priv.h declares _dyld_get_dlopen_image_header',
      DYLDPRIV.match?(/^extern const struct mach_header\* _dyld_get_dlopen_image_header\(void\* handle\);/))
check('dyld3/APIs.h declares both',
      D3HDR.match?(/_dyld_objc_register_callbacks\(const struct _dyld_objc_callbacks\* callbacks\) TEMP_HIDDEN;/) &&
      D3HDR.match?(/_dyld_get_dlopen_image_header\(void\* handle\) TEMP_HIDDEN;/))
check('dyld3/APIs.cpp defines both',
      D3APIS.match?(/^void _dyld_objc_register_callbacks\(/m) &&
      D3APIS.match?(/^const mach_header\* _dyld_get_dlopen_image_header\(void\* handle\)/m))
check('dyldAPIs.cpp defines both',
      APIS.match?(/^void _dyld_objc_register_callbacks\(/m) &&
      APIS.match?(/^const struct mach_header\* _dyld_get_dlopen_image_header\(void\* handle\)/m))
check('both images include the shared callbacks header',
      D3APIS.match?(/^#include "DarlingObjCCallbacks\.h"/) && APIS.match?(/^#include "DarlingObjCCallbacks\.h"/))
check('both images register the old-shape thunks',
      D3APIS.include?('gAllImages.setObjCNotifiers(darling::objcMappedThunk, darling::objcInitThunk, darling::objcUnmappedThunk);') &&
      APIS.include?('dyld::registerObjCNotifiers(dyld3::darling::objcMappedThunk, dyld3::darling::objcInitThunk, dyld3::darling::objcUnmappedThunk);'))
check('libdyld answers RTLD_SELF before dispatching to the loader',
      WRAPPERS.match?(/if \( handle == RTLD_SELF \)\s*\n\s*return _dyld_get_image_header_containing_address\(__builtin_return_address\(0\)\);/))

# --- the structs the host driver declares the callbacks with --------------------------------------
BLOCK_START = '// >>> Darling dyld4 objc callbacks'
BLOCK_STOP = '// <<< Darling dyld4 objc callbacks'
def callbacks_block(text)
  from = text.index(BLOCK_START) or abort 'the dyld4 objc callbacks block not found'
  to = text.index(BLOCK_STOP, from) or abort 'the end of the dyld4 objc callbacks block not found'
  text[from...to]
end

SHIM = <<~'CPP'
  #pragma once
  #include <stdint.h>
  struct mach_header {
      uint32_t magic, cputype, cpusubtype, filetype, ncmds, sizeofcmds, flags;
  };
  typedef void (*_dyld_objc_notify_unmapped)(const char* path, const struct mach_header* mh);
  typedef struct _dyld_section_location_info_s* _dyld_section_location_info_t;
CPP

# Literal values of the real <mach/machine.h> constants the callbacks header uses (CPU_TYPE_ARM64 0x0100000c).
SHIM_MACHINE = <<~'CPP'
  #pragma once
  typedef int cpu_subtype_t;
  #define CPU_SUBTYPE_MASK 0xff000000
  #define CPU_SUBTYPE_ARM64E ((cpu_subtype_t) 2)
  #define CPU_TYPE_ARM64 0x0100000c
CPP

DRIVER = <<~'CPP'
  #include <stdint.h>
  #include <stddef.h>
  #include <stdio.h>
  #include <string.h>
  #include <unistd.h>
  #include <sys/wait.h>
  #include "DarlingObjCCallbacks.h"

  using namespace dyld3::darling;

  static int failures;
  static void expect(const char* what, bool ok)
  {
      if ( ok ) { printf("ok %s\n", what); return; }
      ++failures;
      printf("FAIL %s\n", what);
  }

  // A CPU that implements pointer authentication makes xpaci clear the top 16 bits; elsewhere it is a HINT.
  static bool pacHost()
  {
      const uint64_t probe = 0x12340000FFFFFFFFull;
      return stripSignedPointer(probe) != probe;
  }

  // The discriminators and the modifier shape are the interface facts our clang emits for the string
  // discriminators in dyld_priv.h; pinned here rather than read from the header under test, so a wrong
  // constant or a wrong modifier in that header fails this test instead of agreeing with itself.
  static const uint16_t kMappedDisc = 0xd15a, kInitDisc = 0x4b12, kUnmappedDisc = 0x4840, kPatchDisc = 0x318c;

  static uint64_t modifier(uint64_t field, uint16_t disc)
  {
      return (field & 0x0000FFFFFFFFFFFFull) | ((uint64_t)disc << 48);
  }

  // The versioned structs share only their leading version word; libobjc passes them as the base struct.
  template <typename T>
  static const struct _dyld_objc_callbacks* asCallbacks(const T* callbacks)
  {
      return reinterpret_cast<const struct _dyld_objc_callbacks*>(callbacks);
  }

  // PACIB, the key libobjc signs its callback fields with.
  static uint64_t signCallbackIB(uint64_t pointer, uint64_t mod)
  {
      uint64_t result;
      __asm__("mov x17, %1\n\tmov x16, %2\n\t.inst 0xDAC10611\n\tmov %0, x17" : "=r"(result) : "r"(pointer), "r"(mod) : "x16", "x17");
      return result;
  }

  // AUTIA, the key libclosure uses for a block's invoke field.
  static uint64_t authInvokeIA(uint64_t invoke, uint64_t field)
  {
      uint64_t result;
      __asm__("mov x17, %1\n\tmov x16, %2\n\t.inst 0xDAC11211\n\tmov %0, x17" : "=r"(result) : "r"(invoke), "r"(field) : "x16", "x17");
      return result;
  }

  static bool canonical(uint64_t pointer) { return (pointer & 0xFFFF000000000000ull) == 0; }

  static const struct mach_header* recordedMhs[256];
  static const char* recordedPaths[256];
  static unsigned recordedRefs[256];
  static unsigned recordedCount;
  static unsigned mappedCalls, initCalls, unmappedCalls, patchCalls;
  static bool metadataAlwaysNull = true;
  static unsigned chunkCounts, chunkSizes[8];
  static const ObjCBlockLayout* blockSeen;
  static uint64_t blockInvokeField, blockInvokeAuth;
  static unsigned mutableCalls;
  static uint32_t mutableLastIndex;
  static void* mutableBlock;

  static void resetRecorder()
  {
      recordedCount = mappedCalls = initCalls = unmappedCalls = patchCalls = chunkCounts = 0;
      metadataAlwaysNull = true;
      blockSeen = nullptr;
      blockInvokeField = blockInvokeAuth = 0;
  }

  static void recordInfo(const struct _dyld_objc_notify_mapped_info* info)
  {
      if ( recordedCount < 256 ) {
          recordedMhs[recordedCount] = info->mh;
          recordedPaths[recordedCount] = info->path;
          recordedRefs[recordedCount] = info->dyldObjCRefsOptimized;
          ++recordedCount;
      }
      if ( info->sectionLocationMetadata != nullptr )
          metadataAlwaysNull = false;
  }

  static void onMapped2(unsigned count, const struct _dyld_objc_notify_mapped_info infos[])
  {
      ++mappedCalls;
      if ( chunkCounts < 8 ) chunkSizes[chunkCounts++] = count;
      for ( unsigned i = 0; i < count; ++i ) recordInfo(&infos[i]);
  }

  static void onMapped3(unsigned count, const struct _dyld_objc_notify_mapped_info infos[],
                        _dyld_objc_mark_image_mutable callback)
  {
      ++mappedCalls;
      if ( chunkCounts < 8 ) chunkSizes[chunkCounts++] = count;
      for ( unsigned i = 0; i < count; ++i ) recordInfo(&infos[i]);
      blockSeen = (const ObjCBlockLayout*)callback;
      blockInvokeField = blockSeen->invoke;
      blockInvokeAuth = authInvokeIA(blockSeen->invoke, (uint64_t)(uintptr_t)&blockSeen->invoke);
  }

  static void onInit2(const struct _dyld_objc_notify_mapped_info* info)
  {
      ++initCalls;
      recordInfo(info);
  }

  static void onUnmapped(const char*, const struct mach_header*) { ++unmappedCalls; }
  static void onPatch(const struct mach_header*, void*, const struct mach_header*, const void*) { ++patchCalls; }

  // The loader's skip log: one call per logged line, with the path it names.
  static const char* loggedPaths[16];
  static unsigned loggedLines;
  static bool loggedFormatNamesPath;
  static void recordSkipLog(const char* format, const char* path)
  {
      if ( loggedLines < 16 ) loggedPaths[loggedLines] = path;
      ++loggedLines;
      loggedFormatNamesPath = strstr(format, "%s") != nullptr && strstr(format, "unsigned plain arm64") != nullptr;
  }

  static unsigned loggedFor(const char* path)
  {
      unsigned n = 0;
      for ( unsigned i = 0; i < loggedLines && i < 16; ++i )
          if ( loggedPaths[i] == path ) ++n;
      return n;
  }

  // Registers a v4 struct signed the way the arm64e libobjc signs it.
  static bool registerV4(ObjCCallbackState& s)
  {
      _dyld_objc_callbacks_v4 v4;
      v4.version = 4;
      v4.mapped = reinterpret_cast<_dyld_objc_notify_mapped3>(signCallbackIB((uint64_t)(uintptr_t)onMapped3, modifier((uint64_t)(uintptr_t)&v4.mapped, kMappedDisc)));
      v4.init = reinterpret_cast<_dyld_objc_notify_init2>(signCallbackIB((uint64_t)(uintptr_t)onInit2, modifier((uint64_t)(uintptr_t)&v4.init, kInitDisc)));
      v4.unmapped = reinterpret_cast<_dyld_objc_notify_unmapped>(signCallbackIB((uint64_t)(uintptr_t)onUnmapped, modifier((uint64_t)(uintptr_t)&v4.unmapped, kUnmappedDisc)));
      v4.patches = reinterpret_cast<_dyld_objc_notify_patch_class>(signCallbackIB((uint64_t)(uintptr_t)onPatch, modifier((uint64_t)(uintptr_t)&v4.patches, kPatchDisc)));
      return s.registerCallbacks(asCallbacks(&v4));
  }

  static void recordMutable(void* block, uint32_t objcImageIndex)
  {
      ++mutableCalls;
      mutableLastIndex = objcImageIndex;
      mutableBlock = block;
  }

  int main()
  {
      const bool pac = pacHost();
      printf("pointer authentication: %s\n", pac ? "present" : "absent");

      _dyld_objc_callbacks_v2 v2 = { 2, onMapped2, onInit2, onUnmapped, onPatch };
      _dyld_objc_callbacks_v2 nullV2 = { 2, nullptr, nullptr, nullptr, nullptr };
      _dyld_objc_callbacks_v3 v3 = { 3, onMapped3, onInit2, onUnmapped, onPatch };
      struct mach_header cacheMh = {};
      struct mach_header diskMh = {};
      cacheMh.flags = MH_DYLIB_IN_CACHE;
      const char* paths[2] = { "cache/libobjc.A.dylib", "disk/libfoo.dylib" };
      const struct mach_header* mhs[2] = { &cacheMh, &diskMh };

      {
          ObjCCallbackState s;
          expect("null callbacks refused", !s.registerCallbacks(nullptr));
          expect("null callbacks name the failure", s.error != nullptr && strstr(s.error, "null") != nullptr);
      }
      {
          struct _dyld_objc_callbacks bad = { 5 };
          ObjCCallbackState s;
          expect("version 5 refused", !s.registerCallbacks(&bad));
          expect("version 5 names the failure", s.error != nullptr && strstr(s.error, "unsupported") != nullptr);
      }
      {
          struct _dyld_objc_callbacks bad = { 1 };
          ObjCCallbackState s;
          expect("version 1 refused", !s.registerCallbacks(&bad));
      }
      {
          ObjCCallbackState s;
          expect("v2 registers", s.registerCallbacks(asCallbacks(&v2)));
          expect("v2 version", s.version == 2);
          expect("v2 mapped", s.mapped2 == onMapped2);
          expect("v2 init", s.init2 == onInit2);
          expect("v2 unmapped", s.unmapped == onUnmapped);
          expect("v2 patches", s.patches == onPatch);
          expect("v2 leaves mapped3 null", s.mapped3 == nullptr);
      }
      {
          ObjCCallbackState s;
          expect("v3 registers", s.registerCallbacks(asCallbacks(&v3)));
          expect("v3 version", s.version == 3);
          expect("v3 mapped", s.mapped3 == onMapped3);
      }
      {
          _dyld_objc_callbacks_v4 v4;
          v4.version = 4;
          v4.mapped = reinterpret_cast<_dyld_objc_notify_mapped3>(signCallbackIB((uint64_t)(uintptr_t)onMapped3, modifier((uint64_t)(uintptr_t)&v4.mapped, kMappedDisc)));
          v4.init = reinterpret_cast<_dyld_objc_notify_init2>(signCallbackIB((uint64_t)(uintptr_t)onInit2, modifier((uint64_t)(uintptr_t)&v4.init, kInitDisc)));
          v4.unmapped = reinterpret_cast<_dyld_objc_notify_unmapped>(signCallbackIB((uint64_t)(uintptr_t)onUnmapped, modifier((uint64_t)(uintptr_t)&v4.unmapped, kUnmappedDisc)));
          v4.patches = reinterpret_cast<_dyld_objc_notify_patch_class>(signCallbackIB((uint64_t)(uintptr_t)onPatch, modifier((uint64_t)(uintptr_t)&v4.patches, kPatchDisc)));
          ObjCCallbackState s;
          expect("v4 signed callbacks register", s.registerCallbacks(asCallbacks(&v4)));
          expect("v4 version", s.version == 4);
          expect("v4 stores the plain mapped", s.mapped3 == onMapped3);
          expect("v4 stores the plain init", s.init2 == onInit2);
          expect("v4 stores the plain unmapped", s.unmapped == onUnmapped);
          expect("v4 stores the plain patches", s.patches == onPatch);
      }
      if ( pac ) {
          _dyld_objc_callbacks_v4 v4;
          v4.version = 4;
          v4.mapped = reinterpret_cast<_dyld_objc_notify_mapped3>(signCallbackIB((uint64_t)(uintptr_t)onMapped3, modifier((uint64_t)(uintptr_t)&v4.mapped, kMappedDisc)));
          v4.init = reinterpret_cast<_dyld_objc_notify_init2>(signCallbackIB((uint64_t)(uintptr_t)onInit2, modifier((uint64_t)(uintptr_t)&v4.init, kInitDisc)));
          v4.unmapped = reinterpret_cast<_dyld_objc_notify_unmapped>(signCallbackIB((uint64_t)(uintptr_t)onUnmapped, modifier((uint64_t)(uintptr_t)&v4.unmapped, kUnmappedDisc)));
          v4.patches = reinterpret_cast<_dyld_objc_notify_patch_class>(signCallbackIB((uint64_t)(uintptr_t)onPatch, modifier((uint64_t)(uintptr_t)&v4.patches, kPatchDisc)) ^ (1ull << 63));
          ObjCCallbackState s;
          expect("a v4 field with a corrupted signature is refused", !s.registerCallbacks(asCallbacks(&v4)));
          expect("a corrupted signature names the failure", s.error != nullptr && strstr(s.error, "authenticate") != nullptr);

          v4 = _dyld_objc_callbacks_v4();
          v4.version = 4;
          v4.mapped = reinterpret_cast<_dyld_objc_notify_mapped3>(signCallbackIB((uint64_t)(uintptr_t)onMapped3, modifier((uint64_t)(uintptr_t)&v4.mapped, kMappedDisc)));
          v4.init = reinterpret_cast<_dyld_objc_notify_init2>(signCallbackIB((uint64_t)(uintptr_t)onInit2, modifier((uint64_t)(uintptr_t)&v4.init, kMappedDisc)));
          v4.unmapped = reinterpret_cast<_dyld_objc_notify_unmapped>(signCallbackIB((uint64_t)(uintptr_t)onUnmapped, modifier((uint64_t)(uintptr_t)&v4.unmapped, kUnmappedDisc)));
          v4.patches = reinterpret_cast<_dyld_objc_notify_patch_class>(signCallbackIB((uint64_t)(uintptr_t)onPatch, modifier((uint64_t)(uintptr_t)&v4.patches, kPatchDisc)));
          ObjCCallbackState s2;
          expect("a field signed for another callback is refused", !s2.registerCallbacks(asCallbacks(&v4)));
      } else {
          printf("skip v4 field authentication (no pointer authentication)\n");
      }
      {
          _dyld_objc_callbacks_v4 v4;
          v4.version = 4;
          v4.mapped = reinterpret_cast<_dyld_objc_notify_mapped3>(signCallbackIB((uint64_t)(uintptr_t)onMapped3, modifier((uint64_t)(uintptr_t)&v4.mapped, kMappedDisc)));
          v4.init = reinterpret_cast<_dyld_objc_notify_init2>(signCallbackIB((uint64_t)(uintptr_t)onInit2, modifier((uint64_t)(uintptr_t)&v4.init, kInitDisc)));
          v4.unmapped = reinterpret_cast<_dyld_objc_notify_unmapped>(signCallbackIB((uint64_t)(uintptr_t)onUnmapped, modifier((uint64_t)(uintptr_t)&v4.unmapped, kUnmappedDisc)));
          v4.patches = nullptr;
          ObjCCallbackState s;
          expect("a v4 field the runtime left null is accepted", s.registerCallbacks(asCallbacks(&v4)));
          expect("a null v4 field stays null", s.patches == nullptr);
      }
      {
          ObjCCallbackState s;
          expect("v2 with null callbacks registers", s.registerCallbacks(asCallbacks(&nullV2)));
          resetRecorder();
          s.notifyMapped(2, paths, mhs);
          s.notifyInit(paths[0], &cacheMh);
          s.notifyUnmapped(paths[0], &cacheMh);
          expect("absent callbacks are not called", mappedCalls == 0 && initCalls == 0 && unmappedCalls == 0);
      }
      {
          ObjCCallbackState s;
          s.registerCallbacks(asCallbacks(&v2));
          resetRecorder();
          s.notifyMapped(2, paths, mhs);
          expect("the mapped batch reaches the callback", mappedCalls == 1 && recordedCount == 2);
          expect("a cache image is refs-optimized", recordedRefs[0] == 1);
          expect("a disk image is not", recordedRefs[1] == 0);
          expect("the batch carries the paths", recordedPaths[0] == paths[0] && recordedPaths[1] == paths[1]);
          expect("the batch carries the headers", recordedMhs[0] == &cacheMh && recordedMhs[1] == &diskMh);
          expect("no section metadata", metadataAlwaysNull);
          resetRecorder();
          s.notifyMapped(0, paths, mhs);
          expect("an empty batch is not delivered", mappedCalls == 0);
          s.notifyInit(paths[0], &cacheMh);
          expect("init carries the cache bit", initCalls == 1 && recordedRefs[0] == 1 && recordedMhs[0] == &cacheMh);
          s.notifyUnmapped(paths[0], &cacheMh);
          expect("unmapped forwards the path", unmappedCalls == 1);
      }
      {
          static const struct mach_header* many[130];
          static const char* manyPaths[130];
          static struct mach_header manyMh[130];
          for ( unsigned i = 0; i < 130; ++i ) {
              manyMh[i].flags = (i % 2) ? 0 : MH_DYLIB_IN_CACHE;
              many[i] = &manyMh[i];
              manyPaths[i] = "p";
          }
          ObjCCallbackState s;
          s.registerCallbacks(asCallbacks(&v2));
          resetRecorder();
          s.notifyMapped(130, manyPaths, many);
          expect("a large batch is chunked at 64", chunkCounts == 3 && chunkSizes[0] == 64 && chunkSizes[1] == 64 && chunkSizes[2] == 2);
          expect("the chunks carry the whole batch", recordedCount == 130 && recordedMhs[129] == many[129]);
          expect("the cache bit follows each image", recordedRefs[0] == 1 && recordedRefs[1] == 0 && recordedRefs[128] == 1 && recordedRefs[129] == 0);
      }
      {
          ObjCCallbackState s;
          s.markImageMutableInvoke = recordMutable;
          s.registerCallbacks(asCallbacks(&v3));
          resetRecorder();
          mutableCalls = 0;
          s.notifyMapped(1, paths, mhs);
          expect("mapped3 receives the block", blockSeen != nullptr);
          if ( pac ) {
              expect("the invoke is signed", blockInvokeField != (uint64_t)(uintptr_t)recordMutable);
              expect("the invoke is not a plain pointer", !canonical(blockInvokeField));
              expect("the invoke authenticates at its field", blockInvokeAuth == (uint64_t)(uintptr_t)recordMutable);
          } else {
              printf("skip invoke signing (no pointer authentication)\n");
              expect("the invoke is the plain pointer", blockInvokeField == (uint64_t)(uintptr_t)recordMutable);
          }
          reinterpret_cast<ObjCBlockInvoke>(blockInvokeAuth)(const_cast<ObjCBlockLayout*>(blockSeen), 7);
          expect("the authenticated invoke calls the implementation", mutableCalls == 1 && mutableLastIndex == 7);
          expect("the block is the one handed over", mutableBlock == (void*)blockSeen);
      }
      {
          ObjCCallbackState& state = objcCallbackState();
          state.registerCallbacks(asCallbacks(&v2));
          resetRecorder();
          objcMappedThunk(1, paths, mhs);
          expect("the mapped thunk forwards", mappedCalls == 1 && recordedCount == 1 && recordedMhs[0] == &cacheMh);
          objcInitThunk(paths[0], &cacheMh);
          expect("the init thunk forwards", initCalls == 1 && recordedMhs[0] == &cacheMh);
          objcUnmappedThunk(paths[0], &cacheMh);
          expect("the unmapped thunk forwards", unmappedCalls == 1);
      }
    // The arm64e runtime (v4) must not be handed plain arm64 images. Header values are literals here:
    // CPU_TYPE_ARM64 0x0100000c, ARM64_ALL 0, ARM64E 2, and the ptrauth ABI bits in the subtype's high byte.
    {
        struct mach_header cacheArm64e = {};
        cacheArm64e.cputype = 0x0100000c;
        cacheArm64e.cpusubtype = 0x81000002;
        cacheArm64e.flags = MH_DYLIB_IN_CACHE;
        struct mach_header diskArm64e = {};
        diskArm64e.cputype = 0x0100000c;
        diskArm64e.cpusubtype = 0x00000002;
        struct mach_header plainA = {};
        plainA.cputype = 0x0100000c;
        plainA.cpusubtype = 0x00000000;
        struct mach_header plainB = {};
        plainB.cputype = 0x0100000c;
        plainB.cpusubtype = 0x80000000;
        struct mach_header foreign = {};
        foreign.cputype = 0x01000007;
        foreign.cpusubtype = 0x00000002;
        const char* mixPaths[4] = { "disk/libplainA.dylib", "cache/libobjc.A.dylib", "disk/libplainB.dylib", "disk/libarm64e.dylib" };
        const struct mach_header* mix[4] = { &plainA, &cacheArm64e, &plainB, &diskArm64e };

        ObjCCallbackState s;
        s.logSkip = recordSkipLog;
        expect("v4 registers for the arm64e filter", registerV4(s));
        resetRecorder();
        loggedLines = 0;
        s.notifyMapped(4, mixPaths, mix);
        expect("v4 delivers exactly the arm64e images", mappedCalls == 1 && recordedCount == 2);
        expect("v4 keeps the batch order", recordedMhs[0] == &cacheArm64e && recordedMhs[1] == &diskArm64e);
        expect("v4 keeps the paths with their images", recordedPaths[0] == mixPaths[1] && recordedPaths[1] == mixPaths[3]);
        expect("v4 refs-optimized bits follow the delivered images", recordedRefs[0] == 1 && recordedRefs[1] == 0);
        expect("v4 logs each plain image once", loggedLines == 2 && loggedFor(mixPaths[0]) == 1 && loggedFor(mixPaths[2]) == 1);
        expect("the log line names the path and the reason", loggedFormatNamesPath);
        expect("the arm64e images are not logged", loggedFor(mixPaths[1]) == 0 && loggedFor(mixPaths[3]) == 0);

        resetRecorder();
        const char* onlyPlainPaths[2] = { mixPaths[0], mixPaths[2] };
        const struct mach_header* onlyPlain[2] = { &plainA, &plainB };
        s.notifyMapped(2, onlyPlainPaths, onlyPlain);
        expect("a batch of only plain images makes no mapped call", mappedCalls == 0 && recordedCount == 0);

        resetRecorder();
        const char* foreignPath = "disk/libforeign.dylib";
        const struct mach_header* foreignMhs[1] = { &foreign };
        s.notifyMapped(1, &foreignPath, foreignMhs);
        expect("the arm64e subtype under another cputype is not arm64e", mappedCalls == 0 && loggedLines == 5);

        resetRecorder();
        s.notifyInit(mixPaths[0], &plainA);
        expect("init for a plain image makes no call", initCalls == 0);
        s.notifyInit(mixPaths[1], &cacheArm64e);
        expect("init for a cache arm64e image makes one call", initCalls == 1 && recordedMhs[0] == &cacheArm64e && recordedRefs[0] == 1);
        s.notifyInit(mixPaths[3], &diskArm64e);
        expect("init for a disk arm64e image makes one call", initCalls == 2 && recordedMhs[1] == &diskArm64e && recordedRefs[1] == 0);
        expect("init makes no log line", loggedLines == 5);

        resetRecorder();
        s.notifyUnmapped(mixPaths[0], &plainA);
        expect("v4 unmapped is still delivered for a plain image", unmappedCalls == 1);

        // The subtype is compared without the ptrauth ABI byte: 1 (ARM64_V8) and 3 are not arm64e, 0xC0000002 is.
        static const struct { uint32_t subtype; bool delivered; } subtypes[] = {
            { 0x00000001, false }, { 0x00000003, false }, { 0x80000001, false }, { 0xC0000002, true }, { 0x01000002, true },
        };
        for ( const auto& row : subtypes ) {
            struct mach_header one = {};
            one.cputype = 0x0100000c;
            one.cpusubtype = row.subtype;
            const char* onePath = "disk/libsubtype.dylib";
            const struct mach_header* oneMh[1] = { &one };
            resetRecorder();
            s.notifyMapped(1, &onePath, oneMh);
            char what[64];
            snprintf(what, sizeof what, "subtype 0x%08x is %sdelivered", row.subtype, row.delivered ? "" : "not ");
            expect(what, mappedCalls == (row.delivered ? 1u : 0u));
        }

        static const struct mach_header* many[130];
        static const char* manyPaths[130];
        static struct mach_header manyMh[130];
        for ( unsigned i = 0; i < 130; ++i ) {
            const bool plain = i >= 64 && i < 128;
            manyMh[i].cputype = 0x0100000c;
            manyMh[i].cpusubtype = plain ? 0 : 2;
            many[i] = &manyMh[i];
            manyPaths[i] = "p";
        }
        ObjCCallbackState big;
        registerV4(big);
        resetRecorder();
        big.notifyMapped(130, manyPaths, many);
        expect("a chunk of only plain images makes no call", mappedCalls == 2 && chunkCounts == 2 && chunkSizes[0] == 64 && chunkSizes[1] == 2);
        expect("the delivered chunks omit exactly the plain run", recordedCount == 66 && recordedMhs[63] == many[63] && recordedMhs[64] == many[128]);
    }
    {
        struct mach_header plain = {};
        plain.cputype = 0x0100000c;
        const char* plainPath = "disk/libplain.dylib";
        const struct mach_header* plainMhs[1] = { &plain };
        ObjCCallbackState s2;
        s2.logSkip = recordSkipLog;
        s2.registerCallbacks(asCallbacks(&v2));
        resetRecorder();
        loggedLines = 0;
        s2.notifyMapped(1, &plainPath, plainMhs);
        s2.notifyInit(plainPath, &plain);
        expect("v2 still receives plain images", mappedCalls == 1 && recordedCount == 2 && initCalls == 1 && loggedLines == 0);
        ObjCCallbackState s3;
        s3.logSkip = recordSkipLog;
        s3.registerCallbacks(asCallbacks(&v3));
        resetRecorder();
        s3.notifyMapped(1, &plainPath, plainMhs);
        s3.notifyInit(plainPath, &plain);
        expect("v3 still receives plain images", mappedCalls == 1 && recordedCount == 2 && initCalls == 1 && loggedLines == 0);
    }
      {
          fflush(stdout);
          pid_t pid = fork();
          if ( pid == 0 ) {
              ObjCCallbackState s;
              s.markImageMutableInvoke = recordMutable;
              if ( !s.registerCallbacks(asCallbacks(&v3)) ) _exit(10);
              s.notifyMapped(1, paths, mhs);
              reinterpret_cast<ObjCBlockInvoke>(blockInvokeField)(const_cast<ObjCBlockLayout*>(blockSeen), 7);
              _exit(0);
          }
          int status = 0;
          waitpid(pid, &status, 0);
          if ( pac )
              expect("an unauthenticated invoke faults", WIFSIGNALED(status));
          else
              expect("an unauthenticated invoke runs without PAC", WIFEXITED(status) && WEXITSTATUS(status) == 0);
      }

      if ( failures != 0 )
          return 1;
      printf("all objc callback cases pass\n");
      return 0;
  }
CPP

# --- _dyld_get_dlopen_image_header: the loader's handle dispatch and libdyld's wrapper, replayed ----
# Both functions are cut out of the tracked sources and compiled against stubs of the loader state they
# consult, so deleting a branch, a bound or the mode-bit mask in the real code changes this run.
DYLD2 = File.read("#{ROOT}/src/dyld2.cpp")
MEGA = File.read("#{ROOT}/src/ImageLoaderMegaDylib.cpp")
DISPATCH_SIG = 'const struct mach_header* _dyld_get_dlopen_image_header(void* handle)'
CACHE_HEADER_SIG = 'const mach_header* cacheImageMachHeader(void* handle)'
INDEX_SIG = 'const macho_header* ImageLoaderMegaDylib::machHeaderForIndex(unsigned index) const'
CACHE_HANDLE_SIG = 'bool ImageLoaderMegaDylib::isCacheHandle(void* handle, unsigned* index, uint8_t* flags)'

def function_text(source, signature, origin)
  start = source.index("#{signature}\n{") or abort "#{origin}: #{signature} not found"
  stop = source.index("\n}\n", start) or abort "#{origin}: the end of #{signature} not found"
  source[start...(stop + 3)]
end

def function_body(source, signature, origin)
  start = source.index("#{signature}\n{") or abort "#{origin}: #{signature} not found"
  stop = source.index("\n}\n", start) or abort "#{origin}: the end of #{signature} not found"
  source[(start + signature.length + 2)...stop]
end

HANDLE_PRELUDE = <<~'CPP'
  #include <stddef.h>
  #include <stdint.h>
  #include <stdio.h>
  #include <string.h>

  // Darwin's dlfcn sentinels; RTLD_MAIN_ONLY is dyld's private extension.
  #define RTLD_NEXT ((void*)-1L)
  #define RTLD_DEFAULT ((void*)-2L)
  #define RTLD_SELF ((void*)-3L)
  #define RTLD_MAIN_ONLY ((void*)-5L)
  #define SUPPORT_ACCELERATE_TABLES 1
  #define DYLD_NO_LOCK_THIS_BLOCK
  #define __ptrauth_dyld_function_ptr

  struct mach_header { uint32_t magic, cputype, cpusubtype, filetype, ncmds, sizeofcmds, flags; };
  typedef struct mach_header macho_header;
  struct dyld_cache_image_info { uint64_t address; };

  struct ImageLoader {
      const mach_header* header;
      const mach_header* machHeader() const { return header; }
  };

  // ImageLoaderMegaDylib's handle decoder and image table, with the two bodies under test copied in.
  struct MegaProxy {
      unsigned _imageCount;
      const dyld_cache_image_info* _images;
      int64_t _slide;
      bool isCacheHandle(void* handle, unsigned* index, uint8_t* flags)
      {
  __CACHEHANDLE_BODY__
      }
      const macho_header* machHeaderForIndex(unsigned index) const
      {
  __INDEX_BODY__
      }
  };

  namespace dyld {
      bool gLogAPIs = false;
      void log(const char*, ...) {}
      ImageLoader* sMainExecutable = nullptr;
      ImageLoader* mainExecutable() { return sMainExecutable; }
      ImageLoader* sAllImages[8];
      unsigned sImageCount;
      bool validImage(const ImageLoader* possible)
      {
          for ( unsigned i = 0; i < sImageCount; ++i )
              if ( sAllImages[i] == possible )
                  return true;
          return false;
      }
      MegaProxy* sAllCacheImagesProxy = nullptr;
      bool isCacheHandle(void* handle)
      {
          if ( sAllCacheImagesProxy == nullptr )
              return false;
          return sAllCacheImagesProxy->isCacheHandle(handle, nullptr, nullptr);
      }
  __CACHE_HEADER__
  }

  namespace dyld2impl {
  __DISPATCH__
  }

  namespace dyld3 {
      static const struct mach_header cacheHeader = {};
      inline const struct mach_header* _dyld_get_dlopen_image_header(void*) { return &cacheHeader; }
  }

  static bool gUseDyld3 = false;

  static const struct mach_header selfH = {};
  static const void* containingAddress;
  static unsigned containingCalls;
  static const struct mach_header* _dyld_get_image_header_containing_address(const void* address)
  {
      containingAddress = address;
      ++containingCalls;
      return &selfH;
  }

  static unsigned lookupCalls;
  static const char* lookedUpName;
  template <typename T>
  static void dyld_func_lookup_and_resign(const char* name, T** address)
  {
      ++lookupCalls;
      lookedUpName = name;
      *address = dyld2impl::_dyld_get_dlopen_image_header;
  }

  const struct mach_header* _dyld_get_dlopen_image_header(void* handle) __attribute__((noinline));

__WRAPPER__
CPP

HANDLE_DRIVER = <<~'CPP'
  static int failures;
  static void expect(const char* what, bool ok)
  {
      if ( ok ) { printf("ok %s\n", what); return; }
      ++failures;
      printf("FAIL %s\n", what);
  }

  static struct mach_header mainH, dylibH, otherH;
  static ImageLoader mainImage = { &mainH };
  static ImageLoader dylibImage = { &dylibH };
  static ImageLoader otherImage = { &otherH };
  static dyld_cache_image_info cacheImages[4] = {
      { 0x0000000100000000ull }, { 0x0000000100001000ull },
      { 0x00000000DEADBEEFull }, { 0x00000000FEEDFACEull },
  };
  static MegaProxy proxy = { 2, cacheImages, 0x1000 };

  static void* cacheHandle(unsigned index)
  {
      return (void*)(uintptr_t)(0xFFEEDDCC00000000ull | ((uint64_t)index << 8));
  }

  int main()
  {
      dyld::sMainExecutable = &mainImage;
      dyld::sAllImages[0] = &mainImage;
      dyld::sAllImages[1] = &dylibImage;
      dyld::sAllImages[2] = &otherImage;
      dyld::sImageCount = 3;
      dyld::sAllCacheImagesProxy = &proxy;

      expect("RTLD_MAIN_ONLY answers the main executable",
             dyld2impl::_dyld_get_dlopen_image_header(RTLD_MAIN_ONLY) == &mainH);
      expect("RTLD_DEFAULT answers null",
             dyld2impl::_dyld_get_dlopen_image_header(RTLD_DEFAULT) == nullptr);
      expect("RTLD_NEXT answers null",
             dyld2impl::_dyld_get_dlopen_image_header(RTLD_NEXT) == nullptr);
      expect("the loader leaves RTLD_SELF to libdyld",
             dyld2impl::_dyld_get_dlopen_image_header(RTLD_SELF) == nullptr);
      expect("a handle answers its image header",
             dyld2impl::_dyld_get_dlopen_image_header(&dylibImage) == &dylibH);
      expect("a handle's mode bits are cleared",
             dyld2impl::_dyld_get_dlopen_image_header((void*)((uintptr_t)&dylibImage | 3)) == &dylibH);
      expect("an unknown handle answers null",
             dyld2impl::_dyld_get_dlopen_image_header((void*)(uintptr_t)0x12348) == nullptr);
      expect("a forged cache handle answers that image",
             dyld2impl::_dyld_get_dlopen_image_header(cacheHandle(1)) == (const struct mach_header*)(uintptr_t)0x0000000100002000ull);
      expect("cache index 0 answers the first image",
             dyld2impl::_dyld_get_dlopen_image_header(cacheHandle(0)) == (const struct mach_header*)(uintptr_t)0x0000000100001000ull);
      expect("an out-of-range cache index answers null",
             dyld2impl::_dyld_get_dlopen_image_header(cacheHandle(2)) == nullptr);
      expect("the largest cache index answers null",
             dyld2impl::_dyld_get_dlopen_image_header(cacheHandle(0xFFFF)) == nullptr);
      dyld::sAllCacheImagesProxy = nullptr;
      expect("without a cache a cache handle answers null",
             dyld2impl::_dyld_get_dlopen_image_header(cacheHandle(1)) == nullptr);
      expect("without a cache cacheImageMachHeader answers null",
             dyld::cacheImageMachHeader(cacheHandle(1)) == nullptr);
      dyld::sAllCacheImagesProxy = &proxy;
      expect("cacheImageMachHeader decodes the index",
             dyld::cacheImageMachHeader(cacheHandle(1)) == (const struct mach_header*)(uintptr_t)0x0000000100002000ull);

      gUseDyld3 = true;
      expect("libdyld dispatches to dyld3",
             _dyld_get_dlopen_image_header(RTLD_MAIN_ONLY) == &dyld3::cacheHeader);
      gUseDyld3 = false;
      {
          uintptr_t site = (uintptr_t)&&here;
          const struct mach_header* answered = _dyld_get_dlopen_image_header(RTLD_SELF);
        here:
          expect("libdyld answers RTLD_SELF with the containing image", answered == &selfH);
          expect("libdyld passes the caller's return address",
                 containingCalls == 1 && (uintptr_t)containingAddress > site - 128 && (uintptr_t)containingAddress < site + 128);
          expect("libdyld does not dispatch RTLD_SELF", lookupCalls == 0);
          expect("libdyld looks the loader up for a main-only handle",
                 _dyld_get_dlopen_image_header(RTLD_MAIN_ONLY) == &mainH);
          expect("the lookup names the SPI",
                 lookedUpName != nullptr && strcmp(lookedUpName, "__dyld_get_dlopen_image_header") == 0);
          expect("the looked-up function is cached",
                 _dyld_get_dlopen_image_header(&dylibImage) == &dylibH && lookupCalls == 1);
      }

      if ( failures != 0 )
          return 1;
      printf("all dlopen handle cases pass\n");
      return 0;
  }
CPP

def handle_source
  HANDLE_PRELUDE
    .sub('__CACHEHANDLE_BODY__', function_body(MEGA, CACHE_HANDLE_SIG, 'src/ImageLoaderMegaDylib.cpp'))
    .sub('__INDEX_BODY__', function_body(MEGA, INDEX_SIG, 'src/ImageLoaderMegaDylib.cpp'))
    .sub('__CACHE_HEADER__', function_text(DYLD2, CACHE_HEADER_SIG, 'src/dyld2.cpp'))
    .sub('__DISPATCH__', function_text(APIS, DISPATCH_SIG, 'src/dyldAPIs.cpp'))
    .sub('__WRAPPER__', function_text(WRAPPERS, DISPATCH_SIG, 'src/dyldAPIsInLibSystem.cpp')) + HANDLE_DRIVER
end

def build_handle(dir, source)
  work = File.join(dir, 'handle')
  FileUtils.rm_rf(work)
  FileUtils.mkdir_p(work)
  File.write(File.join(work, 'test.cpp'), source)
  exe = File.join(work, 'host')
  out, status = Open3.capture2e('clang++', '-std=c++17', '-O1', '-Wall', '-Werror',
                                File.join(work, 'test.cpp'), '-o', exe)
  return [false, "build failed:\n#{out}"] unless status.success?
  o, e, st = Open3.capture3('timeout', '20', exe)
  [st.success?, o + e]
end

def build_and_run(dir, callbacks_text, block_text, adapters_text = ADAPTERS)
  work = File.join(dir, 'work')
  FileUtils.rm_rf(work)
  FileUtils.mkdir_p(File.join(work, 'mach-o'))
  FileUtils.mkdir_p(File.join(work, 'mach'))
  File.write(File.join(work, 'mach', 'machine.h'), SHIM_MACHINE)
  File.write(File.join(work, 'DarlingArm64eAdapters.h'), adapters_text)
  File.write(File.join(work, 'mach-o', 'dyld_priv.h'), SHIM + block_text + "\n")
  File.write(File.join(work, 'DarlingObjCCallbacks.h'), callbacks_text)
  File.write(File.join(work, 'test.cpp'), DRIVER)
  exe = File.join(work, 'host')
  out, status = Open3.capture2e('clang++', '-std=c++17', '-O1', '-fblocks', '-Wall', '-Werror',
                                '-I', work, File.join(work, 'test.cpp'), '-o', exe)
  return [false, "build failed:\n#{out}"] unless status.success?
  o, e, st = Open3.capture3('timeout', '20', exe)
  [st.success?, o + e]
end

Dir.mktmpdir('dyld-objc-callbacks-') do |dir|
  block = callbacks_block(DYLDPRIV)
  ok, out = build_and_run(dir, CALLBACKS, block)
  puts out
  check('objc callback replay', ok, out)
  check('the runtime PAC probe agrees with the auxv check',
        PAC_HOST == out.include?('pointer authentication: present'))
  check('the PAC checks ran where PAC is present', !PAC_HOST || !out.include?('skip '))

  handle = handle_source
  ok, out = build_handle(dir, handle)
  puts out
  check('dlopen handle replay', ok, out)
  next unless RUN_PROBES

  probes = [
    ['cache images are refs-optimized',
     'dyldObjCRefsOptimized = (mhs[base + i]->flags & MH_DYLIB_IN_CACHE) ? 1 : 0',
     'dyldObjCRefsOptimized = 0', false, :callbacks],
    ['init notices carry the cache bit',
     'dyldObjCRefsOptimized = (mh->flags & MH_DYLIB_IN_CACHE) ? 1 : 0',
     'dyldObjCRefsOptimized = 0', false, :callbacks],
    ['a field authenticates at its own address',
     'authenticateField(reinterpret_cast<uintptr_t>(v4->mapped), &v4->mapped,',
     'authenticateField(reinterpret_cast<uintptr_t>(v4->mapped), &v4->init,', true, :callbacks],
    ['an authenticated field is stored stripped',
     'stored = stripSignedPointer(authenticated);', 'stored = signedValue;', true, :callbacks],
    ['mapped signs with the mapped discriminator', '0xd15a', '0xd15b', true, :callbacks],
    ['the invoke is signed against its field',
     'markImageMutable.invoke = signBlockInvoke((uint64_t)(uintptr_t)markImageMutableInvoke, (uint64_t)(uintptr_t)&markImageMutable.invoke);',
     'markImageMutable.invoke = (uint64_t)(uintptr_t)markImageMutableInvoke;', true, :callbacks],
    ['the invoke is signed with key IA', '.inst 0xDAC10211', '.inst 0xDAC11211', true, :callbacks],
    ['batches are chunked at 64', 'kMaxBatch = 64', 'kMaxBatch = 65', false, :callbacks],
    ['the arm64e check includes the cputype',
     'mh->cputype == CPU_TYPE_ARM64 && ', '', false, :callbacks],
    ['the filter keeps arm64e images', 'return !arm64eRuntime || machHeaderIsArm64e(mh);',
     'return !arm64eRuntime || !machHeaderIsArm64e(mh);', false, :callbacks],
    ['only a v4 runtime is filtered', 'arm64eRuntime = kV4RuntimeIsArm64e && callbacksVersion == 4;', 'arm64eRuntime = kV4RuntimeIsArm64e;', false, :callbacks],
    ['init is filtered too', "if ( !acceptsImage(mh) )\n\t\t\treturn;", "if ( false )\n\t\t\treturn;", false, :callbacks],
    ['an emptied chunk makes no call', "if ( delivered == 0 )\n\t\t\t\tcontinue;", "if ( false )\n\t\t\t\tcontinue;", false, :callbacks],
    ['a skipped image is logged', 'if ( logSkip != nullptr )', 'if ( false )', false, :callbacks],
    ['a v4 runtime is not filtered on unmapped', 'if ( unmapped != nullptr )', 'if ( unmapped != nullptr && acceptsImage(mh) )', false, :callbacks],
    ['the subtype is the arm64e one, not any nonzero', '(subtype & ~CPU_SUBTYPE_MASK) == CPU_SUBTYPE_ARM64E', '(subtype & ~CPU_SUBTYPE_MASK) != 0', false, :adapters],
    ['the subtype is the arm64e one, not any at least it', '(subtype & ~CPU_SUBTYPE_MASK) == CPU_SUBTYPE_ARM64E', '(subtype & ~CPU_SUBTYPE_MASK) >= CPU_SUBTYPE_ARM64E', false, :adapters],
    ['the subtype ABI byte is masked off', '(subtype & ~CPU_SUBTYPE_MASK) == CPU_SUBTYPE_ARM64E', 'subtype == CPU_SUBTYPE_ARM64E', false, :adapters],
    ['version 2 is the v2 struct', 'callbacksVersion == 2', 'callbacksVersion == 1', false, :callbacks],
    ['a null unmapped callback is not called', 'if ( unmapped != nullptr )', 'if ( true )', false, :callbacks],
    ['RTLD_MAIN_ONLY answers the main executable',
     'return dyld::mainExecutable()->machHeader();', 'return NULL;', false, :handle],
    ['a handle has its mode bits cleared', '& (-4)', '& (-1)', false, :handle],
    ['a handle is validated as an image', 'if ( dyld::validImage(image) )', 'if ( true )', false, :handle],
    ['a cache handle goes to the cache table', 'if ( dyld::isCacheHandle(handle) )', 'if ( false )', false, :handle],
    ['cache indices are bounds-checked', 'if ( index >= _imageCount )', 'if ( index >= _imageCount + 4 )', false, :handle],
    ['libdyld answers RTLD_SELF itself', 'if ( handle == RTLD_SELF )', 'if ( false )', false, :handle],
    ['libdyld dispatches to dyld3 first', 'if ( gUseDyld3 )', 'if ( gUseDyld3 && false )', false, :handle],
    ['cacheImageMachHeader asks the cache', 'return sAllCacheImagesProxy->machHeaderForIndex(index);', 'return nullptr;', false, :handle],
  ]
  probes.each do |name, from, to, pac_only, kind|
    if pac_only && !PAC_HOST
      puts "skip probe #{name} (no pointer authentication on this host)"
      next
    end
    source = { handle: handle, adapters: ADAPTERS }.fetch(kind, CALLBACKS)
    abort "probe text not found: #{name}" unless source.include?(from)
    mutated = source.sub(from, to)
    ok, out = case kind
              when :handle then build_handle(dir, mutated)
              when :adapters then build_and_run(dir, CALLBACKS, block, mutated)
              else build_and_run(dir, mutated, block)
              end
    if out.start_with?('build failed')
      abort "probe does not compile: #{name}\n#{out}"
    elsif ok
      $failures += 1
      puts "SURVIVED #{name}"
    else
      puts "killed   #{name}"
    end
  end
end

abort 'tests failed' if $failures != 0
