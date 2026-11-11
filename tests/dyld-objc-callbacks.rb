# The dyld4 objc surface in dyld: the wiring of _dyld_objc_register_callbacks and _dyld_get_dlopen_image_header
# in both images, and a replay of _dyld_get_dlopen_image_header: the loader's dispatch, the libdyld wrapper and
# the cache table's two functions are cut out of the tracked sources and driven with sentinel, forged-cache and
# invalid handles. Mutants of the replay must each fail (--probes).
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

def build_and_run(dir, callbacks_text, block_text)
  work = File.join(dir, 'work')
  FileUtils.rm_rf(work)
  FileUtils.mkdir_p(File.join(work, 'mach-o'))
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

  handle = handle_source
  ok, out = build_handle(dir, handle)
  puts out
  check('dlopen handle replay', ok, out)
  next unless RUN_PROBES

  probes = [
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
  probes.each do |name, from, to, pac_only|
    if pac_only && !PAC_HOST
      puts "skip probe #{name} (no pointer authentication on this host)"
      next
    end
    abort "probe text not found: #{name}" unless handle.include?(from)
    ok, out = build_handle(dir, handle.sub(from, to))
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