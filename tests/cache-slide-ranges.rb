# Run the actual pre-signature validation and mapping-output blocks with native
# file descriptors. Signature registration/mmap and slide-byte decoding are not
# executed. Requires Ruby and clang++ with ASan/UBSan.
# Usage: ruby tests/cache-slide-ranges.rb [checkout] [scenario]
# CACHE_SOURCE_REF=42010bd selects the prerequisite without this fix.
require 'tmpdir'
require 'open3'
root = File.realpath(ARGV.fetch(0, File.expand_path('..', __dir__)))
source = File.read("#{root}/dyld3/SharedCacheRuntime.cpp")
if ENV['CACHE_SOURCE_REF']
  source, status = Open3.capture2('git', '-C', root, 'show',
                                "#{ENV.fetch('CACHE_SOURCE_REF')}:dyld3/SharedCacheRuntime.cpp")
  abort 'source unavailable' unless status.success?
end
helper = source[/static bool cacheRangeContains\(.*?^\}/m] or abort 'helper missing'
preflight = source[/    if \( \(cache->header.mappingCount < 3\).*?(?=    \/\/ register code signature)/m] or abort 'validation missing'
output = source[/    \/\/ fill out results.*?    return true;\n\}/m] or abort 'output missing'
header = File.read("#{root}/dyld3/shared-cache/dyld_cache_format.h")
max_mappings = File.read("#{root}/dyld3/shared-cache/DyldSharedCache.h")[/MaxMappings = (\d+)/, 1] or abort 'mapping limit missing'
structs = %w[dyld_cache_header dyld_cache_mapping_info dyld_cache_mapping_and_slide_info].map do |name|
  header[/struct #{name}\s*\{.*?^\};/m] or abort "missing #{name}"
end.join("\n")
flags = header[/enum \{\s*DYLD_CACHE_MAPPING_AUTH_DATA.*?^\};/m] or abort 'flags missing'
Dir.mktmpdir('cache-slide-ranges-') do |dir|
  File.write("#{dir}/test.cpp", <<~CPP)
    #include <stdint.h>
    #include <stddef.h>
    #include <assert.h>
    #include <stdio.h>
    #include <stdlib.h>
    #include <unistd.h>
    #include <fcntl.h>
    #include <errno.h>
    #define __offsetof offsetof
    typedef unsigned char uuid_t[16];
    typedef uint64_t user_addr_t;
    typedef unsigned vm_prot_t;
    enum { VM_PROT_READ=1, VM_PROT_WRITE=2, VM_PROT_EXECUTE=4,
           VM_PROT_NOAUTH=8, VM_PROT_SLIDE=16 };
    #{structs}
    #{flags}
    struct DyldSharedCache { dyld_cache_header header; enum { MaxMappings=#{max_mappings} }; };
    struct Result { const char *errorMessage=nullptr; };
    struct Mapping {
      uint64_t sms_address, sms_size, sms_file_offset, sms_slide_size, sms_slide_start;
      vm_prot_t sms_max_prot, sms_init_prot;
    };
    struct Info {
      unsigned mappingsCount; int fd; Mapping mappings[DyldSharedCache::MaxMappings];
      uint64_t sharedRegionStart, sharedRegionSize, maxSlide;
    };
    static bool gEnableSharedCacheDataConst=true;
    #{helper}
    static bool verify(int fd, const uint8_t (&firstPage)[0x4000], Result *results, Info *info) {
      uint64_t cacheFileLength=0x4000;
      const DyldSharedCache *cache = reinterpret_cast<const DyldSharedCache *>(firstPage);
    #{preflight}
    #{output}
    int main(int argc, char **argv) {
      unsigned first=argc>1 ? unsigned(atoi(argv[1])) : 0;
      unsigned end=argc>1 ? first+1 : 17;
      assert(first<17);
      for (unsigned scenario=first; scenario!=end; ++scenario) {
        alignas(16) uint8_t firstPage[0x4000]={};
        auto &h = reinterpret_cast<DyldSharedCache *>(firstPage)->header;
        h.mappingCount=3; h.mappingOffset=0x168;
        bool legacy=(scenario==10 || scenario==11 || scenario==12);
        if (legacy) h.mappingOffset=offsetof(dyld_cache_header, mappingWithSlideOffset);
        h.sharedRegionStart=0x1000; h.sharedRegionSize=0x8000;
        h.codeSignatureOffset=0x300; h.codeSignatureSize=0x4000-0x300;
        auto m = reinterpret_cast<dyld_cache_mapping_info *>(firstPage+h.mappingOffset);
        m[0].address=0x1000; m[0].size=0x100; m[0].fileOffset=0; m[0].maxProt=5;
        m[1].address=0x2000; m[1].size=0x100; m[1].fileOffset=0x100; m[1].maxProt=3;
        m[2].address=0x3000; m[2].size=0x100; m[2].fileOffset=0x200; m[2].maxProt=1;
        if (legacy) {
          // The legacy mapping table occupies the later header fields.
          h.slideInfoOffsetUnused=0x220; h.slideInfoSizeUnused=0x20;
          if (scenario==11) h.slideInfoOffsetUnused=0x2f0;
          if (scenario==12) h.slideInfoOffsetUnused=0x120;
        } else {
          h.mappingWithSlideCount=3; h.mappingWithSlideOffset=0x400;
          if (scenario==6) h.mappingWithSlideOffset=sizeof(firstPage)-3*sizeof(dyld_cache_mapping_and_slide_info);
          auto sm = reinterpret_cast<dyld_cache_mapping_and_slide_info *>(firstPage+h.mappingWithSlideOffset);
          sm[1].slideInfoFileOffset=0x220; sm[1].slideInfoFileSize=0x20;
          switch(scenario) {
            case 1: h.mappingWithSlideCount=0; break;
            case 2: h.mappingWithSlideCount=2; break;
            case 3: h.mappingWithSlideOffset=0x4000; break;
            case 4: h.mappingWithSlideOffset=UINT32_MAX; break;
            case 5: h.mappingWithSlideOffset+=1; break;
            case 7: sm[1].slideInfoFileOffset=0x120; break; // stored in DATA
            case 8: sm[1].slideInfoFileOffset=0x2f0; break; // crosses mapping end
            case 9: sm[1].slideInfoFileOffset=UINT64_MAX-7; break;
            case 13: sm[1].slideInfoFileOffset=UINT64_MAX; sm[1].slideInfoFileSize=0; break;
            case 14: sm[1].slideInfoFileOffset=0x2e0; break; // exact end
            case 15: sm[1].flags=DYLD_CACHE_MAPPING_AUTH_DATA | DYLD_CACHE_MAPPING_CONST_DATA;
                     gEnableSharedCacheDataConst=false; break;
            case 16: h.mappingWithSlideCount=UINT32_MAX; break;
          }
        }
        bool expected=(scenario==0 || scenario==6 || scenario==7 || scenario==10 ||
                       scenario==12 || scenario==13 || scenario==14 || scenario==15);
        int fd=open("/dev/null",O_RDONLY); assert(fd>=0);
        Result result; Info info={};
        bool actual=verify(fd, firstPage, &result, &info);
        if (actual!=expected) {
          fprintf(stderr,"FAIL scenario %u: accepted=%d expected=%d\\n",scenario,actual,expected);
          close(fd); return 1;
        }
        if (expected) {
          assert(!result.errorMessage && fcntl(fd,F_GETFD)>=0 && info.fd==fd);
          assert(info.mappingsCount==3);
          assert(info.mappings[0].sms_slide_size==0 && info.mappings[2].sms_slide_size==0);
          if (scenario==13) assert(info.mappings[1].sms_slide_size==0 && info.mappings[1].sms_slide_start==0);
          else {
            uint64_t address=(scenario==7 || scenario==12) ? 0x2020 : (scenario==14 ? 0x30e0 : 0x3020);
            assert(info.mappings[1].sms_slide_start==address && info.mappings[1].sms_slide_size==0x20);
            assert(info.mappings[1].sms_init_prot & VM_PROT_SLIDE);
            assert(bool(info.mappings[1].sms_max_prot & VM_PROT_NOAUTH)==(!legacy && scenario!=15));
            if (scenario==15) assert(info.mappings[1].sms_init_prot & VM_PROT_WRITE);
          }
          close(fd);
        } else { assert(result.errorMessage); errno=0; assert(fcntl(fd,F_GETFD)==-1 && errno==EBADF); }
      }
      puts("PASS: actual slide-table validation/output, address translation and descriptor ownership");
    }
  CPP
  output, status = Open3.capture2e('clang++', '-std=c++11', '-fsanitize=address,undefined',
                                  '-fno-sanitize-recover=all', "#{dir}/test.cpp", '-o', "#{dir}/test")
  abort output unless status.success?
  output, status = Open3.capture2e("#{dir}/test", *ARGV.drop(1))
  puts output
  abort 'slide range regression failed' unless status.success?
end
