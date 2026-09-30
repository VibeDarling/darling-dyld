# Exercise the actual pre-signature mapping validation, using native descriptors.
# Usage: ruby tests/cache-preflight-ranges.rb [checkout]
# CACHE_SOURCE_REF selects an older implementation for a negative control.
require 'tmpdir'
require 'open3'
root = File.realpath(ARGV.fetch(0, File.expand_path('..', __dir__)))
source = File.read("#{root}/dyld3/SharedCacheRuntime.cpp")
if ENV['CACHE_SOURCE_REF']
  source, status = Open3.capture2('git', '-C', root, 'show',
                                "#{ENV.fetch('CACHE_SOURCE_REF')}:dyld3/SharedCacheRuntime.cpp")
  abort 'source unavailable' unless status.success?
end
helper = source[/static bool cacheRangeContains\(.*?^\}/m] || ''
block = source[/    if \( \(cache->header.mappingCount < 3\).*?(?=    \/\/ register code signature)/m]
abort 'mapping validation missing' unless block
header = File.read("#{root}/dyld3/shared-cache/dyld_cache_format.h")
structs = %w[dyld_cache_header dyld_cache_mapping_info].map do |name|
  header[/struct #{name}\s*\{.*?^\};/m] or abort "missing #{name}"
end.join("\n")
Dir.mktmpdir('cache-preflight-ranges-') do |dir|
  File.write("#{dir}/test.cpp", <<~CPP)
    #include <stdint.h>
    #include <stddef.h>
    #include <assert.h>
    #include <stdio.h>
    #include <string.h>
    #include <unistd.h>
    #include <fcntl.h>
    #include <errno.h>
    typedef unsigned char uuid_t[16];
    enum { VM_PROT_READ=1, VM_PROT_WRITE=2, VM_PROT_EXECUTE=4 };
    #{structs}
    struct DyldSharedCache { dyld_cache_header header; enum { MaxMappings=16 }; };
    struct Result { const char *errorMessage=nullptr; };
    #{helper}
    static bool verify(int fd, const uint8_t *firstPage, uint64_t cacheFileLength, Result *results) {
      const DyldSharedCache *cache = reinterpret_cast<const DyldSharedCache *>(firstPage);
    #{block}
      return true;
    }
    int main() {
      for (unsigned scenario=0; scenario!=9; ++scenario) {
        alignas(16) uint8_t firstPage[0x4000]={};
        auto &h = reinterpret_cast<DyldSharedCache *>(firstPage)->header;
        h.mappingCount=3; h.mappingOffset=0x168;
        h.sharedRegionStart=0x1000; h.sharedRegionSize=0x4000;
        h.codeSignatureOffset=64; h.codeSignatureSize=0x4000-64;
        auto m = reinterpret_cast<dyld_cache_mapping_info *>(firstPage+h.mappingOffset);
        m[0].address=0x1000; m[0].size=16; m[0].fileOffset=0; m[0].maxProt=5;
        m[1].address=0x2000; m[1].size=32; m[1].fileOffset=16; m[1].maxProt=3;
        m[2].address=0x3000; m[2].size=16; m[2].fileOffset=48; m[2].maxProt=1;
        switch (scenario) {
          case 1: m[1].address=UINT64_MAX-15; break; // wrapped data VM end
          case 2: m[2].address=UINT64_MAX-7; break; // wrapped linkedit VM end
          case 3: m[2].size=0x3ff0; h.sharedRegionSize=0x10000; break; // file overrun
          case 4: h.codeSignatureOffset=UINT64_MAX-15;
                  h.codeSignatureSize=0x4010; break; // wraps to exact file length
          case 5: h.sharedRegionStart=UINT64_MAX-15; h.sharedRegionSize=0x5000;
                  m[0].address=h.sharedRegionStart; m[0].size=32;
                  m[1].address=0x100; m[1].fileOffset=32; m[1].size=16;
                  m[2].address=0x200; break; // parent and text ends both wrap
          case 6: h.sharedRegionSize=0x2010; break; // exact VM end accepted
          case 7: h.codeSignatureOffset=0x4000; h.codeSignatureSize=0;
                  m[2].size=0x4000-48; h.sharedRegionSize=0x10000; break; // exact file end
          case 8: m[1].address=0x1008; break; // existing overlap check preserved
        }
        bool expected=(scenario==0 || scenario==6 || scenario==7);
        int fd=open("/dev/null",O_RDONLY); assert(fd>=0);
        Result result;
        bool actual=verify(fd, firstPage, sizeof(firstPage), &result);
        if (actual!=expected) {
          fprintf(stderr,"FAIL scenario %u: accepted=%d expected=%d\\n",scenario,actual,expected);
          close(fd); return 1;
        }
        if (expected) { assert(!result.errorMessage); assert(fcntl(fd,F_GETFD)>=0); close(fd); }
        else { assert(result.errorMessage); errno=0; assert(fcntl(fd,F_GETFD)==-1 && errno==EBADF); }
      }
      puts("PASS: actual preflight mapping checks reject wrapped/file extents and preserve valid boundaries and FD ownership");
    }
  CPP
  output, status = Open3.capture2e('clang++', '-std=c++11', '-fsanitize=address,undefined',
                                  "#{dir}/test.cpp", '-o', "#{dir}/test")
  abort output unless status.success?
  output, status = Open3.capture2e("#{dir}/test")
  puts output
  abort 'preflight range regression failed' unless status.success?
end
