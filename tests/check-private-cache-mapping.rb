# Actual mapCachePrivate control flow with host mappings and controlled preflight,
# rebasing and DataConst protection collaborators; not a Mach-O loader boot.
require 'tmpdir'
require 'open3'
root=File.realpath(ARGV.fetch(0, File.expand_path('..', __dir__)))
source=File.read("#{root}/dyld3/SharedCacheRuntime.cpp")
helper=source[/class DarlingCacheReservation \{.*?^\};/m] or abort 'helper missing'
if ENV['BASELINE_MAPPER_REF']
  source,ok=Open3.capture2('git','-C',root,'show',"#{ENV.fetch('BASELINE_MAPPER_REF')}:dyld3/SharedCacheRuntime.cpp")
  abort 'baseline source unavailable' unless ok.success?
end
mapping=source[/static bool mapCachePrivate\(.*?^\}/m] or abort 'mapper missing'
mapping=mapping.gsub('::mmap(', 'test_mmap(')
Dir.mktmpdir('private-cache-mapping-') do |dir|
  File.write("#{dir}/test.cpp", <<~CPP)
    #include <sys/mman.h>
    #include <unistd.h>
    #include <stdint.h>
    #include <assert.h>
    #include <stdio.h>
    #include <stdlib.h>
    #include <fcntl.h>
    #include <errno.h>
    #define DARLING 1
    #define TARGET_OS_SIMULATOR 0
    #define TARGET_OS_WATCH 0
    #define VM_PROT_READ PROT_READ
    #define VM_PROT_WRITE PROT_WRITE
    #define VM_PROT_EXECUTE PROT_EXEC
    struct dyld_cache_slide_info {};
    namespace dyld { static void log(const char*, ...) {} }
    static int mach_task_self() { return 0; }
    struct DyldSharedCache {
      struct DataConstScopedWriter {
        DataConstScopedWriter(const DyldSharedCache*, int, void(*)(const char*,...)) {}
      };
    };
    struct Mapping {
      uint64_t sms_address, sms_size, sms_slide_start, sms_slide_size;
      int sms_init_prot;
      off_t sms_file_offset;
    };
    struct CacheInfo {
      Mapping mappings[3]; unsigned mappingsCount;
      uint64_t sharedRegionStart, sharedRegionSize;
      int fd;
    };
    struct SharedCacheOptions { bool disableASLR=true, verbose=false; };
    struct SharedCacheLoadInfo {
      uintptr_t slide=0;
      const DyldSharedCache *loadAddress=nullptr;
      const char *errorMessage=nullptr, *path="fixture";
    };
    static CacheInfo fixture;
    #define SHARED_REGION_BASE fixture.sharedRegionStart
    #define SHARED_REGION_SIZE fixture.sharedRegionSize
    static void deallocateExistingSharedCache() {}
    static int sourceFd, openedFd, fixedCalls, failFixedAt;
    static bool failRebase;
    static bool preflightCacheFile(const SharedCacheOptions&, SharedCacheLoadInfo*, CacheInfo *out) {
      *out=fixture; openedFd=out->fd=dup(sourceFd); assert(openedFd>=0); return true;
    }
    static uintptr_t pickCacheASLRSlide(const CacheInfo&) { return 0; }
    static bool rebaseDataPages(bool, const dyld_cache_slide_info*, const uint8_t*, uint64_t, SharedCacheLoadInfo *result) {
      if (failRebase) result->errorMessage="injected rebase failure";
      return !failRebase;
    }
    static void verboseSharedCacheMappings(const Mapping*, unsigned) {}
    static void *test_mmap(void *a, size_t n, int p, int f, int fd, off_t o) {
      if (f & MAP_FIXED) {
        ++fixedCalls;
        if (fixedCalls==failFixedAt) { errno=ENOMEM; return MAP_FAILED; }
      }
      return mmap(a,n,p,f,fd,o);
    }
    #{helper}
    #{mapping}
    static bool mapped(char *p, size_t page) {
      unsigned char residency;
      errno=0;
      int result=mincore(p,page,&residency);
      assert(result==0 || errno==ENOMEM);
      return result==0;
    }
    static bool run(SharedCacheLoadInfo &result) {
      fixedCalls=0; result=SharedCacheLoadInfo{};
      bool success=mapCachePrivate(SharedCacheOptions{},&result);
      errno=0; assert(fcntl(openedFd,F_GETFD)==-1 && errno==EBADF);
      return success;
    }
    int main() {
      size_t page=sysconf(_SC_PAGESIZE);
      char filename[]="/tmp/cache-map-test-XXXXXX";
      sourceFd=mkstemp(filename); assert(sourceFd>=0); unlink(filename);
      assert(ftruncate(sourceFd,page*3)==0);
      char byte=77; assert(pwrite(sourceFd,&byte,1,0)==1);
      char *span=(char*)mmap(nullptr,page*3,PROT_READ|PROT_WRITE,MAP_PRIVATE|MAP_ANON,-1,0);
      assert(span!=MAP_FAILED); span[0]=41; span[page*2]=43;
      fixture.sharedRegionStart=(uintptr_t)span; fixture.sharedRegionSize=page*3;
      fixture.mappingsCount=2;
      fixture.mappings[0]={(uintptr_t)span,page,0,0,PROT_READ|PROT_WRITE,0};
      fixture.mappings[1]={(uintptr_t)(span+page*2),page,0,0,PROT_READ|PROT_WRITE,(off_t)(page*2)};
      SharedCacheLoadInfo result;
      assert(!run(result) && !result.loadAddress && fixedCalls==0);
      assert(span[0]==41 && span[page*2]==43);
      assert(munmap(span+page,page)==0);
      assert(!run(result) && fixedCalls==0);
      assert(span[0]==41 && span[page*2]==43);
      assert(munmap(span,page*3)==0);
      failFixedAt=2;
      assert(!run(result) && !result.loadAddress && fixedCalls==2);
      for (unsigned i=0;i<3;++i) assert(!mapped(span+page*i,page));
      failFixedAt=0; failRebase=true;
      fixture.mappings[0].sms_slide_size=1;
      assert(!run(result) && !result.loadAddress && fixedCalls==2);
      for (unsigned i=0;i<3;++i) assert(!mapped(span+page*i,page));
      failRebase=false;
      fixture.mappings[1].sms_address=(uintptr_t)(span+page*3);
      assert(!run(result) && fixedCalls==0 && !result.loadAddress);
      fixture.mappings[1].sms_address=(uintptr_t)(span+page*2);
      assert(run(result) && result.loadAddress==(void*)span && fixedCalls==2);
      assert(span[0]==77);
      for (unsigned i=0;i<3;++i) assert(mapped(span+page*i,page));
      assert(munmap(span,page*3)==0); close(sourceFd);
      puts("PASS actual mapper collision, partial failure, rebase rollback, extent rejection, success and FD cleanup");
    }
  CPP
  out,ok=Open3.capture2e('clang++','-std=c++11','-fblocks','-fsanitize=undefined',"#{dir}/test.cpp",'-o',"#{dir}/test")
  abort out unless ok.success?
  out,ok=Open3.capture2e("#{dir}/test")
  puts out
  abort 'mapping regression failed' unless ok.success?
end
