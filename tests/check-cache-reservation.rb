# Exercise the actual private-cache reservation helper with host mmap semantics.
require 'tmpdir'
require 'open3'
source=File.read(File.join(File.realpath(ARGV.fetch(0, File.expand_path('..', __dir__))), 'dyld3/SharedCacheRuntime.cpp'))
helper=source[/class DarlingCacheReservation \{.*?^\};/m]
abort 'reservation helper missing' unless helper
Dir.mktmpdir('cache-reservation-') do |dir|
  File.write("#{dir}/test.cpp", <<~CPP)
    #include <sys/mman.h>
    #include <unistd.h>
    #include <stdint.h>
    #include <assert.h>
    #include <stdio.h>
    #{helper}
    int main() {
      size_t page=(size_t)sysconf(_SC_PAGESIZE);
      char *span=(char*)mmap(nullptr,page*3,PROT_READ|PROT_WRITE,MAP_PRIVATE|MAP_ANON,-1,0);
      assert(span!=MAP_FAILED);
      span[0]=41; span[page]=42; span[page*2]=43;
      {
        DarlingCacheReservation occupied;
        assert(!occupied.acquire((uintptr_t)span,page*3));
        assert(span[0]==41 && span[page]==42 && span[page*2]==43);
      }
      assert(munmap(span+page,page)==0);
      {
        DarlingCacheReservation partial;
        assert(!partial.acquire((uintptr_t)span,page*3));
        assert(span[0]==41 && span[page*2]==43);
      }
      {
        DarlingCacheReservation freeSlot;
        assert(freeSlot.acquire((uintptr_t)(span+page),page));
        // Simulate replacing a reserved page with a cache file mapping.
        assert(mmap(span+page,page,PROT_READ|PROT_WRITE,
                    MAP_PRIVATE|MAP_ANON|MAP_FIXED,-1,0)==span+page);
        span[page]=44;
      }
      unsigned char residency;
      assert(mincore(span+page,page,&residency)==-1);
      assert(span[0]==41 && span[page*2]==43);
      {
        DarlingCacheReservation kept;
        assert(kept.acquire((uintptr_t)(span+page),page));
        kept.keep();
      }
      assert(mincore(span+page,page,&residency)==0);
      DarlingCacheReservation invalid;
      assert(!invalid.acquire(0,page));
      assert(!invalid.acquire((uintptr_t)span,0));
      assert(!invalid.acquire(UINTPTR_MAX-page/2,page));
      assert(munmap(span,page*3)==0);
      puts("PASS occupied and partial collisions preserve bytes; rollback, keep and overflow");
    }
  CPP
  out,ok=Open3.capture2e('clang++','-std=c++11','-fsanitize=undefined',"#{dir}/test.cpp",'-o',"#{dir}/test")
  abort out unless ok.success?
  out,ok=Open3.capture2e("#{dir}/test")
  puts out
  abort 'reservation regression failed' unless ok.success?
end
