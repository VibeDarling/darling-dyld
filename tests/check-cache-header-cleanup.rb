# Extract the actual mapped-header verification block; keep host mmap/close.
require 'tmpdir'
require 'open3'
root=File.realpath(ARGV.fetch(0, File.expand_path('..', __dir__)))
source=File.read("#{root}/dyld3/SharedCacheRuntime.cpp")
if ENV['HEADER_SOURCE_REF']
  source,ok=Open3.capture2('git','-C',root,'show',"#{ENV.fetch('HEADER_SOURCE_REF')}:dyld3/SharedCacheRuntime.cpp")
  abort 'source unavailable' unless ok.success?
end
block=source[/    void\* mappedData = ::mmap\(NULL, sizeof\(firstPage\).*?^    ::munmap\(mappedData, sizeof\(firstPage\)\);/m] or abort 'verification block missing'
block=block.sub('::mmap(', 'tracked_mmap(')
Dir.mktmpdir('cache-header-cleanup-') do |dir|
  File.write("#{dir}/test.cpp", <<~CPP)
    #include <sys/mman.h>
    #include <unistd.h>
    #include <fcntl.h>
    #include <errno.h>
    #include <stdint.h>
    #include <stdio.h>
    #include <stdlib.h>
    #include <string.h>
    #include <assert.h>
    static bool failMapping;
    static void *lastMapping=MAP_FAILED;
    struct Result { const char *errorMessage=nullptr; };
    static void *tracked_mmap(void *a,size_t n,int p,int flags,int fd,off_t o) {
      if (failMapping) { errno=ENOMEM; return MAP_FAILED; }
      lastMapping=mmap(a,n,p,flags,fd,o);
      return lastMapping;
    }
    static bool verify(int fd, const uint8_t (&firstPage)[0x4000], Result *results) {
    #{block}
      return true;
    }
    static int newFile() {
      char path[]="/tmp/cache-header-XXXXXX";
      int fd=mkstemp(path); assert(fd>=0); unlink(path);
      assert(ftruncate(fd,0x4000)==0);
      return fd;
    }
    static void assertClosed(int fd) {
      errno=0; assert(fcntl(fd,F_GETFD)==-1 && errno==EBADF);
    }
    static void assertUnmapped() {
      assert(lastMapping!=MAP_FAILED);
      unsigned char resident[16]; errno=0;
      assert(mincore(lastMapping,0x4000,resident)==-1 && errno==ENOMEM);
    }
    int main() {
      uint8_t page[0x4000]={}; Result result;
      int fd=newFile();
      assert(verify(fd,page,&result)); assert(!result.errorMessage);
      assert(fcntl(fd,F_GETFD)>=0); assertUnmapped(); close(fd);
      fd=newFile(); page[0]=1;
      assert(!verify(fd,page,&result));
      assert(strcmp(result.errorMessage,"first page of mmap()ed shared cache not valid")==0);
      assertClosed(fd); assertUnmapped();
      fd=newFile(); failMapping=true; lastMapping=MAP_FAILED;
      assert(!verify(fd,page,&result));
      assert(strcmp(result.errorMessage,"first page of shared cache not mmap()able")==0);
      assertClosed(fd); assert(lastMapping==MAP_FAILED);
      puts("PASS actual header verification releases mappings and closes failure FDs");
    }
  CPP
  out,ok=Open3.capture2e('clang++','-std=c++11','-fsanitize=undefined',"#{dir}/test.cpp",'-o',"#{dir}/test")
  abort out unless ok.success?
  out,ok=Open3.capture2e("#{dir}/test")
  puts out
  abort 'header cleanup regression failed' unless ok.success?
end
