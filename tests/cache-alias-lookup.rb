# Actual cache lookup function with controlled path-trie/ImageArray collaborators.
require 'tmpdir'
require 'open3'
root=File.realpath(ARGV.fetch(0))
source=File.read("#{root}/dyld3/SharedCacheRuntime.cpp")
if ENV['LOOKUP_SOURCE_REF']
  source,ok=Open3.capture2('git','-C',root,'show',"#{ENV.fetch('LOOKUP_SOURCE_REF')}:dyld3/SharedCacheRuntime.cpp")
  abort 'source unavailable' unless ok.success?
end
lookup=source[/bool findInSharedCacheImage\(.*?^\}/m] or abort 'lookup missing'
Dir.mktmpdir('cache-alias-lookup-') do |dir|
  File.write("#{dir}/test.cpp", <<~CPP)
    #include <stdint.h>
    #include <stddef.h>
    #include <string.h>
    #include <assert.h>
    #include <stdio.h>
    #define TARGET_OS_IPHONE 0
    struct mach_header {};
    struct dyld_cache_image_info { uint64_t address,modTime,inode; uint32_t pathFileOffset,pad; };
    namespace dyld3 { namespace closure {
      const unsigned kFormatVersion=1;
      struct Image { uintptr_t cacheOffset() const { return 64; } const char *path() const { return "closure-image"; } };
      struct ImageArray { Image image; const Image *imageForNum(uint32_t n) const { return n==1?&image:nullptr; } };
    }}
    struct DyldSharedCache {
      struct Header {
        unsigned formatVersion=2,mappingOffset=0x200,imagesOffset=0,imagesCount=1;
        uint64_t dylibsImageArrayAddr=0,dylibsTrieAddr=1,dylibsTrieSize=1;
      } header;
      uint32_t trieIndex=0;
      bool trieFound=true;
      dyld3::closure::ImageArray array;
      bool hasImagePath(const char *path,uint32_t &index) const {
        index=trieIndex; return trieFound && strcmp(path,"alias")==0;
      }
      const dyld3::closure::ImageArray *cachedDylibsImageArray() const { return header.dylibsImageArrayAddr?&array:nullptr; }
    };
    struct SharedCacheLoadInfo { const DyldSharedCache *loadAddress; long slide; };
    struct SharedCacheFindDylibResults { const mach_header *mhInCache; const char *pathInCache; long slideInCache; const dyld3::closure::Image *image; };
    #{lookup}
    struct Fixture { DyldSharedCache cache; dyld_cache_image_info images[1]; char canonical[32]; };
    int main() {
      Fixture f={}; strcpy(f.canonical,"canonical");
      f.cache.header.imagesOffset=offsetof(Fixture,images);
      f.images[0].address=0x100000;
      f.images[0].pathFileOffset=offsetof(Fixture,canonical);
      SharedCacheLoadInfo load={&f.cache,0x2000}; SharedCacheFindDylibResults result={};
      assert(findInSharedCacheImage(load,"alias",&result));
      assert((uintptr_t)result.mhInCache==0x102000 && result.slideInCache==0x2000);
      assert(strcmp(result.pathInCache,"canonical")==0 && !result.image);
      // A matching format without an ImageArray must also take the safe fallback.
      f.cache.header.formatVersion=dyld3::closure::kFormatVersion;
      assert(findInSharedCacheImage(load,"alias",&result) && !result.image);
      f.cache.trieIndex=1;
      assert(!findInSharedCacheImage(load,"alias",&result));
      f.cache.trieIndex=UINT32_MAX;
      assert(!findInSharedCacheImage(load,"alias",&result));
      assert(findInSharedCacheImage(load,"canonical",&result));
      f.cache.trieIndex=0;
      f.cache.header.dylibsTrieAddr=0;
      assert(!findInSharedCacheImage(load,"alias",&result));
      assert(findInSharedCacheImage(load,"canonical",&result));
      f.cache.header.dylibsTrieAddr=1; f.cache.header.dylibsTrieSize=0;
      assert(!findInSharedCacheImage(load,"alias",&result));
      f.cache.header.dylibsTrieSize=1; f.cache.header.mappingOffset=0x100;
      assert(!findInSharedCacheImage(load,"alias",&result));
      assert(findInSharedCacheImage(load,"canonical",&result));
      f.cache.header.mappingOffset=0x200; f.cache.trieFound=false;
      assert(!findInSharedCacheImage(load,"alias",&result));
      f.cache.trieFound=true; f.cache.header.dylibsImageArrayAddr=1;
      assert(findInSharedCacheImage(load,"alias",&result));
      assert(result.image==&f.cache.array.image);
      assert((uintptr_t)result.mhInCache==(uintptr_t)&f.cache+64);
      assert(strcmp(result.pathInCache,"closure-image")==0);
      load.loadAddress=nullptr; assert(!findInSharedCacheImage(load,"alias",&result));
      puts("PASS actual cache alias lookup, index bounds, missing ImageArray, legacy scan and closure route");
    }
  CPP
  out,ok=Open3.capture2e('clang++','-std=c++11','-fsanitize=address,undefined',"#{dir}/test.cpp",'-o',"#{dir}/test")
  abort out unless ok.success?
  out,ok=Open3.capture2e("#{dir}/test"); puts out
  abort 'cache alias lookup regression failed' unless ok.success?
end
