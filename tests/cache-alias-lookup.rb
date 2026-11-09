# Actual cache lookup function with controlled path-trie/ImageArray collaborators.
require 'tmpdir'
require 'open3'
root=File.realpath(ARGV.fetch(0))
source=File.read("#{root}/dyld3/SharedCacheRuntime.cpp")
if ENV['LOOKUP_SOURCE_REF']
  source,ok=Open3.capture2('git','-C',root,'show',"#{ENV.fetch('LOOKUP_SOURCE_REF')}:dyld3/SharedCacheRuntime.cpp")
  abort 'source unavailable' unless ok.success?
end
header=File.read("#{root}/dyld3/SharedCacheRuntime.h")
results=header[/^static const uint32_t kNoCacheImageIndex.*?^\};/m] or abort 'results struct missing'
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
      struct ImageArray { Image image; const Image *imageForNum(uint32_t n) const { return (n==1||n==2)?&image:nullptr; } };
    }}
    struct DyldSharedCache {
      struct Header {
        unsigned formatVersion=2,mappingOffset=0x200,imagesOffset=0,imagesCount=1;
        uint64_t dylibsImageArrayAddr=0,dylibsTrieAddr=1,dylibsTrieSize=1;
      } header;
      uint32_t trieIndex=0;
      bool trieFound=true;
      dyld3::closure::ImageArray array;
      bool split=false; uint32_t splitOffset=0,splitCount=0;
      bool isSplitCache() const { return split; }
      const dyld_cache_image_info *imageTable(uint32_t &count) const {
        count=split?splitCount:header.imagesCount;
        return (const dyld_cache_image_info*)((const char*)this+(split?splitOffset:header.imagesOffset));
      }
      bool hasImagePath(const char *path,uint32_t &index) const {
        index=trieIndex; return trieFound && strcmp(path,"alias")==0;
      }
      const dyld3::closure::ImageArray *cachedDylibsImageArray() const { return header.dylibsImageArrayAddr?&array:nullptr; }
    };
    struct SharedCacheLoadInfo { const DyldSharedCache *loadAddress; long slide; };
    namespace dyld3 {
    #{results}
    }
    using namespace dyld3;
    #{lookup}
    struct Fixture { DyldSharedCache cache; dyld_cache_image_info images[2]; char canonical[32]; char second[32]; };
    int main() {
      Fixture f={}; strcpy(f.canonical,"canonical"); strcpy(f.second,"second");
      f.cache.header.imagesOffset=offsetof(Fixture,images);
      f.images[0].address=0x100000;
      f.images[0].pathFileOffset=offsetof(Fixture,canonical);
      f.images[1].address=0x200000;
      f.images[1].pathFileOffset=offsetof(Fixture,second);
      SharedCacheLoadInfo load={&f.cache,0x2000}; SharedCacheFindDylibResults result={};
      assert(findInSharedCacheImage(load,"alias",&result));
      assert((uintptr_t)result.mhInCache==0x102000 && result.slideInCache==0x2000);
      assert(strcmp(result.pathInCache,"canonical")==0 && !result.image && result.cacheImageIndex==0);
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
      assert(result.image==&f.cache.array.image && result.cacheImageIndex==0);
      assert((uintptr_t)result.mhInCache==(uintptr_t)&f.cache+64);
      assert(strcmp(result.pathInCache,"closure-image")==0);
      f.cache.trieIndex=1; assert(findInSharedCacheImage(load,"alias",&result) && result.cacheImageIndex==1); f.cache.trieIndex=0;
      // A split cache reads its own table even though a closure ImageArray is advertised, and the
      // alias index is bounded by that table, not by the (empty) legacy one.
      f.cache.split=true; f.cache.header.imagesCount=0;
      f.cache.splitOffset=offsetof(Fixture,images); f.cache.splitCount=1; f.cache.trieIndex=0;
      assert(findInSharedCacheImage(load,"alias",&result) && !result.image);
      assert(strcmp(result.pathInCache,"canonical")==0 && (uintptr_t)result.mhInCache==0x102000);
      f.cache.trieIndex=1; assert(!findInSharedCacheImage(load,"alias",&result));
      f.cache.splitCount=0; f.cache.trieIndex=0; assert(!findInSharedCacheImage(load,"canonical",&result));
      // The index a caller records for an override: the table position, whichever route found the image.
      f.cache.header.dylibsImageArrayAddr=0; f.cache.split=false; f.cache.header.imagesCount=2;
      assert(findInSharedCacheImage(load,"second",&result) && result.cacheImageIndex==1 && strcmp(result.pathInCache,"second")==0);
      f.cache.trieIndex=1; assert(findInSharedCacheImage(load,"alias",&result) && result.cacheImageIndex==1 && strcmp(result.pathInCache,"second")==0);
      f.cache.split=true; f.cache.splitCount=2;
      assert(findInSharedCacheImage(load,"alias",&result) && result.cacheImageIndex==1 && !result.image);
      assert(!findInSharedCacheImage(load,"missing",&result) && result.cacheImageIndex==kNoCacheImageIndex);
      load.loadAddress=nullptr; assert(!findInSharedCacheImage(load,"alias",&result) && result.cacheImageIndex==kNoCacheImageIndex);
      puts("PASS actual cache alias lookup, index bounds, missing ImageArray, legacy scan and closure route");
    }
  CPP
  out,ok=Open3.capture2e('clang++','-std=c++11','-fsanitize=address,undefined',"#{dir}/test.cpp",'-o',"#{dir}/test")
  abort out unless ok.success?
  out,ok=Open3.capture2e("#{dir}/test"); puts out
  abort 'cache alias lookup regression failed' unless ok.success?
end
