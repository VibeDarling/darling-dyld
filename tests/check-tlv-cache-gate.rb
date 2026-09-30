require 'tmpdir'
require 'open3'
root=File.realpath(ARGV.fetch(0, File.expand_path('..', __dir__)))
source=File.read("#{root}/src/dyldAPIsInLibSystem.cpp")
fn=source[/extern "C" __attribute__\(\(visibility\("hidden"\)\)\) bool tlv_image_uses_cache_v2\(.*?^\}/m] or abort 'gate missing'
fn=fn.sub('extern "C" __attribute__((visibility("hidden")))','static')
header=File.read("#{root}/dyld3/shared-cache/dyld_cache_format.h")
layout=header[/struct dyld_cache_header\s*\{.*?^\};/m] or abort 'header layout missing'
Dir.mktmpdir('tlv-cache-gate-') do |d|
  File.write("#{d}/p.c", <<~C)
    #include <stdint.h>
    #include <stddef.h>
    #include <stdbool.h>
    #include <assert.h>
    #include <stdio.h>
    typedef unsigned char uuid_t[16];
    #{layout}
    struct mach_header { unsigned magic; };
    static unsigned char storage[4096] __attribute__((aligned(16)));
    static size_t extent;
    static bool available;
    static const void *_dyld_get_shared_cache_range(size_t *size) { *size=extent; return available ? storage : NULL; }
    #{fn}
    int main(void) {
      struct dyld_cache_header *h=(void*)storage;
      struct mach_header *image=(void*)(storage+2048);
      size_t prefix=offsetof(struct dyld_cache_header,sharedRegionStart);
      available=true; extent=sizeof(storage); h->mappingOffset=sizeof(*h); h->newFormatTLVs=1;
      assert(tlv_image_uses_cache_v2(image));
      h->newFormatTLVs=0; assert(!tlv_image_uses_cache_v2(image)); h->newFormatTLVs=1;
      assert(!tlv_image_uses_cache_v2((void*)((uintptr_t)storage-1)));
      assert(!tlv_image_uses_cache_v2((void*)(storage+sizeof(storage))));
      extent=prefix-1; assert(!tlv_image_uses_cache_v2(image)); extent=sizeof(storage);
      h->mappingOffset=prefix-1; assert(!tlv_image_uses_cache_v2(image)); h->mappingOffset=sizeof(*h);
      available=false; assert(!tlv_image_uses_cache_v2(image));
      puts("PASS cache TLV flag, range endpoints, short prefix and absent cache");
    }
  C
  out,status=Open3.capture2e('clang','-O2','-fsanitize=address,undefined',"#{d}/p.c",'-o',"#{d}/p")
  abort out unless status.success?
  abort 'gate failed' unless system("#{d}/p")
end
