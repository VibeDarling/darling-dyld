# Extracted normalization check; not shared-cache loading or TLV allocation.
require 'tmpdir'
require 'open3'
root=File.realpath(ARGV.fetch(0, File.expand_path('..', __dir__)))
s=File.read("#{root}/src/threadLocalVariables.c")
fn=s[/static void tlv_normalize_descriptor\(.*?^\}/m] or abort 'helper missing'
Dir.mktmpdir('tlv-normalize-') do |d|
  File.write("#{d}/p.c", <<~C)
    #include <stdint.h>
    #include <assert.h>
    #include <stdio.h>
    typedef struct { void *thunk; unsigned long key,offset; } TLVDescriptor;
    #{fn}
    int main(void) {
      TLVDescriptor modern={0, ((uint64_t)24<<32)|7, ((uint64_t)64<<32)|0xfffffff0};
      tlv_normalize_descriptor(&modern,64);
      assert(modern.offset==24 && modern.key==(((uint64_t)24<<32)|7));
      TLVDescriptor legacy={0,0,24}; tlv_normalize_descriptor(&legacy,64);
      assert(legacy.offset==24);
      TLVDescriptor mismatch={0,((uint64_t)24<<32)|7,((uint64_t)63<<32)};
      uint64_t original=mismatch.offset; tlv_normalize_descriptor(&mismatch,64);
      assert(mismatch.offset==original);
      TLVDescriptor outOfRange={0,((uint64_t)65<<32)|7,((uint64_t)64<<32)};
      original=outOfRange.offset; tlv_normalize_descriptor(&outOfRange,64);
      assert(outOfRange.offset==original);
      puts("PASS TLV v2 offset normalization, legacy preservation, size/range guards");
    }
  C
  out,status=Open3.capture2e('clang','-O2','-fsanitize=address,undefined',"#{d}/p.c",'-o',"#{d}/p")
  abort out unless status.success?
  abort 'failed' unless system("#{d}/p")
end
