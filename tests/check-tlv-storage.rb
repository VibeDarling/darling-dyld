# Actual TLV span helper with synthetic Mach-O commands, not a cache launch.
require 'tmpdir'
require 'open3'
root=File.realpath(ARGV.fetch(0, File.expand_path('..', __dir__)))
s=File.read("#{root}/src/threadLocalVariables.c")
if ENV['TLV_SOURCE_REF']
  s,status=Open3.capture2('git','-C',root,'show',"#{ENV.fetch('TLV_SOURCE_REF')}:src/threadLocalVariables.c")
  abort 'source lookup failed' unless status.success?
end
fn=s[/static unsigned long tlv_storage_size\(.*?^\}/m] or abort 'helper missing'
Dir.mktmpdir('tlv-storage-') do |d|
  File.write("#{d}/p.c", <<~C)
    #include <stdint.h>
    #include <stdbool.h>
    #include <stdio.h>
    #include <assert.h>
    #define LC_SEGMENT_COMMAND 25
    #define SECTION_TYPE 255
    #define S_THREAD_LOCAL_REGULAR 17
    #define S_THREAD_LOCAL_ZEROFILL 18
    struct mach_header { uint32_t ncmds,sizeofcmds; };
    typedef struct mach_header macho_header;
    struct load_command { uint32_t cmd,cmdsize; };
    typedef struct { uint32_t cmd,cmdsize,nsects,pad; } macho_segment_command;
    typedef struct { uint64_t addr,size; uint32_t flags,pad; } macho_section;
    #{fn}
    int main(void) {
      /* Pack the command immediately after this deliberately minimal header. */
      unsigned char buffer[sizeof(macho_header)+sizeof(macho_segment_command)+2*sizeof(macho_section)] __attribute__((aligned(8)))={0};
      macho_header *h=(void*)buffer;
      macho_segment_command *seg=(void*)(buffer+sizeof(*h));
      seg->cmd=LC_SEGMENT_COMMAND; seg->cmdsize=sizeof(*seg)+2*sizeof(macho_section); seg->nsects=2; h->ncmds=1;
      h->sizeofcmds=seg->cmdsize;
      macho_section *sections=(void*)(seg+1);
      sections[0]=(macho_section){0x1000,16,S_THREAD_LOCAL_REGULAR,0};
      sections[1]=(macho_section){0x1020,32,S_THREAD_LOCAL_ZEROFILL,0};
      unsigned long regular=tlv_storage_size(h);
      sections[0].addr=0; sections[1].addr=32;
      unsigned long zero_based=tlv_storage_size(h);
      macho_section swap=sections[0]; sections[0]=sections[1]; sections[1]=swap;
      unsigned long reversed=tlv_storage_size(h);
      uint32_t validSize=seg->cmdsize;
      sections[0].addr=UINTPTR_MAX-15; sections[0].size=32;
      assert(tlv_storage_size(h)==0);
      sections[0]=(macho_section){32,32,S_THREAD_LOCAL_ZEROFILL,0};
      seg->nsects=3; assert(tlv_storage_size(h)==0); seg->nsects=2;
      seg->cmdsize=0; assert(tlv_storage_size(h)==0);
      seg->cmdsize=8; assert(tlv_storage_size(h)==0);
      seg->cmdsize=validSize+8; assert(tlv_storage_size(h)==0);
      seg->cmdsize=validSize-1; assert(tlv_storage_size(h)==0);
      seg->cmdsize=validSize;
      h->sizeofcmds=4; assert(tlv_storage_size(h)==0);
      h->sizeofcmds=validSize; h->ncmds=2; assert(tlv_storage_size(h)==0);
      h->ncmds=0;
      unsigned long empty=tlv_storage_size(h);
      printf("regular span=%lu zero-based span=%lu expected=64\\n",regular,zero_based);
      return regular==64 && zero_based==64 && reversed==64 && empty==0 ? 0 : 1;
    }
  C
  out,status=Open3.capture2e('clang','-O2','-fsanitize=address,undefined',"#{d}/p.c",'-o',"#{d}/p")
  abort out unless status.success?
  exit(system("#{d}/p") ? 0 : 1)
end
