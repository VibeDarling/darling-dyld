# Actual legacy allocator plus candidate v2 normalization; synthetic Mach-O,
# real pthread storage. Not execution of a shared-cache thunk or Mach-O loader.
require 'tmpdir'
require 'open3'
root=File.realpath(ARGV.fetch(0, File.expand_path('..', __dir__)))
source=File.read("#{root}/src/threadLocalVariables.c")
allocate=source[/void\* tlv_allocate_and_initialize_for_key\(.*?^\}/m]
normalize=source[/static void tlv_normalize_descriptor\(.*?^\}/m]
abort 'missing implementation' unless allocate && normalize
Dir.mktmpdir('tlv-allocation-') do |dir|
  File.write("#{dir}/test.c", <<~C)
    #include <assert.h>
    #include <stdbool.h>
    #include <stdint.h>
    #include <stdlib.h>
    #include <string.h>
    #include <stdio.h>
    #include <pthread.h>
    #define LC_SEGMENT_COMMAND 25
    #define SECTION_TYPE 255
    #define S_THREAD_LOCAL_REGULAR 17
    #define S_THREAD_LOCAL_ZEROFILL 18
    #define S_THREAD_LOCAL_INIT_FUNCTION_POINTERS 21
    struct mach_header { uint32_t ncmds, sizeofcmds; };
    typedef struct mach_header macho_header;
    struct load_command { uint32_t cmd,cmdsize; };
    typedef struct { uint32_t cmd,cmdsize,nsects,pad; uint64_t vmaddr,filesize; } macho_segment_command;
    typedef struct { uint64_t addr,size; uint32_t flags,pad; } macho_section;
    typedef struct { void *thunk; unsigned long key,offset; } TLVDescriptor;
    static const struct mach_header *image;
    static const struct mach_header *tlv_get_image_for_key(pthread_key_t key) { (void)key; return image; }
    #{allocate}
    #{normalize}
    static pthread_key_t key;
    static void *parent;
    static unsigned char expectedByte;
    static void *worker(void *unused) {
      (void)unused;
      unsigned char *value=tlv_allocate_and_initialize_for_key(key);
      assert(value && value!=parent && value[8]==expectedByte && value[32]==0);
      assert(pthread_getspecific(key)==value);
      value[8]=0x92;
      return NULL; // pthread destructor releases this thread's allocation
    }
    int main(void) {
      unsigned char bytes[1024] __attribute__((aligned(8)))={0};
      macho_header *header=(void*)bytes; image=header; header->ncmds=1;
      macho_segment_command *segment=(void*)(header+1);
      segment->cmd=LC_SEGMENT_COMMAND; segment->cmdsize=sizeof(*segment)+2*sizeof(macho_section);
      segment->nsects=2; segment->vmaddr=0; segment->filesize=sizeof bytes;
      header->sizeofcmds=segment->cmdsize;
      macho_section *sections=(void*)(segment+1);
      sections[0]=(macho_section){512,32,S_THREAD_LOCAL_REGULAR,0};
      sections[1]=(macho_section){544,32,S_THREAD_LOCAL_ZEROFILL,0};
      for(unsigned variant=0;variant<3;++variant) {
      bool allZero=variant==2;
      sections[0].flags=allZero ? S_THREAD_LOCAL_ZEROFILL : S_THREAD_LOCAL_REGULAR;
      for(unsigned i=0;i<32;++i) bytes[512+i]=allZero ? 0 : (unsigned char)(0x30+i);
      expectedByte=bytes[520];
      TLVDescriptor *descriptor=(void*)(bytes+(variant==1 ? 768 : 256));
      // Match cache builder's signed delta relative to the delta field itself.
      int32_t delta=allZero ? 0 : (int32_t)((bytes+512)-(unsigned char*)&descriptor->offset);
      *descriptor=(TLVDescriptor){0,((uint64_t)8<<32)|7,((uint64_t)64<<32)|(uint32_t)delta};
      unsigned char reference[64];
      if(delta) memcpy(reference,(unsigned char*)&descriptor->offset+delta,64);
      else memset(reference,0,64);
      tlv_normalize_descriptor(descriptor,64); assert(descriptor->offset==8);
      assert(pthread_key_create(&key,free)==0); descriptor->key=key;
      parent=tlv_allocate_and_initialize_for_key(descriptor->key);
      assert(parent && pthread_getspecific(key)==parent);
      assert(memcmp(parent,bytes+512,64)==0);
      assert(memcmp(parent,reference,64)==0);
      ((unsigned char*)parent)[descriptor->offset]=0x81;
      pthread_t thread; assert(pthread_create(&thread,NULL,worker,NULL)==0);
      assert(pthread_join(thread,NULL)==0);
      assert(((unsigned char*)parent)[8]==0x81 && bytes[520]==expectedByte);
      free(parent); assert(pthread_setspecific(key,NULL)==0); assert(pthread_key_delete(key)==0);
      }
      puts("PASS builder-shaped positive/negative/zero deltas match legacy allocation and thread isolation");
    }
  C
  output,status=Open3.capture2e('clang','-O1','-g','-pthread','-fsanitize=address,undefined',
    '-fno-sanitize-recover=all',"#{dir}/test.c",'-o',"#{dir}/test")
  abort output unless status.success?
  abort 'allocation regression' unless system("#{dir}/test")
end
