# Compile the production cache veneer generator and execute its output on ARM64.
require 'tmpdir'
require 'open3'
root=File.realpath(ARGV.fetch(0))
source=File.read("#{root}/dyld3/SharedCacheRuntime.cpp")
helper=source[/class DarlingTSDReadVeneers \{.*?^\};/m] or abort 'veneer generator missing'
mapper=source[/static bool translateDarlingCacheTSD\(.*?^\}/m] or abort 'cache translator missing'
Dir.mktmpdir('arm64-tsd-veneers-') do |dir|
 File.write("#{dir}/test.cpp", <<~CPP)
 #include <stdint.h>
 #include <stddef.h>
 #include <sys/mman.h>
 #include <assert.h>
 #include <pthread.h>
 #include <signal.h>
 #include <ucontext.h>
 #include <stdio.h>
 static void sys_icache_invalidate(void* p,size_t n) { __builtin___clear_cache((char*)p,(char*)p+n); }
 #{helper}
 static thread_local void* slot;
 static thread_local unsigned long value;
 static thread_local unsigned traps;
 static void handler(int sig,siginfo_t* info,void* opaque) {
   auto* ctx=(ucontext_t*)opaque;
   uint32_t instruction=*(uint32_t*)ctx->uc_mcontext.pc;
   assert(sig==SIGILL && info->si_code>0 && (instruction&~31U)==0xda00);
   unsigned reg=instruction&31;
   if(reg!=31) ctx->uc_mcontext.regs[reg]=(uintptr_t)&value;
   ctx->uc_mcontext.pc+=4; ++traps;
 }
 static void* (*read_slot)();
 static unsigned long offset;
 enum { VM_PROT_READ=1, VM_PROT_WRITE=2, VM_PROT_EXECUTE=4 };
 struct TestMapping { uintptr_t sms_address; size_t sms_size; unsigned sms_init_prot; };
 struct CacheInfo { TestMapping mappings[2]; unsigned mappingsCount; };
 static unsigned long sys_thread_get_native_tsd_slot_offset() { return offset; }
 #{mapper}
 static void* worker(void* argument) {
   assert((uintptr_t)&slot-(uintptr_t)__builtin_thread_pointer()==offset);
   value=(uintptr_t)argument;
   slot=nullptr;
   assert(read_slot()==&value && traps==1);
   slot=&value;
   for(unsigned i=0;i<100000;++i) assert(read_slot()==&value);
   assert(traps==1 && value==(uintptr_t)argument);
   return nullptr;
 }
 int main() {
   uintptr_t start=0x180000000ULL;
   uint32_t* original=(uint32_t*)mmap((void*)start,4096,PROT_READ|PROT_WRITE,MAP_PRIVATE|MAP_ANON|MAP_FIXED_NOREPLACE,-1,0);
   assert(original==(void*)start);
   offset=(uintptr_t)&slot-(uintptr_t)__builtin_thread_pointer();
   assert(offset>=16 && offset<=32760 && !(offset&7));
   { DarlingTSDReadVeneers invalid(start,~0UL); assert(invalid.translate(9,start)==0xda09); }
   void* occupied=mmap((void*)(start-1024*1024),1024*1024,PROT_READ|PROT_WRITE,MAP_PRIVATE|MAP_ANON|MAP_FIXED_NOREPLACE,-1,0);
   assert(occupied==(void*)(start-1024*1024)); *(unsigned*)occupied=0x12345678;
   { DarlingTSDReadVeneers blocked(start,offset); assert(blocked.translate(9,start)==0xda09); assert(*(unsigned*)occupied==0x12345678); }
   munmap(occupied,1024*1024);
   DarlingTSDReadVeneers veneers(start,offset);
   assert(veneers.translate(31,start)==0xd503201f);
   assert(veneers.translate(9,start+0x10000000)==0xda09);
   original[0]=veneers.translate(9,start);
   assert((original[0]&0xfc000000)==0x14000000);
   original[1]=0xaa0903e0; // mov x0,x9
   original[2]=0xd65f03c0; // ret
   assert(veneers.count()==1 && veneers.finish());
   sys_icache_invalidate(original,12); assert(mprotect(original,4096,PROT_READ|PROT_EXEC)==0);
   read_slot=(void*(*)())original;
   struct sigaction action{}; action.sa_sigaction=handler; action.sa_flags=SA_SIGINFO; sigemptyset(&action.sa_mask); assert(sigaction(SIGILL,&action,nullptr)==0);
   pthread_t threads[4];
   for(uintptr_t i=0;i<4;++i) assert(pthread_create(&threads[i],nullptr,worker,(void*)(i+1))==0);
   for(auto t:threads) assert(pthread_join(t,nullptr)==0);
   uintptr_t cacheStart=0x190000000ULL;
   auto* cache=(uint32_t*)mmap((void*)cacheStart,8192,PROT_READ|PROT_WRITE,MAP_PRIVATE|MAP_ANON|MAP_FIXED_NOREPLACE,-1,0);
   assert(cache==(void*)cacheStart);
   cache[0]=0xd53bd069; // data that resembles an instruction must remain intact
   uint32_t* text=cache+1024;
   text[0]=0xd53bd069; text[1]=0xaa0903e0; text[2]=0xd65f03c0;
   text[8]=0xd53bd06a; text[9]=0xd34cfc00 | (10<<5) | 10;
   text[12]=0xd53bd07f;
   assert(mprotect(text,4096,PROT_READ|PROT_EXEC)==0);
   CacheInfo info{{{cacheStart,4096,VM_PROT_READ|VM_PROT_WRITE},{cacheStart+4096,4096,VM_PROT_READ|VM_PROT_EXECUTE}},2};
   const char* error=nullptr;
   assert(translateDarlingCacheTSD(info,&error) && !error);
   assert(cache[0]==0xd53bd069 && text[8]==(0xaa1f03e0|10) && text[12]==0xd503201f);
   slot=&value; assert(((void*(*)())text)()==&value);
   CacheInfo invalid{{{0,4096,VM_PROT_READ|VM_PROT_EXECUTE},{0,0,0}},1};
   assert(!translateDarlingCacheTSD(invalid,&error) && error);
   puts("PASS actual cache mapping translation, non-executable data, CPU-index reads, XZR and protection failure");
   puts("PASS production veneers: 400000 native-slot reads, per-thread null fallback, invalid metadata, branch range and occupied mapping");
 }
 CPP
 out,status=Open3.capture2e('c++','-std=c++11','-O2','-pthread',"#{dir}/test.cpp",'-o',"#{dir}/test")
 abort out unless status.success?
 out,status=Open3.capture2e("#{dir}/test"); puts out; abort 'veneer test failed' unless status.success?
end
