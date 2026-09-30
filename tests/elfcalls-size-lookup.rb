# Test the actual lookup entry against the matching XNU getter, not a substitute.
require 'tmpdir'
require 'open3'
root=File.expand_path('..',__dir__)
xnu=File.realpath(ARGV.fetch(0))
dyld=File.read("#{root}/src/dyldAPIs.cpp")
entry=dyld.lines.find{|l|l.include?('{"__dyld_get_elfcalls_size",')} or abort 'size lookup missing'
kernel=File.read("#{xnu}/darling/src/libsystem_kernel/emulation/src/other/mach/lkm.c")
getter=kernel[/size_t elfcalls_get_size\(void\) \{.*?^\}/m] or abort 'matching XNU getter missing'
Dir.mktmpdir('elfcalls-lookup-') do |dir|
  File.write("#{dir}/probe.cpp",<<~CPP)
    #include <cstddef>
    #include <cassert>
    #include <cstring>
    #include <cstdio>
    static void *_elfcalls;
    static size_t _elfcalls_size;
    extern "C" { #{getter} }
    static const struct { const char *name; void *address; } entries[]={#{entry}};
    int main() {
      assert(!strcmp(entries[0].name,"__dyld_get_elfcalls_size"));
      auto get_size=reinterpret_cast<size_t (*)(void)>(entries[0].address);
      int token;
      _elfcalls=nullptr; _elfcalls_size=123; assert(get_size()==0);
      _elfcalls=&token; _elfcalls_size=0; assert(get_size()==0);
      _elfcalls_size=123; assert(get_size()==123);
      puts("PASS: actual dyld entry and XNU getter preserve unknown/null/sized cases");
    }
  CPP
  out,status=Open3.capture2e('clang++','-std=c++11','-fsanitize=address,undefined',"#{dir}/probe.cpp",'-o',"#{dir}/probe")
  abort out unless status.success?
  out,status=Open3.capture2e("#{dir}/probe")
  puts out
  abort 'lookup test failed' unless status.success?
end
