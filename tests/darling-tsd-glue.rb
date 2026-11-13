# Compiles the real translateSplitCacheTSD() (the sidecar load, UUID check, executable-range collection) out of
# dyld3/SharedCacheRuntime.cpp against small stubs and runs it on this ARM64 host, one scenario per process.
# usage: ruby tests/darling-tsd-glue.rb REPO [--probes]
require 'tmpdir'
require 'open3'

root = File.realpath(ARGV.fetch(0))
abort 'needs an ARM64 host' unless RbConfig::CONFIG['host_cpu'] =~ /aarch64|arm64/
PROBES = [
  ['UUID not compared', 'memcmp(sSplitTSD.table.uuid(), cache.loadAddress->header.uuid, sizeof(cache.loadAddress->header.uuid)) != 0', 'false'],
  ['non-executable mappings are executable ranges', 'if ( (initProt & VM_PROT_EXECUTE) == 0 )', 'if ( false )'],
  ['no executable range given', 'sSplitTSD.patcher->init(ranges, rangeCount)', 'sSplitTSD.patcher->init(ranges, 0)'],
  ['sidecar named differently', '".tsdsites"', '".tsdsitez"'],
  ['cache base is not the header address', '(uintptr_t)cache.loadAddress, sys_thread_get', '(uintptr_t)cache.loadAddress + 0x4000, sys_thread_get'],
  ['translation state never kept', "        sSplitTSD.ready = true;\n", ""],
].freeze

def run_all(root, source)
  pread = source[/^static bool preadAll\(.*?^\}/m] or abort 'preadAll missing'
  glue = source[/^#if defined\(__arm64__\)\n\/\/ The sidecar table, its patcher.*?^\}\n(?=#endif)/m] or abort 'glue missing'
  failures = 0
  Dir.mktmpdir('darling-tsd-glue-') do |dir|
  File.write("#{dir}/test.cpp", <<~CPP)
    #include <stdint.h>
    #include <stdio.h>
    #include <stdlib.h>
    #include <string.h>
    #include <errno.h>
    #include <fcntl.h>
    #include <unistd.h>
    #include <sys/stat.h>
    #include "test_support.h"
    #define VM_PROT_EXECUTE 4
    #define __arm64__ 1
    #if !__GLIBC_PREREQ(2, 38)
    static size_t strlcpy(char *d, const char *s, size_t n) { size_t l=strlen(s); if (n) { size_t c=l<n-1?l:n-1; memcpy(d,s,c); d[c]=0; } return l; }
    static size_t strlcat(char *d, const char *s, size_t n) { size_t dl=strnlen(d,n); if (dl==n) return n+strlen(s); return dl+strlcpy(d+dl,s,n-dl); }
    #endif
    extern "C" { void *_NSConcreteStackBlock[32]; void *_NSConcreteGlobalBlock[32];
                 void _Block_object_assign(void*, const void*, const int) {}
                 void _Block_object_dispose(const void*, const int) {} }
    static unsigned long gSlot;
    extern "C" unsigned long sys_thread_get_native_tsd_slot_offset(void) { return gSlot; }
    struct mach_header;
    namespace dyld3 {
    // two mappings: the header page, read-only, and the executable page after it
    struct DyldSharedCache {
      struct { uint8_t uuid[16]; } header;
      void forEachRegion(void (^handler)(const void*, uint64_t, uint64_t, uint32_t, uint32_t, uint64_t)) const {
        handler(this, (uint64_t)(uintptr_t)this, 0x4000, 1, 1, 0);
        handler((const void*)((uintptr_t)this + 0x4000), (uint64_t)(uintptr_t)this + 0x4000, (uint64_t)sysconf(_SC_PAGESIZE), 5, 5, 0);
      }
    };
    struct SharedCacheLoadInfo { const DyldSharedCache* loadAddress; long slide; const char* errorMessage; char path[256]; };
    #{pread}
    #{glue}#endif
    }
    #{File.read("#{root}/tests/darling-tsd/glue_check.cpp")}
  CPP
  out, status = Open3.capture2e('clang++', '-std=c++17', '-fblocks', '-O1', '-Wall', '-I', "#{root}/dyld3", '-I', "#{root}/tests/darling-tsd",
                                "#{dir}/test.cpp", "#{root}/dyld3/DarlingTSDIslands.cpp", "#{root}/tests/darling-tsd/oracle.S", '-lpthread', '-o', "#{dir}/test")
  return [1, out] unless status.success?
  %w[missing uuid truncated unlisted gap-in-data ok].each do |scenario|
    Dir.mktmpdir('scratch', dir) do |scratch|
      out, status = Open3.capture2e('timeout', '30', "#{dir}/test", scenario, scratch)
      puts out if $verbose
      failures += 1 unless status.success? && out.include?("PASS #{scenario}")
    end
  end
  end
  [failures, nil]
end

$verbose = true
source = File.read("#{root}/dyld3/SharedCacheRuntime.cpp")
failures, out = run_all(root, source)
abort(out || "#{failures} scenario(s) failed") unless failures.zero?
if ARGV.include?('--probes')
  $verbose = false
  killed = 0
  PROBES.each do |name, from, to|
    abort "probe text not found: #{name}" unless source.include?(from)
    failures, = run_all(root, source.sub(from) { to })
    puts "#{failures.zero? ? 'SURVIVED' : 'killed  '} #{name}"
    killed += 1 unless failures.zero?
  end
  puts "#{killed}/#{PROBES.size} probes killed"
  abort 'a probe survived' unless killed == PROBES.size
end
