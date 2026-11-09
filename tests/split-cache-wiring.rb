# The pieces dyld uses to wire a split macOS cache into a process (DYLD_SHARED_CACHE_SPLIT_DIR): the cache
# file name derived from the main executable's architecture, the directory validation and the main file
# path. Each check runs the real function extracted from dyld3/SharedCacheRuntime.cpp.
# Usage: ruby tests/split-cache-wiring.rb [checkout]
require 'tmpdir'
require 'open3'
root = File.realpath(ARGV.fetch(0, File.expand_path('..', __dir__)))
runtime = File.read("#{root}/dyld3/SharedCacheRuntime.cpp")
runtime_h = File.read("#{root}/dyld3/SharedCacheRuntime.h")

def run_cpp(dir, name, source, root)
  File.write("#{dir}/#{name}.cpp", source)
  out, ok = Open3.capture2e('clang++', '-std=c++17', '-fblocks', '-fsanitize=address,undefined', '-Wno-everything',
                            "-I#{root}/dyld3/shared-cache", "#{dir}/#{name}.cpp", '-o', "#{dir}/#{name}")
  abort out unless ok.success?
  out, ok = Open3.capture2e("#{dir}/#{name}")
  puts out
  abort "split cache wiring test #{name} failed" unless ok.success?
end

COMMON = <<~CPP
  #include <stdint.h>
  #include <stddef.h>
  #include <stdio.h>
  #include <stdlib.h>
  #include <string.h>
  #include <string>
  #define DARLING 1
  #define TARGET_OS_SIMULATOR 0
  #if !__GLIBC_PREREQ(2, 38)
  static size_t strlcpy(char *d, const char *s, size_t n) { size_t l=strlen(s); if (n) { size_t c=l<n-1?l:n-1; memcpy(d,s,c); d[c]=0; } return l; }
  static size_t strlcat(char *d, const char *s, size_t n) { size_t dl=strnlen(d,n); if (dl==n) return n+strlen(s); return dl+strlcpy(d+dl,s,n-dl); }
  #endif
  static int failures = 0;
  #define CHECK(cond) do { if (!(cond)) { printf("FAIL line %d: %s\\n", __LINE__, #cond); ++failures; } } while (0)
CPP

names_src = (runtime[/^\/\/ The longest directory accepted.*?^const char\* splitCacheMainFilePath\(.*?^\}/m] or abort 'name helpers missing')
decls = %w[splitCacheArchName splitCacheDirError splitCacheMainFilePath].map { |n| runtime_h[/^const char\* #{n}\(.*?;/m] }.join("\n")
abort 'name helper declarations missing' if decls.scan(/splitCache/).size != 3

Dir.mktmpdir('split-cache-wiring-') do |dir|
  run_cpp(dir, 'names', <<~CPP, root)
    #{COMMON}
    #include "dyld_cache_format.h"
    #define CPU_TYPE_ARM64 0x0100000C
    #define CPU_TYPE_ARM64_32 0x0200000C
    #define CPU_TYPE_X86_64 0x01000007
    #define CPU_TYPE_ARM 12
    #define CPU_SUBTYPE_MASK 0xff000000
    #define CPU_SUBTYPE_ARM64_ALL 0
    #define CPU_SUBTYPE_ARM64_V8 1
    #define CPU_SUBTYPE_ARM64E 2
    #{decls}
    #{names_src}

    static const char* path_for(const char* dir, uint32_t type, uint32_t sub, std::string* out) {
      char path[256]; memset(path, 'x', sizeof path);
      const char* error = splitCacheMainFilePath(dir, type, sub, path, sizeof path);
      if (!error) *out = path;
      return error;
    }

    int main() {
      // --- the name: arch of the main executable, flag bits ignored ---
      CHECK(!strcmp(splitCacheArchName(CPU_TYPE_ARM64, CPU_SUBTYPE_ARM64E), "arm64e"));
      CHECK(!strcmp(splitCacheArchName(CPU_TYPE_ARM64, 0x80000002), "arm64e"));    // pointer authentication ABI byte
      CHECK(!strcmp(splitCacheArchName(CPU_TYPE_ARM64, 0x00000002), "arm64e"));
      CHECK(!strcmp(splitCacheArchName(CPU_TYPE_ARM64, CPU_SUBTYPE_ARM64_ALL), "arm64"));
      CHECK(!strcmp(splitCacheArchName(CPU_TYPE_ARM64, CPU_SUBTYPE_ARM64_V8), "arm64"));
      CHECK(!strcmp(splitCacheArchName(CPU_TYPE_X86_64, 3), "x86_64"));
      CHECK(!strcmp(splitCacheArchName(CPU_TYPE_X86_64, 8), "x86_64"));
      CHECK(splitCacheArchName(CPU_TYPE_ARM64, 3) == nullptr);                       // an unknown arm64 subtype
      CHECK(splitCacheArchName(CPU_TYPE_ARM64, 0x80000003) == nullptr);
      CHECK(splitCacheArchName(CPU_TYPE_ARM64_32, 1) == nullptr);
      CHECK(splitCacheArchName(CPU_TYPE_ARM, 9) == nullptr);
      CHECK(splitCacheArchName(0, 0) == nullptr);

      // --- the main file path ---
      std::string p;
      CHECK(!path_for("/cache", CPU_TYPE_ARM64, 0x80000002, &p) && p == "/cache/dyld_shared_cache_arm64e");
      CHECK(!path_for("/cache/", CPU_TYPE_ARM64, CPU_SUBTYPE_ARM64E, &p) && p == "/cache/dyld_shared_cache_arm64e");
      CHECK(!path_for("/", CPU_TYPE_ARM64, CPU_SUBTYPE_ARM64E, &p) && p == "/dyld_shared_cache_arm64e");
      CHECK(!path_for("/a b/c", CPU_TYPE_ARM64, CPU_SUBTYPE_ARM64_V8, &p) && p == "/a b/c/dyld_shared_cache_arm64");
      // refusals say why, and leave nothing usable behind
      const char* e;
      e = path_for("/cache", CPU_TYPE_X86_64, 3, &p);
      CHECK(e && strstr(e, "x86_64"));
      e = path_for("/cache", CPU_TYPE_ARM64_32, 1, &p);
      CHECK(e && strstr(e, "architecture"));
      e = path_for("/cache", CPU_TYPE_ARM64, 7, &p);
      CHECK(e && strstr(e, "architecture"));
      e = path_for("relative/dir", CPU_TYPE_ARM64, CPU_SUBTYPE_ARM64E, &p);
      CHECK(e && strstr(e, "absolute"));
      // a path longer than the buffer is refused, not truncated
      char small[20];
      e = splitCacheMainFilePath("/cache", CPU_TYPE_ARM64, CPU_SUBTYPE_ARM64E, small, sizeof small);
      CHECK(e && strstr(e, "too long"));

      // --- the directory ---
      CHECK(splitCacheDirError("/cache") == nullptr);
      CHECK(splitCacheDirError("/") == nullptr);
      CHECK(splitCacheDirError("/a b/c.d") == nullptr);
      CHECK(splitCacheDirError(nullptr) != nullptr);
      CHECK(strstr(splitCacheDirError(""), "empty"));
      CHECK(strstr(splitCacheDirError("cache"), "absolute"));
      CHECK(strstr(splitCacheDirError("./cache"), "absolute"));
      CHECK(strstr(splitCacheDirError(" /cache"), "absolute"));
      CHECK(strstr(splitCacheDirError("/cache\\n"), "control"));            // trailing newline
      CHECK(strstr(splitCacheDirError("/cache\\t/x"), "control"));
      CHECK(strstr(splitCacheDirError("/cache\\x7f"), "control"));
      CHECK(strstr(splitCacheDirError("/cache\\x01"), "control"));
      // an embedded NUL ends the C string, so the value is judged by what precedes it
      CHECK(splitCacheDirError("/cache\\0junk") == nullptr);
      CHECK(strstr(splitCacheDirError("\\0/cache"), "empty"));
      // length bound: kSplitCacheDirMaxLength is accepted, one more is not, and a huge string is not read past the bound
      std::string at_limit = "/" + std::string(kSplitCacheDirMaxLength - 1, 'a');
      std::string over = at_limit + "a";
      CHECK(splitCacheDirError(at_limit.c_str()) == nullptr);
      CHECK(strstr(splitCacheDirError(over.c_str()), "too long"));
      std::string huge = "/" + std::string(1 << 20, 'a');
      CHECK(strstr(splitCacheDirError(huge.c_str()), "too long"));
      // the bound leaves room for the main file name and a sub-cache suffix in SharedCacheLoadInfo::path (256 bytes)
      CHECK(kSplitCacheDirMaxLength + 1 + strlen("dyld_shared_cache_arm64e") + strlen(".dyldlinkedit") < 256);
      CHECK(!path_for(at_limit.c_str(), CPU_TYPE_ARM64, CPU_SUBTYPE_ARM64E, &p) && p.size() < 256);

      if (failures) { printf("%d failure(s)\\n", failures); return 1; }
      puts("PASS split cache name derivation, directory validation and main file path");
      return 0;
    }
  CPP
end
