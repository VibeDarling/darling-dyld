# The cache policy file (DYLD_SHARED_CACHE_SPLIT_POLICY): the actual loadSplitCachePolicy and its parser from
# dyld3/SharedCacheRuntime.cpp, run on real files. Every refusal must leave the allow-list as it was, and the built-in
# libz list must be what applies until a policy loads. No Apple bytes: the files are synthetic.
# Usage: ruby tests/split-cache-policy.rb [checkout]
require 'tmpdir'
require 'open3'
root = File.realpath(ARGV.fetch(0, File.expand_path('..', __dir__)))
source = File.read("#{root}/dyld3/SharedCacheRuntime.cpp")
header = File.read("#{root}/dyld3/SharedCacheRuntime.h")
preadall = source[/^static bool preadAll\(.*?^\}/m] or abort 'preadAll missing'
allow = source[/^static const char\* const kSharedCacheServedOverDisk\[\].*?^bool pathIsPinnedToSharedCache\(.*?^\}/m] or abort 'allow-list code missing'
policy = source[/^\/\/ ---- the cache policy file \(DYLD_SHARED_CACHE_SPLIT_POLICY\) ----.*?^const char\* loadSplitCachePolicy\(.*?^\}/m] or abort 'policy loader missing'
decls = (header[/^static const uint32_t kNoCacheImageIndex.*?^\};/m] or abort 'results struct missing') + "\n" +
        (header[/^enum SharedCacheLoadSource.*?^bool pathIsPinnedToSharedCache\(.*?;/m] or abort 'allow-list declarations missing') + "\n" +
        (header[/^const char\* loadSplitCachePolicy\(.*?;/m] or abort 'loader declaration missing')

# name => file content; every one must be refused (the line is the 1-based line the reason is on, 0 when not about a line)
HEADER = "darling-dyld-cache-policy 1\n"
def names(count, prefix = '/n')
  (0...count).map { |i| format("#{prefix}%04d\n", i) }.join
end
REFUSED = {
  'empty file' => ['', 0],
  'no header, only a name' => ["/usr/lib/libz.1.dylib\n", 1],
  'header version 2' => ["darling-dyld-cache-policy 2\n/usr/lib/libz.1.dylib\n", 1],
  'header without version' => ["darling-dyld-cache-policy\n", 1],
  'header trailing space' => ["darling-dyld-cache-policy 1 \n", 1],
  'header with another case' => ["Darling-Dyld-Cache-Policy 1\n", 1],
  'header with a BOM' => ["\xEF\xBB\xBFdarling-dyld-cache-policy 1\n", 1],
  'header with CRLF' => ["darling-dyld-cache-policy 1\r\n", 1],
  'header without a line feed' => ["darling-dyld-cache-policy 1", 1],
  'a blank first line' => ["\n" + HEADER, 1],
  'last name without a line feed' => [HEADER + "/usr/lib/libz.1.dylib", 2],
  'empty line between names' => [HEADER + "/usr/lib/a.dylib\n\n/usr/lib/b.dylib\n", 3],
  'empty line at the end' => [HEADER + "/usr/lib/a.dylib\n\n", 3],
  'relative name' => [HEADER + "usr/lib/libz.1.dylib\n", 2],
  'dot-relative name' => [HEADER + "/usr/lib/a.dylib\n./usr/lib/b.dylib\n", 3],
  'name with leading space' => [HEADER + " /usr/lib/a.dylib\n", 2],
  'comment line' => [HEADER + "# a comment\n", 2],
  'NUL in a name' => [HEADER + "/usr/lib/a\0b.dylib\n", 2],
  'NUL as a whole line' => [HEADER + "\0\n", 2],
  'NUL in the header' => ["darling-dyld-cache-policy\0 1\n", 1],
  'CR in a name' => [HEADER + "/usr/lib/a.dylib\r\n", 2],
  'tab in a name' => [HEADER + "/usr/lib/a\tb.dylib\n", 2],
  'DEL in a name' => [HEADER + "/usr/lib/a\x7f.dylib\n", 2],
  'escape in a name' => [HEADER + "/usr/lib/a\e[0m.dylib\n", 2],
  'duplicate name' => [HEADER + "/usr/lib/a.dylib\n/usr/lib/b.dylib\n/usr/lib/a.dylib\n", 4],
  'duplicate of the first name' => [HEADER + "/usr/lib/a.dylib\n/usr/lib/a.dylib\n", 3],
  'name of 1025 bytes' => [HEADER + '/' + 'a' * 1024 + "\n", 2],
  'header and a name of 1025 bytes after a good one' => [HEADER + "/usr/lib/a.dylib\n/" + 'b' * 1024 + "\n", 3],
  '4097 names' => [HEADER + names(4097), 4098],
  'file over 256 KiB' => [HEADER + (1..255).map { |i| "/#{i.to_s.rjust(3, '0')}#{'a' * 1020}\n" }.join + '/' + 'z' * 740 + "\n", 0],
}

# every one must be accepted, with these names in this order
ACCEPTED = {
  'zero names' => [HEADER, []],
  'one name' => [HEADER + "/usr/lib/libz.1.dylib\n", ['/usr/lib/libz.1.dylib']],
  'two names, order kept' => [HEADER + "/usr/lib/libz.1.dylib\n/usr/lib/libbz2.1.0.dylib\n", ['/usr/lib/libz.1.dylib', '/usr/lib/libbz2.1.0.dylib']],
  'a name with a space and UTF-8' => [HEADER + "/Library/A B/café.dylib\n", ["/Library/A B/café.dylib"]],
  'names differing only in case' => [HEADER + "/usr/lib/a.dylib\n/usr/lib/A.dylib\n", ['/usr/lib/a.dylib', '/usr/lib/A.dylib']],
  'a name that is a prefix of another' => [HEADER + "/usr/lib/a\n/usr/lib/ab\n", ['/usr/lib/a', '/usr/lib/ab']],
  'a name of 1024 bytes' => [HEADER + '/' + 'a' * 1023 + "\n", ['/' + 'a' * 1023]],
  '4096 names' => [HEADER + names(4096), (0...4096).map { |i| format('/n%04d', i) }],
}

Dir.mktmpdir('split-cache-policy-') do |dir|
  # exactly 256 KiB: the header, 255 names of 1024 bytes and one of 740
  big = HEADER + (1..255).map { |i| "/#{i.to_s.rjust(3, '0')}#{'a' * 1020}\n" }.join + '/' + 'z' * 739 + "\n"
  abort "the 256 KiB fixture is #{big.bytesize} bytes" unless big.bytesize == 256 * 1024
  ACCEPTED['a file of exactly 256 KiB'] = [big, big.lines.drop(1).map(&:chomp)]
  over = REFUSED['file over 256 KiB'][0]
  abort "the oversize fixture is #{over.bytesize} bytes" unless over.bytesize == 256 * 1024 + 1

  files = {}
  (REFUSED.merge(ACCEPTED.transform_values { |content, _| [content, 0] })).each_with_index do |(name, (content, _)), i|
    path = "#{dir}/f#{i}"
    File.binwrite(path, content)
    files[name] = path
  end
  File.write("#{dir}/emptydir_marker", '')
  Dir.mkdir("#{dir}/adir")
  File.symlink("#{dir}/f#{REFUSED.size}", "#{dir}/link") rescue nil

  def cpp_string(s) = '"' + s.bytes.map { |b| format('\\x%02x', b) }.join + '"'
  refused = REFUSED.map { |name, (_, line)| "{ #{cpp_string(name)}, #{cpp_string(files[name])}, #{line} }" }.join(",\n        ")
  accepted = ACCEPTED.map do |name, (_, list)|
    "{ #{cpp_string(name)}, #{cpp_string(files[name])}, { #{list.map { |n| cpp_string(n) }.join(', ')} } }"
  end.join(",\n        ")

  File.write("#{dir}/test.cpp", <<~CPP)
    #include <stdint.h>
    #include <stddef.h>
    #include <stdlib.h>
    #include <string.h>
    #include <unistd.h>
    #include <fcntl.h>
    #include <sys/stat.h>
    #include <stdio.h>
    #include <string>
    #include <vector>
    #define TARGET_OS_IPHONE 0
    struct mach_header {};
    namespace dyld3 {
    namespace closure { struct Image {}; }
    struct DyldSharedCache { bool isSplitCache() const { return true; } };
    struct SharedCacheLoadInfo { const DyldSharedCache *loadAddress; long slide; };
    static int open(const char *path, int flags, int mode) { return ::open(path, flags, mode); }
    #{decls}
    bool findInSharedCacheImage(const SharedCacheLoadInfo&, const char*, SharedCacheFindDylibResults*) { return false; }
    #{preadall}
    #{allow}
    #{policy}
    } // namespace dyld3
    using namespace dyld3;

    static int failures = 0;
    #define CHECK(cond) do { if (!(cond)) { printf("FAIL line %d: %s\\n", __LINE__, #cond); ++failures; } } while (0)
    static const SharedCacheLoadSource C = kSharedCacheLoadFromCache, D = kSharedCacheLoadFromDisk;
    static const char* kLibz = "/usr/lib/libz.1.dylib";
    static const char* kExpat = "/usr/lib/libexpat.1.dylib";

    static std::vector<std::string> current() {
      const SharedCacheAllowList& l = sharedCacheAllowList();
      std::vector<std::string> v; for (size_t i = 0; i != l.count; ++i) v.push_back(l.paths[i]); return v;
    }
    struct Refused { const char* name; const char* path; size_t line; };
    struct Accepted { const char* name; const char* path; std::vector<std::string> names; };

    int main() {
      const std::vector<std::string> builtin = { kLibz, kExpat };
      // before any policy (the variable unset): the built-in list, libz and libexpat; a policy does not extend it
      CHECK(current() == builtin);
      CHECK(chooseSharedCacheLoadSource(true, true, true, kExpat, sharedCacheAllowList()) == C);
      CHECK(chooseSharedCacheLoadSource(true, true, true, kLibz, sharedCacheAllowList()) == C);

      static const Refused refused[] = {
        #{refused}
      };
      for (const Refused& r : refused) {
        size_t line = 12345;
        const char* error = loadSplitCachePolicy(r.path, &line);
        if (error == nullptr) printf("not refused: %s\\n", r.name);
        CHECK(error != nullptr);
        if (error != nullptr && line != r.line) printf("%s: reported line %zu, expected %zu (%s)\\n", r.name, line, r.line, error);
        CHECK(line == r.line);
        CHECK(current() == builtin);   // never a half-read or broader list
        CHECK(chooseSharedCacheLoadSource(true, true, true, "/usr/lib/a.dylib", sharedCacheAllowList()) == D);
      }

      // the file itself: missing, a directory, a path that is not absolute, empty
      size_t line = 99;
      const char* error;
      error = loadSplitCachePolicy("#{dir}/does-not-exist", &line);  CHECK(error && strstr(error, "opened") && line == 0 && current() == builtin);
      error = loadSplitCachePolicy("#{dir}/adir", &line);            CHECK(error && current() == builtin);
      error = loadSplitCachePolicy("policy", &line);                 CHECK(error && strstr(error, "absolute") && current() == builtin);
      error = loadSplitCachePolicy("./#{dir}/f0", &line);            CHECK(error && strstr(error, "absolute") && current() == builtin);
      error = loadSplitCachePolicy("", &line);                       CHECK(error && strstr(error, "absolute") && current() == builtin);
      error = loadSplitCachePolicy("/dev/null", &line);              CHECK(error && current() == builtin);   // a device, not a policy

      static const Accepted accepted[] = {
        #{accepted}
      };
      for (const Accepted& a : accepted) {
        line = 99;
        error = loadSplitCachePolicy(a.path, &line);
        if (error != nullptr) printf("refused: %s: %s (line %zu)\\n", a.name, error, line);
        CHECK(error == nullptr);
        CHECK(current() == a.names);
      }

      // a refusal after a good policy keeps the good policy
      loadSplitCachePolicy(accepted[1].path, &line);
      CHECK(current() == accepted[1].names);
      error = loadSplitCachePolicy(refused[0].path, &line);
      CHECK(error != nullptr && current() == accepted[1].names);

      // what a policy changes: it replaces the built-in libz list instead of adding to it
      std::string foo = "/usr/lib/libfoo.dylib";
      static char fooPolicy[] = "#{dir}/foo.policy";
      FILE* f = fopen(fooPolicy, "w"); fputs("darling-dyld-cache-policy 1\\n/usr/lib/libfoo.dylib\\n", f); fclose(f);
      CHECK(loadSplitCachePolicy(fooPolicy, &line) == nullptr);
      CHECK(chooseSharedCacheLoadSource(true, true, true, foo.c_str(), sharedCacheAllowList()) == C);
      CHECK(chooseSharedCacheLoadSource(true, true, true, kLibz, sharedCacheAllowList()) == D);
      // an empty policy serves nothing over a disk copy, whatever it was before
      CHECK(loadSplitCachePolicy(accepted[0].path, &line) == nullptr);
      CHECK(sharedCacheAllowList().count == 0);
      CHECK(chooseSharedCacheLoadSource(true, true, true, foo.c_str(), sharedCacheAllowList()) == D);
      CHECK(chooseSharedCacheLoadSource(true, true, true, kLibz, sharedCacheAllowList()) == D);
      CHECK(chooseSharedCacheLoadSource(true, true, false, kLibz, sharedCacheAllowList()) == C);   // a cache-only path is still served

      if (failures) { printf("%d failure(s)\\n", failures); return 1; }
      printf("PASS policy file: %zu refusals, %zu accepted shapes, the list is replaced only by a whole valid file\\n",
             sizeof(refused)/sizeof(refused[0]), sizeof(accepted)/sizeof(accepted[0]));
      return 0;
    }
  CPP
  out, st = Open3.capture2e('clang++', '-std=c++17', '-fblocks', '-fsanitize=address,undefined', '-Wno-everything', "#{dir}/test.cpp", '-o', "#{dir}/test")
  abort out unless st.success?
  # dyld loads the policy once and keeps it for the life of the process; the test loads many, so it does not check for leaks
  out, st = Open3.capture2e({ 'ASAN_OPTIONS' => 'detect_leaks=0' }, "#{dir}/test")
  puts out
  abort 'split cache policy test failed' unless st.success?
end
