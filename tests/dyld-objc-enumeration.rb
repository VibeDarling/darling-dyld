# The two objc name enumerations the shared cache's libobjc imports (_dyld_for_each_objc_class and
# _dyld_for_each_objc_protocol): their saved-call rows and libdyld dispatch, the strip that lets dyld call
# libobjc's signed block, and the version-16 table walk. The walk is cut out of src/dyldAPIs.cpp and
# replayed here against hand-built tables; the block helper runs against a signed fixture. Mutants of each
# rule must fail (--probes).
# Usage: ruby tests/dyld-objc-enumeration.rb [checkout] [--probes]
require 'tmpdir'
require 'open3'

ROOT = File.realpath(ARGV.fetch(0, File.expand_path('..', __dir__)))
RUN_PROBES = ARGV.include?('--probes')

$failures = 0
def check(desc, ok, detail = nil)
  if ok
    puts "PASS #{desc}"
  else
    $failures += 1
    puts "FAIL #{desc}#{detail ? ": #{detail}" : ''}"
  end
end

APIS = File.read("#{ROOT}/src/dyldAPIs.cpp")
WRAPPERS = File.read("#{ROOT}/src/dyldAPIsInLibSystem.cpp")
CALLOUTS = File.read("#{ROOT}/dyld3/DarlingObjCCallbacks.h")
ROWS = File.read("#{ROOT}/dyld3/DarlingArm64eAdapterRows.inc")
DYLDPRIV = File.read("#{ROOT}/gen/usr/local/include/mach-o/dyld_priv.h")

# --- the interface the tables and the block helper fill ------------------------------------------
%w[__dyld_for_each_objc_class __dyld_for_each_objc_protocol].each do |name|
  impl = name.sub(/\A__/, '_')
  check("dyldAPIs.cpp exports #{name}", APIS.match?(/\{"#{name}",\s*\(void\*\)#{impl} \}/))
  check("dyld_priv.h declares #{impl} for a libobjc block", DYLDPRIV.match?(/^extern void #{impl}\(const char\* \w+,\n\s+void \(\^callback\)\(void\* \w+, bool isLoaded, bool\* stop\)\);/))
  check("#{name} is not adapted here", ROWS.match?(/\{\s*"#{name}",[^\n]*AdapterStatus::HandledElsewhere/))
end
check('libdyld sends the class enumeration to the dyld3 loader',
      WRAPPERS.match?(/if \( gUseDyld3 \)\n\s+return dyld3::_dyld_for_each_objc_class\(className, callback\);\n\n\tDYLD_NO_LOCK_THIS_BLOCK;\n\s+typedef void \(\*funcType\)\(const char\*, void \(\^\)\(void\*, bool, bool\*\)\);\n\s+static funcType __ptrauth_dyld_function_ptr p = NULL;\n\n\tif\(p == NULL\)\n\t    dyld_func_lookup_and_resign\("__dyld_for_each_objc_class", &p\);\n\tp\(className, callback\);/))
check('libdyld forwards the protocol enumeration through __dyld_for_each_objc_protocol',
      WRAPPERS.match?(/if \( gUseDyld3 \)\n\s+return dyld3::_dyld_for_each_objc_protocol\(protocolName, callback\);\n\n\tDYLD_NO_LOCK_THIS_BLOCK;\n\s+typedef void \(\*funcType\)\(const char\*, void \(\^\)\(void\*, bool, bool\*\)\);\n\s+static funcType __ptrauth_dyld_function_ptr p = NULL;\n\n\tif\(p == NULL\)\n\t    dyld_func_lookup_and_resign\("__dyld_for_each_objc_protocol", &p\);\n\tp\(protocolName, callback\);/))

# --- the text under test ------------------------------------------------------------------------
def source_span(source, from, to, origin)
  start = source.index(from) or abort "#{origin}: #{from.inspect} not found"
  stop = source.index(to, start) or abort "#{origin}: #{to.inspect} not found after #{from.inspect}"
  source[start, stop + to.length - start]
end

SIGNED_HELPERS = source_span(CALLOUTS, '#if defined(__aarch64__) || defined(__arm64__)', "\n#endif\n",
                             'dyld3/DarlingObjCCallbacks.h')
BLOCK_LAYOUT = source_span(CALLOUTS, 'struct ObjCBlockLayout {',
                           'static_assert(sizeof(ObjCBlockLayout) == 32, "block literal layout");',
                           'dyld3/DarlingObjCCallbacks.h')
ENUMERATION_CALL = source_span(CALLOUTS, 'typedef void (*ObjCEnumerationInvoke)',
                               "\n}\n", 'dyld3/DarlingObjCCallbacks.h')
WALKER = source_span(APIS, 'static void forEachObjCName(', "\n}\n", 'src/dyldAPIs.cpp')
WRAPPER_CLASS = source_span(APIS, 'void _dyld_for_each_objc_class(const char* className,', "\n}\n",
                            'src/dyldAPIs.cpp')
WRAPPER_PROTOCOL = source_span(APIS, 'void _dyld_for_each_objc_protocol(const char* protocolName,', "\n}\n",
                               'src/dyldAPIs.cpp')

STUBS = <<~'CPP'.chomp
  struct DyldSharedCache {
      alignas(16) uint8_t mapping[0x8000];  // the cache mapping the table and entry bounds are checked against
      const objc_opt::objc_opt_t* opt = nullptr;
      const objc_opt::objc_opt_t* objcOpt() const { return opt; }
      uint64_t mappedSize() const { return sizeof(mapping); }
      // Two listed mappings with the unlisted gap the split runtime leaves PROT_NONE; addresses are the
      // unslid ones forEachRegion reports.
      void forEachRegion(void (^handler)(const void*, uint64_t, uint64_t, uint32_t, uint32_t, uint64_t)) const {
          const uint64_t base = (uint64_t)(uintptr_t)mapping;
          handler(mapping, base, 0x7800, 3, 3, 0);
          handler(mapping + 0x7c00, base + 0x7c00, 0x400, 3, 3, 0);
      }
  };
  static DyldSharedCache gCacheStorage;
  // A volatile pointer the walker has to load. It models a cache the compiler cannot see into, so a
  // mutated null-table guard really dereferences null instead of being folded away with the fixture.
  static DyldSharedCache* volatile gCachePtr = &gCacheStorage;

  namespace dyld {
      static bool gLogAPIs = false;
      static void log(const char*, ...) {}
      static const void* imMemorySharedCacheHeader() { return gCachePtr; }
  }
CPP

PRELUDE = [
  '#include <cstddef>',
  '#include <cstdint>',
  '#include <cstdio>',
  '#include <cstring>',
  '#include <unistd.h>',
  '#include <sys/wait.h>',
  '',
  '#include "objc-shared-cache.h"',
  '',
  'namespace dyld3 { namespace darling {',
  SIGNED_HELPERS,
  BLOCK_LAYOUT,
  ENUMERATION_CALL,
  '} }',
  '',
  STUBS,
  '',
  WALKER,
  WRAPPER_CLASS,
  WRAPPER_PROTOCOL,
  '',
].join("\n")

DRIVER = <<~'CPP'
  using dyld3::darling::ObjCBlockLayout;
  using dyld3::darling::ObjCEnumerationInvoke;

  static int failures;

  static void expect(const char* what, bool ok)
  {
      if ( ok ) { printf("ok %s\n", what); return; }
      ++failures;
      printf("FAIL %s\n", what);
  }

  // A CPU that implements pointer authentication makes xpaci clear the top 16 bits; elsewhere it is a HINT.
  static bool pacHost()
  {
      const uint64_t probe = 0x12340000FFFFFFFFull;
      return dyld3::darling::stripSignedPointer(probe) != probe;
  }

  // libclosure's block: five words, then whatever captures the invoke reads past them.
  struct TestBlock {
      ObjCBlockLayout layout;
      const uint32_t* capture;
  };

  static unsigned gInvocations;
  static unsigned gStopOnCall;
  static const void* gInvokeBlock;
  static const void* gInvokeObject;
  static bool gInvokeLoaded;
  static void* gObjects[4];
  static bool gLoadedResults[4];

  static void testInvoke(const ObjCBlockLayout* block, void* objectPtr, bool isLoaded, bool* stop)
  {
      if ( gInvocations < 4 ) {
          gObjects[gInvocations] = objectPtr;
          gLoadedResults[gInvocations] = isLoaded;
      }
      ++gInvocations;
      gInvokeBlock = block;
      gInvokeObject = objectPtr;
      gInvokeLoaded = isLoaded;
      if ( gStopOnCall != 0 && gInvocations >= gStopOnCall )
          *stop = true;
  }

  static void resetInvocation()
  {
      gInvocations = 0;
      gStopOnCall = 0;
      gInvokeBlock = nullptr;
      gInvokeObject = nullptr;
      gInvokeLoaded = false;
      memset(gObjects, 0, sizeof(gObjects));
      memset(gLoadedResults, 0, sizeof(gLoadedResults));
  }

  static void signInvoke(TestBlock& block)
  {
      block.layout.invoke = (uint64_t)(uintptr_t)testInvoke;
      if ( pacHost() )
          block.layout.invoke = dyld3::darling::signBlockInvoke(block.layout.invoke, (uint64_t)(uintptr_t)&block.layout.invoke);
  }

  static TestBlock gBlock;
  // --- the version-16 tables ------------------------------------------------------------------
  // The fixed part is five uint32 words, a uint64 salt at 24 and scramble[256] at 32, so tab[] starts at
  // 1056: tab[mask+1] (one byte at mask 0), checkbytes[capacity], offsets[capacity],
  // objectOffsets[capacity], the uint32 duplicate count, then the duplicate entries.
  enum : uint32_t {
      kTableOffset    = 512,              // the table inside the fixture buffer
      kTab            = 1056,
      kOffsetArray    = kTab + 1 + 1,
      kObjectArray    = kOffsetArray + 4,
      kDuplicateCount = kObjectArray + 8,
      kDuplicates     = kDuplicateCount + 4,
      kName           = 0x500,
      kImages         = 0x800,            // objc_headeropt_rw_t, at an offset from the objc_opt_t itself
  };

  static uint8_t* const gFixture = gCacheStorage.mapping;

  static uint8_t* tableBase() { return gFixture + kTableOffset; }
  static void write32(uint8_t* at, uint32_t value) { memcpy(at, &value, 4); }
  static void write64(uint8_t* at, uint64_t value) { memcpy(at, &value, 8); }

  static void beginTable(const char* key)
  {
      memset(gFixture, 0, sizeof(gCacheStorage.mapping));
      uint8_t* table = tableBase();
      write32(table + 0, 16);            // version
      write32(table + 4, 1);             // capacity
      write32(table + 8, 1);             // occupied
      write32(table + 12, 64);           // shift: hash() then takes only its scramble term
      write32(table + 16, 0);            // mask
      write64(table + 24, 0);            // salt
      // One slot, scramble[0] = 0 and tab[0] = 0, so every key hashes to the single entry; a key the
      // table does not hold is rejected by its check byte, as in a real table where no index leaves
      // the arrays.
      uint8_t* tab = table + kTab;
      tab[0] = 0;
      tab[1] = (uint8_t)(((key[0] & 0x7) << 5) | ((uint8_t)strlen(key) & 0x1f));
      write32(table + kOffsetArray, (uint32_t)kName);
      strcpy((char*)table + kName, key);
  }

  // ObjectData is isDuplicate:1, objectCacheOffset:47, dylibObjCIndex:16 from the low bit up.
  static void setObject(uint64_t objectOffset, uint16_t imageIndex)
  {
      write64(tableBase() + kObjectArray, ((uint64_t)imageIndex << 48) | (objectOffset << 1));
  }

  // Duplicate is isDuplicate:1, index:47, count:16.
  static void setDuplicate(uint32_t count, uint32_t index)
  {
      write64(tableBase() + kObjectArray, ((uint64_t)count << 48) | ((uint64_t)index << 1) | 1);
      write32(tableBase() + kDuplicateCount, count);
  }

  static void setDuplicateEntry(uint32_t slot, uint64_t objectOffset, uint16_t imageIndex)
  {
      write64(tableBase() + kDuplicates + 8 * slot, ((uint64_t)imageIndex << 48) | (objectOffset << 1));
  }

  // objc_headeropt_rw_t: count, entsize, then one header_info_rw word per image whose low bit is that
  // image's loaded bit. objc_opt_t's offset leads from the fixture base, like the class table's does.
  static void setImages(uint32_t count)
  {
      uint8_t* images = gFixture + kImages;
      write32(images + 0, count);
      write32(images + 4, 8);
  }

  static void setImageLoaded(uint32_t imageIndex, bool loaded)
  {
      write64(gFixture + kImages + 8 + 8 * imageIndex, loaded ? 1 : 0);
  }

  static void useFixtureTable(int32_t classOffset, int32_t protocolOffset, int32_t imagesOffset = kImages)
  {
      objc_opt::objc_opt_t* opt = (objc_opt::objc_opt_t*)gFixture;
      opt->largeSharedCachesClassOffset = classOffset;
      opt->largeSharedCachesProtocolOffset = protocolOffset;
      opt->headeropt_rw_offset = imagesOffset;
      gCachePtr->opt = opt;
  }

  // Through a volatile pointer, so the walker stays a real call: with the fixture's values inlined into
  // one function the optimizer may fold a mutated null-table guard away instead of dereferencing.
  static void (* volatile gClassEnumeration)(const char*, void (^)(void*, bool, bool*)) = _dyld_for_each_objc_class;
  static void (* volatile gProtocolEnumeration)(const char*, void (^)(void*, bool, bool*)) = _dyld_for_each_objc_protocol;

  static void enumerateClass(const char* name)
  {
      gClassEnumeration(name, (void (^)(void*, bool, bool*))&gBlock);
  }

  static void enumerateProtocol(const char* name)
  {
      gProtocolEnumeration(name, (void (^)(void*, bool, bool*))&gBlock);
  }

  static void testWalker()
  {
      const uintptr_t cacheBase = (uintptr_t)gCachePtr;
      uintptr_t expected = 0;

      beginTable("NSObject");
      setObject(0x1234, 2);
      setImages(8);
      setImageLoaded(2, true);
      useFixtureTable(kTableOffset, 0);
      resetInvocation();
      enumerateClass("NSObject");
      expect("a class is one call", gInvocations == 1);
      expected = cacheBase + 0x1234;
      expect("the pointer is the cache base plus the entry's offset", (uintptr_t)gInvokeObject == expected);
      expect("the entry reports its image loaded", gInvokeLoaded);
      expect("libobjc's own block is the one called", gInvokeBlock == (const void*)&gBlock);
  }

  int main()
  {
      gBlock.layout.isa = (void*)(uintptr_t)0xDEADBEEFDEADBEEFull;
      gBlock.layout.flags = 0;
      gBlock.capture = nullptr;
      signInvoke(gBlock);

      testWalker();
      if ( failures != 0 ) {
          printf("%d failures\n", failures);
          return 1;
      }
      printf("all enumeration cases pass\n");
      return 0;
  }
CPP

def build_and_run(dir, source, header = nil)
  exe = "#{dir}/objc_enumeration_test"
  File.write("#{dir}/test.cpp", source)
  # A probe of the table walk mutates a copy of the header the source includes, next to test.cpp; the
  # prerequisite puts it there, so no earlier probe's mutation can leak into a later build.
  File.write("#{dir}/objc-shared-cache.h", header || TABLE_HEADER)
  # The signed-helper region is pasted in rather than included, so the callback authenticator it also
  # carries counts as an unused static function here; in the real build the header keeps it quiet.
  out, status = Open3.capture2e('clang++', '-std=c++17', '-O1', '-fblocks', '-Wall', '-Werror',
                                '-Wno-unused-function',
                                "-I#{ROOT}/include", '-o', exe, "#{dir}/test.cpp")
  return [false, "build failed:\n#{out}"] unless status.success?
  out, status = Open3.capture2e(exe)
  [status.success?, out]
end

SOURCE = PRELUDE + DRIVER
TABLE_HEADER = File.read("#{ROOT}/include/objc-shared-cache.h")

Dir.mktmpdir('dyld-objc-enumeration-') do |dir|
  ok, out = build_and_run(dir, SOURCE)
  puts out
  check('enumeration replay', ok, out)
  # The helper says at runtime whether the CPU authenticates; the strip test needs that, not the text.
  pac_host = ok && !out.include?('skip a direct call through the signed invoke faults')
  next unless RUN_PROBES

  probes = [
    # [description, text to replace, replacement, only where the CPU has pointer authentication]
    ['the caller\'s own block is passed on',
     '((ObjCEnumerationInvoke)(uintptr_t)stripSignedPointer(block->invoke))(block, objectPtr, isLoaded, stop);',
     "ObjCBlockLayout copy = *block;\n\t((ObjCEnumerationInvoke)(uintptr_t)stripSignedPointer(copy.invoke))(&copy, objectPtr, isLoaded, stop);", false],
    ['the loaded bit is not a constant false',
     'bool isLoaded = images->isLoaded(dylibObjCIndex);',
     'bool isLoaded = (images->isLoaded(dylibObjCIndex), false);', false],
    ['the loaded bit is the entry\'s own image', 'bool isLoaded = images->isLoaded(dylibObjCIndex);',
     'bool isLoaded = images->isLoaded(0);', false],
    ['the entry offset is added to the cache base',
     '(void*)(cacheBase + objectCacheOffset)', '(void*)(cacheBase - objectCacheOffset)', false],
    ['the class walk reads the class table', 'const objc::ClassHashTable* table = opt->classOpt();',
     'const objc::ClassHashTable* table = (const objc::ClassHashTable*)opt->protocolOpt();', false],
    ['the class wrapper asks for classes', 'forEachObjCName(className, callback, false);',
     'forEachObjCName(className, callback, true);', false],
  ]
  probes.each do |name, from, to, pac_only|
    if SOURCE.include?(from)
      text = SOURCE.sub(from, to)
      header = nil
    elsif TABLE_HEADER.include?(from)
      text = SOURCE
      header = TABLE_HEADER.sub(from, to)
    else
      abort "probe text not found: #{name}"
    end
    if pac_only && !pac_host
      puts "skip  #{name} (this CPU does not authenticate pointers)"
      next
    end
    ok, out = build_and_run(dir, text, header)
    if out.start_with?('build failed')
      abort "probe does not compile: #{name}\n#{out}"
    elsif ok
      $failures += 1
      puts "SURVIVED #{name}"
    else
      puts "killed   #{name}"
    end
  end
end

abort 'tests failed' if $failures != 0
