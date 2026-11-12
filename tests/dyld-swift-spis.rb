# The eight dyld SPIs that the shared cache's libswiftCore imports from libdyld and that Darling did not export
# (__dyld_swift_optimizations_version, __dyld_has_preoptimized_swift_protocol_conformances, __dyld_find_protocol_conformance,
# __dyld_find_foreign_type_protocol_conformance, the two _on_disk variants, __dyld_find_pointer_hash_table_entry and
# __dyld_is_preoptimized_objc_image_loaded). A missing export leaves the cache's GOT slot on the cache's own libdyld code,
# which crashed in a guest. This test cuts the declarations out of dyld_priv.h and the definitions out of
# src/dyldAPIsInLibSystem.cpp, checks the dyld4 prototypes, builds them as an arm64 Mach-O object and checks every symbol is
# exported (visible, C linkage), and runs them natively: version 0, {not_found, NULL} from every find_*, false and NULL otherwise.
# Mutants of the definitions and of the exports must each fail.
# Usage: ruby tests/dyld-swift-spis.rb [checkout]
require 'tmpdir'
require 'open3'

ROOT = File.realpath(ARGV.fetch(0, File.expand_path('..', __dir__)))
$failures = 0
def check(desc, ok, detail = nil)
  if ok
    puts "PASS #{desc}"
  else
    $failures += 1
    puts "FAIL #{desc}#{detail ? ": #{detail}" : ''}"
  end
end

WRAPPERS = File.read("#{ROOT}/src/dyldAPIsInLibSystem.cpp")
DYLDPRIV = File.read("#{ROOT}/gen/usr/local/include/mach-o/dyld_priv.h")

# name => [Mach-O symbol, the prototype as dyld4's dyld_priv.h (/tmp/dyld-1378 lines 748-1005) spells it, without availability macros]
SPIS = {
  '_dyld_swift_optimizations_version' => 'extern uint32_t _dyld_swift_optimizations_version(void);',
  '_dyld_has_preoptimized_swift_protocol_conformances' => 'extern bool _dyld_has_preoptimized_swift_protocol_conformances(const struct mach_header* mh);',
  '_dyld_find_protocol_conformance' => "extern struct _dyld_protocol_conformance_result\n_dyld_find_protocol_conformance(const void *protocolDescriptor,\n                                const void *metadataType,\n                                const void *typeDescriptor);",
  '_dyld_find_foreign_type_protocol_conformance' => "extern struct _dyld_protocol_conformance_result\n_dyld_find_foreign_type_protocol_conformance(const void *protocol,\n                                             const char *foreignTypeIdentityStart,\n                                             size_t foreignTypeIdentityLength);",
  '_dyld_find_protocol_conformance_on_disk' => "extern struct _dyld_protocol_conformance_result\n_dyld_find_protocol_conformance_on_disk(const void *protocolDescriptor,\n                                        const void *metadataType,\n                                        const void *typeDescriptor,\n                                        uint32_t flags);",
  '_dyld_find_foreign_type_protocol_conformance_on_disk' => "extern struct _dyld_protocol_conformance_result\n_dyld_find_foreign_type_protocol_conformance_on_disk(const void *protocol,\n                                                     const char *foreignTypeIdentityStart,\n                                                     size_t foreignTypeIdentityLength,\n                                                     uint32_t flags);",
  '_dyld_find_pointer_hash_table_entry' => "extern const void *_dyld_find_pointer_hash_table_entry(const void *table,\n                                                       const void *key1,\n                                                       size_t restKeysCount,\n                                                       const void **restKeys);",
  '_dyld_is_preoptimized_objc_image_loaded' => 'extern bool _dyld_is_preoptimized_objc_image_loaded(uint16_t imageID);',
}.freeze

SPIS.each do |name, prototype|
  check("dyld_priv.h declares #{name} once, as dyld4 does", DYLDPRIV.scan(prototype).size == 1)
end
%w[DYLD_FIND_PROTOCOL_CONFORMANCE_DEFINED DYLD_FIND_PROTOCOL_ON_DISK_CONFORMANCE_DEFINED DYLD_FIND_POINTER_HASH_TABLE_ENTRY_DEFINED].each do |define|
  check("dyld_priv.h defines #{define} as 1 (Swift guards its use of the SPIs with it)", DYLDPRIV.scan(/^#define #{define} 1$/).size == 1)
end
check('the result struct is a kind then a value, and the kind enum has dyld4\'s order',
      DYLDPRIV.include?("  _dyld_protocol_conformance_result_kind_found_descriptor,\n  _dyld_protocol_conformance_result_kind_found_witness_table,\n  _dyld_protocol_conformance_result_kind_not_found,\n  _dyld_protocol_conformance_result_kind_definitive_failure\n") &&
      DYLDPRIV.match?(/struct _dyld_protocol_conformance_result \{\n.*\n    uintptr_t kind;\n.*\n.*\n.*\n    const void \*value;\n\};/))

# the type declarations and the prototypes, as one block, cut out of the header
block_from = DYLDPRIV.index("enum _dyld_protocol_conformance_result_kind {") or abort 'result kind enum not found'
block_to_marker = '#define DYLD_FIND_POINTER_HASH_TABLE_ENTRY_DEFINED 1'
block_to = DYLDPRIV.index(block_to_marker, block_from) or abort 'end of the Swift SPI block not found'
HEADER_BLOCK = DYLDPRIV[block_from...block_to] + "\n"

def definition(text, name)
  from = text.index(/^[^\n]*\b#{Regexp.escape(name)}\([^\n]*(\n[^\n{]*)*?\n\{\n/) or abort "definition of #{name} not found in dyldAPIsInLibSystem.cpp"
  to = text.index("\n}\n", from) or abort "end of #{name} not found"
  text[from..(to + 2)]
end
DEFINITIONS = SPIS.keys.to_h { |n| [n, definition(WRAPPERS, n)] }.freeze
SPIS.each_key { |n| check("libsystem defines #{n} once", WRAPPERS.scan(/^[^\n]*\b#{Regexp.escape(n)}\(/).size == 1) }

PRELUDE = <<~'CPP'
  typedef __SIZE_TYPE__ size_t;
  typedef __UINTPTR_TYPE__ uintptr_t;
  typedef __UINT32_TYPE__ uint32_t;
  typedef __UINT16_TYPE__ uint16_t;
  #define NULL 0
  struct mach_header;
CPP

def source(header_block, definitions, driver = '')
  "#{PRELUDE}\nextern \"C\" {\n#{header_block}}\n#{definitions.values.join("\n")}\n#{driver}"
end

DRIVER = <<~'CPP'
  extern "C" int printf(const char*, ...);
  #define EXPECT(cond) do { if ( !(cond) ) { printf("FAIL line %d: %s\n", __LINE__, #cond); ++failures; } } while (0)
  static bool notFound(struct _dyld_protocol_conformance_result r) { return r.kind == (uintptr_t)_dyld_protocol_conformance_result_kind_not_found && r.value == NULL; }
  int main()
  {
    int failures = 0;
    int d = 0;
    const void* keys[2] = { &d, &d };
    EXPECT(_dyld_swift_optimizations_version() == 0);
    EXPECT(!_dyld_has_preoptimized_swift_protocol_conformances((const struct mach_header*)&d));
    EXPECT(!_dyld_has_preoptimized_swift_protocol_conformances(NULL));
    EXPECT(notFound(_dyld_find_protocol_conformance(&d, &d, &d)));
    EXPECT(notFound(_dyld_find_protocol_conformance(NULL, NULL, NULL)));
    EXPECT(notFound(_dyld_find_foreign_type_protocol_conformance(&d, "x", 1)));
    EXPECT(notFound(_dyld_find_foreign_type_protocol_conformance(NULL, NULL, 0)));
    EXPECT(notFound(_dyld_find_protocol_conformance_on_disk(&d, &d, &d, 0)));
    EXPECT(notFound(_dyld_find_protocol_conformance_on_disk(&d, &d, &d, 0xffffffffu)));
    EXPECT(notFound(_dyld_find_foreign_type_protocol_conformance_on_disk(&d, "x", 1, 0)));
    EXPECT(notFound(_dyld_find_foreign_type_protocol_conformance_on_disk(NULL, NULL, 0, 0xffffffffu)));
    EXPECT(_dyld_find_pointer_hash_table_entry(&d, &d, 2, keys) == NULL);
    EXPECT(_dyld_find_pointer_hash_table_entry(NULL, NULL, 0, NULL) == NULL);
    EXPECT(!_dyld_is_preoptimized_objc_image_loaded(0));
    EXPECT(!_dyld_is_preoptimized_objc_image_loaded(1));
    EXPECT(!_dyld_is_preoptimized_objc_image_loaded(0xffff));
    if ( failures == 0 )
      printf("ok\n");
    return failures != 0;
  }
CPP

def build_run(dir, header_block, definitions)
  File.write("#{dir}/run.cpp", source(header_block, definitions, DRIVER))
  out, status = Open3.capture2e('clang++', '-std=c++17', '-Wall', '-Wno-unused-function', "#{dir}/run.cpp", '-o', "#{dir}/run")
  return [false, "build failed:\n#{out}"] unless status.success?
  out, status = Open3.capture2e("#{dir}/run")
  [status.success? && out.include?('ok'), out]
end

# the symbols an arm64 Mach-O object exports: global, in __TEXT,__text, not hidden
def exported(dir, header_block, definitions)
  File.write("#{dir}/sym.cpp", source(header_block, definitions))
  out, status = Open3.capture2e('clang++', '-std=c++17', '-target', 'aarch64-apple-darwin20', '-c', "#{dir}/sym.cpp", '-o', "#{dir}/sym.o")
  return [nil, "build failed:\n#{out}"] unless status.success?
  out, status = Open3.capture2e('llvm-nm', '-m', "#{dir}/sym.o")
  return [nil, "llvm-nm failed:\n#{out}"] unless status.success?
  [out.lines.filter_map { |l| l[/\(__TEXT,__text\) external (\S+)$/, 1] }, out]
end

Dir.mktmpdir('dyld-swift-spis-') do |dir|
  ok, out = build_run(dir, HEADER_BLOCK, DEFINITIONS)
  check 'the definitions answer version 0, not_found {2, NULL} from every find_*, false and NULL otherwise', ok, out
  syms, out = exported(dir, HEADER_BLOCK, DEFINITIONS)
  check 'the definitions build as an arm64 Mach-O object', !syms.nil?, out
  want = SPIS.keys.map { |n| "_#{n}" }
  check "all #{want.size} SPIs are exported with C names (#{want.size} of #{want.size})", syms && (want - syms).empty?, (want - (syms || [])).inspect

  # probes: each mutant must make a check fail
  runtime = {
    'the version is 1 (the mechanism would depend on dyld_shared_cache_some_image_overridden)' => ['_dyld_swift_optimizations_version', 'return 0;', 'return 1;'],
    'preoptimized conformances are claimed' => ['_dyld_has_preoptimized_swift_protocol_conformances', 'return false;', 'return true;'],
    'find_protocol_conformance answers a definitive failure' => ['_dyld_find_protocol_conformance', '_dyld_protocol_conformance_result_kind_not_found', '_dyld_protocol_conformance_result_kind_definitive_failure'],
    'find_protocol_conformance answers a found descriptor' => ['_dyld_find_protocol_conformance', '_dyld_protocol_conformance_result_kind_not_found', '_dyld_protocol_conformance_result_kind_found_descriptor'],
    'find_protocol_conformance answers a value' => ['_dyld_find_protocol_conformance', ', NULL }', ', typeDescriptor }'],
    'find_foreign_type_protocol_conformance answers a value' => ['_dyld_find_foreign_type_protocol_conformance', ', NULL }', ', protocol }'],
    'find_foreign_type_protocol_conformance answers a witness table' => ['_dyld_find_foreign_type_protocol_conformance', '_dyld_protocol_conformance_result_kind_not_found', '_dyld_protocol_conformance_result_kind_found_witness_table'],
    'find_protocol_conformance_on_disk answers a value' => ['_dyld_find_protocol_conformance_on_disk', ', NULL }', ', metadataType }'],
    'find_protocol_conformance_on_disk answers a definitive failure' => ['_dyld_find_protocol_conformance_on_disk', '_dyld_protocol_conformance_result_kind_not_found', '_dyld_protocol_conformance_result_kind_definitive_failure'],
    'find_foreign_type_protocol_conformance_on_disk answers a value' => ['_dyld_find_foreign_type_protocol_conformance_on_disk', ', NULL }', ', protocol }'],
    'find_foreign_type_protocol_conformance_on_disk answers a definitive failure' => ['_dyld_find_foreign_type_protocol_conformance_on_disk', '_dyld_protocol_conformance_result_kind_not_found', '_dyld_protocol_conformance_result_kind_definitive_failure'],
    'the hash table lookup answers its table' => ['_dyld_find_pointer_hash_table_entry', 'return NULL;', 'return table;'],
    'an objc image is reported loaded' => ['_dyld_is_preoptimized_objc_image_loaded', 'return false;', 'return true;'],
  }
  runtime.each do |name, (spi, from, to)|
    abort "probe text not found: #{name}" unless DEFINITIONS[spi].scan(from).size == 1
    ok, out = build_run(dir, HEADER_BLOCK, DEFINITIONS.merge(spi => DEFINITIONS[spi].sub(from) { to }))
    abort "probe does not compile: #{name}\n#{out}" if out.start_with?('build failed')
    check "probe killed: #{name}", !ok
  end
  # export probes: the symbol must stay visible, with its C name
  SPIS.each_key do |spi|
    hidden = DEFINITIONS.merge(spi => DEFINITIONS[spi].sub(/\A/) { "__attribute__((visibility(\"hidden\"))) " })
    syms, = exported(dir, HEADER_BLOCK, hidden)
    check "probe killed: a hidden definition of #{spi}", syms && !syms.include?("_#{spi}")
  end
  syms, = exported(dir, '', DEFINITIONS.transform_values { |d| d }) # no prototypes, so no C linkage: the definitions are mangled
  # (the header block also carries the types, so this probe builds only when the definitions can name them)
  check 'probe killed: without the header\'s C linkage the symbols are mangled or the build fails', syms.nil? || (want - syms).any?
  syms, = exported(dir, HEADER_BLOCK, DEFINITIONS.reject { |k, _| k == '_dyld_find_pointer_hash_table_entry' })
  check 'probe killed: a missing definition is not exported', syms && !syms.include?('__dyld_find_pointer_hash_table_entry')
end

abort 'tests failed' if $failures != 0
puts 'ALL PASS'
