# The four dyld4 data SPIs the shared cache's libobjc imports (__dyld_for_objc_header_opt_ro/rw,
# __dyld_objc_class_count, __dyld_lookup_section_info): their rows in dyldAPIs.cpp's lookup table, their
# declarations, and the section lookup itself, whose text is cut out of dyld3/ObjCSectionInfo.h and replayed
# here against hand-built mach headers. Mutants of the lookup must each fail (--probes).
# Usage: ruby tests/dyld-objc-data-apis.rb [checkout] [--probes]
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
DYLDPRIV = File.read("#{ROOT}/gen/usr/local/include/mach-o/dyld_priv.h")
D3APIS = File.read("#{ROOT}/dyld3/APIs.cpp")
D3HDR = File.read("#{ROOT}/dyld3/APIs.h")
SECTION_INFO = File.read("#{ROOT}/dyld3/ObjCSectionInfo.h")

# --- the lookup table ---------------------------------------------------------------------------
table = APIS[/static const struct dyld_func dyld_funcs\[\] = \{(.*?)\n\};/m, 1]
abort 'dyld_funcs table not found' unless table
rows = table.scan(/^\s*\{"([^"]+)",\s*\(void\*\)([A-Za-z0-9_:]+)\s*\},?\s*$/)
            .to_h
SIGNATURES = {
  '__dyld_for_objc_header_opt_ro' => 'const void* _dyld_for_objc_header_opt_ro(void)',
  '__dyld_for_objc_header_opt_rw' => 'void* _dyld_for_objc_header_opt_rw(void)',
  '__dyld_objc_class_count'       => 'uint32_t _dyld_objc_class_count(void)',
  '__dyld_lookup_section_info'    => 'struct _dyld_section_info_result _dyld_lookup_section_info(',
}
SIGNATURES.each do |name, sig|
  impl = sig[/_dyld_[a-z0-9_]+\(/]&.delete_suffix('(') or abort "no implementation name in #{sig}"
  check("table row #{name} -> #{impl}", rows[name] == impl, rows[name].inspect)
end
check('unknown name is not in the table', !rows.key?('__dyld_no_such_api'))
check('lookup reports an unknown name as absent',
      APIS.match?(/int _dyld_func_lookup\(const char\* name, void\*\* address\)\n\{\n\tfor \(.*?\) \{\n.*?\*address = 0;\n\treturn false;/m))

# --- declarations and the section-kind enum -----------------------------------------------------
SIGNATURES.each do |_name, sig|
  check("dyld_priv.h declares #{sig}", DYLDPRIV.match?(/^extern #{Regexp.escape(sig)}/m))
end
check('dyld_priv.h declares _dyld_lookup_section_info with the result struct',
      DYLDPRIV.match?(/^extern struct _dyld_section_info_result _dyld_lookup_section_info\(const struct mach_header\* mh,\n\s+_dyld_section_location_info_t locationHandle,\n\s+enum _dyld_section_location_kind kind\);/))
check('result struct carries buffer then bufferSize',
      DYLDPRIV.match?(/struct _dyld_section_info_result \{\n\s+void\*   buffer;\n\s+size_t  bufferSize;\n\};/))
KINDS = %w[
  _dyld_section_location_text_swift5_protos _dyld_section_location_text_swift5_proto
  _dyld_section_location_text_swift5_types _dyld_section_location_text_swift5_replace
  _dyld_section_location_text_swift5_replace2 _dyld_section_location_text_swift5_ac_funcs
  _dyld_section_location_objc_image_info _dyld_section_location_data_sel_refs
  _dyld_section_location_data_msg_refs _dyld_section_location_data_class_refs
  _dyld_section_location_data_super_refs _dyld_section_location_data_protocol_refs
  _dyld_section_location_data_class_list _dyld_section_location_data_non_lazy_class_list
  _dyld_section_location_data_stub_list _dyld_section_location_data_category_list
  _dyld_section_location_data_category_list2 _dyld_section_location_data_non_lazy_category_list
  _dyld_section_location_data_protocol_list _dyld_section_location_data_objc_fork_ok
  _dyld_section_location_data_raw_isa
].freeze
enum_body = DYLDPRIV[/enum _dyld_section_location_kind \{(.*?)\n\};/m, 1]
abort 'section kind enum not found' unless enum_body
declared = enum_body.scan(/_dyld_section_location_[a-z0-9_]+/).reject { |k| k == '_dyld_section_location_count' }
check('section kinds are in dyld order', declared == KINDS, declared.inspect)
check('_dyld_section_location_count follows the kinds', enum_body.match?(/_dyld_section_location_data_raw_isa,\s*\n\s*\/\/[^\n]*\n\s*_dyld_section_location_count,/))
SIGNATURES.each do |_name, sig|
  check("libsystem defines #{sig}", WRAPPERS.match?(/^#{Regexp.escape(sig)}/m))
end
check('libsystem defines _dyld_lookup_section_info with its three parameters',
      WRAPPERS.match?(/^struct _dyld_section_info_result _dyld_lookup_section_info\(const struct mach_header\* mh,\n\s+_dyld_section_location_info_t locationHandle,\n\s+enum _dyld_section_location_kind kind\)\n\{/))
check('dyld3/APIs.h declares the dyld3 branch',
      SIGNATURES.values.all? { |sig| D3HDR.match?(/\b#{Regexp.escape(sig[/\b_dyld_[a-z0-9_]+\(/])}/) })

# Both images define these, and neither links the other's translation unit: libdyld builds dyld3/APIs.cpp
# and the dyld executable builds src/dyldAPIs.cpp, so each needs the definitions and the shared helper.
check('dyld3/APIs.cpp includes the shared section helper', D3APIS.match?(/^#include "ObjCSectionInfo\.h"/))
check('dyld3/APIs.cpp defines the lookup', D3APIS.match?(/^struct _dyld_section_info_result _dyld_lookup_section_info\(/m))
check('dyldAPIs.cpp includes the shared section helper', APIS.match?(/^#include "ObjCSectionInfo\.h"/))
SIGNATURES.each do |_name, sig|
  check("dyldAPIs.cpp defines #{sig}", APIS.match?(/^#{Regexp.escape(sig)}/m))
end

# --- replay of the section lookup ---------------------------------------------------------------
START = 'static const char* const kObjCSectionNames[] = {'
STOP = "\n#endif // __OBJC_SECTION_INFO_H__"
def lookup_source(text)
  from = text.index(START) or abort 'kObjCSectionNames not found'
  to = text.index(STOP, from) or abort 'the header guard after the helper not found'
  text[from...to]
end

PRELUDE = <<~'CPP'
  #include <stdint.h>
  #include <stddef.h>
  #include <string.h>
  #include <stdio.h>
  #include <stdlib.h>

  enum { LC_SEGMENT_64 = 0x19 };

  struct mach_header {
    uint32_t magic, cputype, cpusubtype, filetype, ncmds, sizeofcmds, flags;
  };
  struct mach_header_64 {
    uint32_t magic, cputype, cpusubtype, filetype, ncmds, sizeofcmds, flags, reserved;
  };
  struct load_command { uint32_t cmd, cmdsize; };
  struct segment_command_64 {
    uint32_t cmd, cmdsize; char segname[16];
    uint64_t vmaddr, vmsize, fileoff, filesize;
    int32_t maxprot, initprot; uint32_t nsects, flags;
  };
  struct section_64 {
    char sectname[16], segname[16];
    uint64_t addr, size;
    uint32_t offset, align, reloff, nreloc, flags, reserved1, reserved2, reserved3;
  };
  enum _dyld_section_location_kind {
    _dyld_section_location_text_swift5_protos = 0x0,
    _dyld_section_location_text_swift5_proto,
    _dyld_section_location_text_swift5_types,
    _dyld_section_location_text_swift5_replace,
    _dyld_section_location_text_swift5_replace2,
    _dyld_section_location_text_swift5_ac_funcs,
    _dyld_section_location_objc_image_info,
    _dyld_section_location_data_sel_refs,
    _dyld_section_location_data_msg_refs,
    _dyld_section_location_data_class_refs,
    _dyld_section_location_data_super_refs,
    _dyld_section_location_data_protocol_refs,
    _dyld_section_location_data_class_list,
    _dyld_section_location_data_non_lazy_class_list,
    _dyld_section_location_data_stub_list,
    _dyld_section_location_data_category_list,
    _dyld_section_location_data_category_list2,
    _dyld_section_location_data_non_lazy_category_list,
    _dyld_section_location_data_protocol_list,
    _dyld_section_location_data_objc_fork_ok,
    _dyld_section_location_data_raw_isa,
    _dyld_section_location_count,
  };
  struct _dyld_section_info_result { void* buffer; size_t bufferSize; };
  typedef struct _dyld_section_location_info_s* _dyld_section_location_info_t;
CPP

DRIVER = <<~'CPP'

  static int failures;
  // Section and segment names are 16-byte fields with no terminator when they fill it, like the real ones.
  static void setName(char* field, const char* name) { memset(field, 0, 16); memcpy(field, name, strlen(name)); }
  static void expect(const char* what, struct _dyld_section_info_result got, const void* buffer, size_t size)
  {
    if ( got.buffer == buffer && got.bufferSize == size )
      return;
    ++failures;
    printf("FAIL %s: {%p, %zu}, expected {%p, %zu}\n", what, got.buffer, got.bufferSize, buffer, size);
  }

  int main()
  {
    // One image: __TEXT mapped from file offset 0 at 0x100000000, __DATA_CONST 0x100 past it.
    static uint8_t image[0x400];
    struct mach_header_64* mh = (struct mach_header_64*)image;
    const uint64_t base = 0x100000000ull;
    mh->magic = 0xfeedfacf; mh->ncmds = 2;
    struct segment_command_64* text = (struct segment_command_64*)(image + sizeof(*mh));
    text->cmd = 0x19; text->cmdsize = sizeof(*text) + sizeof(struct section_64);
    setName(text->segname, "__TEXT"); text->vmaddr = base; text->fileoff = 0; text->nsects = 1;
    struct section_64* textSect = (struct section_64*)(text + 1);
    setName(textSect->sectname, "__text"); setName(textSect->segname, "__TEXT");
    textSect->addr = base; textSect->size = 0x100;
    struct segment_command_64* data = (struct segment_command_64*)((uint8_t*)text + text->cmdsize);
    data->cmd = 0x19; data->cmdsize = sizeof(*data) + 2 * sizeof(struct section_64);
    setName(data->segname, "__DATA_CONST"); data->vmaddr = base + 0x100; data->fileoff = 0x100; data->nsects = 2;
    struct section_64* sects = (struct section_64*)(data + 1);
    setName(sects[0].sectname, "__objc_classlist"); setName(sects[0].segname, "__DATA_CONST");
    sects[0].addr = base + 0x110; sects[0].size = 0x28;
    setName(sects[1].sectname, "__objc_selrefs"); setName(sects[1].segname, "__DATA_CONST");
    sects[1].addr = base + 0x138; sects[1].size = 0x10;
    mh->sizeofcmds = text->cmdsize + data->cmdsize;

    expect("data_class_list", lookupObjCSectionInfo((const struct mach_header*)mh, _dyld_section_location_data_class_list),
           image + 0x110, 0x28);
    expect("data_sel_refs", lookupObjCSectionInfo((const struct mach_header*)mh, _dyld_section_location_data_sel_refs),
           image + 0x138, 0x10);
    expect("absent section", lookupObjCSectionInfo((const struct mach_header*)mh, _dyld_section_location_text_swift5_protos),
           NULL, 0);
    expect("absent kind at the end", lookupObjCSectionInfo((const struct mach_header*)mh, _dyld_section_location_data_raw_isa),
           NULL, 0);
    expect("kind past the enum", lookupObjCSectionInfo((const struct mach_header*)mh, _dyld_section_location_count),
           NULL, (size_t)-1);

    mh->ncmds = 1;
    data->cmd = 0;
    expect("no data segment", lookupObjCSectionInfo((const struct mach_header*)mh, _dyld_section_location_data_class_list),
           NULL, 0);

    // A cache-shaped image: file offsets are offsets into the cache file, so nothing sits at 0, and a
    // __TEXT_EXEC segment precedes __TEXT at another address.
    static uint8_t cacheImage[0x400];
    struct mach_header_64* ch = (struct mach_header_64*)cacheImage;
    const uint64_t cacheBase = 0x180000000ull;
    ch->magic = 0xfeedfacf; ch->ncmds = 3;
    struct segment_command_64* execSeg = (struct segment_command_64*)(cacheImage + sizeof(*ch));
    execSeg->cmd = 0x19; execSeg->cmdsize = sizeof(*execSeg);
    setName(execSeg->segname, "__TEXT_EXEC"); execSeg->vmaddr = cacheBase + 0x4000; execSeg->fileoff = 0x1c4000;
    struct segment_command_64* cacheText = (struct segment_command_64*)((uint8_t*)execSeg + execSeg->cmdsize);
    cacheText->cmd = 0x19; cacheText->cmdsize = sizeof(*cacheText);
    setName(cacheText->segname, "__TEXT"); cacheText->vmaddr = cacheBase; cacheText->fileoff = 0x1cb000;
    struct segment_command_64* cacheData = (struct segment_command_64*)((uint8_t*)cacheText + cacheText->cmdsize);
    cacheData->cmd = 0x19; cacheData->cmdsize = sizeof(*cacheData) + sizeof(struct section_64);
    setName(cacheData->segname, "__DATA_CONST"); cacheData->vmaddr = cacheBase + 0x200; cacheData->fileoff = 0x1cb200; cacheData->nsects = 1;
    struct section_64* cacheSect = (struct section_64*)(cacheData + 1);
    setName(cacheSect->sectname, "__objc_classlist"); setName(cacheSect->segname, "__DATA_CONST");
    cacheSect->addr = cacheBase + 0x230; cacheSect->size = 0x28;
    ch->sizeofcmds = execSeg->cmdsize + cacheText->cmdsize + cacheData->cmdsize;
    expect("cache image class list", lookupObjCSectionInfo((const struct mach_header*)ch, _dyld_section_location_data_class_list),
           cacheImage + 0x230, 0x28);
    expect("cache image absent section", lookupObjCSectionInfo((const struct mach_header*)ch, _dyld_section_location_data_sel_refs),
           NULL, 0);

    // No __TEXT segment at all, whatever sits at file offset 0.
    static uint8_t noTextImage[0x200];
    struct mach_header_64* nt = (struct mach_header_64*)noTextImage;
    nt->magic = 0xfeedfacf; nt->ncmds = 2;
    struct segment_command_64* noTextExec = (struct segment_command_64*)(noTextImage + sizeof(*nt));
    noTextExec->cmd = 0x19; noTextExec->cmdsize = sizeof(*noTextExec);
    setName(noTextExec->segname, "__TEXT_EXEC"); noTextExec->vmaddr = base; noTextExec->fileoff = 0;
    struct segment_command_64* noTextData = (struct segment_command_64*)((uint8_t*)noTextExec + noTextExec->cmdsize);
    noTextData->cmd = 0x19; noTextData->cmdsize = sizeof(*noTextData) + sizeof(struct section_64);
    setName(noTextData->segname, "__DATA_CONST"); noTextData->vmaddr = base + 0x100; noTextData->fileoff = 0x100; noTextData->nsects = 1;
    struct section_64* noTextSect = (struct section_64*)(noTextData + 1);
    setName(noTextSect->sectname, "__objc_classlist"); noTextSect->addr = base + 0x110; noTextSect->size = 0x28;
    nt->sizeofcmds = noTextExec->cmdsize + noTextData->cmdsize;
    expect("no __TEXT segment", lookupObjCSectionInfo((const struct mach_header*)nt, _dyld_section_location_data_class_list),
           NULL, 0);

    // Malformed headers: a real image supplies none of these, and none may read past what the header declares.
    // The bytes after each short or lying command spell a section the walk must not believe in.
    static uint8_t shortImage[0x200];
    struct mach_header_64* sh = (struct mach_header_64*)shortImage;
    sh->magic = 0xfeedfacf; sh->ncmds = 1;
    struct segment_command_64* shortSeg = (struct segment_command_64*)(shortImage + sizeof(*sh));
    shortSeg->cmd = 0x19; shortSeg->cmdsize = sizeof(struct load_command);
    setName(shortSeg->segname, "__TEXT"); shortSeg->vmaddr = base; shortSeg->fileoff = 0; shortSeg->nsects = 1;
    struct section_64* shortSect = (struct section_64*)((uint8_t*)shortSeg + sizeof(struct segment_command_64));
    setName(shortSect->sectname, "__objc_classlist"); shortSect->addr = base; shortSect->size = 0x30;
    sh->sizeofcmds = sizeof(struct load_command);
    expect("command shorter than a segment", lookupObjCSectionInfo((const struct mach_header*)sh, _dyld_section_location_data_class_list),
           NULL, 0);

    static uint8_t overrunImage[0x200];
    struct mach_header_64* oh = (struct mach_header_64*)overrunImage;
    oh->magic = 0xfeedfacf; oh->ncmds = 1;
    struct segment_command_64* overrunSeg = (struct segment_command_64*)(overrunImage + sizeof(*oh));
    overrunSeg->cmd = 0x19; overrunSeg->cmdsize = 0x100;
    setName(overrunSeg->segname, "__TEXT"); overrunSeg->vmaddr = base; overrunSeg->fileoff = 0; overrunSeg->nsects = 1;
    struct section_64* overrunSect = (struct section_64*)(overrunSeg + 1);
    setName(overrunSect->sectname, "__objc_classlist"); overrunSect->addr = base; overrunSect->size = 0x30;
    oh->sizeofcmds = sizeof(struct load_command);
    expect("command longer than the command area", lookupObjCSectionInfo((const struct mach_header*)oh, _dyld_section_location_data_class_list),
           NULL, 0);

    static uint8_t nsectsImage[0x200];
    struct mach_header_64* nh = (struct mach_header_64*)nsectsImage;
    nh->magic = 0xfeedfacf; nh->ncmds = 1;
    struct segment_command_64* nsectsSeg = (struct segment_command_64*)(nsectsImage + sizeof(*nh));
    nsectsSeg->cmd = 0x19; nsectsSeg->cmdsize = sizeof(struct segment_command_64) + sizeof(struct section_64);
    setName(nsectsSeg->segname, "__TEXT"); nsectsSeg->vmaddr = base; nsectsSeg->fileoff = 0; nsectsSeg->nsects = 2;
    struct section_64* nsectsSect = (struct section_64*)(nsectsSeg + 1);
    setName(nsectsSect->sectname, "__objc_classlist"); nsectsSect->addr = base; nsectsSect->size = 0x30;
    nh->sizeofcmds = nsectsSeg->cmdsize;
    expect("section table larger than the command", lookupObjCSectionInfo((const struct mach_header*)nh, _dyld_section_location_data_class_list),
           NULL, 0);

    static uint8_t lyingImage[0x200];
    struct mach_header_64* lh = (struct mach_header_64*)lyingImage;
    lh->magic = 0xfeedfacf; lh->ncmds = 0x10000;
    struct segment_command_64* lyingSeg = (struct segment_command_64*)(lyingImage + sizeof(*lh));
    lyingSeg->cmd = 0x19; lyingSeg->cmdsize = sizeof(struct segment_command_64);
    setName(lyingSeg->segname, "__TEXT"); lyingSeg->vmaddr = base; lyingSeg->fileoff = 0; lyingSeg->nsects = 0;
    lh->sizeofcmds = sizeof(struct segment_command_64);
    expect("ncmds larger than the command area", lookupObjCSectionInfo((const struct mach_header*)lh, _dyld_section_location_data_class_list),
           NULL, 0);

    if ( failures != 0 )
      return 1;
    printf("all section lookup cases pass\n");
    return 0;
  }
CPP

def build_and_run(dir, source)
  exe = "#{dir}/objc_data_apis_test"
  File.write("#{dir}/test.cpp", PRELUDE + source + DRIVER)
  out, status = Open3.capture2e('clang++', '-std=c++17', '-O1', '-Wall', '-Werror', '-o', exe, "#{dir}/test.cpp")
  return [false, "build failed:\n#{out}"] unless status.success?
  out, status = Open3.capture2e(exe)
  [status.success?, out]
end

# --- libdyld's three table wrappers, replayed against stubs of the loader --------------------------
# The dyld2 loader decides whether its objc tables fit the process's libobjc, so a wrapper that answers from
# libdyld's own copy of the cache's table (gObjCOpt) would hand them to any runtime. The three functions are
# cut out of src/dyldAPIsInLibSystem.cpp; the cache table here is non-null, so a local answer shows.
WRAPPER_START = 'const void* _dyld_for_objc_header_opt_ro(void)'
wrapper_from = WRAPPERS.index(WRAPPER_START + "\n{") or abort 'libsystem table wrappers not found'
wrapper_to = WRAPPERS.index('struct _dyld_section_info_result _dyld_lookup_section_info(', wrapper_from) or abort 'end of the table wrappers not found'
TABLE_WRAPPERS = WRAPPERS[wrapper_from...wrapper_to]

WRAPPER_SOURCE = <<~'CPP' + TABLE_WRAPPERS + <<~'CPP2'
  #include <stdint.h>
  #include <stdio.h>
  #include <string.h>
  #define DYLD_NO_LOCK_THIS_BLOCK
  #define __ptrauth_dyld_function_ptr
  namespace objc { struct ClassHashTable { uint32_t classCount() const { return 221074; } }; }
  namespace objc_opt {
    struct objc_opt_t {
      const void* headeropt_ro() const { return (const void*)0xc0; }
      void* headeropt_rw() const { return (void*)0xc1; }
      const objc::ClassHashTable* classOpt() const { static objc::ClassHashTable t; return &t; }
    };
  }
  static objc_opt::objc_opt_t gCacheOpt;
  __attribute__((unused)) static const objc_opt::objc_opt_t* gObjCOpt = &gCacheOpt;
  static bool gUseDyld3 = false;
  namespace dyld3 {
    static const void* _dyld_for_objc_header_opt_ro() { return (const void*)0xd0; }
    static void* _dyld_for_objc_header_opt_rw() { return (void*)0xd1; }
    static uint32_t _dyld_objc_class_count() { return 3; }
  }
  // The loader's answers, for a runtime that is not the cache's: none.
  static const void* loaderRo() { return nullptr; }
  static void* loaderRw() { return nullptr; }
  static uint32_t loaderCount() { return 0; }
  static unsigned lookups;
  static char lastName[64];
  static void dyld_func_lookup_and_resign(const char* name, const void* (**address)(void)) { ++lookups; strcpy(lastName, name); *address = loaderRo; }
  static void dyld_func_lookup_and_resign(const char* name, void* (**address)(void)) { ++lookups; strcpy(lastName, name); *address = loaderRw; }
  static void dyld_func_lookup_and_resign(const char* name, uint32_t (**address)(void)) { ++lookups; strcpy(lastName, name); *address = loaderCount; }

CPP
  static int failures;
  static void expect(const char* what, bool ok)
  {
    if ( ok ) { printf("ok %s\n", what); return; }
    ++failures;
    printf("FAIL %s\n", what);
  }

  int main()
  {
    expect("headeropt_ro is the loader's answer, not libdyld's table", _dyld_for_objc_header_opt_ro() == nullptr);
    expect("headeropt_ro asks the loader by its row name", strcmp(lastName, "__dyld_for_objc_header_opt_ro") == 0);
    expect("headeropt_rw is the loader's answer, not libdyld's table", _dyld_for_objc_header_opt_rw() == nullptr);
    expect("headeropt_rw asks the loader by its row name", strcmp(lastName, "__dyld_for_objc_header_opt_rw") == 0);
    expect("the class count is the loader's answer, not libdyld's table", _dyld_objc_class_count() == 0);
    expect("the class count asks the loader by its row name", strcmp(lastName, "__dyld_objc_class_count") == 0);
    expect("each wrapper looked the loader up once", lookups == 3);
    _dyld_for_objc_header_opt_ro(); _dyld_for_objc_header_opt_rw(); _dyld_objc_class_count();
    expect("the loader row is cached after the first call", lookups == 3);
    gUseDyld3 = true;
    expect("the dyld3 branch is kept for headeropt_ro", _dyld_for_objc_header_opt_ro() == (const void*)0xd0);
    expect("the dyld3 branch is kept for headeropt_rw", _dyld_for_objc_header_opt_rw() == (void*)0xd1);
    expect("the dyld3 branch is kept for the class count", _dyld_objc_class_count() == 3);
    return failures != 0;
  }
CPP2

def build_wrappers(dir, source)
  exe = "#{dir}/objc_table_wrappers"
  File.write("#{dir}/wrappers.cpp", source)
  out, status = Open3.capture2e('clang++', '-std=c++17', '-O1', '-Wall', '-Werror', '-Wno-unused-function', '-o', exe, "#{dir}/wrappers.cpp")
  return [false, "build failed:\n#{out}"] unless status.success?
  out, status = Open3.capture2e(exe)
  [status.success?, out]
end

Dir.mktmpdir('dyld-objc-data-apis-') do |dir|
  ok, out = build_and_run(dir, lookup_source(SECTION_INFO))
  puts out
  check('section lookup replay', ok, out)
  ok, out = build_wrappers(dir, WRAPPER_SOURCE)
  puts out
  check('table wrappers forward to the loader', ok, out)
  next unless RUN_PROBES

  probes = [
    ['kind bound is exclusive', 'if ( (unsigned)kind >= (unsigned)_dyld_section_location_count )',
     'if ( (unsigned)kind > (unsigned)_dyld_section_location_count )'],
    ['base comes from the __TEXT segment', 'if ( strncmp(seg->segname, "__TEXT", sizeof(seg->segname)) == 0 ) {',
     'if ( strncmp(seg->segname, "__TEXX", sizeof(seg->segname)) == 0 ) {'],
    ['base is not the first segment', 'if ( strncmp(seg->segname, "__TEXT", sizeof(seg->segname)) == 0 ) {',
     'if ( true ) {'],
    ['base is not any segment at file offset 0', 'if ( strncmp(seg->segname, "__TEXT", sizeof(seg->segname)) == 0 ) {',
     'if ( seg->fileoff == 0 ) {'],
    ['__TEXT_EXEC is not __TEXT', 'if ( strncmp(seg->segname, "__TEXT", sizeof(seg->segname)) == 0 ) {',
     'if ( strncmp(seg->segname, "__TEXT", 6) == 0 ) {'],
    ['offset is relative to the image', '(sect[s].addr - imageVMBase), (size_t)sect[s].size }',
     '(sect[s].addr - imageVMBase) + 0x10, (size_t)sect[s].size }'],
    ['names compare within the field', 'strncmp(sect[s].sectname, name, sizeof(sect[s].sectname)) == 0',
     'strcmp(sect[s].sectname, name) == 0'],
    ['past-the-enum result is -1', 'return { nullptr, (size_t)-1 };', 'return { nullptr, 0 };'],
    ['commands stay inside the command area',
     'if ( (lc->cmdsize < sizeof(load_command)) || (lc->cmdsize > hdr->sizeofcmds - off) )',
     'if ( lc->cmdsize < sizeof(load_command) )'],
    ['a segment command carries a segment',
     '(lc->cmd == LC_SEGMENT_64) && (lc->cmdsize >= sizeof(segment_command_64))',
     '(lc->cmd == LC_SEGMENT_64) && (lc->cmdsize >= sizeof(load_command))'],
    ['the section table fits in its command',
     'if ( seg->nsects > (seg->cmdsize - sizeof(segment_command_64))/sizeof(section_64) )',
     'if ( false )'],
  ]
  [
    ['headeropt_ro answers from libdyld\'s table', "\tDYLD_NO_LOCK_THIS_BLOCK;\n    typedef const void* (*funcType)(void);",
     "    return (gObjCOpt != nullptr) ? gObjCOpt->headeropt_ro() : nullptr;\n\tDYLD_NO_LOCK_THIS_BLOCK;\n    typedef const void* (*funcType)(void);"],
    ['headeropt_rw answers from libdyld\'s table', "\tDYLD_NO_LOCK_THIS_BLOCK;\n    typedef void* (*funcType)(void);",
     "    return (gObjCOpt != nullptr) ? gObjCOpt->headeropt_rw() : nullptr;\n\tDYLD_NO_LOCK_THIS_BLOCK;\n    typedef void* (*funcType)(void);"],
    ['the class count answers from libdyld\'s table', "\tDYLD_NO_LOCK_THIS_BLOCK;\n    typedef uint32_t (*funcType)(void);",
     "    if ( gObjCOpt != nullptr )\n        return gObjCOpt->classOpt()->classCount();\n\tDYLD_NO_LOCK_THIS_BLOCK;\n    typedef uint32_t (*funcType)(void);"],
    ['headeropt_ro keeps its dyld3 branch', 'return dyld3::_dyld_for_objc_header_opt_ro();', 'return nullptr;'],
    ['the class count asks its own row', '"__dyld_objc_class_count"', '"__dyld_for_objc_header_opt_ro"'],
  ].each do |name, from, to|
    abort "probe text not found: #{name}" unless WRAPPER_SOURCE.include?(from)
    ok, out = build_wrappers(dir, WRAPPER_SOURCE.sub(from, to))
    if out.start_with?('build failed')
      abort "probe does not compile: #{name}\n#{out}"
    elsif ok
      $failures += 1
      puts "SURVIVED #{name}"
    else
      puts "killed   #{name}"
    end
  end
  probes.each do |name, from, to|
    source = lookup_source(SECTION_INFO)
    abort "probe text not found: #{name}" unless source.include?(from)
    ok, out = build_and_run(dir, source.sub(from, to))
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
