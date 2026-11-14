// Body of the glue test (tests/darling-tsd-glue.rb): runs the real translateSplitCacheTSD() from SharedCacheRuntime.cpp,
// one scenario per process because the translation state is static. argv[1] names the scenario, argv[2] a scratch dir.
#include <sys/mman.h>
#include <unistd.h>

extern "C" {
    extern char tsd_code_begin[], tsd_code_end[], tsd_read_site[];
}
using namespace dyld3;
using namespace dyld3::darling_tsd;

static const uintptr_t kCache = 0x1D0000000ULL;     // the cache header page; the executable page follows at +0x4000
static const uint32_t kImage = 0x4100;              // the mach header, offset from the cache base
static const uint32_t kCode = 0x4400;               // the test code, offset from the cache base
static thread_local void* tsdSlot;

static int fail(const char* what, const char* detail) { printf("FAIL %s: %s\n", what, detail ? detail : "(null)"); return 1; }

int main(int argc, char** argv) {
    if ( argc < 3 ) return 2;
    const char* scenario = argv[1];
    gSlot = (uintptr_t)&tsdSlot - (uintptr_t)__builtin_thread_pointer();
    const size_t page = (size_t)sysconf(_SC_PAGESIZE);
    // header page (not executable) holding the cache UUID, then an executable page holding the code
    DyldSharedCache* cache = (DyldSharedCache*)mmap((void*)kCache, 0x4000, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANON | MAP_FIXED_NOREPLACE, -1, 0);
    uint8_t* code = (uint8_t*)mmap((void*)(kCache + 0x4000), page, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANON | MAP_FIXED_NOREPLACE, -1, 0);
    if ( cache != (void*)kCache || code != (uint8_t*)(kCache + 0x4000) ) return 98;
    for (int i = 0; i != 16; ++i) cache->header.uuid[i] = (uint8_t)(0x40 + i);
    memcpy(code + (kCode - 0x4000), tsd_code_begin, tsd_code_end - tsd_code_begin);
    mprotect(code, page, PROT_READ | PROT_EXEC);

    SharedCacheLoadInfo info = {};
    info.loadAddress = cache;
    snprintf(info.path, sizeof(info.path), "%s/cache", argv[2]);
    const uint32_t site = (kCode - kImage) + (uint32_t)(tsd_read_site - tsd_code_begin);
    TableBuilder b;
    b.images = { { kImage, { encodeSite(site, kTSDRead, 0) } } };
    b.gaps = { { kCode + 0x400, 0x100 } };          // zero bytes of the executable page
    memcpy(b.uuid, (const void*)cache->header.uuid, 16);
    uint32_t imageAsked = kImage;
    bool writeTable = true;
    size_t cut = 0;
    if ( !strcmp(scenario, "missing") ) writeTable = false;
    else if ( !strcmp(scenario, "uuid") ) b.uuid[3] ^= 1;
    else if ( !strcmp(scenario, "truncated") ) cut = 4;
    else if ( !strcmp(scenario, "unlisted") ) imageAsked = kImage + 0x40;
    else if ( !strcmp(scenario, "gap-in-data") ) b.gaps = { { 0x1000, 0x100 } };       // inside the cache, but not executable
    else if ( strcmp(scenario, "ok") ) return 99;
    if ( writeTable ) {
        b.build();
        char path[300];
        snprintf(path, sizeof(path), "%s.tsdsites", info.path);
        FILE* f = fopen(path, "wb");
        fwrite(b.storage.data(), 1, b.length - cut, f);
        fclose(f);
    }
    PatchStats stats = {};
    const char* error = translateSplitCacheTSD(info, (const mach_header*)(kCache + imageAsked), &stats);
    const char* want = nullptr;
    if ( !strcmp(scenario, "missing") ) want = "cannot open";
    else if ( !strcmp(scenario, "uuid") ) want = "another cache";
    else if ( !strcmp(scenario, "truncated") ) want = "length";
    else if ( !strcmp(scenario, "unlisted") ) want = "does not describe";
    else if ( !strcmp(scenario, "gap-in-data") ) want = "gap outside";
    if ( want != nullptr )
        return (error && strstr(error, want)) ? (printf("PASS %s\n", scenario), 0) : fail(scenario, error);
    if ( error != nullptr ) return fail(scenario, error);
    static int marker;
    tsdSlot = &marker;
    typedef void* (*Read)();
    if ( stats.veneers != 1 || ((Read)(kCache + kCode))() != &marker ) return fail(scenario, "not translated");
    if ( translateSplitCacheTSD(info, (const mach_header*)(kCache + kImage), &stats) != nullptr ) return fail(scenario, "second call");
    printf("PASS %s\n", scenario);
    return 0;
}
