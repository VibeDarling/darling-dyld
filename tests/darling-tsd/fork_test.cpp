// A forked child that translates a cache image it has not loaded yet must change its own text, not its parent's:
// a /proc/self/mem handle opened before the fork still writes the parent.
#include "test_support.h"

#include <sys/mman.h>
#include <sys/wait.h>
#include <unistd.h>

extern "C" {
    extern char tsd_code_begin[], tsd_code_end[], tsd_read_site[];
}

static const uintptr_t kForkBase = 0x1C0000000ULL;
static const uint32_t kOffsets[2] = { 0, 16U << 20 };
static const uint32_t kCode = 0x400, kGap = 0x800, kGapSize = 0x100;
static thread_local void* forkSlot;

static void mapRegion(uint32_t offset) {
    const size_t page = (size_t)sysconf(_SC_PAGESIZE);
    int fd = memfd_create("tsd-fork-region", 0);
    if ( fd < 0 || ftruncate(fd, page) != 0 ) _exit(98);
    uint8_t* bytes = (uint8_t*)mmap(nullptr, page, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    memset(bytes, 0, page);
    memcpy(bytes + kCode, tsd_code_begin, tsd_code_end - tsd_code_begin);
    munmap(bytes, page);
    void* where = mmap((void*)(kForkBase + offset), page, PROT_READ | PROT_EXEC, MAP_PRIVATE | MAP_FIXED_NOREPLACE, fd, 0);
    close(fd);
    if ( where != (void*)(kForkBase + offset) ) _exit(98);
}

static unsigned word(uint32_t offset, uint32_t within) { return *(const unsigned*)(kForkBase + offset + within); }
static void* callRead(uint32_t offset) { return ((void*(*)())(kForkBase + offset + kCode))(); }

void testForkedChild() {
    const unsigned long slotOffset = (uintptr_t)&forkSlot - (uintptr_t)__builtin_thread_pointer();
    const uint32_t site = kCode + (uint32_t)(tsd_read_site - tsd_code_begin);
    TableBuilder builder;
    ExecutableRange ranges[2];
    for (int i = 0; i != 2; ++i) {
        mapRegion(kOffsets[i]);
        builder.images.push_back({ kOffsets[i], { encodeSite(site, kTSDRead, 0) } });
        builder.gaps.push_back({ kOffsets[i] + kGap, kGapSize });
        ranges[i] = { kForkBase + kOffsets[i], (size_t)sysconf(_SC_PAGESIZE) };
    }
    SiteTable table;
    CHECK(builder.parse(table) == nullptr);
    Patcher patcher(table, kForkBase, slotOffset);
    CHECK(patcher.init(ranges, 2) == nullptr);
    ProcSelfMemory proc;                        // opened first, as dyld does, and inherited by the child
    CHECK(proc.ok());
    PatchStats stats;
    CHECK(patcher.patchImage(kForkBase + kOffsets[0], proc.memory(), &stats) == nullptr && stats.veneers == 1);

    static int marker;
    forkSlot = &marker;
    const pid_t child = fork();
    if ( child == 0 ) {
        PatchStats childStats;
        const char* error = patcher.patchImage(kForkBase + kOffsets[1], proc.memory(), &childStats);
        if ( error != nullptr ) _exit(10);
        if ( (word(kOffsets[1], site) & 0xFC000000U) != 0x14000000U ) _exit(11);     // its own text is translated
        if ( callRead(kOffsets[1]) != &marker ) _exit(12);
        _exit(0);
    }
    int status = 0;
    CHECK(waitpid(child, &status, 0) == child && WIFEXITED(status) && WEXITSTATUS(status) == 0);
    // the parent's copy of the second image was not touched, and the parent can still translate it
    CHECK(word(kOffsets[1], site) == kMRSTPIDRRO);
    CHECK(word(kOffsets[1], kGap) == 0);
    CHECK(patcher.patchImage(kForkBase + kOffsets[1], proc.memory(), &stats) == nullptr && stats.veneers == 1);
    CHECK(callRead(kOffsets[1]) == &marker && callRead(kOffsets[0]) == &marker);
}
