// Runs translated code on this ARM64 host: fake cache text in private file mappings, sites farther apart than a
// branch reaches, four threads with distinct thread-local slots, signals landing inside veneers, and a thread that
// runs code in the page being patched.
#include "test_support.h"

#include <atomic>
#include <stdlib.h>
#include <pthread.h>
#include <signal.h>
#include <sys/mman.h>
#include <sys/wait.h>
#include <ucontext.h>
#include <unistd.h>

extern "C" {
    extern char tsd_code_begin[], tsd_code_end[], tsd_read_site[], tsd_flags_site[];
    void*    tsd_read();
    void*    tsd_flags(int* flags);
    unsigned long tsd_spinner(volatile unsigned char* started, volatile unsigned* stop);
}

static const uintptr_t kBase = 0x180000000ULL;
static const uint32_t kRegionOffsets[3] = { 0, 200U << 20, 400U << 20 };
static const uint32_t kCodeOffset = 0x400;
static const uint32_t kGapOffset = 0x800;
static const uint32_t kGapSize = 0x100;

static thread_local void* slot;
static thread_local unsigned long value;
static thread_local unsigned traps;
static std::atomic<unsigned> veneerHits;
static std::atomic<unsigned> storms;

static void onSignal(int sig, siginfo_t*, void* opaque) {
    ucontext_t* context = (ucontext_t*)opaque;
    const uintptr_t pc = context->uc_mcontext.pc;
    if ( sig == SIGUSR1 ) {
        for (uint32_t offset : kRegionOffsets) {
            if ( pc >= kBase + offset + kGapOffset && pc < kBase + offset + kGapOffset + kGapSize )
                ++veneerHits;
        }
        ++storms;
        return;
    }
    const uint32_t instruction = *(const uint32_t*)pc;
    if ( (instruction & ~31U) != 0xDA00 ) _exit(97);
    if ( (instruction & 31U) != 31 ) context->uc_mcontext.regs[instruction & 31U] = (uintptr_t)&value;
    context->uc_mcontext.pc += 4;
    ++traps;
}

static uint8_t* mapRegion(uint32_t offset, bool code) {
    const size_t page = (size_t)sysconf(_SC_PAGESIZE);
    int fd = memfd_create("tsd-region", 0);
    if ( fd < 0 || ftruncate(fd, page) != 0 ) { perror("memfd"); exit(98); }
    uint8_t* bytes = (uint8_t*)mmap(nullptr, page, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    memset(bytes, 0, page);
    if ( code ) {
        for (uint32_t i = 0; i < 0x800; i += 4) *(uint32_t*)(bytes + i) = 0xD503201FU;
        memcpy(bytes + kCodeOffset, tsd_code_begin, tsd_code_end - tsd_code_begin);
    }
    munmap(bytes, page);
    // like the cache: a private, read-only-or-execute view of a file
    void* where = mmap((void*)(kBase + offset), page, PROT_READ | PROT_EXEC, MAP_PRIVATE | MAP_FIXED_NOREPLACE, fd, 0);
    close(fd);
    if ( where != (void*)(kBase + offset) ) { perror("mmap region"); exit(98); }
    return (uint8_t*)where;
}

static bool mprotectWrite(void*, uintptr_t address, const void* data, size_t length) {
    const uintptr_t page = address & ~(uintptr_t)(sysconf(_SC_PAGESIZE) - 1);
    mprotect((void*)page, (size_t)sysconf(_SC_PAGESIZE), PROT_READ | PROT_WRITE);       // the unsafe way: the page stops being executable
    memcpy((void*)address, data, length);
    mprotect((void*)page, (size_t)sysconf(_SC_PAGESIZE), PROT_READ | PROT_EXEC);
    return true;
}

struct Fixture {
    TableBuilder builder;
    SiteTable table;
    Fixture() {
        const uint32_t read = kCodeOffset + (uint32_t)(tsd_read_site - tsd_code_begin);
        const uint32_t flags = kCodeOffset + (uint32_t)(tsd_flags_site - tsd_code_begin);
        for (uint32_t offset : kRegionOffsets) {
            builder.images.push_back({ offset, { encodeSite(read, kTSDRead, 0), encodeSite(flags, kTSDRead, 0) } });
            builder.gaps.push_back({ offset + kGapOffset, kGapSize });
        }
        const char* error = builder.parse(table);
        if ( error ) { fprintf(stderr, "fixture: %s\n", error); exit(98); }
    }
};

static void* worker(void* argument) {
    value = (unsigned long)argument;
    slot = nullptr;
    // an empty slot takes the kernel trap once and still yields a usable pointer
    CHECK(((void*(*)())(kBase + kCodeOffset))() == &value && traps == 1);
    slot = &value;
    for (volatile unsigned i = 0; i < 20000; ++i) {
        for (uint32_t offset : kRegionOffsets) {
            void* (*read)() = (void*(*)())(kBase + offset + kCodeOffset);
            int flags[2] = { 0, 0 };
            void* (*withFlags)(int*) = (void*(*)(int*))(kBase + offset + kCodeOffset + ((uintptr_t)&tsd_flags - (uintptr_t)tsd_code_begin));
            if ( read() != &value ) { CHECK(false); return nullptr; }
            if ( withFlags(flags) != &value || flags[0] != 1 || flags[1] != 1 ) { CHECK(false); return nullptr; }
        }
    }
    CHECK(traps == 1 && value == (unsigned long)argument);
    return nullptr;
}

static void testNative() {
    const unsigned long slotOffset = (uintptr_t)&slot - (uintptr_t)__builtin_thread_pointer();
    CHECK(isValidSlotOffset(slotOffset));
    struct sigaction action = {};
    action.sa_sigaction = onSignal;
    action.sa_flags = SA_SIGINFO;
    sigemptyset(&action.sa_mask);
    CHECK(sigaction(SIGILL, &action, nullptr) == 0 && sigaction(SIGUSR1, &action, nullptr) == 0);

    uint8_t* regions[3];
    for (int i = 0; i != 3; ++i) regions[i] = mapRegion(kRegionOffsets[i], true);
    // control: untranslated cache text reads nothing useful from TPIDRRO_EL0 on Linux
    CHECK(((void*(*)())(kBase + kCodeOffset))() == nullptr);

    Fixture f;
    Patcher patcher(f.table, kBase, slotOffset);
    ExecutableRange ranges[3];
    for (int i = 0; i != 3; ++i) ranges[i] = { kBase + kRegionOffsets[i], (size_t)sysconf(_SC_PAGESIZE) };
    CHECK(patcher.init(ranges, 3) == nullptr);

    // a thread runs code in the page that is being patched, so protections must never change
    volatile unsigned char started = 0;
    volatile unsigned stop = 0;
    struct Spin { volatile unsigned char* started; volatile unsigned* stop; unsigned long iterations; } spin = { &started, &stop, 0 };
    pthread_t spinner;
    pthread_create(&spinner, nullptr, [](void* p) -> void* {
        Spin* s = (Spin*)p;
        s->iterations = ((unsigned long(*)(volatile unsigned char*, volatile unsigned*))(kBase + kCodeOffset + ((uintptr_t)&tsd_spinner - (uintptr_t)tsd_code_begin)))(s->started, s->stop);
        return nullptr;
    }, &spin);
    while ( !started ) usleep(100);

    ProcSelfMemory proc;
    CHECK(proc.ok());
    for (uint32_t offset : kRegionOffsets) {
        PatchStats stats;
        CHECK(patcher.patchImage(kBase + offset, proc.memory(), &stats) == nullptr);
        CHECK(stats.sites == 2 && stats.veneers == 2 && stats.trapped == 0);
        // the veneer is in this region's gap, not another's
        for (uint32_t site : { kCodeOffset + (uint32_t)(tsd_read_site - tsd_code_begin), kCodeOffset + (uint32_t)(tsd_flags_site - tsd_code_begin) }) {
            const uint32_t word = *(const uint32_t*)(kBase + offset + site);
            int64_t imm = word & 0x03FFFFFF; if ( imm & 0x02000000 ) imm -= 0x04000000;
            const uintptr_t target = kBase + offset + site + imm * 4;
            CHECK((word & 0xFC000000U) == 0x14000000U && target >= kBase + offset + kGapOffset && target < kBase + offset + kGapOffset + kGapSize);
        }
    }
    stop = 1;
    pthread_join(spinner, nullptr);
    CHECK(spin.iterations > 0);

    pthread_t threads[4];
    for (uintptr_t i = 0; i != 4; ++i) CHECK(pthread_create(&threads[i], nullptr, worker, (void*)(i + 1)) == 0);
    // signals arrive while the threads run through veneers; each handler returns with the registers intact
    for (unsigned round = 0; round != 4000; ++round) {
        for (pthread_t t : threads) pthread_kill(t, SIGUSR1);
        if ( round % 8 == 0 ) usleep(50);
    }
    for (pthread_t t : threads) pthread_join(t, nullptr);
    CHECK(storms > 0 && veneerHits > 0);
    printf("native: %u signals, %u of them inside a veneer\n", storms.load(), veneerHits.load());

    // control for the spinner test: a writer that unprotects the page crashes a thread that runs in it
    pid_t child = fork();
    if ( child == 0 ) {
        signal(SIGSEGV, SIG_DFL);
        volatile unsigned char started2 = 0;
        volatile unsigned stop2 = 0;
        Spin spin2 = { &started2, &stop2, 0 };
        pthread_t t;
        pthread_create(&t, nullptr, [](void* p) -> void* {
            Spin* s = (Spin*)p;
            ((unsigned long(*)(volatile unsigned char*, volatile unsigned*))(kBase + kCodeOffset + ((uintptr_t)&tsd_spinner - (uintptr_t)tsd_code_begin)))(s->started, s->stop);
            return nullptr;
        }, &spin2);
        while ( !started2 ) usleep(100);
        uint32_t word = 0xD503201FU;
        for (int i = 0; i != 1000; ++i) mprotectWrite(nullptr, kBase + 0x40, &word, 4);
        _exit(0);
    }
    int status = 0;
    waitpid(child, &status, 0);
    CHECK(WIFSIGNALED(status) && WTERMSIG(status) == SIGSEGV);
}

void testNativeRun() { testNative(); }
