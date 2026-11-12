// The rewrite of on-disk (plain arm64) images, checked against assembler output and run on the host.
#include "test_support.h"

#include <sys/mman.h>
#include <unistd.h>

extern "C" {
    extern uint32_t oracle_disk_in[3], oracle_disk_out[3], oracle_disk_lone_in[2], oracle_disk_lone_out[2], oracle_disk_miss_in[5], oracle_disk_miss_out[5], oracle_disk_end[];
}

static thread_local void* diskSlot;

void testDiskRewrite() {
    {   uint32_t code[3]; memcpy(code, oracle_disk_in, sizeof(code)); size_t n = 0;
        CHECK(rewriteDiskTSDReads(code, 3, 0x170, &n) && n == 1 && memcmp(code, oracle_disk_out, sizeof(code)) == 0); }
    {   uint32_t code[2]; memcpy(code, oracle_disk_lone_in, sizeof(code)); size_t n = 0;
        CHECK(rewriteDiskTSDReads(code, 2, 0x170, &n) && n == 1 && memcmp(code, oracle_disk_lone_out, sizeof(code)) == 0); }
    {   uint32_t code[5]; memcpy(code, oracle_disk_miss_in, sizeof(code)); size_t n = 0;
        CHECK(rewriteDiskTSDReads(code, 5, 0x170, &n) && n == 3 && memcmp(code, oracle_disk_miss_out, sizeof(code)) == 0); }
    // the old TP+64 slot is gone: a different offset gives a different load
    {   uint32_t code[3]; memcpy(code, oracle_disk_in, sizeof(code)); size_t n = 0;
        CHECK(rewriteDiskTSDReads(code, 3, 64, &n) && code[1] != oracle_disk_out[1] && (code[1] & 0xFFC003FFU) == (oracle_disk_out[1] & 0xFFC003FFU)); }
    // a loader that names no slot: everything else is still rewritten, and the caller is told
    {   uint32_t code[5]; memcpy(code, oracle_disk_in, 12); memcpy(code + 3, oracle_disk_lone_in, 8); size_t n = 0;
        CHECK(!rewriteDiskTSDReads(code, 5, ~0UL, &n) && n == 2 && code[0] == oracle_disk_out[0] && code[1] == oracle_disk_in[1] && code[3] == oracle_disk_lone_out[0]); }
    // the count bounds the scan: an and just past the end is not touched
    {   uint32_t code[3]; memcpy(code, oracle_disk_in, sizeof(code)); size_t n = 0;
        CHECK(rewriteDiskTSDReads(code, 1, 0x170, &n) && n == 1 && code[1] == oracle_disk_in[1]); }
    { uint32_t none[1] = { 0xD503201FU }; size_t n = 7; CHECK(rewriteDiskTSDReads(none, 1, ~0UL, &n) && n == 0); }

    // run it: the rewritten pthread_self shape returns the thread's slot, the original returns what Linux has in TPIDRRO_EL0
    const unsigned long slotOffset = (uintptr_t)&diskSlot - (uintptr_t)__builtin_thread_pointer();
    const size_t page = (size_t)sysconf(_SC_PAGESIZE);
    uint32_t* code = (uint32_t*)mmap(nullptr, page, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANON, -1, 0);
    memcpy(code, oracle_disk_in, 8);
    code[2] = 0xAA0903E0U;                                   // mov x0, x9
    code[3] = 0xD65F03C0U;                                   // ret
    __builtin___clear_cache((char*)code, (char*)code + 16);
    mprotect(code, page, PROT_READ | PROT_EXEC);
    static int marker;
    diskSlot = &marker;
    typedef void* (*Read)();
    CHECK(((Read)code)() == nullptr);                        // control: untranslated
    mprotect(code, page, PROT_READ | PROT_WRITE);
    size_t n = 0;
    CHECK(rewriteDiskTSDReads(code, 4, slotOffset, &n) && n == 1);
    __builtin___clear_cache((char*)code, (char*)code + 16);
    mprotect(code, page, PROT_READ | PROT_EXEC);
    CHECK(((Read)code)() == &marker);
    diskSlot = nullptr;
    CHECK(((Read)code)() == nullptr);
}
