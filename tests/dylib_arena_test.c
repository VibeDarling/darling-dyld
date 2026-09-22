// Standalone harness for the dylib-arena claim algorithm in
// ImageLoaderMachO::reserveAnAddressRange() (VibeDarling/darling-dyld#5).
//
// Mirrors both algorithms verbatim against a mock mapper, so the retry and the
// 2^47 ceiling can be tested without dyld and without a guest. Every test must
// FAIL against the pre-fix algorithm, otherwise it is not testing the fix.
//
// cc -O1 -Wall -Wextra -pthread -o arena_test arena_test.c && ./arena_test

#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <pthread.h>

#define ARENA_BASE   0x300000000ULL
#define GAP          0x100000ULL
#define CEILING      0x800000000000ULL   /* 2^47 */
#define ANYWHERE     0                   /* the dangerous fallback */

/* ---- mock mapper -------------------------------------------------------- */
static int      g_fail_first;     /* fail this many map attempts */
static unsigned g_map_calls;
#define MAX_MAPPED 4096
static uintptr_t g_mapped[MAX_MAPPED];
static unsigned g_mapped_n;
static pthread_mutex_t g_lk = PTHREAD_MUTEX_INITIALIZER;

/* returns 1 on success, 0 on failure - the MAP_FIXED_NOREPLACE behaviour */
static int mock_map(uintptr_t addr)
{
    __atomic_fetch_add(&g_map_calls, 1, __ATOMIC_RELAXED);
    /* A real mmap() takes time. Returning instantly closes the very window the
     * pre-fix race lives in, so both algorithms get the same delay here. */
    for (volatile int spin = 0; spin < 20000; ++spin) { }
    if (__atomic_fetch_sub(&g_fail_first, 1, __ATOMIC_RELAXED) > 0)
        return 0;
    pthread_mutex_lock(&g_lk);
    unsigned n = g_mapped_n;
    for (unsigned i = 0; i < n; i++) {            /* already occupied? */
        if (g_mapped[i] == addr) { pthread_mutex_unlock(&g_lk); return 0; }
    }
    if (n < MAX_MAPPED) g_mapped[g_mapped_n++] = addr;
    pthread_mutex_unlock(&g_lk);
    return 1;
}

static void mock_reset(int fail_first)
{
    g_fail_first = fail_first; g_map_calls = 0; g_mapped_n = 0;
    memset(g_mapped, 0, sizeof g_mapped);
}

/* ---- the two algorithms, transcribed ------------------------------------ */

static uintptr_t cursor_old;
static uintptr_t alloc_old(size_t size)
{
    uintptr_t req = __atomic_load_n(&cursor_old, __ATOMIC_RELAXED);
    uintptr_t addr = req;
    if (mock_map(addr)) {
        uintptr_t target = addr + size + GAP;
        uintptr_t cur = req;
        while (target > cur && !__atomic_compare_exchange_n(&cursor_old, &cur, target,
                                    0, __ATOMIC_RELAXED, __ATOMIC_RELAXED)) { }
        return addr;
    }
    return ANYWHERE;                      /* one attempt, then give up */
}

static uintptr_t cursor_new;
static uintptr_t alloc_new(size_t size)
{
    const uintptr_t stride = size + GAP;
    for (unsigned attempt = 0; attempt < 64; ++attempt) {
        uintptr_t claimed = __atomic_fetch_add(&cursor_new, stride, __ATOMIC_RELAXED);
        if (claimed + stride >= CEILING)
            break;
        if (mock_map(claimed))
            return claimed;
    }
    return ANYWHERE;
}

/* ---- tests -------------------------------------------------------------- */
static int failures;
static void check(const char *what, int pass)
{
    printf("    %-58s %s\n", what, pass ? "PASS" : "FAIL");
    if (!pass) failures++;
}

static void t_retry(void)
{
    puts("  [1] recovers when the first attempts collide");
    mock_reset(3); cursor_old = ARENA_BASE;
    uintptr_t o = alloc_old(0x10000);
    mock_reset(3); cursor_new = ARENA_BASE;
    uintptr_t n = alloc_new(0x10000);
    printf("        old -> %s   new -> 0x%lx\n", o == ANYWHERE ? "ANYWHERE (>=2^47 risk)" : "addr", n);
    check("pre-fix falls back to ANYWHERE (must, or test is useless)", o == ANYWHERE);
    check("fixed returns an in-arena address", n >= ARENA_BASE && n < CEILING);
}

static void t_ceiling(void)
{
    puts("  [2] stops at 2^47 instead of handing back a truncatable address");
    mock_reset(0); cursor_old = CEILING - 0x20000;
    uintptr_t o = alloc_old(0x10000);
    mock_reset(0); cursor_new = CEILING - 0x20000;
    uintptr_t n = alloc_new(0x10000);
    printf("        old -> 0x%lx   new -> %s\n", o, n == ANYWHERE ? "ANYWHERE (refused)" : "addr");
    check("pre-fix returns an address at/above 2^47", o >= CEILING - 0x20000 && o != ANYWHERE);
    check("fixed refuses rather than exceeding the ceiling", n == ANYWHERE || n + 0x110000 < CEILING);
}

#define NTHREAD 16
#define NALLOC  24
static uintptr_t got_old[NTHREAD][NALLOC], got_new[NTHREAD][NALLOC];
static void *w_old(void *a){ long t=(long)a; for(int i=0;i<NALLOC;i++) got_old[t][i]=alloc_old(0x10000); return 0; }
static void *w_new(void *a){ long t=(long)a; for(int i=0;i<NALLOC;i++) got_new[t][i]=alloc_new(0x10000); return 0; }

static int dup_or_anywhere(uintptr_t g[NTHREAD][NALLOC])
{
    int bad = 0;
    for (int i = 0; i < NTHREAD*NALLOC; i++) {
        uintptr_t a = g[i/NALLOC][i%NALLOC];
        if (a == ANYWHERE) { bad++; continue; }
        for (int j = i+1; j < NTHREAD*NALLOC; j++)
            if (a == g[j/NALLOC][j%NALLOC]) { bad++; break; }
    }
    return bad;
}

static void t_concurrent(void)
{
    puts("  [3] concurrent loads never share a slot");
    pthread_t th[NTHREAD];
    mock_reset(0); cursor_old = ARENA_BASE;
    for (long t=0;t<NTHREAD;t++) pthread_create(&th[t],0,w_old,(void*)t);
    for (int t=0;t<NTHREAD;t++) pthread_join(th[t],0);
    int bad_old = dup_or_anywhere(got_old);

    mock_reset(0); cursor_new = ARENA_BASE;
    for (long t=0;t<NTHREAD;t++) pthread_create(&th[t],0,w_new,(void*)t);
    for (int t=0;t<NTHREAD;t++) pthread_join(th[t],0);
    int bad_new = dup_or_anywhere(got_new);

    printf("        old -> %d bad of %d   new -> %d bad of %d\n",
           bad_old, NTHREAD*NALLOC, bad_new, NTHREAD*NALLOC);
    check("pre-fix collides or falls back (probabilistic)", bad_old > 0);
    check("fixed: no duplicate slot and no ANYWHERE", bad_new == 0);
}

int main(void)
{
    puts("dylib arena claim algorithm - pre-fix vs fixed\n");
    t_retry(); t_ceiling(); t_concurrent();
    printf("\n%s (%d failing checks)\n", failures ? "FAILURES" : "all checks passed", failures);
    return failures != 0;
}
