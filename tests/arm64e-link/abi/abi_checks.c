// The numbered checks of the ABI probe: pointers an executable hands to Darling's libSystem family,
// libc++abi and libunwind. abi_harness.c runs them; abi_cxx.cpp holds the C++ ones.
#include "abi_harness.h"

// ----------------------------------------------------------------------------- checks
// 01 atexit
static void h_atexit(void) { ok_mark(1); }
static int c_atexit(void) {
    if (atexit((void (*)(void))hand("atexit.fn", (void *)h_atexit))) return fail("atexit failed");
    exit(0);
}

// 02 __cxa_atexit
static void h_cxa(void *arg) { if (arg == (void *)0x1234) ok_mark(2); else fail("wrong argument"); }
static int c_cxa_atexit(void) {
    if (__cxa_atexit((void (*)(void *))hand("cxa_atexit.fn", (void *)h_cxa), (void *)0x1234, &__dso_handle))
        return fail("__cxa_atexit failed");
    exit(0);
}

// 03 pthread_key_create destructor at thread exit. The start routine is stripped by the harness
// in every mode so that the check isolates the destructor (check 04 covers start routines).
static pthread_key_t g_key;
static volatile int g_dtor_seen;
static void key_dtor(void *v) { if (v == (void *)0x55) { g_dtor_seen = 1; ok_mark(3); } }
static void *thr_set(void *arg) { pthread_setspecific(g_key, (void *)0x55); return arg; }
static int c_key_dtor(void) {
    pthread_t t;
    if (pthread_key_create(&g_key, (void (*)(void *))hand("pthread_key.destructor", (void *)key_dtor)))
        return fail("pthread_key_create failed");
    if (pthread_create(&t, 0, (void *(*)(void *))STRIP((void *)thr_set), 0)) return fail("pthread_create failed");
    pthread_join(t, 0);
    return g_dtor_seen ? 0 : fail("destructor did not run");
}

// 04 pthread_create start routine
static void *thr_run(void *arg) { return (void *)((intptr_t)arg + 1); }
static int c_pthread_start(void) {
    pthread_t t; void *rv = 0;
    if (pthread_create(&t, 0, (void *(*)(void *))hand("pthread_create.start", (void *)thr_run), (void *)41))
        return fail("pthread_create failed");
    pthread_join(t, &rv);
    if (rv != (void *)42) return fail("wrong return value");
    ok_mark(4);
    return 0;
}

// 05 pthread_once
static volatile int g_once_runs;
static void once_init(void) { g_once_runs++; }
static int c_once(void) {
    static pthread_once_t once = PTHREAD_ONCE_INIT;
    void (*fn)(void) = (void (*)(void))hand("pthread_once.init", (void *)once_init);
    pthread_once(&once, fn);
    pthread_once(&once, fn);
    if (g_once_runs != 1) return fail("init routine did not run exactly once");
    ok_mark(5);
    return 0;
}

// 06 qsort comparator
static volatile int g_cmp_calls;
static int cmp_int(const void *a, const void *b) {
    g_cmp_calls++;
    int x = *(const int *)a, y = *(const int *)b;
    return x < y ? -1 : x > y;
}
static int c_qsort(void) {
    int v[8] = {5, 3, 8, 1, 9, 2, 7, 4};
    qsort(v, 8, sizeof v[0], (int (*)(const void *, const void *))hand("qsort.cmp", (void *)cmp_int));
    for (int i = 0; i < 8; i++) if (v[i] != i + 1 + (i >= 5)) return fail("not sorted");
    if (!g_cmp_calls) return fail("comparator never called");
    ok_mark(6);
    return 0;
}

// 07 dispatch_async with a capturing (stack) block: the invoke pointer is signed with the address
// of the block's invoke field, and Block_copy moves the block
static volatile int g_async_val;
static dispatch_semaphore_t g_sem;
static int wait_async(int want, int mark) {
    if (dispatch_semaphore_wait(g_sem, dispatch_time(0, 5000000000LL))) return fail("block never ran (5 s)");
    if (g_async_val != want) return fail("block ran with wrong captures");
    ok_mark(mark);
    return 0;
}
static int c_async_stack(void) {
    struct blk scratch;
    g_sem = dispatch_semaphore_create(0);
    dispatch_semaphore_t sem = g_sem;
    int salt = 41;
    dispatch_block_t b = ^{ g_async_val = salt + 1; dispatch_semaphore_signal(sem); };
    dispatch_async(dispatch_get_global_queue(0, 0), hand_block("dispatch_async.block.invoke", b, &scratch));
    return wait_async(42, 7);
}

// 08 dispatch_async with a global block (no captures; Block_copy returns it unchanged)
static int c_async_global(void) {
    struct blk scratch;
    g_sem = dispatch_semaphore_create(0);
    dispatch_block_t b = ^{ g_async_val = 43; dispatch_semaphore_signal(g_sem); };
    dispatch_async(dispatch_get_global_queue(0, 0), hand_block("dispatch_async.globalblock.invoke", b, &scratch));
    return wait_async(43, 8);
}

// 09 dispatch_once with a capturing block
static int c_dispatch_once(void) {
    static dispatch_once_t tok;
    struct blk scratch;
    int salt = 70;
    g_async_val = 0;
    dispatch_block_t b = ^{ g_async_val = salt + 4; };
    dispatch_once(&tok, hand_block("dispatch_once.block.invoke", b, &scratch));
    if (g_async_val != 74) return fail("block did not run");
    ok_mark(9);
    return 0;
}

// 10 _dyld_register_func_for_add_image: dyld calls the callback at once for each loaded image
static volatile int g_images;
static void on_image(const void *mh, intptr_t slide) { (void)mh; (void)slide; g_images++; }
static int c_dyld_add_image(void) {
    _dyld_register_func_for_add_image((void (*)(const void *, intptr_t))hand("dyld.add_image.cb", (void *)on_image));
    if (g_images < 1) return fail("callback not called for the loaded images");
    put("images="); putdec(g_images); nl();
    ok_mark(10);
    return 0;
}

// 11-14 C++ exceptions through Darling's libc++abi and libunwind (abi_cxx.cpp)
extern int cxx_same_frame(void), cxx_callee_frame(void), cxx_class_base(void), cxx_cleanup(void);
static int c_cxx_same(void) { int r = cxx_same_frame(); if (!r) ok_mark(11); return r; }
static int c_cxx_callee(void) { int r = cxx_callee_frame(); if (!r) ok_mark(12); return r; }
static int c_cxx_class(void) { int r = cxx_class_base(); if (!r) ok_mark(13); return r; }
static int c_cxx_cleanup(void) { int r = cxx_cleanup(); if (!r) ok_mark(14); return r; }

// 15 Darling's libunwind walking signed frames: diagnostic for 11-14. Walks four nested frames of
// this executable with unw_step and prints, per frame, the return address as the unwinder reports
// it (does it still carry a signature?), whether the frame's unwind info is found and the
// personality pointer the unwinder read (is it signed?). The unwind_info_size field of
// unw_proc_info_t is 0 when no info was found.
#define WALK_DEPTH 3
__attribute__((noinline, disable_tail_calls)) static int walk(int depth) {
    if (depth) return walk(depth - 1) + g_check - g_check;
    char ctx[1024] __attribute__((aligned(16))), cur[2048] __attribute__((aligned(16)));
    int frames = 0, bad = 0;
    if (unw_getcontext(ctx) || unw_init_local(cur, ctx)) return fail("unw_getcontext/unw_init_local failed");
    for (;;) {
        uintptr_t ip = 0, pi[16] = {0};
        unw_get_reg(cur, UNW_REG_IP, &ip);
        int rc = unw_get_proc_info(cur, pi);
        int ip_signed = ip != (uintptr_t)STRIP((void *)ip);
        int h_signed = pi[3] != (uintptr_t)STRIP((void *)pi[3]);
        put("FRAME "); putdec(frames); put(" ip="); puthex(ip); put(" ip_signed="); putyn(ip_signed);
        put(" proc_info_rc="); putdec(rc); put(" start_ip="); puthex(pi[0]);
        put(" handler="); puthex(pi[3]); put(" handler_signed="); putyn(h_signed); nl();
        if (rc || ip_signed) bad++;
        frames++;
        int st = unw_step(cur);
        if (st <= 0) { put("unw_step="); putdec(st); nl(); if (st < 0) bad++; break; }
        if (frames >= 16) break;
    }
    put("frames="); putdec(frames); put(" bad="); putdec(bad); nl();
    if (frames < WALK_DEPTH + 2) return fail("walk ended early");
    return bad ? fail("a frame has a signed ip or no unwind info") : 0;
}
static int c_unwind_walk(void) { int r = walk(WALK_DEPTH); if (!r) ok_mark(15); return r; }


// 16 The reverse direction: a function pointer that a plain lib returns (dlsym) and this arm64e code
// calls. The compiler authenticates the pointer before the call and the plain lib returns it
// unsigned. Under mutation the harness signs it the way the compiler would (IA, discriminator 0).
static int c_dlsym_result(void) {
    void *p = dlsym(RTLD_DEFAULT, "getpid");
    if (!p) return fail("dlsym returned NULL");
    p = hand("dlsym.result", p);
    if (g_mutate) p = SIGN_IA0(p);
    pid_t (*fn)(void) = (pid_t (*)(void))p;
    if (fn() != getpid()) return fail("wrong result");
    ok_mark(16);
    return 0;
}

const struct check checks[] = {
    {"atexit", c_atexit},
    {"cxa_atexit", c_cxa_atexit},
    {"pthread_key_destructor", c_key_dtor},
    {"pthread_create_start", c_pthread_start},
    {"pthread_once", c_once},
    {"qsort_comparator", c_qsort},
    {"dispatch_async_stack_block", c_async_stack},
    {"dispatch_async_global_block", c_async_global},
    {"dispatch_once_block", c_dispatch_once},
    {"dyld_add_image_callback", c_dyld_add_image},
    {"cxx_throw_catch_same_frame", c_cxx_same},
    {"cxx_throw_through_callee_frame", c_cxx_callee},
    {"cxx_throw_class_base_catch", c_cxx_class},
    {"cxx_cleanup_landing_pad", c_cxx_cleanup},
    {"libunwind_walk_signed_frames", c_unwind_walk},
    {"dlsym_result_called_by_arm64e", c_dlsym_result},
};
const int nchecks = (int)(sizeof checks / sizeof checks[0]);
