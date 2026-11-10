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
extern int cxx_class_manual_throw(int strip_dtor);
static int c_cxx_class_dtor(void) { int r = cxx_class_manual_throw(g_mutate); if (!r) ok_mark(20); return r; }
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
// calls. The compiler authenticates the pointer before the call. Darling's dyld already returns it
// signed to an arm64e caller (HAND orig_signed=yes), so the unmutated run is the dyld side's own
// behaviour. Mutation strips it before the call: the call must then fault.
static int c_dlsym_result(void) {
    void *p = dlsym(RTLD_DEFAULT, "getpid");
    if (!p) return fail("dlsym returned NULL");
    p = hand("dlsym.result", p);     /* compiler-signed pointers are what mutation strips; here the lib signed it */
    pid_t (*fn)(void) = (pid_t (*)(void))p;
    if (fn() != getpid()) return fail("wrong result");
    ok_mark(16);
    return 0;
}

// 17 A block that plain libclosure copied and arm64e code then calls. The literal's invoke pointer is
// signed with the address of its own field; Block_copy moves the literal, so the signature no longer
// matches. Mutation re-signs the copy the way an arm64e Block_copy would.
static int c_block_copy_then_call(void) {
    int salt = 5;
    dispatch_block_t b = ^{ g_async_val = salt + 100; };
    struct blk *heap = (struct blk *)_Block_copy((void *)b);
    note("Block_copy.copy.invoke", heap->invoke);
    if (g_mutate) heap->invoke = SIGN_FIELD(STRIP(heap->invoke), &heap->invoke);
    g_async_val = 0;
    ((dispatch_block_t)(void *)heap)();
    if (g_async_val != 105) return fail("block ran with wrong captures");
    ok_mark(17);
    return 0;
}

// 18 A function pointer inside a struct handed to the plain lib (sigaction.sa_handler), called later
// by the lib's signal trampoline when the signal arrives.
static void h_usr1(int sig) { (void)sig; ok_mark(18); }
static int c_sigaction_handler(void) {
    struct sigaction sa;
    sa.handler = hand("sigaction.sa_handler", (void *)h_usr1);
    sa.mask = 0;
    sa.flags = 0;
    if (sigaction(SIGUSR1, &sa, 0)) return fail("sigaction failed");
    kill(getpid(), SIGUSR1);
    poll(0, 0, 300);
    return 0;
}

// 19 A pointer the plain lib stores and returns later (signal's previous handler), then called by
// arm64e code. The lib returns the raw value it was given; the first handler is installed with a
// stripped pointer (harness) so the check isolates the returned value. Mutation signs it.
static volatile int g_sig_ran;
static void sig_a(int sig) { (void)sig; g_sig_ran = 1; }
static void sig_b(int sig) { (void)sig; g_sig_ran = 2; }
static int c_signal_return(void) {
    signal(SIGUSR1, (sig_t)STRIP((void *)sig_a));
    sig_t old = signal(SIGUSR1, (sig_t)STRIP((void *)sig_b));
    note("signal.return", (void *)old);
    if (g_mutate) old = (sig_t)SIGN_IA0(old);
    old(SIGUSR1);
    if (g_sig_ran != 1) return fail("previous handler did not run");
    ok_mark(19);
    return 0;
}

// ---- T1 extras (libunwind PAC work): 21-23 hand libunwind a function pointer the compiler signed
// and expect it to run; 24-28 corrupt the signature and expect the unwinder to fault or abort, never to
// run the callback. 29-32 are the same for a DWARF-mode frame (abi_cxx.cpp, dwarf_frame_call).
// A negative check reports ok only when the corrupted value carried no signature (an unsigned build or
// a zero PAC field): there is nothing to authenticate. If it carried one and the subject used the
// corrupted value, the check fails (CHECKFAIL): the unwinder stripped the signature.
struct uex { unsigned long long exception_class; void (*exception_cleanup)(int, struct uex *);
             unsigned long long private_1, private_2; } __attribute__((aligned(16)));
extern void _Unwind_DeleteException(struct uex *);
extern int _Unwind_Backtrace(int (*)(void *, void *), void *);
extern int _Unwind_ForcedUnwind(struct uex *, int (*)(int, int, unsigned long long, struct uex *, void *, void *), void *);
static volatile int g_ran;
static void x_cleanup(int reason, struct uex *e) { (void)e; g_ran = reason; }
static int x_trace(void *ctx, void *ref) { (void)ctx; return ++*(int *)ref >= 2 ? 4 : 0; }
static int x_stop(int v, int a, unsigned long long c, struct uex *e, void *ctx, void *p) {
    (void)v; (void)a; (void)c; (void)e; (void)ctx; g_ran = 1; *(int *)p = 1; return 2; }

/* Flip the lowest set bit of p's signature. STRIP clears exactly the signature bits, so the flip
   lies in the PAC field; a pointer with no signature is returned unchanged. The selftest row
   selftest_corrupt_changes_signed_values proves this behaviourally in the guest. */
void *corrupt(void *p) {
    uintptr_t v = (uintptr_t)p, sig = v ^ (uintptr_t)STRIP(p);
    return (void *)(v ^ (sig & (0 - sig)));
}
static int signed_pointer(void *p) { return (uintptr_t)p != (uintptr_t)STRIP(p); }

/* A negative check that reaches the end of its body has seen the subject use the corrupted value
   (or the corrupted return address resume). With a signature that use is the defect the check exists
   to catch; without one the check does not apply and reports ok. */
static int neg_finished(int number, int applied, const char *why) {
    if (!applied) { ok_mark(number); return 0; }
    return fail(why);
}

static int c_x_cleanup(void) {
    struct uex e = {0}; g_ran = 0;
    e.exception_cleanup = (void (*)(int, struct uex *))hand("x_cleanup.cleanup", (void *)x_cleanup);
    _Unwind_DeleteException(&e);
    if (g_ran != 1) return fail("cleanup did not run with reason 1");
    ok_mark(21); return 0;
}
static int c_x_trace(void) {
    int n = 0;
    int r = _Unwind_Backtrace((int (*)(void *, void *))hand("x_trace.trace", (void *)x_trace), &n);
    if (n != 2 || r != 4) return fail("trace function not called twice or its result not returned");
    ok_mark(22); return 0;
}
static int c_x_stop(void) {
    struct uex e = {0}; int hit = 0;
    int r = _Unwind_ForcedUnwind(&e, (int (*)(int, int, unsigned long long, struct uex *, void *, void *))
                                     hand("x_stop.stop", (void *)x_stop), &hit);
    if (!hit) return fail("stop function not called");
    ok_mark(23); (void)r; return 0;
}
extern int cxx_neg_return_address(void);
static int c_n_ra(void) {
    int r = cxx_neg_return_address();
    return neg_finished(24, r != 0,
                        r == 2 ? "no catch and no fault" : "the corrupted return address resumed at the catch");
}
static int c_n_cleanup(void) {
    struct uex e = {0}; g_ran = 0;
    void (*cleanup)(int, struct uex *) = (void (*)(int, struct uex *))hand("neg_cleanup.cleanup", (void *)x_cleanup);
    int applied = signed_pointer((void *)cleanup);
    e.exception_cleanup = (void (*)(int, struct uex *))corrupt((void *)cleanup);
    _Unwind_DeleteException(&e);
    if (!g_ran) return fail("the corrupted cleanup was not called");
    return neg_finished(25, applied, "the unwinder called a corrupted cleanup pointer");
}
static int c_n_trace(void) {
    int n = 0;
    int (*trace)(void *, void *) = (int (*)(void *, void *))hand("neg_trace.trace", (void *)x_trace);
    int applied = signed_pointer((void *)trace);
    _Unwind_Backtrace((int (*)(void *, void *))corrupt((void *)trace), &n);
    if (!n) return fail("the corrupted trace function was not called");
    return neg_finished(26, applied, "the unwinder called a corrupted trace function");
}
static int c_n_stop(void) {
    struct uex e = {0}; int hit = 0;
    int (*stopfn)(int, int, unsigned long long, struct uex *, void *, void *) =
        (int (*)(int, int, unsigned long long, struct uex *, void *, void *))hand("neg_stop.stop", (void *)x_stop);
    int applied = signed_pointer((void *)stopfn);
    _Unwind_ForcedUnwind(&e, (int (*)(int, int, unsigned long long, struct uex *, void *, void *))
                             corrupt((void *)stopfn), &hit);
    if (!hit) return fail("the corrupted stop function was not called");
    return neg_finished(27, applied, "the unwinder called a corrupted stop function");
}

// 28: the personality's GOT slot is corrupted (one signature bit flipped) before a throw: an
// authenticating unwinder calls a poisoned pointer (fault); one that strips calls the real personality.
extern int mprotect(void *, size_t, int);
extern int cxx_same_frame(void);
static int c_n_personality(void) {
    const unsigned char *mh = (const unsigned char *)_dyld_get_image_header(0);
    const unsigned char *lc = mh + 32;
    uintptr_t text_vmaddr = 0; const unsigned char *ui = 0;
    for (uint32_t i = 0; i < *(const uint32_t *)(mh + 16); i++, lc += *(const uint32_t *)(lc + 4)) {
        if (*(const uint32_t *)lc != 0x19 || lc[8] != '_' || lc[9] != '_' || lc[10] != 'T' || lc[11] != 'E') continue;
        text_vmaddr = *(const uintptr_t *)(lc + 24);
        uint32_t nsects = *(const uint32_t *)(lc + 64);
        const unsigned char *sc = lc + 72;
        for (uint32_t j = 0; j < nsects; j++, sc += 80)
            if (sc[0] == '_' && sc[2] == 'u' && sc[3] == 'n' && sc[4] == 'w' && sc[5] == 'i' && sc[6] == 'n' && sc[7] == 'd' && sc[8] == '_' && sc[9] == 'i')
                ui = (const unsigned char *)((uintptr_t)mh - text_vmaddr + *(const uintptr_t *)(sc + 32));
    }
    if (!ui) return fail("no __unwind_info");
    uint32_t poff = *(const uint32_t *)(ui + 12), pcount = *(const uint32_t *)(ui + 16);
    put("personality slots="); putdec(pcount); nl();
    if (!pcount) return fail("no personality slots");
    int applied = 0;
    for (uint32_t i = 0; i < pcount; i++) {
        uintptr_t *slot = (uintptr_t *)(mh + *(const uint32_t *)(ui + poff + 4 * i));
        if (mprotect((void *)((uintptr_t)slot & ~16383UL), 16384, 3)) return fail("mprotect failed");
        uintptr_t word = *slot;
        applied |= signed_pointer((void *)word);
        *slot = (uintptr_t)corrupt((void *)word);
    }
    int r = cxx_same_frame();
    if (r) return fail("the throw through the corrupted personality slot failed for another reason");
    return neg_finished(28, applied, "the unwinder called a corrupted personality pointer");
}

// 29-32 a DWARF-mode frame (abi_cxx.cpp, dwarf_frame_call) in the middle of the stack.
extern int dwarf_frame_call(int (*)(void), int);
extern int cxx_dwarf_frame(int mode);
extern unsigned long g_dwf_saved_lr;
static int dwf_walk(void) {
    char ctx[1024] __attribute__((aligned(16))), cur[2048] __attribute__((aligned(16)));
    int frames = 0, bad = 0, found = 0, after = 0;
    if (unw_getcontext(ctx) || unw_init_local(cur, ctx)) return fail("unw_getcontext/unw_init_local failed");
    for (;;) {
        uintptr_t ip = 0, pi[16] = {0};
        unw_get_reg(cur, UNW_REG_IP, &ip);
        int rc = unw_get_proc_info(cur, pi);
        if (rc || ip != (uintptr_t)STRIP((void *)ip)) bad++;
        if (pi[0] == (uintptr_t)STRIP((void *)dwarf_frame_call)) {
            found = 1;
            put("DWARF-FRAME format="); puthex((uint32_t)pi[6]); nl();
            if (((uint32_t)pi[6] & 0x0f000000) != 0x03000000) bad++;
        } else if (found) after++;
        frames++;
        if (unw_step(cur) <= 0 || frames >= 16) break;
    }
    put("frames="); putdec(frames); put(" after="); putdec(after); put(" bad="); putdec(bad); nl();
    if (!found) return fail("dwarf_frame_call frame not seen");
    if (bad) return fail("a frame has a signed ip, no unwind info, or is not in DWARF mode");
    if (after < 2) return fail("the walk ended too soon after the DWARF frame");
    return 0;
}
// 31/32 corrupt the frame, so a fault after that is only the authentication if the unwinder can see
// the frame at all: walk to it first, or a frame it never found would be reported as a refusal.
static int dwf_preflight(void) {
    return dwarf_frame_call(dwf_walk, 0) ? fail("the DWARF frame was not found before the corruption test") : 0;
}
static int c_dwf_walk(void) {
    int r = dwarf_frame_call(dwf_walk, 0);
#if __has_feature(ptrauth_returns)
    hand("dwarf_frame.saved_lr", (void *)g_dwf_saved_lr);
#endif
    if (!r) ok_mark(29);
    return r;
}
static int c_dwf_throw(void) {
    int r = cxx_dwarf_frame(0);
    if (r) return fail("throw and catch through the DWARF frame failed");
    ok_mark(30); return 0;
}
static int c_dwf_flip(void) {
    if (dwf_preflight()) return 1;
    int r = cxx_dwarf_frame(1);
    return neg_finished(31, r != 0, "the corrupted DWARF return address was accepted");
}
static int c_dwf_unsigned(void) {
    if (dwf_preflight()) return 1;
    int r = cxx_dwarf_frame(2);
    return neg_finished(32, r != 0, "the corrupted DWARF return address was accepted");
}

// expect is the verdict the check must get in the reference run (arm64e, unmutated); the driver
// compares it there only. Checks 01-20 are the measurement and carry none. A negative check expects
// faulted; a stripping unwinder makes it fail instead.
const struct check checks[] = {
    {"atexit", c_atexit, 0},
    {"cxa_atexit", c_cxa_atexit, 0},
    {"pthread_key_destructor", c_key_dtor, 0},
    {"pthread_create_start", c_pthread_start, 0},
    {"pthread_once", c_once, 0},
    {"qsort_comparator", c_qsort, 0},
    {"dispatch_async_stack_block", c_async_stack, 0},
    {"dispatch_async_global_block", c_async_global, 0},
    {"dispatch_once_block", c_dispatch_once, 0},
    {"dyld_add_image_callback", c_dyld_add_image, 0},
    {"cxx_throw_catch_same_frame", c_cxx_same, 0},
    {"cxx_throw_through_callee_frame", c_cxx_callee, 0},
    {"cxx_throw_class_base_catch", c_cxx_class, 0},
    {"cxx_cleanup_landing_pad", c_cxx_cleanup, 0},
    {"libunwind_walk_signed_frames", c_unwind_walk, 0},
    {"dlsym_result_called_by_arm64e", c_dlsym_result, 0},
    {"block_copy_then_called_by_arm64e", c_block_copy_then_call, 0},
    {"sigaction_handler_in_struct", c_sigaction_handler, 0},
    {"signal_return_value_called_by_arm64e", c_signal_return, 0},
    {"cxx_class_throw_manual_dtor_pointer", c_cxx_class_dtor, 0},
    {"x_unwind_delete_exception_cleanup", c_x_cleanup, "ok"},
    {"x_unwind_backtrace_callback", c_x_trace, "ok"},
    {"x_unwind_forced_stop_callback", c_x_stop, "ok"},
    {"neg_corrupt_return_address", c_n_ra, "faulted"},
    {"neg_corrupt_exception_cleanup", c_n_cleanup, "faulted"},
    {"neg_corrupt_backtrace_callback", c_n_trace, "faulted"},
    {"neg_corrupt_forced_stop_callback", c_n_stop, "faulted"},
    {"neg_corrupt_personality_slot", c_n_personality, "faulted"},
    {"dwarf_frame_walk", c_dwf_walk, "ok"},
    {"dwarf_frame_throw_catch", c_dwf_throw, "ok"},
    {"neg_dwarf_frame_flip_pac_bit", c_dwf_flip, "faulted"},
    {"neg_dwarf_frame_unsigned_lr", c_dwf_unsigned, "faulted"},
};
const int nchecks = (int)(sizeof checks / sizeof checks[0]);
