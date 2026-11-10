// C++ exception checks for the ABI probe (checks 11-14). No headers: the compiler's own
// declarations of __cxa_throw / __gxx_personality_v0 / _Unwind_Resume resolve against Darling's
// plain-arm64 libc++abi and libunwind. In an arm64e build every function below has a signed
// return address (paciasp/pacibsp), the exception's typeinfo and destructor pointers are signed,
// and the personality reaches the unwinder through a signed GOT slot.
extern "C" {

static volatile int g_dtor_runs;

__attribute__((noinline)) static void throw_int(int v) { throw v; }

// 11: throw and catch in one frame (the unwinder still walks __cxa_throw's and throw_int's frames)
int cxx_same_frame(void) {
    try { throw_int(7); } catch (int v) { return v == 7 ? 0 : 1; }
    return 2;
}

// 12: the throwing frame is two signed frames below the catching one
__attribute__((noinline)) static int middle(int v) { throw_int(v + 1); return 0; }
__attribute__((noinline)) static int outer(int v) { return middle(v) + 1; }
int cxx_callee_frame(void) {
    try { outer(40); } catch (int v) { return v == 41 ? 0 : 1; }
    return 2;
}

// 13: a class type: typeinfo vptr and the __cxa_throw destructor pointer are signed, and the
// handler matches a base class through __si_class_type_info::can_catch (a virtual call on the
// signed typeinfo)
struct Base { virtual ~Base() {} virtual int id() { return 1; } };
struct Derived : Base { int v; explicit Derived(int x) : v(x) {} ~Derived() { g_dtor_runs++; } int id() override { return 2; } };
__attribute__((noinline)) static void throw_derived() { throw Derived(9); }
int cxx_class_base(void) {
    g_dtor_runs = 0;
    try { throw_derived(); } catch (Base &b) { if (b.id() != 2) return 1; }
    return g_dtor_runs >= 1 ? 0 : 3;
}

// 14: a cleanup landing pad in an intermediate frame (the unwinder calls back into the frame and
// the frame ends with _Unwind_Resume)
struct Guard { int *c; ~Guard() { ++*c; } };
__attribute__((noinline)) static void with_guard(int *c) { Guard g{c}; throw_int(1); }
int cxx_cleanup(void) {
    int c = 0;
    try { with_guard(&c); } catch (int) { return c == 1 ? 0 : 1; }
    return 2;
}


// 20: check 13's throw spelled out, so the destructor pointer that __cxa_throw stores (and
// libc++abi calls when the exception dies) can be stripped by itself: strip_dtor != 0 passes it
// unsigned. The thrown object is still a polymorphic class with a typeinfo and a signed vptr.
void *__cxa_allocate_exception(unsigned long);
void __cxa_throw(void *, void *, void (*)(void *));
extern char derived_typeinfo[] __asm__("__ZTI7Derived");
__attribute__((noinline)) static void derived_dtor(void *p) { static_cast<Derived *>(p)->~Derived(); }
inline void *operator new(unsigned long, void *p) noexcept { return p; }
int cxx_class_manual_throw(int strip_dtor) {
    g_dtor_runs = 0;
    (void)strip_dtor;
    void (*dtor)(void *) = derived_dtor;
#if __has_feature(ptrauth_intrinsics)
    if (strip_dtor) dtor = (void (*)(void *))__builtin_ptrauth_strip((void *)dtor, 0);
#endif
    try {
        void *ex = __cxa_allocate_exception(sizeof(Derived));
        new (ex) Derived(9);
        __cxa_throw(ex, derived_typeinfo, dtor);
    } catch (Base &b) { if (b.id() != 2) return 1; }
    return g_dtor_runs >= 1 ? 0 : 3;
}


// 24: a signed return address is corrupted (a PAC bit flipped) in the frame that throws. An authenticating
// unwinder ends the walk at that frame (no handler, terminate); one that strips resumes at the catch.
__attribute__((noinline)) static void corrupt_and_throw(void) {
    unsigned long *saved_lr = (unsigned long *)__builtin_frame_address(0) + 1;
    *saved_lr ^= 1UL << 50;
    throw_int(1);
}
int cxx_neg_return_address(void) {
    try { corrupt_and_throw(); } catch (int) { return 0; }
    return 2;
}


// 29-32: a frame that unwinds in DWARF mode (not compact). Apple's clang emits no negate_ra_state CFI for
// Mach-O, so such a frame in an arm64e image saves a signed return address (pacibsp, IB key, entry SP =
// CFA) with plain CFI offsets. The .cfi_escape (DW_CFA_GNU_args_size) is not expressible as a compact
// encoding and forces DWARF mode, as a function with a cleanup attribute does under clang. mode 1 flips a
// PAC bit in the saved lr before the callee runs, mode 2 overwrites it with the raw unsigned address.
#if __has_feature(ptrauth_returns)
#define DWF_SIGN "pacibsp\n"
#define DWF_RET "retab\n"
#define DWF_CORRUPT                                                                   \
    "ldr x9, [sp, #8]\n"                                                              \
    "cmp w1, #1\n b.eq Ldwf_flip\n cmp w1, #2\n b.ne Ldwf_call\n"                     \
    "xpaci x9\n b Ldwf_store\n"                                                       \
    "Ldwf_flip: eor x9, x9, #0x4000000000000\n"                                       \
    "Ldwf_store: str x9, [sp, #8]\n"
#else
#define DWF_SIGN ""
#define DWF_RET "ret\n"
#define DWF_CORRUPT ""
#endif
#if __has_feature(ptrauth_calls)
#define DWF_CALL "blraaz x0\n"
#else
#define DWF_CALL "blr x0\n"
#endif
__asm__(
    ".text\n.globl _dwarf_frame_call\n.p2align 2\n_dwarf_frame_call:\n"
    ".cfi_startproc\n"
    DWF_SIGN
    "stp x29, x30, [sp, #-16]!\n"
    ".cfi_def_cfa_offset 16\n.cfi_offset w29, -16\n.cfi_offset w30, -8\n"
    ".cfi_escape 0x2e, 0x00\n"
    "mov x29, sp\n.cfi_def_cfa w29, 16\n"
    DWF_CORRUPT
    "Ldwf_call: " DWF_CALL
    "ldp x29, x30, [sp], #16\n"
    DWF_RET
    ".cfi_endproc\n");
extern "C" int dwarf_frame_call(int (*)(void), int);
__attribute__((noinline)) static int thrower_cb(void) { throw_int(5); return 0; }
int cxx_dwarf_frame(int mode) {
    try { dwarf_frame_call(thrower_cb, mode); } catch (int v) { return v == 5 ? 0 : 1; }
    return 2;
}

}
