// C++ exception checks for the ABI probe (checks 11-14). No SDK headers: the compiler's own
// declarations of __cxa_throw / __gxx_personality_v0 / _Unwind_Resume resolve against Darling's
// plain-arm64 libc++abi and libunwind. In an arm64e build every function below has a signed
// return address (paciasp/pacibsp), the exception's typeinfo and destructor pointers are signed,
// and the personality reaches the unwinder through a signed GOT slot.
extern "C" {
// The two harness services this file uses. abi_harness.h would also pull in the block types,
// which the C++ checks do not use and a compile without -fblocks refuses.
void *hand(const char *what, void *p);
#if __has_feature(ptrauth_intrinsics)
#define STRIP(p) ((void *)__builtin_ptrauth_strip((void *)(p), 0))
#else
#define STRIP(p) ((void *)(p))
#endif

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


// 24: a signed return address is corrupted (one signature bit flipped) in the frame that throws. An
// authenticating unwinder ends the walk at that frame (no handler, terminate); one that strips resumes
// at the catch. The flipped bit is taken from the signature itself (saved ^ xpaci(saved)), so it lies
// in the PAC field; a zero signature leaves the value unchanged and the check is not applicable. The
// saved lr is recorded so the harness can flag a zero PAC field.
static int g_ra_was_signed;
__attribute__((noinline)) static void corrupt_and_throw(void) {
    unsigned long *saved_lr = (unsigned long *)__builtin_frame_address(0) + 1;
    unsigned long signed_lr = *saved_lr;
    unsigned long signature = signed_lr ^ (unsigned long)STRIP((void *)signed_lr);
    g_ra_was_signed = signature != 0;
#if __has_feature(ptrauth_returns)
    hand("neg_return_address.saved_lr", (void *)signed_lr);
#endif
    *saved_lr = signed_lr ^ (signature & (0UL - signature));
    throw_int(1);
}
// 0: no signed return address to corrupt (the loop did not walk it); 1: the corrupted value resumed
// at the catch, so the unwinder accepted it.
int cxx_neg_return_address(void) {
    g_ra_was_signed = 0;
    try { corrupt_and_throw(); } catch (int) { return g_ra_was_signed ? 1 : 0; }
    return 2;
}


// 29-32: a frame that unwinds in DWARF mode (not compact). Inline asm has no compact-unwind entry, so the
// linker emits the DWARF-mode encoding for it. The frame's CFI states what the frame does, in the convention
// the open-source libunwind implements: the CIE's B augmentation marks the return address as signed with the
// B key (DwarfParser.hpp: 'B' -> addressesSignedWithBKey), and DW_CFA_AARCH64_negate_ra_state sets the RA
// sign state (DwarfInstructions.hpp: autib1716 with x16 = CFA when it is set). pacibsp signs with SP and
// CFA is the entry SP here, so the modifier agrees. mode 1 flips the lowest bit of the saved signature,
// mode 2 stores the unsigned address; both read the signature as saved ^ xpaci(saved), so a change is always
// inside the PAC field. A zero signature leaves either mode a no-op, and the caller records the saved lr so
// the harness flags it.
#if __has_feature(ptrauth_returns)
#define DWF_SIGN ".cfi_b_key_frame\n.cfi_negate_ra_state\npacibsp\n"
#define DWF_RET "retab\n"
#define DWF_CORRUPT                                                                   \
    "ldr x9, [sp, #8]\n"                                                              \
    "adrp x10, _g_dwf_saved_lr@PAGE\n"                                                \
    "add x10, x10, _g_dwf_saved_lr@PAGEOFF\n"                                         \
    "str x9, [x10]\n"                                                                 \
    "mov x13, x9\n"                                                                   \
    "xpaci x13\n"                                                                     \
    "eor x11, x9, x13\n"                                                              \
    "neg x12, x11\n"                                                                  \
    "and x11, x11, x12\n"                                                             \
    "cmp w1, #1\n b.eq Ldwf_flip\n cmp w1, #2\n b.ne Ldwf_call\n"                     \
    "mov x9, x13\n b Ldwf_store\n"                                                    \
    "Ldwf_flip: eor x9, x9, x11\n"                                                    \
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
unsigned long g_dwf_saved_lr;      /* the lr the frame saved, before corruption: the signature test */
__asm__(
    ".text\n.globl _dwarf_frame_call\n.p2align 2\n_dwarf_frame_call:\n"
    ".cfi_startproc\n"
    DWF_SIGN
    "stp x29, x30, [sp, #-16]!\n"
    ".cfi_def_cfa_offset 16\n.cfi_offset w29, -16\n.cfi_offset w30, -8\n"
    "mov x29, sp\n.cfi_def_cfa w29, 16\n"
    DWF_CORRUPT
    "Ldwf_call: " DWF_CALL
    "ldp x29, x30, [sp], #16\n"
    DWF_RET
    ".cfi_endproc\n");
extern "C" int dwarf_frame_call(int (*)(void), int);
__attribute__((noinline)) static int thrower_cb(void) { throw_int(5); return 0; }
int cxx_dwarf_frame(int mode) {
    int rc = 2;
    try { dwarf_frame_call(thrower_cb, mode); } catch (int v) { rc = v == 5 ? 0 : 1; }
#if __has_feature(ptrauth_returns)
    hand("dwarf_frame.saved_lr", (void *)g_dwf_saved_lr);
    if (rc == 0 && mode != 0 && g_dwf_saved_lr != (unsigned long)STRIP((void *)g_dwf_saved_lr))
        rc = 1;   /* there was a signature and the catch resumed: the unwinder did not authenticate it */
#endif
    return rc;
}

}
