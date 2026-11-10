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

}
