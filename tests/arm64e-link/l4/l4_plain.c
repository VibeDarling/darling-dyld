/* A plain arm64 dylib that binds the shared cache's libc++ handler functions, so that the arm64e probe can drive the
   dyld reverse adapters from real plain code (z1..z8 of l4_checks.cpp). Built by build_plain_dylib.py, loaded by dlopen
   from the directory of the probe executable. */
typedef void (*handler_t)(void);
extern handler_t cxx_set_terminate(handler_t) __asm__("__ZSt13set_terminatePFvvE");
extern handler_t cxx_get_terminate(void) __asm__("__ZSt13get_terminatev");

__attribute__((noinline, visibility("default"))) handler_t plain_set_terminate(handler_t h) { return cxx_set_terminate(h); }
__attribute__((noinline, visibility("default"))) handler_t plain_get_terminate(void) { return cxx_get_terminate(); }
/* a function entry of a plain image, with enough body that entry + 4 is still inside it */
__attribute__((noinline, visibility("default"))) void plain_entry(void) { __asm__ volatile("nop\n nop\n nop\n nop"); }
__attribute__((visibility("default"))) int plain_data = 7;
