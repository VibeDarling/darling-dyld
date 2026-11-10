// The harness (../abi/abi_harness.c, plain C) as the C++ checks see it. The checks do not include
// abi_harness.h: its hand-written libSystem declarations would clash with the libc++ headers.
#ifndef L4_IFACE_H
#define L4_IFACE_H

#ifndef __has_feature
#define __has_feature(x) 0
#endif
// Without pointer authentication (the plain control and the native build) these are the identity, so that every build
// compiles the same checks and references the same names; the checks that depend on a signature are recorded only there.
#if __has_feature(ptrauth_intrinsics)
#define L4_STRIP(p) ((void *)__builtin_ptrauth_strip((void *)(p), 0))
#define L4_SIGN(p, key, disc) ((void *)__builtin_ptrauth_sign_unauthenticated((void *)(p), (key), (disc)))
#define L4_BLEND(address, disc) ((unsigned long)__builtin_ptrauth_blend_discriminator((void *)(address), (disc)))
#else
#define L4_STRIP(p) ((void *)(p))
#define L4_SIGN(p, key, disc) ((void *)(p))
#define L4_BLEND(address, disc) ((unsigned long)(address))
#endif

extern "C" {
void put(const char *s);
void putdec(long v);
void puthex(unsigned long v);
void nl(void);
void ok_mark(int n);
int fail(const char *why);
extern int g_check;                    // number of the check running in this process

// the harness's table type; expect and need are the grammar in abi_harness.h
struct check { const char *name; int (*fn)(void); const char *expect; };
extern const struct check checks[];
extern const int nchecks;
}

#endif
