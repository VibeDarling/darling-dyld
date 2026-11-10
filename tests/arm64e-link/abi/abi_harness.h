// Shared declarations of the ABI probe (see abi_harness.c for what the probe is and how to run it).
#ifndef ABI_HARNESS_H
#define ABI_HARNESS_H
#include "abi_decl.h"

#if __has_feature(ptrauth_intrinsics)
#define ARCH "arm64e"
#define HAS_PAC 1
#define STRIP(p) ((void *)__builtin_ptrauth_strip((void *)(p), 0))
#define SIGN_IA0(p) ((void *)__builtin_ptrauth_sign_unauthenticated((void *)(p), 0, 0))   /* what paciza makes */
#else
#define ARCH "arm64"
#define HAS_PAC 0
#define STRIP(p) ((void *)(p))
#define SIGN_IA0(p) ((void *)(p))
#endif

struct check { const char *name; int (*fn)(void); };
extern const struct check checks[];     // the numbered checks, defined in abi_checks.c
extern const int nchecks;

void put(const char *s);
void putdec(long v);
void puthex(uintptr_t v);
void putyn(int v);
void nl(void);

extern int g_mutate;                    // 1: strip every pointer before handing it to the subject
extern int g_check;                     // number of the check running in this process
void *hand(const char *what, void *p);  // record (and under mutation strip) a pointer handed over
void ok_mark(int n);                    // the check's callback or body ran
int fail(const char *why);              // print a reason, return 1

struct blk { void *isa; int flags; int reserved; void *invoke; void *desc; };   // Block_layout
dispatch_block_t hand_block(const char *what, dispatch_block_t b, struct blk *scratch);
#endif
