// Shared declarations of the ABI probe (see abi_harness.c for what the probe is and how to run it).
#ifndef ABI_HARNESS_H
#define ABI_HARNESS_H
#include "abi_decl.h"

#ifndef __has_feature
#define __has_feature(x) 0
#endif

#if __has_feature(ptrauth_intrinsics)
#define ARCH "arm64e"
#define HAS_PAC 1
#define STRIP(p) ((void *)__builtin_ptrauth_strip((void *)(p), 0))
#define SIGN_IA0(p) ((void *)__builtin_ptrauth_sign_unauthenticated((void *)(p), 0, 0))   /* what paciza makes */
/* what the compiler stores in a block literal's invoke field at address `slot` */
#define SIGN_FIELD(p, slot) ((void *)__builtin_ptrauth_sign_unauthenticated(                  \
    (void *)(p), 0, __builtin_ptrauth_blend_discriminator((void *)(slot), 0)))
#else
#ifdef ABI_NATIVE
#define ARCH "native"
#else
#define ARCH "arm64"
#endif
#define HAS_PAC 0
#define STRIP(p) ((void *)(p))
#define SIGN_IA0(p) ((void *)(p))
#define SIGN_FIELD(p, slot) ((void *)(p))
#endif

#if __has_feature(ptrauth_calls)
#define HAS_PAC_CALLS 1     /* the compiler signs the function pointers it makes */
#else
#define HAS_PAC_CALLS 0
#endif

// expect: the verdict a check must get, or NULL (the verdicts are the data). Grammar:
//   "ok"                               one verdict (ok, faulted, hung, failed) or "a|b", or "any" (recorded only)
//   "c1=ok,c2=any,c3=failed|faulted"   per configuration; the configuration is $PROBE_CONFIG ("none" if unset),
//                                      and a configuration without an entry is a mismatch
//   "<either form>;need=TEXT"          an "ok" verdict needs TEXT in the child's output (what the child
//                                      cannot see itself, such as output flushed by exit); a "faulted" one
//                                      needs it to show the child reached the fault judged, so a crash in
//                                      the wrong place is failed, not that check's fault
struct check { const char *name; int (*fn)(void); const char *expect; };
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
void note(const char *what, void *p);   // record a pointer a plain lib produced (not signed by the compiler)
void ok_mark(int n);                    // the check's callback or body ran
int fail(const char *why);              // print a reason, return 1

#ifndef ABI_NATIVE
struct blk { void *isa; int flags; int reserved; void *invoke; void *desc; };   // Block_layout
dispatch_block_t hand_block(const char *what, dispatch_block_t b, struct blk *scratch);
#endif
#endif
