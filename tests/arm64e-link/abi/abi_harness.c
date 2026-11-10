// ABI probe (plan rung L2): what does Darling's plain-arm64 libSystem family do with the
// pointers an arm64e executable hands it? The same source builds as arm64e (signed function
// pointers, block invoke pointers, signed return addresses) and as plain arm64 (the control).
//
//   abi_probe                 driver: run every check in its own child, print one RESULT per check
//   abi_probe mutate          same, but every pointer handed to the subject API is first stripped
//                             of its signature (xpaci): the mutation probe
//   abi_probe run N [0|1] [SET]  one check of SET (checks or selftest) in this process (the driver
//                             execs this); 1 = mutate
//   abi_probe selftest [mutate]  harness self-test: children with a known verdict, compared in code
//                             (EXPECT-MISMATCH, expect_mismatches=); also run with mutate
//   abi_probe list
//
// Output lines: "FAULT ..." (from the child's fault handler), "OKMARK nn" (the callback ran),
// "RESULT nn name verdict ...", "SUMMARY ...". Verdicts: ok, faulted, hung, failed.
#include "abi_harness.h"

#ifndef ABI_VARIANT
#define ABI_VARIANT "unset"
#endif

// ----------------------------------------------------------------------------- output
void put(const char *s) { size_t n = 0; while (s[n]) n++; write(1, s, n); }
void putdec(long v) {
    char b[24]; int i = 24; unsigned long u = v < 0 ? -(unsigned long)v : (unsigned long)v;
    do { b[--i] = '0' + u % 10; u /= 10; } while (u);
    if (v < 0) b[--i] = '-';
    write(1, b + i, 24 - i);
}
void puthex(uintptr_t v) {
    char b[18]; int i = 18;
    do { b[--i] = "0123456789abcdef"[v & 15]; v >>= 4; } while (v);
    b[--i] = 'x'; b[--i] = '0';
    write(1, b + i, 18 - i);
}
void putyn(int v) { put(v ? "yes" : "no"); }
void nl(void) { put("\n"); }

// ------------------------------------------------------------------- harness state
int g_mutate;
int g_check;
static const char *g_what = "";
static volatile uintptr_t g_orig, g_handed;   // the pointer as the compiler made it / as handed over

static void record(const char *what, void *orig, void *handed, int expect_signed) {
    g_what = what;
    g_orig = (uintptr_t)orig;
    g_handed = (uintptr_t)handed;
    put("HAND "); put(what); put(" orig="); puthex(g_orig); put(" handed="); puthex(g_handed);
    put(" expect_signed="); putyn(expect_signed);
    put(" orig_signed="); putyn(g_orig != (uintptr_t)STRIP((void *)g_orig));
    put(" handed_signed="); putyn(g_handed != (uintptr_t)STRIP((void *)g_handed)); nl();
}

// Record a pointer the compiler made (signed in an arm64e build) and hand it over; under mutation
// it is returned stripped.
void *hand(const char *what, void *p) {
    void *out = g_mutate ? STRIP(p) : p;
    record(what, p, out, HAS_PAC_CALLS);
    return out;
}

// Record a pointer that a plain lib produced: nothing signed it, so it is never mutated here.
void note(const char *what, void *p) { record(what, p, p, 0); }
void ok_mark(int n) { put("OKMARK "); putdec(n); nl(); }
int fail(const char *why) { put("CHECKFAIL "); put(why); nl(); return 1; }

#ifndef ABI_NATIVE
#define BLOCK_IS_GLOBAL (1 << 28)
// Hand a block to the subject. Under mutation the invoke pointer is stripped: in place for a stack
// block (the captures sit behind the header, so it cannot be copied), in a header copy for a
// global block (its literal is read-only and has no captures).
dispatch_block_t hand_block(const char *what, dispatch_block_t b, struct blk *scratch) {
    struct blk *l = (struct blk *)(void *)b;
    hand(what, l->invoke);
    if (!g_mutate) return b;
    if (l->flags & BLOCK_IS_GLOBAL) {
        *scratch = *l;
        scratch->invoke = STRIP(l->invoke);
        return (dispatch_block_t)(void *)scratch;
    }
    l->invoke = STRIP(l->invoke);
    return b;
}
#endif

// ------------------------------------------------------------------- fault handler
// Image table captured before the check runs, so the handler can name the library a pc or lr
// lies in without calling into dyld (offsets are resolved against the dylib's symbols offline).
#define MAX_IMAGES 160
static struct { uintptr_t base; const char *name; } g_images_tab[MAX_IMAGES];
static int g_nimages_tab;
#ifdef ABI_NATIVE
static void capture_images(void) { }   // no dyld image list: faults are located by address only
#else
static void capture_images(void) {
    uint32_t n = _dyld_image_count();
    for (uint32_t i = 0; i < n && g_nimages_tab < MAX_IMAGES; i++) {
        g_images_tab[g_nimages_tab].base = (uintptr_t)_dyld_get_image_header(i);
        g_images_tab[g_nimages_tab].name = _dyld_get_image_name(i);
        g_nimages_tab++;
    }
}
#endif
static void put_where(const char *label, uintptr_t a) {
    uintptr_t clean = (uintptr_t)STRIP((void *)a);
    int best = -1;
    for (int i = 0; i < g_nimages_tab; i++)
        if (g_images_tab[i].base <= clean && (best < 0 || g_images_tab[i].base > g_images_tab[best].base)) best = i;
    put(" "); put(label); put("_in=");
    if (best < 0 || clean - g_images_tab[best].base > 0x4000000) { put("none"); return; }
    put(g_images_tab[best].name); put("+"); puthex(clean - g_images_tab[best].base);
}

static void on_fault(int sig, siginfo_min *si, void *uc) {
    uintptr_t addr = (uintptr_t)si->si_addr;
#ifdef ABI_NATIVE
    uintptr_t pc = 0, lr = 0;
#ifdef __aarch64__
    pc = ((ucontext_t *)uc)->uc_mcontext.pc;
    lr = ((ucontext_t *)uc)->uc_mcontext.regs[30];
#endif
    put("FAULT check="); putdec(g_check); put(" sig="); putdec(sig);
    put(" si_code="); putdec(si->si_code); put(" si_addr="); puthex(addr);
    put(" pc="); puthex(pc); put(" lr="); puthex(lr);
#else
    char *mc = uc ? *(char **)((char *)uc + UC_MCONTEXT_OFFSET) : 0;
    uintptr_t pc = mc ? *(uintptr_t *)(mc + MC_PC_OFFSET) : 0;
    uintptr_t lr = mc ? *(uintptr_t *)(mc + MC_LR_OFFSET) : 0;
    put("FAULT check="); putdec(g_check); put(" sig="); putdec(sig);
    put(" si_code="); putdec(si->si_code); put(" si_addr="); puthex(addr);
    put(" pc="); puthex(pc); put(" lr="); puthex(lr);
    if (mc) {
        put(" far="); puthex(*(uintptr_t *)(mc + MC_FAR_OFFSET));
        put(" esr="); puthex(*(unsigned *)(mc + MC_ESR_OFFSET));
    }
#endif
    put_where("pc", pc); put_where("lr", lr);
    nl();
    put("FAULT-PTR what="); put(g_what); put(" orig="); puthex(g_orig); put(" handed="); puthex(g_handed);
    put(" orig_signed="); putyn(g_orig != (uintptr_t)STRIP((void *)g_orig));
    put(" handed_signed="); putyn(g_handed != (uintptr_t)STRIP((void *)g_handed));
    put(" addr_has_pac_bits="); putyn(addr != (uintptr_t)STRIP((void *)addr));
    put(" pc_has_pac_bits="); putyn(pc != (uintptr_t)STRIP((void *)pc));
    put(" addr_or_pc_is_handed="); putyn(g_handed && (addr == g_handed || pc == g_handed));
    put(" addr_or_pc_stripped_is_handed_stripped=");
    putyn(g_handed && ((uintptr_t)STRIP((void *)addr) == (uintptr_t)STRIP((void *)g_handed) ||
                       (uintptr_t)STRIP((void *)pc) == (uintptr_t)STRIP((void *)g_handed)));
    nl();
    _exit(70);
}

// The harness (not the subject) installs the handler with its own signature stripped, so a
// fault report does not depend on the thing under test. sigaction stores the pointer raw.
static void install_handlers(void) {
    static const int sigs[] = {SIGSEGV, SIGBUS, SIGILL, SIGTRAP, SIGABRT};
#ifdef ABI_NATIVE
    struct sigaction sa;
    sigemptyset(&sa.sa_mask);
    sa.sa_sigaction = on_fault;
    sa.sa_flags = SA_SIGINFO;
    for (unsigned i = 0; i < sizeof sigs / sizeof sigs[0]; i++) sigaction(sigs[i], &sa, 0);
#else
    struct sigaction sa;
    sa.handler = STRIP((void *)on_fault);
    sa.mask = 0;
    sa.flags = SA_SIGINFO;
    for (unsigned i = 0; i < sizeof sigs / sizeof sigs[0]; i++) sigaction(sigs[i], &sa, 0);
#endif
}

// Harness self-test (abi_probe selftest): one child per verdict class and per fault location, so a
// verdict in the real table can be trusted. Expected: ok, faulted x3 (main thread, thread, TSD
// destructor at thread exit), hung, failed.
static pthread_key_t st_key;
static void st_dtor(void *v) { (void)v; *(volatile int *)8 = 1; }
static void *st_thread_fault(void *a) { (void)a; *(volatile int *)8 = 1; return 0; }
static void *st_thread_setkey(void *a) { (void)a; pthread_setspecific(st_key, (void *)1); return 0; }
static int st_ok(void) { ok_mark(1); return 0; }
static int st_fault_main(void) { *(volatile int *)8 = 1; return 0; }
static int st_fault_thread(void) {
    pthread_t t;
    pthread_create(&t, 0, (void *(*)(void *))STRIP((void *)st_thread_fault), 0);
    pthread_join(t, 0);
    return 0;
}
static int st_fault_tsd_dtor(void) {
    pthread_t t;
    pthread_key_create(&st_key, (void (*)(void *))STRIP((void *)st_dtor));
    pthread_create(&t, 0, (void *(*)(void *))STRIP((void *)st_thread_setkey), 0);
    pthread_join(t, 0);
    return 0;
}
static int st_hang(void) { for (;;) { } }
static int st_fail(void) { return fail("deliberate failure, no OKMARK"); }
static int st_exit0_without_okmark(void) { return 0; }
// hand() must return its argument unchanged, or stripped under mutation
static int st_hand(void) {
    void *f = (void *)st_ok;
    void *h = hand("selftest.hand", f);
    if (g_mutate ? h != STRIP(f) : h != f) return fail("hand() returned the wrong pointer");
    ok_mark(g_check);
    return 0;
}
// STRIP removes what SIGN_IA0 adds, and the compiler signs function pointers (any of four: a zero
// PAC field is a 1 in 128 chance each)
static int st_strip(void) {
    void *fns[4] = {(void *)st_ok, (void *)st_hand, (void *)st_fail, (void *)st_hang};
    int signed_by_compiler = 0, signed_by_us = 0;
    for (int i = 0; i < 4; i++) {
        void *s = SIGN_IA0(STRIP(fns[i]));
        if (STRIP(s) != STRIP(fns[i])) return fail("STRIP(SIGN_IA0(f)) is not f");
        signed_by_us += s != STRIP(fns[i]);
        signed_by_compiler += fns[i] != STRIP(fns[i]);
    }
    if (HAS_PAC_CALLS && !(signed_by_us && signed_by_compiler)) return fail("nothing was signed");
    if (!HAS_PAC_CALLS && (signed_by_us || signed_by_compiler)) return fail("a plain build signed a pointer");
    ok_mark(g_check);
    return 0;
}

static const struct check selftests[] = {
    {"selftest_ok", st_ok, "ok"},
    {"selftest_fault_main_thread", st_fault_main, "faulted"},
    {"selftest_fault_in_thread", st_fault_thread, "faulted"},
    {"selftest_fault_in_tsd_destructor_at_thread_exit", st_fault_tsd_dtor, "faulted"},
    {"selftest_hang", st_hang, "hung"},
    {"selftest_failed_without_okmark", st_fail, "failed"},
    {"selftest_exit0_without_okmark_is_failed", st_exit0_without_okmark, "failed"},
    {"selftest_hand_returns_the_right_pointer", st_hand, "ok"},
    {"selftest_strip_and_sign_round_trip", st_strip, "ok"},
};
struct set { const char *name; const struct check *t; int n; };
static struct set sets[] = {
    {"checks", 0, 0},
    {"selftest", selftests, (int)(sizeof selftests / sizeof selftests[0])},
};
static const struct set *find_set(const char *name);

// ----------------------------------------------------------------------------- driver
static int streq(const char *a, const char *b) { while (*a && *a == *b) a++, b++; return *a == *b; }
static int atoi_(const char *s) { int v = 0; while (*s >= '0' && *s <= '9') v = v * 10 + *s++ - '0'; return v; }
static int contains(const char *hay, const char *needle) {
    for (; *hay; hay++) { const char *h = hay, *n = needle; while (*n && *h == *n) h++, n++; if (!*n) return 1; }
    return 0;
}
static const struct set *find_set(const char *name) {
    for (unsigned i = 0; i < sizeof sets / sizeof sets[0]; i++) if (streq(sets[i].name, name)) return &sets[i];
    return 0;
}
static const char *g_config = "none";   // $PROBE_CONFIG: which configuration this run measures

// The expectation grammar is in abi_harness.h. spec_alts finds the alternatives that apply to
// `config`: it returns the start of a "a|b" list and stores its length, or returns 0 when a keyed
// spec has no entry for the configuration.
static int spec_keyed(const char *spec) {
    for (const char *q = spec; *q && *q != ';'; q++) if (*q == '=') return 1;
    return 0;
}
static const char *spec_alts(const char *spec, const char *config, int *len) {
    const char *p = spec;
    int keyed = spec_keyed(spec);
    for (;;) {
        const char *key = p, *val = p;
        int klen = 0;
        if (keyed) {
            while (*val && *val != '=') val++;
            klen = (int)(val - key);
            val++;
        }
        const char *end = val;
        while (*end && *end != ',' && *end != ';') end++;
        int match = !keyed;
        if (keyed) {
            int i = 0;
            while (i < klen && config[i] == key[i]) i++;
            match = i == klen && !config[i];
        }
        if (match) { *len = (int)(end - val); return val; }
        if (*end != ',') return 0;
        p = end + 1;
    }
}
static int alt_has(const char *alts, int len, const char *verdict) {
    int vl = 0; while (verdict[vl]) vl++;
    for (int i = 0; i <= len;) {
        int j = i; while (j < len && alts[j] != '|') j++;
        if (j - i == vl) { int k = 0; while (k < vl && alts[i + k] == verdict[k]) k++; if (k == vl) return 1; }
        if (j - i == 3 && alts[i] == 'a' && alts[i + 1] == 'n' && alts[i + 2] == 'y') return 1;
        i = j + 1;
    }
    return 0;
}
// the TEXT of ";need=TEXT", copied into buf (empty if none)
static void spec_need(const char *spec, char *buf, int sz) {
    int n = 0; buf[0] = 0;
    for (const char *q = spec; *q; q++)
        if (q[0] == ';' && q[1] == 'n' && q[2] == 'e' && q[3] == 'e' && q[4] == 'd' && q[5] == '=') {
            for (q += 6; *q && n < sz - 1; q++) buf[n++] = *q;
            break;
        }
    buf[n] = 0;
}
static void putnum2(int n) { if (n < 10) put("0"); putdec(n); }

#define WATCHDOG_TICKS 12   /* seconds */
static int run_one(const char *self, const char *set, int n, int mutate, char *out, int outsz, int *status, int *hung,
                   int *truncated) {
    static char sink[256];
    int fd[2], len = 0; *hung = 0; *status = 0; *truncated = 0;
    if (pipe(fd)) return -1;
    pid_t pid = fork();
    if (pid < 0) return -1;
    if (pid == 0) {
        char num[8], *argv[6]; int i = 0;
        num[i++] = '0' + n / 10; num[i++] = '0' + n % 10; num[i] = 0;
        dup2(fd[1], 1); dup2(fd[1], 2); close(fd[0]); close(fd[1]);
        argv[0] = (char *)self; argv[1] = "run"; argv[2] = num; argv[3] = mutate ? "1" : "0"; argv[4] = (char *)set;
        argv[5] = 0;
        execv(self, argv);
        _exit(127);
    }
    close(fd[1]);
    int ticks = 0;
    for (;;) {
        struct pollfd p = {fd[0], 1, 0};
        int r = poll(&p, 1, 1000);
        if (r == 0) { if (++ticks >= WATCHDOG_TICKS) { *hung = 1; break; } continue; }
        if (r < 0) break;
        // keep draining once the buffer is full: a child blocked on (or killed by) a closed pipe
        // would otherwise be reported as faulted
        int room = outsz - 1 - len;
        ssize_t got = read(fd[0], room > 0 ? out + len : sink, room > 0 ? (size_t)room : sizeof sink);
        if (got <= 0) break;
        if (room > 0) len += (int)got; else *truncated = 1;
    }
    out[len] = 0;
    if (*hung) kill(pid, SIGKILL);
    close(fd[0]);
    for (int t = 0; t < 8; t++) {
        pid_t w = waitpid(pid, status, *hung ? 1 /* WNOHANG */ : 0);
        if (w == pid) return 0;
        struct pollfd none = {-1, 0, 0};
        poll(&none, 0, 1000);
    }
    return 0;
}

static void print_prefixed(const char *buf) {
    const char *line = buf;
    while (*line) {
        const char *e = line; while (*e && *e != '\n') e++;
        put("  | "); write(1, line, e - line); nl();
        line = *e ? e + 1 : e;
    }
}

static int driver(const char *self, const struct set *set, int mutate) {
    static char out[8192];
    int counts[4] = {0, 0, 0, 0};   // ok faulted hung failed
    int mismatches = 0, expecting = 0;
    put("ABI-PROBE arch="); put(ARCH); put(" set="); put(set->name); put(" mutate="); putdec(mutate);
    put(" variant="); put(ABI_VARIANT); put(" config="); put(g_config);
    put(" checks="); putdec(set->n); put(" fault_handler_signature_stripped_by_harness=1"); nl();
    for (int n = 1; n <= set->n; n++) {
        int status, hung, truncated;
        const char *verdict = "failed";
        if (run_one(self, set->name, n, mutate, out, sizeof out, &status, &hung, &truncated)) {
            out[0] = 0; status = 0; hung = 0; truncated = 0;
        }
        print_prefixed(out);
        int sig = status & 0x7f, code = (status >> 8) & 0xff;
        char mark[16] = "OKMARK ";
        int mi = 7;
        if (n >= 10) mark[mi++] = '0' + n / 10;
        mark[mi++] = '0' + n % 10; mark[mi++] = '\n'; mark[mi] = 0;
        if (hung) { verdict = "hung"; counts[2]++; }
        else if (sig && sig != 0x7f) { verdict = "faulted"; counts[1]++; }
        else if (code == 70) { verdict = "faulted"; counts[1]++; }
        // Darling ends a process whose fault cannot be delivered (a fault inside its signal
        // trampoline, check 18) with exit status 137: a death, not a result
        else if (code > 128) { verdict = "faulted"; counts[1]++; }
        else if (code == 0 && contains(out, mark)) {
            char need[64];
            if (set->t[n - 1].expect) spec_need(set->t[n - 1].expect, need, sizeof need); else need[0] = 0;
            if (need[0] && !contains(out, need)) counts[3]++;
            else { verdict = "ok"; counts[0]++; }
        }
        else counts[3]++;
        put("RESULT "); putnum2(n); put(" "); put(set->t[n - 1].name); put(" "); put(verdict);
        if (hung) put(" (no exit within the watchdog, killed)");
        else if (sig && sig != 0x7f) { put(" killed_by_signal="); putdec(sig); }
        else { put(" exit="); putdec(code); }
        // A signed pointer whose PAC field is all zero (about 1 in 128 with 7 PAC bits) is a valid
        // plain pointer, so a plain callee can use it: report it, it is not a pass of the ABI.
        if (!hung && code == 0 && !sig && !mutate && contains(out, mark) &&
            contains(out, "expect_signed=yes orig_signed=no"))
            put(" pac_field_was_zero=yes");
        if (truncated) put(" output_truncated=yes");
        if (set->t[n - 1].expect) {
            int alen = 0;
            const char *alts = spec_alts(set->t[n - 1].expect, g_config, &alen);
            expecting = 1;
            if (!alts || !alt_has(alts, alen, verdict)) {
                put(" EXPECT-MISMATCH expected="); put(alts ? "" : "(no entry for the configuration) ");
                for (int i = 0; alts && i < alen; i++) write(1, alts + i, 1);
                mismatches++;
            } else if (spec_keyed(set->t[n - 1].expect) && !(alen == 2 && alts[0] == 'o' && alts[1] == 'k')) {
                put(" expected_not_ok="); for (int i = 0; i < alen; i++) write(1, alts + i, 1);
            }
        }
        nl();
    }
    put("SUMMARY arch="); put(ARCH); put(" set="); put(set->name); put(" mutate="); putdec(mutate);
    put(" config="); put(g_config);
    put(" ok="); putdec(counts[0]); put(" faulted="); putdec(counts[1]);
    put(" hung="); putdec(counts[2]); put(" failed="); putdec(counts[3]);
    put(" expect_mismatches="); putdec(mismatches); nl();
    if (streq(set->name, "selftest") || expecting) return mismatches ? 1 : 0;
    return counts[0] == set->n ? 0 : 1;
}

int main(int argc, char **argv) {
    const char *cfg = getenv("PROBE_CONFIG");
    if (cfg && *cfg) g_config = cfg;
    sets[0].t = checks;
    sets[0].n = nchecks;
    const struct set *set = find_set(argc >= 5 ? argv[4] : "checks");
    if (argc >= 2 && streq(argv[1], "list")) {
        for (int i = 0; i < set->n; i++) { putnum2(i + 1); put(" "); put(set->t[i].name); nl(); }
        return 0;
    }
    if (argc >= 3 && streq(argv[1], "run")) {
        int n = atoi_(argv[2]);
        if (!set || n < 1 || n > set->n) { put("bad check number or set\n"); return 2; }
        g_check = n;
        g_mutate = argc >= 4 && streq(argv[3], "1");
        install_handlers();
        capture_images();
        return set->t[n - 1].fn();
    }
    int selftest = argc >= 2 && streq(argv[1], "selftest");
    int mutate = argc >= 2 && (streq(argv[1], "mutate") || (selftest && argc >= 3 && streq(argv[2], "mutate")));
    set = find_set(selftest ? "selftest" : "checks");
    return driver(argv[0], set, mutate);
}
