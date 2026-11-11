// L5 exit proof (plan rung L5): the cache's arm64e libobjc, served by Darling's plain-arm64 dyld2
// loader. One C file, no Objective-C compiler: the runtime entry points are declared locally and
// every message goes through a cast objc_msgSend.
//
//   l5_probe                     driver: one child per check, a fault handler and a 12 s watchdog
//   l5_probe run N [0|1] [SET]   one check of SET in this process (the driver execs this)
//   l5_probe selftest            driver over known-verdict children, compared in code
//   l5_probe selftest-wrong      same, with one deliberately wrong expectation (must exit 1)
//   l5_probe list                the check table
//
// The driver (from ../abi/abi_harness.c, reused whole) prints exactly one OKMARK line per check and
// the FAILED/HUNG/FAULT lines for the failure paths. Check 01's policy field is filled in by the
// driver from the loader's own "cache load source" line in the child's output, never from a file.
#define main abi_harness_unused_main
#include "../abi/abi_harness.c"
#undef main
#include "l5_decl.h"

// The expected -hash value is the instance's own address (NSObject -hash returns self); the skew is
// the mutation: -DL5_HASH_SKEW=1 must make the native selftest report the hash child as failed.
#ifndef L5_HASH_SKEW
#define L5_HASH_SKEW 0
#endif

// Facts the checks gate on, never values read back from the accessors under test: 221074 =
// 186655 occupied + 34419 duplicate class entries; the cache libobjc's __objc_classlist is 0x28 bytes.
#define L5_CLASS_COUNT    221074u
#define L5_CLASSLIST_SIZE ((size_t)0x28)

// ----------------------------------------------------------------------------- L5 output
static void l5_put2(int n) { if (n < 10) put("0"); putdec(n); }
static void l5_ok(int n) { put("OKMARK "); l5_put2(n); put(" selftest=ok"); nl(); }
static int l5_fail(const char *why) {
    put("FAILED check="); l5_put2(g_check); put(" reason="); put(why); nl();
    return 1;
}

static int l5_hash_ok(uintptr_t h1, uintptr_t h2, uintptr_t obj) {
    return h1 == h2 && h1 == obj + L5_HASH_SKEW;
}

// ------------------------------------------------------------------- driver helpers
static int l5_starts(const char *s, const char *prefix) {
    while (*prefix)
        if (*s++ != *prefix++)
            return 0;
    return 1;
}

// The loader's line inside useCacheImageWithoutClosure: "cache load source <path>: policy=<src>
// allow_list=<hit|miss>", behind the log's "dyld: " prefix. Only a line start counts, so text the
// child prints itself cannot supply it. A missing line is a failed check, not an unparsed field.
static int l5_policy_from_log(const char *out, char *policy, int sz) {
    static const char tag[] = "cache load source /usr/lib/libobjc.A.dylib: policy=";
    for (const char *p = out; *p; ) {
        const char *h = l5_starts(p, "dyld: ") ? p + 6 : p;
        if (l5_starts(h, tag)) {
            const char *v = h + sizeof tag - 1;
            int n = 0;
            while (v[n] && v[n] != ' ' && v[n] != '\n' && n < sz - 1) {
                policy[n] = v[n];
                n++;
            }
            policy[n] = 0;
            return n > 0;
        }
        while (*p && *p != '\n')
            p++;
        if (*p)
            p++;
    }
    return 0;
}

// Lines starting with `prefix`: a check prints exactly one OKMARK line, so a second one is a failure.
static int l5_count_lines(const char *out, const char *prefix) {
    int n = 0;
    for (const char *p = out; *p; ) {
        if (l5_starts(p, prefix))
            n++;
        while (*p && *p != '\n')
            p++;
        if (*p)
            p++;
    }
    return n;
}

// The line starting with `prefix`, or null. `out` is the whole captured child output.
static const char *l5_find_line(const char *out, const char *prefix) {
    for (const char *p = out; *p; ) {
        const char *h = p;
        int i = 0;
        while (prefix[i] && h[i] == prefix[i]) i++;
        if (!prefix[i])
            return p;
        while (*h && *h != '\n') h++;
        if (!*h)
            break;
        p = h + 1;
    }
    return 0;
}

static void l5_echo_line(const char *line) {
    const char *e = line;
    while (*e && *e != '\n') e++;
    write(1, line, (size_t)(e - line));
    nl();
}

// Check 01's line as the child printed it, with the driver's measured policy in place of "policy=?".
static void l5_echo_policy_line(const char *line, const char *policy) {
    static const char tag[] = "policy=";
    const char *end = line;
    while (*end && *end != '\n')
        end++;
    for (const char *p = line; p + 7 <= end; p++) {
        int i = 0;
        while (tag[i] && p[i] == tag[i])
            i++;
        if (!tag[i]) {
            write(1, line, (size_t)(p + i - line));
            put(policy);
            nl();
            return;
        }
    }
    l5_echo_line(line);
}

static const char *l5_image_name(uintptr_t a) {
    uintptr_t clean = (uintptr_t)STRIP((void *)a);
    int best = -1;
    for (int i = 0; i < g_nimages_tab; i++)
        if (g_images_tab[i].base <= clean && (best < 0 || g_images_tab[i].base > g_images_tab[best].base))
            best = i;
    if (best < 0 || clean - g_images_tab[best].base > 0x4000000)
        return "none";
    return g_images_tab[best].name;
}

// The failure line carries what the check needs to be located: the signal, its code, the pc and the
// image the pc lies in (resolved from the image table captured before the check ran).
static void l5_on_fault(int sig, siginfo_min *si, void *uc) {
    uintptr_t pc = 0;
#ifdef ABI_NATIVE
    (void)uc;
#else
    char *mc = uc ? *(char **)((char *)uc + UC_MCONTEXT_OFFSET) : 0;
    if (mc)
        pc = *(uintptr_t *)(mc + MC_PC_OFFSET);
#endif
    put("FAULT check="); l5_put2(g_check); put(" sig="); putdec(sig);
    put(" code="); putdec(si->si_code); put(" pc="); puthex(pc);
    put(" image="); put(l5_image_name(pc)); nl();
    _exit(70);
}

#ifndef ABI_NATIVE
// The guest run may have the arm64e adapters on (configs c2/c3), whose sigaction row authenticates
// the code pointer: the handler goes over unstripped there, stripped everywhere else.
static int l5_adapters_on(void) {
    const char *c = getenv("PROBE_CONFIG");
    return c && (streq(c, "c2") || streq(c, "c3"));
}
#endif

static void l5_install_handlers(void) {
    static const int sigs[] = {SIGSEGV, SIGBUS, SIGILL, SIGTRAP, SIGABRT};
#ifdef ABI_NATIVE
    struct sigaction sa;
    sigemptyset(&sa.sa_mask);
    sa.sa_sigaction = l5_on_fault;
    sa.sa_flags = SA_SIGINFO;
#else
    struct sigaction sa;
    sa.handler = l5_adapters_on() ? (void *)l5_on_fault : STRIP((void *)l5_on_fault);
    sa.mask = 0;
    sa.flags = SA_SIGINFO;
#endif
    for (unsigned i = 0; i < sizeof sigs / sizeof sigs[0]; i++)
        sigaction(sigs[i], &sa, 0);
}

// ------------------------------------------------------------------------- the driver
// One verdict per child. "ok" needs exit 0 and the check's own OKMARK line. A child that dies is
// "faulted" (its FAULT line is echoed, or one is printed here when the handler could not run). A
// child that exits 0 without its mark, or exits nonzero, is "failed".
static int l5_driver(const char *self, const char *setname, const struct check *t, int n, int use_expect,
                     int wrong_expect) {
    static char out[1 << 19];
    int ok = 0, bad = 0, mismatches = 0;
    put("L5-PROBE arch="); put(ARCH); put(" set="); put(setname); put(" checks="); putdec(n); nl();
    for (int i = 1; i <= n; i++) {
        int status = 0, hung = 0, truncated = 0;
        if (run_one(self, setname, i, 0, out, sizeof out, &status, &hung, &truncated)) {
            out[0] = 0;
            status = 0;
            hung = 0;
        }
        (void)drop_adapter_warnings(out);
        int sig = status & 0x7f, code = (status >> 8) & 0xff;
        char mark[16];
        mark[0] = 'O'; mark[1] = 'K'; mark[2] = 'M'; mark[3] = 'A'; mark[4] = 'R'; mark[5] = 'K'; mark[6] = ' ';
        int mi = 7;
        mark[mi++] = (char)('0' + (i < 10 ? 0 : i / 10));
        mark[mi++] = (char)('0' + i % 10);
        mark[mi++] = ' ';
        mark[mi] = 0;
        int marks = l5_count_lines(out, mark);
        const char *markline = marks ? l5_find_line(out, mark) : 0;
        const char *faultline = l5_find_line(out, "FAULT ");
        const char *failedline = l5_find_line(out, "FAILED ");
        const char *verdict;
        const char *why = 0;
        if (hung) {
            verdict = "hung";
        } else if ((sig && sig != 0x7f) || code == 70 || code > 128) {
            verdict = "faulted";
        } else if (code == 0 && marks == 1) {
            verdict = "ok";
        } else {
            verdict = "failed";
            why = code != 0 ? "child exited nonzero without a FAILED line"
                : marks > 1  ? "child printed more than one OKMARK line"
                             : "child exited 0 without its OKMARK line";
            if (failedline)
                why = 0;
        }
        // Check 01's proof is the loader's policy line in this child's output, not the child's claim.
        char policy[16];
        policy[0] = 0;
        if (i == 1 && !use_expect && streq(verdict, "ok")) {
            if (!l5_policy_from_log(out, policy, sizeof policy)) {
                verdict = "failed";
                why = "no loader policy line for /usr/lib/libobjc.A.dylib";
            }
        }
        if (use_expect) {
            const char *expect = t[i - 1].expect;
            if (wrong_expect && i == 1)
                expect = "hung";
            put("SELFTEST check="); l5_put2(i); put(" name="); put(t[i - 1].name);
            put(" verdict="); put(verdict);
            if (expect && !streq(expect, verdict)) {
                put(" EXPECT-MISMATCH expected="); put(expect);
                mismatches++;
            }
            nl();
        } else if (streq(verdict, "ok")) {
            if (i == 1)
                l5_echo_policy_line(markline, policy);
            else
                l5_echo_line(markline);
        } else if (streq(verdict, "hung")) {
            put("HUNG check="); l5_put2(i); nl();
        } else if (streq(verdict, "faulted")) {
            if (faultline)
                l5_echo_line(faultline);
            else {
                put("FAULT check="); l5_put2(i); put(" sig="); putdec(sig);
                put(" code="); putdec(code); put(" pc=0x0 image=none"); nl();
            }
        } else {
            if (failedline)
                l5_echo_line(failedline);
            else {
                put("FAILED check="); l5_put2(i); put(" reason=");
                put(why ? why : "child failed"); nl();
            }
        }
        if (truncated)
            put("  note: child output was truncated\n");
        if (streq(verdict, "ok")) ok++; else bad++;
    }
    put("SUMMARY arch="); put(ARCH); put(" set="); put(setname); put(" ok="); putdec(ok);
    put(" not_ok="); putdec(bad); put(" expect_mismatches="); putdec(mismatches); nl();
    if (use_expect)
        return mismatches ? 1 : 0;
    return bad ? 1 : 0;
}

// ----------------------------------------------------------------------------- selftests
static int l5_st_ok(void) { l5_ok(g_check); return 0; }
static int l5_st_fail(void) { return l5_fail("deliberate failure, no OKMARK"); }
static int l5_st_exit0(void) { return 0; }
static int l5_st_hang(void) { for (;;) { } }
static int l5_st_fault(void) { *(volatile int *)8 = 1; return 0; }

static int l5_st_hash_ok(void) {
    uintptr_t a = 0x1000;
    if (!l5_hash_ok(a, a, a))
        return l5_fail("hash rejected the self value");
    l5_ok(g_check);
    return 0;
}

static int l5_st_hash_skew(void) {
    uintptr_t a = 0x1000;
    if (l5_hash_ok(a, a, a + 1))
        return l5_fail("hash accepted a skewed expected value");
    l5_ok(g_check);
    return 0;
}

static int l5_st_policy(void) {
    char p[16];
    if (!l5_policy_from_log("dyld: cache load source /usr/lib/libobjc.A.dylib: policy=cache "
                            "allow_list=hit\n", p, sizeof p) || !streq(p, "cache"))
        return l5_fail("policy parse missed the cache line");
    if (!l5_policy_from_log("dyld: cache load source /usr/lib/libobjc.A.dylib: policy=disk "
                            "allow_list=miss\n", p, sizeof p) || !streq(p, "disk"))
        return l5_fail("policy parse missed the disk line");
    if (!l5_policy_from_log("cache load source /usr/lib/libobjc.A.dylib: policy=cache\n", p, sizeof p) ||
        !streq(p, "cache"))
        return l5_fail("policy parse missed the line without a log prefix");
    if (l5_policy_from_log("OKMARK 01 cache load source /usr/lib/libobjc.A.dylib: policy=cache\n", p,
                           sizeof p))
        return l5_fail("policy parse accepted the tag in the middle of a line");
    if (l5_policy_from_log("no policy line here\n", p, sizeof p))
        return l5_fail("policy parse invented a source");
    l5_ok(g_check);
    return 0;
}

static int l5_st_mark(void) {
    char m[16];
    int mi = 7;
    m[0] = 'O'; m[1] = 'K'; m[2] = 'M'; m[3] = 'A'; m[4] = 'R'; m[5] = 'K'; m[6] = ' ';
    m[mi++] = '0'; m[mi++] = '7'; m[mi++] = ' '; m[mi] = 0;
    if (!l5_find_line("junk\nOKMARK 07 callbacks version=4\n", m))
        return l5_fail("mark 07 was not found");
    m[8] = '0'; m[9] = '8';
    if (l5_find_line("junk\nOKMARK 07 callbacks version=4\n", m))
        return l5_fail("mark 08 matched 07's line");
    l5_ok(g_check);
    return 0;
}

static int l5_st_double_mark(void) {
    l5_ok(g_check);
    l5_ok(g_check);
    return 0;
}

static const struct check l5_selftests[] = {
    {"l5_selftest_ok", l5_st_ok, "ok"},
    {"l5_selftest_failed", l5_st_fail, "failed"},
    {"l5_selftest_exit0_without_mark", l5_st_exit0, "failed"},
    {"l5_selftest_hang", l5_st_hang, "hung"},
    {"l5_selftest_fault", l5_st_fault, "faulted"},
    {"l5_selftest_hash_ok", l5_st_hash_ok, "ok"},
    {"l5_selftest_hash_rejects_skew", l5_st_hash_skew, "ok"},
    {"l5_selftest_policy_line", l5_st_policy, "ok"},
    {"l5_selftest_mark_match", l5_st_mark, "ok"},
    {"l5_selftest_double_mark", l5_st_double_mark, "failed"},
};
#define L5_NSELFTESTS ((int)(sizeof l5_selftests / sizeof l5_selftests[0]))

// --------------------------------------------------------------------------- guest checks
// Placeholders until the guest bodies land: a guest-only check reports a failure rather than a
// silent pass, and no selftest calls one.
static int l5_check01(void) { return l5_fail("guest-only check"); }
static int l5_check02(void) { return l5_fail("guest-only check"); }
static int l5_check03(void) { return l5_fail("guest-only check"); }
static int l5_check04(void) { return l5_fail("guest-only check"); }

const struct check checks[] = {
    {"check01_served", l5_check01, 0},
    {"check02_getclass", l5_check02, 0},
    {"check03_createinstance", l5_check03, 0},
    {"check04_msgsend", l5_check04, 0},
};
const int nchecks = (int)(sizeof checks / sizeof checks[0]);

int main(int argc, char **argv) {
    if (argc >= 2 && streq(argv[1], "list")) {
        for (int i = 0; i < nchecks; i++) { l5_put2(i + 1); put(" "); put(checks[i].name); nl(); }
        for (int i = 0; i < L5_NSELFTESTS; i++) { put("s"); l5_put2(i + 1); put(" "); put(l5_selftests[i].name); nl(); }
        return 0;
    }
    const char *setname = argc >= 5 ? argv[4] : "checks";
    const struct check *t = streq(setname, "checks") ? checks : l5_selftests;
    int n = streq(setname, "checks") ? nchecks : L5_NSELFTESTS;
    if (argc >= 3 && streq(argv[1], "run")) {
        int k = atoi_(argv[2]);
        if (k < 1 || k > n) { put("bad check number\n"); return 2; }
        g_check = k;
        g_mutate = 0;
        l5_install_handlers();
        capture_images();
        return t[k - 1].fn();
    }
    int selftest = argc >= 2 && (streq(argv[1], "selftest") || streq(argv[1], "selftest-wrong"));
    int wrong = argc >= 2 && streq(argv[1], "selftest-wrong");
    if (selftest)
        return l5_driver(argv[0], "selftest", l5_selftests, L5_NSELFTESTS, 1, wrong);
    return l5_driver(argv[0], "checks", checks, nchecks, 0, 0);
}
