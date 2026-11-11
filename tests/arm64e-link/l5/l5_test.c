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

// Check 07's evidence: what the loader logs about libobjc's own callback registration, behind the log's
// "dyld: " prefix, one line each:
//   objc register_callbacks version=<n>                 once per successful registration
//   objc mapped <path> refs_optimized=<0|1>             per image handed to the mapped callback
//   objc init <path> refs_optimized=<0|1>               per image handed to the init callback
// Only line starts count, so a line the child's own output merely embeds cannot supply them. Like check 01's
// policy line this trusts the child's code (this file) not to print a loader line itself: the loader and the
// child share one stream and nothing in it marks the loader's lines.
struct l5_objc_seen {
    int registers, version, libobjc_bit, exe_bit, inits;   // bits are -1 until a line names the image
    int repeats;                                           // mapped lines naming an image already seen
};

static int l5_eq_n(const char *a, int n, const char *b) {
    int i = 0;
    for (; i < n; i++)
        if (!b[i] || a[i] != b[i])
            return 0;
    return !b[i];
}

// `s` is the tail of a line after the verb: "<path> refs_optimized=<b>". Returns the bit, or -1 when the
// tail has no such suffix; *plen is the path length.
static int l5_path_and_bit(const char *s, int *plen) {
    static const char tag[] = " refs_optimized=";
    const char *last = 0;
    const char *e = s;
    while (*e && *e != '\n')
        e++;
    for (const char *p = s; p < e; p++)
        if (l5_starts(p, tag))
            last = p;
    if (!last)
        return -1;
    const char *v = last + sizeof tag - 1;
    if ((v[0] != '0' && v[0] != '1') || v + 1 != e)
        return -1;
    *plen = (int)(last - s);
    return v[0] - '0';
}

static void l5_objc_scan(const char *out, const char *exe, struct l5_objc_seen *seen) {
    static const char libobjc[] = "/usr/lib/libobjc.A.dylib";
    // the kind word is matched whole: "objc skipping ..." shares the prefix and is not one of these
    static const char kRegister[] = "objc register_callbacks version=", kMapped[] = "objc mapped ",
                      kInit[] = "objc init ";
    seen->registers = 0; seen->version = -1; seen->libobjc_bit = -1; seen->exe_bit = -1; seen->inits = 0;
    seen->repeats = 0;
    for (const char *p = out; *p; ) {
        const char *h = l5_starts(p, "dyld: ") ? p + 6 : p;
        int n = 0, bit;
        if (l5_starts(h, kRegister)) {
            const char *v = h + sizeof kRegister - 1;
            seen->registers++;
            int ver = 0, digits = 0;
            for (; v[digits] >= '0' && v[digits] <= '9'; digits++)
                ver = ver < 100000 ? ver * 10 + (v[digits] - '0') : ver;
            seen->version = digits && (v[digits] == '\n' || !v[digits]) ? ver : -2;   // -2: not a clean %u
        } else if (l5_starts(h, kMapped)) {
            const char *r = h + sizeof kMapped - 1;
            if ((bit = l5_path_and_bit(r, &n)) >= 0) {
                // an image is mapped once; a repeat could hide a wrong bit behind a right one
                if (l5_eq_n(r, n, libobjc)) {
                    seen->repeats += seen->libobjc_bit >= 0;
                    seen->libobjc_bit = bit;
                }
                if (exe && l5_eq_n(r, n, exe)) {
                    seen->repeats += seen->exe_bit >= 0;
                    seen->exe_bit = bit;
                }
            }
        } else if (l5_starts(h, kInit)) {
            if (l5_path_and_bit(h + sizeof kInit - 1, &n) >= 0)
                seen->inits++;
        }
        while (*p && *p != '\n')
            p++;
        if (*p)
            p++;
    }
}

// The verdict on a scan: null when the loader's lines prove libobjc registered version 4 callbacks once,
// was reported cache-served (bit 1) and this disk-served executable was reported with bit 0.
static const char *l5_objc_verdict(const struct l5_objc_seen *s) {
    if (s->registers > 1)
        return "the loader logged more than one objc register_callbacks line (in L5 only libobjc registers)";
    if (s->registers != 1)
        return "the loader did not log an objc register_callbacks line (DYLD_PRINT_OBJC_NOTIFICATIONS=1 set?)";
    if (s->version != 4)
        return "libobjc did not register version 4 callbacks";
    if (s->repeats)
        return "the loader reported an image to the mapped callback more than once";
    if (s->libobjc_bit != 1)
        return "the loader did not report the cache-served libobjc with refs_optimized=1";
    if (s->exe_bit != 0)
        return "the loader did not report the disk-served executable with refs_optimized=0";
    if (s->inits < 1)
        return "the loader logged no objc init callback";
    return 0;
}

// The value after `tag` up to a space or the line end, copied into buf; 0 when absent or too long.
static int l5_token(const char *line, const char *tag, char *buf, int sz) {
    const char *e = line;
    while (*e && *e != '\n')
        e++;
    for (const char *p = line; p < e; p++) {
        if (l5_starts(p, tag)) {
            const char *v = p;
            for (const char *t = tag; *t; t++)
                v++;
            int n = 0;
            while (v + n < e && v[n] != ' ' && n < sz - 1) {
                buf[n] = v[n];
                n++;
            }
            buf[n] = 0;
            return n > 0 && v + n <= e && (v + n == e || v[n] == ' ');
        }
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

// A child's OKMARK line up to and including `tag`; the caller puts the driver's measured value after it.
// A line without the tag is echoed whole and 0 is returned.
static int l5_echo_through(const char *line, const char *tag) {
    const char *end = line;
    while (*end && *end != '\n')
        end++;
    for (const char *p = line; p < end; p++) {
        if (l5_starts(p, tag)) {
            const char *after = p;
            while (*tag++) after++;
            write(1, line, (size_t)(after - line));
            return 1;
        }
    }
    l5_echo_line(line);
    return 0;
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

static void l5_install_handlers(void) {
    static const int sigs[] = {SIGSEGV, SIGBUS, SIGILL, SIGTRAP, SIGABRT};
#ifdef ABI_NATIVE
    struct sigaction sa;
    sigemptyset(&sa.sa_mask);
    sa.sa_sigaction = l5_on_fault;
    sa.sa_flags = SA_SIGINFO;
#else
    struct sigaction sa;
    // dyld's arm64e adapters are on for every arm64e image (with or without the cache) and wrap sigaction:
    // an unsigned handler is replaced by a poisoned pointer and the first fault hangs signal delivery.
    // So the handler goes over exactly as the compiler signed it, in every config.
    sa.handler = (void *)l5_on_fault;
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
        // Check 07's proof is what the loader logged about libobjc's own registration, not the child's claim.
        struct l5_objc_seen seen;
        seen.registers = 0;
        if (i == 7 && !use_expect && streq(verdict, "ok")) {
            char exe[256];
            if (!markline || !l5_token(markline, " exe=", exe, sizeof exe)) {
                verdict = "failed";
                why = "check 07's line names no executable path";
            } else {
                l5_objc_scan(out, exe, &seen);
                const char *bad = l5_objc_verdict(&seen);
                if (bad) {
                    verdict = "failed";
                    why = bad;
                }
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
            if (i == 1) {
                if (l5_echo_through(markline, "policy=")) {
                    put(policy); nl();
                }
            } else if (i == 7) {
                if (l5_echo_through(markline, "loader=")) {
                    put("registered_version="); putdec(seen.version);
                    put(" libobjc_bit="); putdec(seen.libobjc_bit);
                    put(" exe_bit="); putdec(seen.exe_bit);
                    put(" inits="); putdec(seen.inits); nl();
                }
            } else {
                l5_echo_line(markline);
            }
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

static int l5_st_objc_lines(void) {
    static const char good[] =
        "dyld: objc register_callbacks version=4\n"
        "dyld: objc skipping /usr/lib/libswiftCore.dylib: its metadata is unsigned plain arm64\n"
        "dyld: objc skipping /x/objc mapped /y refs_optimized=1\n"   // shares the prefix, is not a mapped line
        "dyld: objc mapped /usr/lib/libobjc.A.dylib refs_optimized=1\n"
        "dyld: objc skipping /tmp/z: plain arm64\n"
        "dyld: objc mapped /tmp/a b/l5_probe refs_optimized=0\n"
        "dyld: objc init /tmp/a b/l5_probe refs_optimized=0\n";
    static const char exe[] = "/tmp/a b/l5_probe";
    struct l5_objc_seen s;
    l5_objc_scan(good, exe, &s);
    if (l5_objc_verdict(&s) || s.version != 4 || s.libobjc_bit != 1 || s.exe_bit != 0 || s.inits != 1)
        return l5_fail("objc line parse rejected the good lines");
    static const char *const bad[] = {
        "dyld: objc mapped /usr/lib/libobjc.A.dylib refs_optimized=1\ndyld: objc mapped /tmp/a b/l5_probe refs_optimized=0\n"
        "dyld: objc init /tmp/a b/l5_probe refs_optimized=0\n",                                   // no register line
        "dyld: objc register_callbacks version=3\ndyld: objc mapped /usr/lib/libobjc.A.dylib refs_optimized=1\n"
        "dyld: objc mapped /tmp/a b/l5_probe refs_optimized=0\ndyld: objc init /tmp/a b/l5_probe refs_optimized=0\n",
        "dyld: objc register_callbacks version=4\ndyld: objc register_callbacks version=4\n"
        "dyld: objc mapped /usr/lib/libobjc.A.dylib refs_optimized=1\ndyld: objc mapped /tmp/a b/l5_probe refs_optimized=0\n"
        "dyld: objc init /tmp/a b/l5_probe refs_optimized=0\n",                                   // two registrations
        "dyld: objc register_callbacks version=4\ndyld: objc mapped /usr/lib/libobjc.A.dylib refs_optimized=0\n"
        "dyld: objc mapped /tmp/a b/l5_probe refs_optimized=0\ndyld: objc init /tmp/a b/l5_probe refs_optimized=0\n",
        "dyld: objc register_callbacks version=4\ndyld: objc mapped /usr/lib/libobjc.A.dylib refs_optimized=1\n"
        "dyld: objc mapped /tmp/a b/l5_probe refs_optimized=1\ndyld: objc init /tmp/a b/l5_probe refs_optimized=0\n",
        "dyld: objc register_callbacks version=4\ndyld: objc mapped /usr/lib/libobjc.A.dylib refs_optimized=1\n"
        "dyld: objc init /tmp/a b/l5_probe refs_optimized=0\n",                                   // exe never mapped
        "dyld: objc register_callbacks version=4\ndyld: objc mapped /usr/lib/libobjc.A.dylib refs_optimized=1\n"
        "dyld: objc mapped /tmp/a b/l5_probe refs_optimized=0\n",                                 // no init
        "dyld: objc register_callbacks version=4\ndyld: objc mapped /usr/lib/libobjc.A.dylib refs_optimized=0\n"
        "dyld: objc mapped /usr/lib/libobjc.A.dylib refs_optimized=1\ndyld: objc mapped /tmp/a b/l5_probe refs_optimized=0\n"
        "dyld: objc init /tmp/a b/l5_probe refs_optimized=0\n",                                   // wrong bit, then right
        "dyld: objc register_callbacks version=4\ndyld: objc mapped /usr/lib/libobjc.A.dylib refs_optimized=1\n"
        "dyld: objc mapped /tmp/a b/l5_probe refs_optimized=1\ndyld: objc mapped /tmp/a b/l5_probe refs_optimized=0\n"
        "dyld: objc init /tmp/a b/l5_probe refs_optimized=0\n",
        "dyld: objc register_callbacks version=4\ndyld: objc mapped2 /usr/lib/libobjc.A.dylib refs_optimized=1\n"
        "dyld: objc mapped /tmp/a b/l5_probe refs_optimized=0\ndyld: objc init /tmp/a b/l5_probe refs_optimized=0\n",  // near-miss kind
        "dyld: objc register_callbacks version=4\ndyld: objc mapped /usr/lib/libobjc.A.dylib refs_optimized=1\n"
        "dyld: objc mapped /tmp/a b/l5_probe refs_optimized=0\ndyld: objc initialized /tmp/a b/l5_probe refs_optimized=0\n",  // near-miss init
        "dyld: objc register_callbacks version=4\ndyld: objc mapped /usr/lib/libobjc.A.dylib refs_optimized=1 \n"
        "dyld: objc mapped /tmp/a b/l5_probe refs_optimized=0\ndyld: objc init /tmp/a b/l5_probe refs_optimized=0\n",  // trailing space
        "OKMARK 07 dyld: objc register_callbacks version=4\ndyld: objc mapped /usr/lib/libobjc.A.dylib refs_optimized=1\n"
        "dyld: objc mapped /tmp/a b/l5_probe refs_optimized=0\ndyld: objc init /tmp/a b/l5_probe refs_optimized=0\n",
    };
    for (unsigned i = 0; i < sizeof bad / sizeof bad[0]; i++) {
        l5_objc_scan(bad[i], exe, &s);
        if (!l5_objc_verdict(&s)) {
            put("bad sample accepted: "); putdec((long)i); nl();
            return l5_fail("objc line parse accepted a bad sample");
        }
    }
    // the version is the whole %u: 14 is read as 14 (and rejected), 4 plus junk is not a version
    static const char v14[] = "dyld: objc register_callbacks version=14\n";
    static const char v4x[] = "dyld: objc register_callbacks version=4x\n";
    l5_objc_scan(v14, exe, &s);
    if (s.version != 14)
        return l5_fail("version=14 was not read as 14");
    l5_objc_scan(v4x, exe, &s);
    if (s.version != -2)
        return l5_fail("version=4x was read as a version");
    static const char vnone[] = "dyld: objc register_callbacks version=\n";
    l5_objc_scan(vnone, exe, &s);
    if (s.version != -2)
        return l5_fail("an empty version was read as a number");
    // a second registration has its own reason, not the missing-line one
    static const char two[] =
        "dyld: objc register_callbacks version=4\ndyld: objc register_callbacks version=4\n"
        "dyld: objc mapped /usr/lib/libobjc.A.dylib refs_optimized=1\ndyld: objc mapped /tmp/a b/l5_probe refs_optimized=0\n"
        "dyld: objc init /tmp/a b/l5_probe refs_optimized=0\n";
    l5_objc_scan(two, exe, &s);
    const char *why = l5_objc_verdict(&s);
    if (!why || !l5_starts(why, "the loader logged more than one"))
        return l5_fail("two registrations did not get their own reason");
    l5_ok(g_check);
    return 0;
}

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
    {"l5_selftest_objc_lines", l5_st_objc_lines, "ok"},
    {"l5_selftest_mark_match", l5_st_mark, "ok"},
    {"l5_selftest_double_mark", l5_st_double_mark, "failed"},
};
#define L5_NSELFTESTS ((int)(sizeof l5_selftests / sizeof l5_selftests[0]))

// --------------------------------------------------------------------------- guest checks
#ifndef ABI_NATIVE

// The cache libobjc's loaded bits, measured (the dyld2 path never notifies libobjc about cache
// images, so the truthful answer here is 0 until such a notifier exists; the check does not assume).
static uint32_t l5_rw_loaded(void) {
    const struct l5_headeropt_rw *t = (const struct l5_headeropt_rw *)_dyld_for_objc_header_opt_rw();
    if (t == 0 || t->entsize < sizeof(struct l5_header_info_rw))
        return 0;
    uint32_t n = 0;
    for (uint32_t i = 0; i < t->count; i++) {
        const struct l5_header_info_rw *h =
            (const struct l5_header_info_rw *)((const char *)t->headers + (size_t)i * t->entsize);
        n += (uint32_t)h->isLoaded;
    }
    return n;
}

// 01: the image behind objc_getClass is inside the shared cache range, and the prefix's disk copy
// did not win; the driver pairs this with the loader's own policy line.
static int l5_check01(void) {
    void *fn = STRIP((void *)objc_getClass);
    struct l5_dl_info info;
    if (!dladdr(fn, &info) || !info.dli_fname)
        return l5_fail("dladdr found no image for objc_getClass");
    size_t len = 0;
    const void *base = _dyld_get_shared_cache_range(&len);
    uintptr_t a = (uintptr_t)fn;
    int inside = base && (uintptr_t)base <= a && a < (uintptr_t)base + len;
    int disk = access("/usr/lib/libobjc.A.dylib", L5_F_OK) == 0;
    if (!inside)
        return l5_fail("objc_getClass lies outside the shared cache range");
    put("OKMARK 01 served image="); put(info.dli_fname); put(" inside="); putdec(inside);
    put(" base="); puthex((uintptr_t)base); put(" size="); puthex(len);
    put(" disk_copy="); putdec(disk); put(" policy=?"); nl();
    return 0;
}

// 02: a class from the runtime whose name, isa and address all agree, plus the measured
// header-opt-rw loaded bits the dyld2 path reports today (the T4 gate: measure, never assume).
static int l5_check02(void) {
    void *cls = objc_getClass("NSObject");
    if (!cls)
        return l5_fail("objc_getClass(NSObject) returned null");
    const char *name = class_getName(cls);
    // object_getClass, not a raw load: an arm64e class's isa field is a signed pointer.
    void *isa = object_getClass(cls);
    const char *isaName = isa ? class_getName(isa) : 0;
    if (!name || !streq(name, "NSObject"))
        return l5_fail("class name is not NSObject");
    if (isa == cls)
        return l5_fail("the class's isa is the class itself, not its metaclass");
    if (!isaName || !streq(isaName, "NSObject"))
        return l5_fail("the class's isa is not NSObject");
    size_t len = 0;
    const void *base = _dyld_get_shared_cache_range(&len);
    uintptr_t c = (uintptr_t)cls;
    int inside = base && (uintptr_t)base <= c && c < (uintptr_t)base + len;
    if (!inside)
        return l5_fail("NSObject lies outside the shared cache range");
    put("OKMARK 02 getclass cls="); puthex(c); put(" name="); put(name);
    put(" isa="); put(isaName); put(" cls_in_cache="); putdec(inside);
    put(" rw_loaded="); putdec(l5_rw_loaded()); nl();
    return 0;
}

// 03: class_createInstance on the cache's class.
static int l5_check03(void) {
    void *cls = objc_getClass("NSObject");
    if (!cls)
        return l5_fail("objc_getClass(NSObject) returned null");
    void *obj = class_createInstance(cls, 0);
    if (!obj)
        return l5_fail("class_createInstance returned null");
    // object_getClass, not a raw load: an instance's isa is a non-pointer isa (packed bits), not a Class.
    void *isa = object_getClass(obj);
    const char *isaName = isa ? class_getName(isa) : 0;
    if (isa != cls)
        return l5_fail("the instance's class is not the class it was created from");
    if (!isaName || !streq(isaName, "NSObject"))
        return l5_fail("the instance's isa is not NSObject");
    put("OKMARK 03 createinstance obj="); puthex((uintptr_t)obj); put(" isa="); put(isaName); nl();
    return 0;
}

// 04: objc_msgSend of -hash (stable across two calls, and the instance's own address) and
// -isEqual: (YES for self, NO for a second instance). l5_hash_ok is the harness mutation point.
static int l5_check04(void) {
    void *cls = objc_getClass("NSObject");
    void *o1 = cls ? class_createInstance(cls, 0) : 0;
    void *o2 = cls ? class_createInstance(cls, 0) : 0;
    if (!o1 || !o2)
        return l5_fail("class_createInstance returned null");
    void *hashSel = sel_registerName("hash");
    void *eqSel = sel_registerName("isEqual:");
    if (!hashSel || !eqSel)
        return l5_fail("sel_registerName returned null");
    uintptr_t h1 = ((uintptr_t (*)(void *, void *))(void *)objc_msgSend)(o1, hashSel);
    uintptr_t h2 = ((uintptr_t (*)(void *, void *))(void *)objc_msgSend)(o1, hashSel);
    int eqSelf = ((signed char (*)(void *, void *, void *))(void *)objc_msgSend)(o1, eqSel, o1) != 0;
    int eqOther = ((signed char (*)(void *, void *, void *))(void *)objc_msgSend)(o1, eqSel, o2) != 0;
    if (!l5_hash_ok(h1, h2, (uintptr_t)o1))
        return l5_fail("hash is not stable, or is not the instance's address");
    if (!eqSelf)
        return l5_fail("isEqual: with self returned NO");
    if (eqOther)
        return l5_fail("isEqual: with another instance returned YES");
    put("OKMARK 04 msgsend hash1="); puthex(h1); put(" hash2="); puthex(h2);
    put(" eq_self=1 eq_other=0"); nl();
    return 0;
}

// 05: a class built at runtime: allocate, add a method, register, instantiate, send.
static int l5_method_answer(void *self, void *cmd) { (void)self; (void)cmd; return 42; }

static int l5_check05(void) {
    void *base = objc_getClass("NSObject");
    if (!base)
        return l5_fail("objc_getClass(NSObject) returned null");
    void *cls = objc_allocateClassPair(base, "L5Dynamic", 0);
    if (!cls)
        return l5_fail("objc_allocateClassPair returned null");
    void *sel = sel_registerName("answer");
    if (!sel)
        return l5_fail("sel_registerName returned null");
    if (!class_addMethod(cls, sel, (l5_imp)(void *)l5_method_answer, "i@:"))
        return l5_fail("class_addMethod returned NO");
    objc_registerClassPair(cls);
    void *obj = class_createInstance(cls, 0);
    if (!obj)
        return l5_fail("class_createInstance returned null");
    const char *name = class_getName(cls);
    void *super = class_getSuperclass(cls);
    int answer = ((int (*)(void *, void *))(void *)objc_msgSend)(obj, sel);
    if (!name || !streq(name, "L5Dynamic"))
        return l5_fail("the dynamic class name is not L5Dynamic");
    if (super != base)
        return l5_fail("the dynamic class does not inherit NSObject");
    if (answer != 42)
        return l5_fail("the added method did not return 42");
    put("OKMARK 05 subclass name="); put(name); put(" answer="); putdec(answer);
    put(" super="); put(super ? class_getName(super) : "none"); nl();
    return 0;
}

// 06: the six dyld4 objc SPIs against independent facts: the class count from T0's own walk of
// the cache's table, and libobjc's __objc_classlist size. Never the accessor's value against itself.
static int l5_check06(void) {
    uint32_t count = _dyld_objc_class_count();
    const void *ro = _dyld_for_objc_header_opt_ro();
    void *rw = _dyld_for_objc_header_opt_rw();
    void *fn = STRIP((void *)objc_getClass);
    struct l5_dl_info info;
    if (!dladdr(fn, &info) || !info.dli_fbase)
        return l5_fail("dladdr found no image for objc_getClass");
    const struct l5_mach_header *mh = (const struct l5_mach_header *)info.dli_fbase;
    struct l5_section_info_result list =
        _dyld_lookup_section_info(mh, 0, l5_section_data_class_list);
    struct l5_section_info_result missing =
        _dyld_lookup_section_info(mh, 0, l5_section_text_swift5_protos);
    void *h = dlopen("/usr/lib/libobjc.A.dylib", L5_RTLD_NOW);
    const struct l5_mach_header *dh = h ? _dyld_get_dlopen_image_header(h) : 0;
    int lookup = list.buffer != 0 && list.bufferSize == L5_CLASSLIST_SIZE &&
                 missing.buffer == 0 && missing.bufferSize == 0;
    if (count != L5_CLASS_COUNT)
        return l5_fail("_dyld_objc_class_count is not 221074");
    if (!ro || !rw)
        return l5_fail("a header-opt SPI returned null");
    if (!lookup)
        return l5_fail("the section lookup does not give {__objc_classlist, 0x28} and {null, 0}");
    if (dh != mh)
        return l5_fail("the dlopen header is not libobjc's");
    put("OKMARK 06 apis count="); putdec(count);
    put(" opt_ro=1 opt_rw=1 lookup=1 dlopen_header=1"); nl();
    return 0;
}

// 07: libobjc's own callback registration, seen through the loader's log lines (the driver parses them: dyld
// keeps one callback state, so this test must not register a second set over libobjc's). The child proves the
// two images the driver looks for differ: the cache-served libobjc and this disk-served arm64e executable,
// which carries an __objc_imageinfo section so the loader reports it to the runtime (bit 0, not optimized).
__attribute__((used, section("__DATA,__objc_imageinfo"))) static const unsigned l5_objc_imageinfo[2] = {0, 0};

static int l5_check07(void) {
    struct l5_dl_info exe, objc;
    size_t len = 0;
    const void *base = _dyld_get_shared_cache_range(&len);
    if (!dladdr(STRIP((void *)l5_check07), &exe) || !exe.dli_fname)
        return l5_fail("dladdr found no image for the test executable");
    if (!dladdr(STRIP((void *)objc_getClass), &objc) || !objc.dli_fname)
        return l5_fail("dladdr found no image for objc_getClass");
    uintptr_t e = (uintptr_t)exe.dli_fbase, o = (uintptr_t)objc.dli_fbase, b = (uintptr_t)base;
    int exe_in = base && b <= e && e < b + len;
    int objc_in = base && b <= o && o < b + len;
    if (exe_in)
        return l5_fail("the test executable lies inside the shared cache range");
    if (!objc_in)
        return l5_fail("libobjc lies outside the shared cache range");
    put("OKMARK 07 callbacks observed_by=driver exe_in_cache=0 libobjc_in_cache=1 exe=");
    put(exe.dli_fname); put(" loader=?"); nl();
    return 0;
}

// 08: dispose a runtime-created object, then read the two commpage words libobjc loads (T6).
static int l5_check08(void) {
    void *cls = objc_getClass("NSObject");
    void *obj = cls ? class_createInstance(cls, 0) : 0;
    if (!obj)
        return l5_fail("class_createInstance returned null");
    object_dispose(obj);
    volatile const uint64_t *cp = (volatile const uint64_t *)L5_COMMPAGE_BASE;
    uint64_t d0 = cp[L5_COMMPAGE_D0 / 8];
    uint64_t d8 = cp[L5_COMMPAGE_D8 / 8];
    put("OKMARK 08 dispose done d0="); puthex((uintptr_t)d0);
    put(" d8="); puthex((uintptr_t)d8); nl();
    return 0;
}

#else   // ABI_NATIVE: the guest checks need libobjc; their decisions are covered by the selftests

static int l5_check01(void) { return l5_fail("guest-only check"); }
static int l5_check02(void) { return l5_fail("guest-only check"); }
static int l5_check03(void) { return l5_fail("guest-only check"); }
static int l5_check04(void) { return l5_fail("guest-only check"); }
static int l5_check05(void) { return l5_fail("guest-only check"); }
static int l5_check06(void) { return l5_fail("guest-only check"); }
static int l5_check07(void) { return l5_fail("guest-only check"); }
static int l5_check08(void) { return l5_fail("guest-only check"); }

#endif   // ABI_NATIVE

const struct check checks[] = {
    {"check01_served", l5_check01, 0},
    {"check02_getclass", l5_check02, 0},
    {"check03_createinstance", l5_check03, 0},
    {"check04_msgsend", l5_check04, 0},
    {"check05_subclass", l5_check05, 0},
    {"check06_apis", l5_check06, 0},
    {"check07_callbacks", l5_check07, 0},
    {"check08_dispose", l5_check08, 0},
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
