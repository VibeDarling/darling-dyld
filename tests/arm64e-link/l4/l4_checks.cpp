// L4 proof test (plan rung L4): a C++ program that uses libc++, libc++abi and libunwind. Built as
// arm64e it is the consumer of the shared cache's libc++/libc++abi (config c3) or of Darling's own
// (c2); built plain arm64 it is the control (c1); built natively on the host it validates the
// checks themselves. One numbered check per child process; the driver is ../abi/abi_harness.c.
//
// The groups are the plan's Q4 list: 1 where the C++ runtime came from, 2 throw/catch,
// 3 library objects, 4 threads, 5 the exit path, 6 thread-safe static initialisation.
//
// Exceptions of user-defined polymorphic classes are kept apart (names end in _known_ld64_addend):
// their typeinfo lives in this executable and the in-tree ld64 drops the +16 vtable address point
// from the authenticated vtable bind (../abi/README.md, item 3). Everything else throws and catches
// types whose typeinfo the C++ runtime defines.
#include "l4_iface.h"

#include <atomic>
#include <condition_variable>
#include <cstdlib>
#include <cstring>
#include <dlfcn.h>
#include <exception>
#include <functional>
#include <iostream>
#include <map>
#include <memory>
#include <mutex>
#include <sstream>
#include <stdexcept>
#include <string>
#include <thread>
#include <typeinfo>
#include <utility>
#include <unordered_map>
#include <vector>

extern "C" void *__cxa_allocate_exception(size_t);
extern "C" void __cxa_free_exception(void *);

#define STR_(x) #x
#define STR(x) STR_(x)
#define REQUIRE(c) do { if (!(c)) return fail("line " STR(__LINE__) ": " #c); } while (0)
#define PASS() do { ok_mark(g_check); return 0; } while (0)

namespace {

// ------------------------------------------------------------------------ 1: where it came from
#ifdef __APPLE__
extern "C" const void *_dyld_get_shared_cache_range(size_t *length);
const void *cache_range(size_t *n) { return _dyld_get_shared_cache_range(n); }
#else
const void *cache_range(size_t *n) { *n = 0; return nullptr; }
#endif

// The fact is printed; the verdict is the expectation table's business: a run without the cache is
// expected to report "failed" here, not to fault.
int served_by_cache(const char *what, void *fn, const char *install_name) {
    void *addr = L4_STRIP(fn);
    Dl_info di;
    REQUIRE(dladdr(addr, &di) != 0);
    size_t size = 0;
    const char *base = static_cast<const char *>(cache_range(&size));
    bool in_cache = base && static_cast<const char *>(addr) >= base && static_cast<const char *>(addr) < base + size;
    put("FACT served what="); put(what); put(" image="); put(di.dli_fname ? di.dli_fname : "(none)");
    put(" in_cache="); put(in_cache ? "yes" : "no");
    put(" addr="); puthex(reinterpret_cast<unsigned long>(addr));
    put(" cache_base="); puthex(reinterpret_cast<unsigned long>(base)); put(" cache_size="); puthex(size); nl();
    if (!in_cache) return fail("not served from the shared cache");
    REQUIRE(di.dli_fname && std::strcmp(di.dli_fname, install_name) == 0);
    PASS();
}
int served_libcxx() {
    return served_by_cache("libc++ std::locale::classic", reinterpret_cast<void *>(&std::locale::classic),
                           "/usr/lib/libc++.1.dylib");
}
extern "C" void __cxa_throw(void *, void *, void (*)(void *));
int served_cxa_throw() {
    return served_by_cache("libc++abi __cxa_throw", reinterpret_cast<void *>(&__cxa_throw), "/usr/lib/libc++abi.dylib");
}

// ------------------------------------------------------------------------------ 2: exceptions
__attribute__((noinline)) void throw_int(int v) { throw v; }
int throw_catch_int() {
    try { throw_int(7); } catch (int v) { REQUIRE(v == 7); PASS(); }
    return fail("not caught");
}

__attribute__((noinline)) int frame3(int v) { throw_int(v + 1); return 0; }
__attribute__((noinline)) int frame2(int v) { return frame3(v) + 1; }
__attribute__((noinline)) int frame1(int v) { return frame2(v) + 1; }
int throw_nested_frames() {
    try { frame1(40); } catch (int v) { REQUIRE(v == 41); PASS(); }
    return fail("not caught");
}

int rethrow() {
    int stage = 0;
    try {
        try { throw_int(3); }
        catch (int &v) { stage = 1; REQUIRE(v == 3); throw; }
    } catch (int v) { REQUIRE(stage == 1 && v == 3); PASS(); }
    return fail("the rethrown exception was lost");
}

int catch_all() {
    int caught = 0;
    try { throw 3.5; } catch (...) { caught++; }
    try { throw static_cast<const char *>("text"); } catch (const char *s) { REQUIRE(std::strcmp(s, "text") == 0); caught++; }
    try { throw std::runtime_error("x"); } catch (...) { caught++; }
    REQUIRE(caught == 3);
    PASS();
}

struct Counter { int *c; int order; static int next; ~Counter() { *c = ++next; } };
int Counter::next = 0;
__attribute__((noinline)) void with_two_guards(int *a, int *b) {
    Counter first{a, 0}, second{b, 0};
    (void)first; (void)second;
    throw_int(1);
}
int cleanup_landing_pad() {
    int a = 0, b = 0;
    Counter::next = 0;
    try { with_two_guards(&a, &b); } catch (int) {
        REQUIRE(b == 1 && a == 2);   // reverse order of construction, each exactly once
        PASS();
    }
    return fail("not caught");
}

int std_exception_hierarchy() {
    try { throw std::runtime_error("runtime"); }
    catch (const std::exception &e) { REQUIRE(std::strcmp(e.what(), "runtime") == 0); }
    try { throw std::out_of_range("range"); }
    catch (const std::logic_error &e) { REQUIRE(std::strcmp(e.what(), "range") == 0); }
    try { throw std::invalid_argument("arg"); }
    catch (const std::runtime_error &) { return fail("invalid_argument caught as runtime_error"); }
    catch (const std::exception &e) { REQUIRE(std::strcmp(e.what(), "arg") == 0); }
    try { std::vector<int> v; (void)v.at(1); }   // thrown inside libc++ itself
    catch (const std::out_of_range &) { PASS(); }
    return fail("vector::at did not throw out_of_range");
}

int exception_through_std_function() {
    std::function<int(int)> f = [](int v) -> int { if (v > 0) throw std::runtime_error("from function"); return v; };
    REQUIRE(f(0) == 0);
    try { f(1); } catch (const std::exception &e) { REQUIRE(std::strcmp(e.what(), "from function") == 0); PASS(); }
    return fail("the exception did not cross std::function");
}

int exception_in_thread() {
    int result = 0;
    std::thread t([&result] {
        try { frame1(1); } catch (int v) { result = v; }
        try { throw std::runtime_error("in thread"); } catch (const std::exception &) { result += 100; }
    });
    t.join();
    REQUIRE(result == 102);
    PASS();
}

// typeinfo defined in this executable too: libc++'s headers emit that of bad_function_call here
int bad_function_call_known_ld64_addend() {
    std::function<void()> empty;
    try { empty(); } catch (const std::bad_function_call &) { PASS(); }
    return fail("an empty std::function did not throw bad_function_call");
}

// user-defined polymorphic classes (typeinfo defined in this executable)
struct Base { virtual ~Base() {} virtual int id() const { return 1; } };
struct Derived : Base { int v; explicit Derived(int x) : v(x) {} int id() const override { return 2; } };
int class_base_catch_known_ld64_addend() {
    try { throw Derived(9); } catch (const Base &b) { REQUIRE(b.id() == 2); PASS(); }
    return fail("not caught");
}
int class_exact_catch_known_ld64_addend() {
    try { throw Derived(5); } catch (const Derived &d) { REQUIRE(d.v == 5); PASS(); }
    return fail("not caught");
}
int dynamic_cast_known_ld64_addend() {
    Derived d(1);
    Base *b = &d;
    REQUIRE(dynamic_cast<Derived *>(b) == &d);
    struct Other : Base {};
    REQUIRE(dynamic_cast<Other *>(b) == nullptr);
    REQUIRE(typeid(*b) == typeid(Derived));
    PASS();
}

// ------------------------------------------------------------------------------ 3: library objects
int string_and_vector() {
    std::string s = "short";
    s += " and then a string long enough to leave the small buffer";
    REQUIRE(s.size() == 61 && s.find("then") == 10 && s.substr(0, 5) == "short");
    std::string t = std::to_string(12345) + std::string(3, 'x');
    REQUIRE(t == "12345xxx");
    std::vector<int> v;
    for (int i = 0; i < 1000; i++) v.push_back(i * 3);
    long sum = 0;
    for (int x : v) sum += x;
    REQUIRE(v.size() == 1000 && sum == 3L * 999 * 1000 / 2);
    std::vector<std::string> names{"a", "bb", "ccc"};
    names.push_back(s);
    REQUIRE(names.size() == 4 && names[3] == s);
    PASS();
}

int map_and_unordered_map() {
    std::map<std::string, int> m;
    for (int i = 0; i < 100; i++) m[std::to_string(i)] = i;
    REQUIRE(m.size() == 100 && m["42"] == 42 && m.begin()->first == "0" && m.count("100") == 0);
    std::unordered_map<int, std::string> u;
    for (int i = 0; i < 1000; i++) u[i] = std::to_string(i);   // rehashes, through libc++'s prime table
    REQUIRE(u.size() == 1000 && u.at(999) == "999" && u.find(1000) == u.end());
    std::unordered_map<std::string, int> w{{"x", 1}, {"y", 2}};
    REQUIRE(w["x"] + w["y"] == 3);
    PASS();
}

struct Tracked { static int alive; Tracked() { alive++; } ~Tracked() { alive--; } };
int Tracked::alive = 0;
int shared_ptr_control_block() {
    {
        std::shared_ptr<Tracked> a = std::make_shared<Tracked>();
        std::weak_ptr<Tracked> w = a;
        {
            std::shared_ptr<Tracked> b = a;
            REQUIRE(a.use_count() == 2 && Tracked::alive == 1);
        }
        REQUIRE(a.use_count() == 1 && !w.expired());
        a.reset();
        REQUIRE(Tracked::alive == 0 && w.expired() && w.lock() == nullptr);
    }
    std::shared_ptr<Tracked> c(new Tracked, [](Tracked *p) { delete p; });
    REQUIRE(Tracked::alive == 1);
    c.reset();
    REQUIRE(Tracked::alive == 0);
    PASS();
}

int ostringstream_and_locale() {
    std::ostringstream os;
    os << "n=" << 42 << " h=" << std::hex << 255 << " d=" << std::dec << 1.5 << ' ' << std::string("s");
    REQUIRE(os.str() == "n=42 h=ff d=1.5 s");
    std::istringstream is("17 3.25 word");
    int i = 0; double d = 0; std::string w;
    is >> i >> d >> w;
    REQUIRE(i == 17 && d == 3.25 && w == "word");
    std::locale loc;
    REQUIRE(std::use_facet<std::ctype<char>>(loc).toupper('a') == 'A');
    REQUIRE(std::locale::classic().name() == "C");
    PASS();
}

int cout_and_cerr() {
    REQUIRE(std::cout.good() && std::cerr.good());
    REQUIRE((std::cerr.flags() & std::ios_base::unitbuf) != 0);
    std::cerr << "L4-CERR-LINE\n";
    std::cout << "L4-COUT-LINE " << 42 << ' ' << 1.25 << std::endl;
    REQUIRE(std::cout.good());
    PASS();
}

// ------------------------------------------------------------------------------ 4: threads
int thread_capturing_lambda() {
    std::vector<int> data{1, 2, 3, 4};
    std::string label = "sum";
    long result = 0;
    std::thread t([data, label, &result] {   // data and label are captured by copy
        for (int x : data) result += x;
        result += static_cast<long>(label.size());
    });
    t.join();
    REQUIRE(result == 13 && !t.joinable());
    std::thread u([&result] { result = 99; });
    u.join();
    REQUIRE(result == 99);
    PASS();
}

int mutex_counter() {
    std::mutex mu;
    long counter = 0;
    std::vector<std::thread> threads;
    for (int i = 0; i < 4; i++)
        threads.emplace_back([&] {
            for (int j = 0; j < 20000; j++) { std::lock_guard<std::mutex> g(mu); counter++; }
        });
    for (auto &t : threads) t.join();
    REQUIRE(counter == 80000);
    PASS();
}

int condition_variable_handoff() {
    std::mutex mu;
    std::condition_variable cv;
    std::vector<int> queue;
    bool done = false;
    long consumed = 0;
    std::thread consumer([&] {
        std::unique_lock<std::mutex> lk(mu);
        for (;;) {
            cv.wait(lk, [&] { return !queue.empty() || done; });
            while (!queue.empty()) { consumed += queue.back(); queue.pop_back(); }
            if (done) return;
        }
    });
    for (int i = 1; i <= 100; i++) {
        { std::lock_guard<std::mutex> g(mu); queue.push_back(i); }
        cv.notify_one();
    }
    { std::lock_guard<std::mutex> g(mu); done = true; }
    cv.notify_all();
    consumer.join();
    REQUIRE(consumed == 5050);
    std::unique_lock<std::mutex> lk(mu);
    REQUIRE(cv.wait_for(lk, std::chrono::milliseconds(20)) == std::cv_status::timeout);   // times out, not hangs
    PASS();
}

int call_once_across_threads() {
    std::once_flag flag;
    std::atomic<int> runs{0};
    std::vector<std::thread> threads;
    for (int i = 0; i < 6; i++)
        threads.emplace_back([&] { std::call_once(flag, [&] { runs++; }); });
    for (auto &t : threads) t.join();
    REQUIRE(runs == 1);
    std::once_flag again;
    int tries = 0;
    try { std::call_once(again, [&] { tries++; throw std::runtime_error("first call fails"); }); } catch (const std::exception &) {}
    std::call_once(again, [&] { tries++; });   // an exception leaves the flag unset
    REQUIRE(tries == 2);
    PASS();
}

std::atomic<int> g_tl_dtors{0};
struct TlProbe { int v = 0; ~TlProbe() { g_tl_dtors++; } };
thread_local TlProbe tl_probe;
int thread_local_destructor() {
    g_tl_dtors = 0;
    std::atomic<int> seen{0};
    std::vector<std::thread> threads;
    for (int i = 0; i < 3; i++)
        threads.emplace_back([i, &seen] { tl_probe.v = i + 1; seen += tl_probe.v; });   // first use registers the destructor
    for (auto &t : threads) t.join();
    REQUIRE(seen == 6);
    REQUIRE(g_tl_dtors == 3);   // each thread's object died with its thread, before join returned
    PASS();
}

// ------------------------------------------------------------------------------ 5: the exit path
int g_static_ctor_ran = 0;
int g_arm_static_dtor = 0;
struct StaticProbe {
    StaticProbe() { g_static_ctor_ran = 1; }
    ~StaticProbe() { if (g_arm_static_dtor) std::cout << "L4-STATIC-DTOR"; }   // no newline, no flush: exit must flush
} g_static_probe;

int g_exit_order = 0;
void exit_first_registered() {   // registered first, so it runs last of the handlers registered by main
    if (g_exit_order == 21 && g_static_ctor_ran) ok_mark(g_check);
}
void exit_second() { g_exit_order = g_exit_order * 10 + 1; }
void exit_third() { g_exit_order = g_exit_order * 10 + 2; }
int atexit_and_static_destructor() {
    REQUIRE(g_static_ctor_ran == 1);   // the static initializer of this executable ran before main
    g_arm_static_dtor = 1;
    REQUIRE(std::atexit(exit_first_registered) == 0);
    REQUIRE(std::atexit(exit_second) == 0);
    REQUIRE(std::atexit(exit_third) == 0);
    std::exit(0);   // handlers run in reverse order, then the static destructor, then the cout flush
}

int exit_flushes_cout() {
    std::cout << "L4-FLUSHED-BY-EXIT";   // buffered: stdout is a pipe
    ok_mark(g_check);
    std::exit(0);
}

// ------------------------------------------------------------------------------ 6: static locals
constexpr int kLocals = 16;
std::atomic<int> g_local_inits[kLocals];
std::atomic<int> g_go{0};
template <int I> struct Lazy {
    int v;
    Lazy() : v(0) {
        g_local_inits[I]++;
        for (int k = 0; k < 5; k++) std::this_thread::yield();   // keep the initialisation open for the other threads
        v = 100 + I;
    }
};
template <int I> int lazy() { static Lazy<I> x; return x.v; }   // one guard variable each
template <int... Is> void run_locals(std::atomic<int> *bad, std::integer_sequence<int, Is...>) {
    while (!g_go) std::this_thread::yield();
    int values[] = {lazy<Is>()...};
    for (int i = 0; i < kLocals; i++) if (values[i] != 100 + i) (*bad)++;   // saw a half-initialised object
}
int static_local_contention() {
    std::atomic<int> bad{0};
    std::vector<std::thread> threads;
    for (int i = 0; i < 8; i++)
        threads.emplace_back([&bad] { run_locals(&bad, std::make_integer_sequence<int, kLocals>()); });
    g_go = 1;
    for (auto &t : threads) t.join();
    REQUIRE(bad == 0);
    for (int i = 0; i < kLocals; i++) REQUIRE(g_local_inits[i] == 1);   // each ran exactly once
    PASS();
}

std::atomic<int> g_flaky_attempts{0};
int flaky() {
    static int v = [] { if (g_flaky_attempts++ == 0) throw std::runtime_error("first initialisation fails"); return 5; }();
    return v;
}
int static_local_init_throws() {
    try { flaky(); return fail("the first initialisation did not throw"); } catch (const std::runtime_error &) {}
    REQUIRE(flaky() == 5);   // the guard was aborted, so the next call initialises
    REQUIRE(flaky() == 5 && g_flaky_attempts == 2);
    PASS();
}

// Diagnostics x1..x8 bisect the c3 throw failure with the public C++ runtime API (L4 T5, not part of the plan's 28
// checks). They are recorded only: the finding is which of them fault, not that they pass.
int x1_get_terminate() { REQUIRE(std::get_terminate() != nullptr); PASS(); }
int x2_set_get_terminate() {
    std::terminate_handler h = std::get_terminate();
    std::terminate_handler old = std::set_terminate(h);
    REQUIRE(old == h && std::get_terminate() == h);
    PASS();
}
int x3_allocate_free_exception() {
    void *p = __cxa_allocate_exception(8);
    REQUIRE(p != nullptr);
    __cxa_free_exception(p);
    PASS();
}
typedef void (*init_primary_fn)(void *, std::type_info *, void (*)(void *));
void x_dtor(void *) {}
// __cxa_init_primary_exception is not in every libc++abi's export list, so it is found by name
int x_init_primary(std::type_info *ti, void (*dest)(void *)) {
    init_primary_fn f = (init_primary_fn)dlsym(RTLD_DEFAULT, "__cxa_init_primary_exception");
    if (!f) return fail("dlsym(__cxa_init_primary_exception) failed");
    f(__cxa_allocate_exception(8), ti, dest);
    PASS();
}
int x4_init_primary_null_dtor() { return x_init_primary((std::type_info *)&typeid(int), nullptr); }
int x5_init_primary_signed_dtor() { return x_init_primary((std::type_info *)&typeid(int), x_dtor); }
int x6_init_primary_stripped_dtor() { return x_init_primary((std::type_info *)&typeid(int), (void (*)(void *))L4_STRIP(x_dtor)); }
int x7_init_primary_class_typeinfo() { return x_init_primary((std::type_info *)&typeid(std::runtime_error), x_dtor); }
int x8_get_unexpected_via_dlsym() {
    typedef void *(*fn)(void);
    fn f = (fn)dlsym(RTLD_DEFAULT, "_ZSt14get_unexpectedv");
    if (!f) return fail("dlsym(get_unexpected) failed");
    REQUIRE(f() != nullptr);
    PASS();
}

// Diagnostics y1 and y2 look at the cache's terminate-handler slot, the pointer that made every c3 throw trap: Darling's libobjc
// calls std::set_terminate(&_objc_terminate) at init with a plain pointer, and the cache's arm64e libc++abi then failed to
// re-sign it for the exception header. Recorded only.
static unsigned long y_sign(unsigned long stripped, int key, unsigned long disc) {
    switch (key) {
    case 0: return (unsigned long)L4_SIGN(stripped, 0, disc);
    case 1: return (unsigned long)L4_SIGN(stripped, 1, disc);
    case 2: return (unsigned long)L4_SIGN(stripped, 2, disc);
    default: return (unsigned long)L4_SIGN(stripped, 3, disc);
    }
}
// non-trapping: a slot value authenticates under (key, disc) iff it equals the signature of its own stripped value
static void y_try(const char *label, unsigned long raw, unsigned long slot) {
    unsigned long stripped = (unsigned long)L4_STRIP(raw);
    unsigned long blend = slot ? L4_BLEND(slot, 0) : 0;
    put("Y variant="); put(label);
    put(" raw_is_unsigned="); puthex(raw == stripped);
    put(" IA_d0="); puthex(raw == y_sign(stripped, 0, 0));
    put(" IA_addr_d0="); puthex(slot && raw == y_sign(stripped, 0, blend));
    put(" DA_d0="); puthex(raw == y_sign(stripped, 2, 0));
    put(" IB_d0="); puthex(raw == y_sign(stripped, 1, 0));
    nl();
}
static unsigned long y_slot(const char *sym) {
    void *p = dlsym(RTLD_DEFAULT, sym);
    put("Y sym="); put(sym); put(" addr="); puthex((unsigned long)p); nl();
    if (!p) return 0;
    unsigned long raw = *(unsigned long *)p;
    Dl_info di;
    put("Y target of="); put(sym); put(" raw="); puthex(raw);
    if (dladdr(L4_STRIP(raw), &di)) {
        put(" image="); put(di.dli_fname ? di.dli_fname : "(none)");
        put(" sname="); put(di.dli_sname ? di.dli_sname : "(none)");
    }
    nl();
    y_try(sym, raw, (unsigned long)p);
    return raw;
}
int y1_handler_slots() {
    y_slot("__cxa_terminate_handler");
    y_slot("__cxa_unexpected_handler");
    y_try("get_terminate()", (unsigned long)(void *)std::get_terminate(), 0);
    PASS();
}
void y_my_handler() { std::abort(); }
// the counterfactual: hand the runtime a compiler-signed handler, then the trap site must pass and a throw must work
int y2_set_signed_terminate_then_init() {
    y_slot("__cxa_terminate_handler");
    std::set_terminate(y_my_handler);
    unsigned long after = y_slot("__cxa_terminate_handler");
    put("Y after_set slot_equals_signed_handler="); puthex(after == y_sign((unsigned long)L4_STRIP(y_my_handler), 0, 0)); nl();
    typedef void (*init_fn)(void *, std::type_info *, void (*)(void *));
    init_fn f = (init_fn)dlsym(RTLD_DEFAULT, "__cxa_init_primary_exception");
    if (!f) return fail("dlsym(__cxa_init_primary_exception) failed");
    f(__cxa_allocate_exception(8), (std::type_info *)&typeid(int), nullptr);
    try { throw 7; } catch (int v) { REQUIRE(v == 7); }
    PASS();
}


// Checks z1..z8 drive the dyld reverse adapters from real plain code: l4_plain.dylib (plain arm64, built by build_plain_dylib.py,
// loaded by dlopen from the directory of this executable) binds the cache's std::set_terminate and std::get_terminate. In c3
// those binds are thunks that sign a function pointer argument only when it is a function entry of a plain image (or a handler
// handed back before), and authenticate a handler result before plain code gets it raw. Each check looks at the cache's
// __cxa_terminate_handler slot, the value the arm64e libc++abi stored.
typedef void (*z_handler_t)(void);
struct z_plain { z_handler_t (*set)(z_handler_t); z_handler_t (*get)(void); void (*entry)(void); int *data; unsigned long *slot; };
static unsigned long z_sign(unsigned long p) { return (unsigned long)L4_SIGN(p, 0, 0); }
static unsigned long z_strip(unsigned long p) { return (unsigned long)L4_STRIP(p); }
void z_arm64e_handler() { std::abort(); }
static int z_load(z_plain *p) {
    Dl_info self;
    if (!dladdr((void *)&g_check, &self) || !self.dli_fname || self.dli_fname[0] != '/') return fail("cannot find the directory of this executable");
    std::string path(self.dli_fname);
    path.resize(path.rfind('/') + 1);
    path += "l4_plain.dylib";
    void *h = dlopen(path.c_str(), RTLD_NOW);
    if (!h) return fail("dlopen of l4_plain.dylib failed");
    p->set = (z_handler_t (*)(z_handler_t))dlsym(h, "plain_set_terminate");   // dlsym signs these for this arm64e caller
    p->get = (z_handler_t (*)(void))dlsym(h, "plain_get_terminate");
    p->entry = (void (*)(void))dlsym(h, "plain_entry");
    p->data = (int *)dlsym(h, "plain_data");
    p->slot = (unsigned long *)dlsym(RTLD_DEFAULT, "__cxa_terminate_handler");
    if (!p->set || !p->get || !p->entry || !p->data || !p->slot) return fail("a symbol of l4_plain.dylib or the handler slot is missing");
    return 0;
}
int z1_plain_entry_is_signed() {
    z_plain p; if (z_load(&p)) return 1;
    unsigned long entry = z_strip((unsigned long)p.entry);
    z_handler_t old = p.set((z_handler_t)entry);
    REQUIRE((unsigned long)old == z_strip((unsigned long)old));   // the old handler came back raw
    REQUIRE(*p.slot == z_sign(entry));                            // and the callee got the IA/0 signature of the entry
    REQUIRE(*p.slot != entry);
    PASS();
}
int z2_mid_function_address_not_signed() {
    z_plain p; if (z_load(&p)) return 1;
    unsigned long mid = z_strip((unsigned long)p.entry) + 4;
    p.set((z_handler_t)mid);
    REQUIRE(*p.slot == mid);   // stored as it was: no signature for an address that is not a function entry
    PASS();
}
int z3_arm64e_image_address_not_signed() {
    z_plain p; if (z_load(&p)) return 1;
    unsigned long a = z_strip((unsigned long)z_arm64e_handler);
    p.set((z_handler_t)a);
    REQUIRE(*p.slot == a);
    PASS();
}
int z4_data_address_not_signed() {
    z_plain p; if (z_load(&p)) return 1;
    unsigned long a = (unsigned long)p.data;
    p.set((z_handler_t)a);
    REQUIRE(*p.slot == a);
    PASS();
}
int z5_round_trip() {
    z_plain p; if (z_load(&p)) return 1;
    std::set_terminate(z_arm64e_handler);                       // arm64e code installs a handler (signed by the compiler)
    unsigned long h = (unsigned long)p.get();                   // plain code receives it
    REQUIRE(h == z_strip((unsigned long)z_arm64e_handler));     // raw, authenticated
    p.set((z_handler_t)z_strip((unsigned long)p.entry));        // something else in the slot
    REQUIRE(*p.slot != 0 && *p.slot != z_strip(*p.slot));
    p.set((z_handler_t)h);                                      // plain code restores it: an arm64e address it was handed
    REQUIRE(*p.slot == z_sign(h));
    // control: an arm64e address that plain code was never handed is not signed
    unsigned long other = z_strip((unsigned long)dlsym(RTLD_DEFAULT, "_ZSt9terminatev"));
    REQUIRE(other != 0);
    p.set((z_handler_t)other);
    REQUIRE(*p.slot == other);
    PASS();
}
int z6_corrupted_return_stops() {
    z_plain p; if (z_load(&p)) return 1;
    *p.slot = 0x0000000100001234UL;   // a handler that does not authenticate
    p.get();                          // must stop the process, not hand plain code a stripped pointer
    return fail("plain code was handed a handler that failed authentication");
}
int z7_null_maps_to_default() {
    z_plain p; if (z_load(&p)) return 1;
    p.set((z_handler_t)(void *)0);   // the standard maps a null handler to the default one, which the cache signed
    REQUIRE(*p.slot != 0 && *p.slot != z_strip(*p.slot));
    unsigned long got = (unsigned long)p.get();
    REQUIRE(got != 0 && got == z_strip(*p.slot));
    PASS();
}
int z8_throw_after_plain_set() {
    z_plain p; if (z_load(&p)) return 1;
    p.set((z_handler_t)z_strip((unsigned long)p.entry));   // plain code installs its own handler through the thunk
    try { throw 5; } catch (int v) { REQUIRE(v == 5); }
    PASS();
}

#define EXP_STD "c1=ok,c2=any,c3=ok,native=ok"
// not from the cache is a recorded fact (failed), never a fault
#define EXP_CACHE "c1=failed,c2=failed,c3=ok,native=failed"
// the in-tree ld64 loses the vtable address point of an authenticated typeinfo vtable bind
#define EXP_ADDEND "c1=ok,c2=any,c3=any,native=ok"
// recorded only, in every configuration
#define EXP_DIAG "c1=any,c2=any,c3=any,native=any"
// the reverse-adapter checks need the cache and the dyld that has them; elsewhere they are recorded only
#define EXP_REVERSE "c1=any,c2=any,c3=ok,native=any"
// plain code is handed a handler that fails authentication: the process stops, which the driver reports as faulted
#define EXP_REVERSE_STOP "c1=any,c2=any,c3=faulted,native=any"

}  // namespace

extern "C" {
const struct check checks[] = {
    {"q1_libcxx_function_served_from_cache", served_libcxx, EXP_CACHE},
    {"q1_cxa_throw_served_from_cache", served_cxa_throw, EXP_CACHE},
    {"q2_throw_catch_int", throw_catch_int, EXP_STD},
    {"q2_throw_through_nested_frames", throw_nested_frames, EXP_STD},
    {"q2_rethrow", rethrow, EXP_STD},
    {"q2_catch_all", catch_all, EXP_STD},
    {"q2_cleanup_landing_pad", cleanup_landing_pad, EXP_STD},
    {"q2_std_exception_hierarchy", std_exception_hierarchy, EXP_STD},
    {"q2_exception_through_std_function", exception_through_std_function, EXP_STD},
    {"q2_exception_in_thread", exception_in_thread, EXP_STD},
    {"q2_bad_function_call_known_ld64_addend", bad_function_call_known_ld64_addend, EXP_ADDEND},
    {"q2_class_base_catch_known_ld64_addend", class_base_catch_known_ld64_addend, EXP_ADDEND},
    {"q2_class_exact_catch_known_ld64_addend", class_exact_catch_known_ld64_addend, EXP_ADDEND},
    {"q2_dynamic_cast_known_ld64_addend", dynamic_cast_known_ld64_addend, EXP_ADDEND},
    {"q3_string_and_vector", string_and_vector, EXP_STD},
    {"q3_map_and_unordered_map", map_and_unordered_map, EXP_STD},
    {"q3_shared_ptr_control_block", shared_ptr_control_block, EXP_STD},
    {"q3_ostringstream_and_locale", ostringstream_and_locale, EXP_STD},
    {"q3_cout_and_cerr", cout_and_cerr, EXP_STD ";need=L4-COUT-LINE 42 1.25"},
    {"q4_thread_capturing_lambda", thread_capturing_lambda, EXP_STD},
    {"q4_mutex_counter", mutex_counter, EXP_STD},
    {"q4_condition_variable_handoff", condition_variable_handoff, EXP_STD},
    {"q4_call_once_across_threads", call_once_across_threads, EXP_STD},
    {"q4_thread_local_destructor", thread_local_destructor, EXP_STD},
    {"q5_atexit_and_static_destructor", atexit_and_static_destructor, EXP_STD ";need=L4-STATIC-DTOR"},
    {"q5_exit_flushes_cout", exit_flushes_cout, EXP_STD ";need=L4-FLUSHED-BY-EXIT"},
    {"q6_static_local_contention", static_local_contention, EXP_STD},
    {"q6_static_local_init_throws", static_local_init_throws, EXP_STD},
    {"x1_get_terminate", x1_get_terminate, EXP_DIAG},
    {"x2_set_get_terminate", x2_set_get_terminate, EXP_DIAG},
    {"x3_allocate_free_exception", x3_allocate_free_exception, EXP_DIAG},
    {"x4_init_primary_null_dtor", x4_init_primary_null_dtor, EXP_DIAG},
    {"x5_init_primary_signed_dtor", x5_init_primary_signed_dtor, EXP_DIAG},
    {"x6_init_primary_stripped_dtor", x6_init_primary_stripped_dtor, EXP_DIAG},
    {"x7_init_primary_class_typeinfo", x7_init_primary_class_typeinfo, EXP_DIAG},
    {"x8_get_unexpected_via_dlsym", x8_get_unexpected_via_dlsym, EXP_DIAG},
    {"y1_handler_slots", y1_handler_slots, EXP_DIAG},
    {"y2_set_signed_terminate_then_init", y2_set_signed_terminate_then_init, EXP_DIAG},
    {"z1_plain_entry_is_signed", z1_plain_entry_is_signed, EXP_REVERSE},
    {"z2_mid_function_address_not_signed", z2_mid_function_address_not_signed, EXP_REVERSE},
    {"z3_arm64e_image_address_not_signed", z3_arm64e_image_address_not_signed, EXP_REVERSE},
    {"z4_data_address_not_signed", z4_data_address_not_signed, EXP_REVERSE},
    {"z5_round_trip", z5_round_trip, EXP_REVERSE},
    {"z6_corrupted_return_stops", z6_corrupted_return_stops, EXP_REVERSE_STOP},
    {"z7_null_maps_to_default", z7_null_maps_to_default, EXP_REVERSE},
    {"z8_throw_after_plain_set", z8_throw_after_plain_set, EXP_REVERSE},
};
const int nchecks = sizeof checks / sizeof checks[0];
}
