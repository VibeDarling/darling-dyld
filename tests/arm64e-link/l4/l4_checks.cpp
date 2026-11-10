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

#define EXP_STD "c1=ok,c2=any,c3=ok,native=ok"
// not from the cache is a recorded fact (failed), never a fault
#define EXP_CACHE "c1=failed,c2=failed,c3=ok,native=failed"
// the in-tree ld64 loses the vtable address point of an authenticated typeinfo vtable bind
#define EXP_ADDEND "c1=ok,c2=any,c3=any,native=ok"

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
};
const int nchecks = sizeof checks / sizeof checks[0];
}
