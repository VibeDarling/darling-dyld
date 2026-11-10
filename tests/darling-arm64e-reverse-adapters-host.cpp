// Native driver of tests/darling-arm64e-reverse-adapters.rb: the opposite-direction thunks (a PLAIN importer binding an
// export of an arm64e image) of dyld3/DarlingArm64eAdapters.cpp on this arm64 host with real pointer authentication.
// The expectations use PAC instructions directly (pacia, autia, xpaci), not the module's helpers. `rows` prints the table and
// `reverse-thunk` the bytes of one thunk, which the Ruby test compares with llvm-mc.
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <string>
#include <sys/mman.h>
#include <sys/wait.h>
#include <unistd.h>
#include <signal.h>

#include "DarlingArm64eAdapters.h"

using namespace dyld3::darling;

static std::string gWarnings;
namespace dyld {
void warn(const char* format, ...)
{
	char line[512];
	va_list list;
	va_start(list, format);
	vsnprintf(line, sizeof(line), format, list);
	va_end(list);
	gWarnings += line;
}
}

static int gFailures, gChecks;
#define CHECK(cond, ...) do { ++gChecks; if (!(cond)) { ++gFailures; printf("FAIL %s:%d %s: ", __FILE__, __LINE__, #cond); printf(__VA_ARGS__); printf("\n"); } } while (0)

__attribute__((target("arch=armv8.3-a"))) static uint64_t oracleSign(uint64_t p, uint64_t modifier) { asm("pacia %0, %1" : "+r"(p) : "r"(modifier)); return p; }
__attribute__((target("arch=armv8.3-a"))) static uint64_t oracleAuth(uint64_t p, uint64_t modifier) { asm("autia %0, %1" : "+r"(p) : "r"(modifier)); return p; }
__attribute__((target("arch=armv8.3-a"))) static uint64_t oracleStrip(uint64_t p) { asm("xpaci %0" : "+r"(p)); return p; }

// the fake arm64e callee: records its arguments and returns what the test put in gResult
static uint64_t gSeen[8];
static int gCalls;
static uint64_t gResult;
static uint64_t fakeCallee(uint64_t a0, uint64_t a1, uint64_t a2, uint64_t a3, uint64_t a4, uint64_t a5, uint64_t a6, uint64_t a7)
{
	const uint64_t a[8] = { a0, a1, a2, a3, a4, a5, a6, a7 };
	memcpy(gSeen, a, sizeof(a));
	++gCalls;
	return gResult;
}
typedef uint64_t (*Fn8)(uint64_t, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t);

// The fake dyld predicate. A plain image's function entries are the multiples of 0x40 in [kCodeLow, kCodeHigh) that are in
// kEntries; every other address is a mid-function address of that image, an address in an arm64e image (kArm64eLow..), or
// data, and none of them is an entry.
static const uint64_t kCodeLow = 0x0000000100003000ULL, kCodeHigh = 0x0000000100009000ULL;
static const uint64_t kArm64eLow = 0x0000000180000000ULL;
static bool isEntry(uint64_t a)
{
	return (a >= kCodeLow) && (a < kCodeHigh) && (((a - kCodeLow) % 0x40) == 0);
}
static uint64_t codeAddress(int n) { return kCodeLow + 0x40 * n; }
// a second predicate with a disjoint answer, for the check that a thunk carries its own
static const uint64_t kOtherEntry = kArm64eLow + 0x4000;
static bool isEntryOther(uint64_t a) { return a == kOtherEntry; }
// an entry whose signature differs from the address, and from its signature under another modifier
static uint64_t goodCode(int n)
{
	uint64_t p = codeAddress(n);
	while ( (oracleSign(p, 0) == p) || (oracleSign(p, 1) == oracleSign(p, 0)) )
		p += 0x40;
	return p;
}

static Fn8 thunkFor(const char* symbol)
{
	const uint64_t t = reverseAdaptedTarget(symbol, (uint64_t)&fakeCallee, true, &isEntry);
	CHECK(t != (uint64_t)&fakeCallee, "%s was not adapted", symbol);
	return (Fn8)t;
}

static const uint64_t kS[8] = { 0x1111111111111111, 0x2222222222222222, 0x3333333333333333, 0x4444444444444444,
								0x5555555555555555, 0x6666666666666666, 0x7777777777777777, 0x0888888888888888 };

static uint64_t callWith(Fn8 f, const uint64_t* args) { return f(args[0], args[1], args[2], args[3], args[4], args[5], args[6], args[7]); }

static void checkTable()
{
	size_t n = 0;
	const ReverseRow* rows = reverseRows(&n);
	const char* error = validateReverseRows(rows, n);
	CHECK(error == nullptr, "built-in table: %s", error ? error : "");
	CHECK(n >= 20, "rows: %zu", n);
	ReverseRow bad[2] = { { "_a", 1, false, 1, AdapterStatus::Probed, "e" }, { "_a", 1, false, 1, AdapterStatus::Probed, "e" } };
	CHECK(validateReverseRows(bad, 2) != nullptr, "a duplicate symbol was accepted");
	ReverseRow noop[1] = { { "_a", 0, false, 1, AdapterStatus::Probed, "e" } };
	CHECK(validateReverseRows(noop, 1) != nullptr, "a row that does nothing was accepted");
	ReverseRow range[1] = { { "_a", 0x4, false, 2, AdapterStatus::Probed, "e" } };
	CHECK(validateReverseRows(range, 1) != nullptr, "a mask naming a missing argument was accepted");
	ReverseRow noev[1] = { { "_a", 1, false, 1, AdapterStatus::Probed, "" } };
	CHECK(validateReverseRows(noev, 1) != nullptr, "a row without evidence was accepted");
	ReverseRow unsupportedActs[1] = { { "_a", 1, false, 1, AdapterStatus::Unsupported, "e" } };
	CHECK(validateReverseRows(unsupportedActs, 1) != nullptr, "an unsupported row with an action was accepted");
}

static void checkSetHandler()
{
	// set_terminate: argument 0 signed IA/0, the old handler comes back stripped
	Fn8 f = thunkFor("__ZSt13set_terminatePFvvE");
	const uint64_t h = goodCode(1), old = goodCode(2);
	uint64_t args[8]; memcpy(args, kS, sizeof(args));
	args[0] = h;
	gResult = oracleSign(old, 0);
	gCalls = 0;
	const uint64_t r = callWith(f, args);
	CHECK(gCalls == 1, "callee called %d times", gCalls);
	CHECK(gSeen[0] == oracleSign(h, 0), "the callee did not get the IA/0 signature of the handler: %llx", (unsigned long long)gSeen[0]);
	CHECK(oracleAuth(gSeen[0], 0) == h, "the signed handler does not authenticate under IA/0");
	CHECK(oracleAuth(gSeen[0], 1) != h, "control: it must not authenticate under another modifier");
	for (int i = 1; i < 8; ++i)
		CHECK(gSeen[i] == kS[i], "argument %d changed", i);
	CHECK(r == old, "the old handler came back as %llx, not stripped to %llx", (unsigned long long)r, (unsigned long long)old);
	CHECK(r == oracleStrip(r), "the result still carries a signature");

	// NULL: never signed
	args[0] = 0; gResult = 0; callWith(f, args);
	CHECK(gSeen[0] == 0, "NULL was changed to %llx", (unsigned long long)gSeen[0]);

	// not function entries: data, garbage, a mid-function address of a plain image, an address of an arm64e image
	args[0] = 0x0000000200001000ULL; callWith(f, args);
	CHECK(gSeen[0] == 0x0000000200001000ULL, "a data address was signed");
	args[0] = 0xdeadbeef; callWith(f, args);
	CHECK(gSeen[0] == 0xdeadbeef, "garbage was signed");
	args[0] = h + 4; callWith(f, args);
	CHECK(gSeen[0] == h + 4, "a mid-function address of a plain image was signed");
	args[0] = kArm64eLow + 0x40; callWith(f, args);
	CHECK(gSeen[0] == kArm64eLow + 0x40, "an address in an arm64e image was signed");

	// a value that already carries a signature (a round trip through plain code) is not in a code window: unchanged
	const uint64_t signedAlready = oracleSign(h, 0);
	args[0] = signedAlready; callWith(f, args);
	CHECK(gSeen[0] == signedAlready, "an already signed pointer was changed");
	// 1 and -1 are not function entries
	for (uint64_t v : { 1ULL, ~0ULL }) {
		args[0] = v; callWith(f, args);
		CHECK(gSeen[0] == v, "%llx was changed", (unsigned long long)v);
	}
	// control: the same address stripped is signed
	args[0] = h; callWith(f, args);
	CHECK(gSeen[0] == oracleSign(h, 0), "control: the stripped address was not signed");
}

static void checkGetters()
{
	for (const char* sym : { "__ZSt13get_terminatev", "__ZSt14get_unexpectedv", "__ZSt15get_new_handlerv" }) {
		Fn8 f = thunkFor(sym);
		const uint64_t h = goodCode(3);
		gResult = oracleSign(h, 0); gCalls = 0;
		const uint64_t r = callWith(f, kS);
		CHECK(r == h, "%s result %llx not the raw handler %llx", sym, (unsigned long long)r, (unsigned long long)h);
		for (int i = 0; i < 8; ++i)
			CHECK(gSeen[i] == kS[i], "%s argument %d changed", sym, i);
		gResult = 0; callWith(f, kS);
		CHECK(callWith(f, kS) == 0, "%s: a NULL handler came back as non-zero", sym);
	}
}

// The thunk must not hand plain code a pointer whose signature failed: the child stops (SIGTRAP or SIGILL) and never gets to
// exit(0). The child's trap handler writes the warnings the module made to a pipe, so the message can be read here.
static int gMessageFd;
static void onTrap(int) { write(gMessageFd, gWarnings.data(), gWarnings.size()); _exit(42); }

static bool childStops(Fn8 f, uint64_t result, std::string* message = nullptr)
{
	fflush(stdout);
	int fds[2];
	if ( pipe(fds) != 0 )
		return false;
	const pid_t pid = fork();
	if ( pid == 0 ) {
		gMessageFd = fds[1];
		close(fds[0]);
		signal(SIGTRAP, onTrap);
		signal(SIGILL, onTrap);
		gResult = result;
		gWarnings.clear();
		callWith(f, kS);
		_exit(0);
	}
	close(fds[1]);
	char text[512];
	const ssize_t n = read(fds[0], text, sizeof(text) - 1);
	close(fds[0]);
	if ( message != nullptr )
		*message = std::string(text, n > 0 ? (size_t)n : 0);
	int status = 0;
	waitpid(pid, &status, 0);
	return WIFEXITED(status) && (WEXITSTATUS(status) == 42);
}

static void checkReturnAuthentication()
{
	for (const char* sym : { "__ZSt13get_terminatev", "__ZSt13set_terminatePFvvE" }) {
		Fn8 f = thunkFor(sym);
		const uint64_t h = goodCode(9);
		CHECK(!childStops(f, oracleSign(h, 0)), "%s: a handler with a good signature stopped the process", sym);
		CHECK(!childStops(f, 0) && !childStops(f, 1) && !childStops(f, ~0ULL), "%s: 0, 1 or -1 stopped the process", sym);
		std::string message;
		CHECK(childStops(f, h, &message), "%s: an unsigned handler was handed to plain code", sym);
		CHECK(message.find(sym) != std::string::npos, "%s: the message does not name the symbol: %s", sym, message.c_str());
		CHECK(childStops(f, oracleSign(h, 1)), "%s: a handler signed with another modifier was handed to plain code", sym);
		CHECK(childStops(f, oracleSign(h, 0) ^ (1ULL << 50)), "%s: a corrupted signature was handed to plain code", sym);
		CHECK(childStops(f, oracleStrip(oracleSign(h, 0)) | (1ULL << 55)), "%s: a pointer with stray high bits was handed to plain code", sym);
	}
	// a row whose result is not a handler hands back whatever it got, signed or not
	Fn8 cxa = thunkFor("___cxa_throw");
	CHECK(!childStops(cxa, goodCode(9)), "a result that is not a handler was authenticated");
}

static void checkRoundTrip()
{
	// get_terminate hands out an authenticated handler in an ARM64E image; plain code that passes it back gets it signed
	// again, but an arm64e address that was never handed out is not signed (no entry, never handed back)
	Fn8 get = thunkFor("__ZSt13get_terminatev");
	Fn8 set = thunkFor("__ZSt13set_terminatePFvvE");
	const uint64_t arm64eHandler = kArm64eLow + 0x1000, other = kArm64eLow + 0x2000;
	CHECK(!isEntry(arm64eHandler), "the fake predicate is wrong");
	gResult = oracleSign(arm64eHandler, 0);
	CHECK(callWith(get, kS) == arm64eHandler, "get_terminate did not hand out the raw handler");
	uint64_t args[8]; memcpy(args, kS, sizeof(args));
	gResult = 0;
	args[0] = arm64eHandler; callWith(set, args);
	CHECK(gSeen[0] == oracleSign(arm64eHandler, 0), "a handed-back handler was not signed again");
	args[0] = other; callWith(set, args);
	CHECK(gSeen[0] == other, "an arm64e address that was never handed out was signed");
}

// The predicate is carried in the thunk: two predicates with the same row and target get their own thunks, and each one
// asks its own predicate, whatever the other call did most recently.
static void checkPredicateIsolation()
{
	Fn8 a = (Fn8)reverseAdaptedTarget("__ZSt13set_terminatePFvvE", (uint64_t)&fakeCallee, true, &isEntry);
	Fn8 b = (Fn8)reverseAdaptedTarget("__ZSt13set_terminatePFvvE", (uint64_t)&fakeCallee, true, &isEntryOther);
	CHECK((uint64_t)a != (uint64_t)b, "two predicates shared one thunk");
	const uint64_t entry = goodCode(11);
	uint64_t args[8]; memcpy(args, kS, sizeof(args));
	gResult = 0;
	args[0] = entry;
	callWith(b, args);
	CHECK(gSeen[0] == entry, "a thunk used a predicate it was not made with");
	args[0] = kOtherEntry;
	callWith(a, args);
	CHECK(gSeen[0] == kOtherEntry, "a thunk used a predicate it was not made with (the other way)");
	callWith(b, args);
	CHECK(gSeen[0] == oracleSign(kOtherEntry, 0), "a thunk did not consult its own predicate");
}

// The two directions keep separate handed-out rings. A handler that plain code invented and the forward direction handed
// out is not a handler this direction authenticated: it must not be signed for an arm64e callee.
static void checkRingIsolation()
{
	Fn8 sig = (Fn8)adaptedTarget("_signal", (uint64_t)&fakeCallee, false);
	Fn8 set = thunkFor("__ZSt13set_terminatePFvvE");
	const uint64_t invented = 0x0000000400005000ULL;
	uint64_t args[8]; memcpy(args, kS, sizeof(args));
	// the forward signal() hands out a result that plain code invented (it fails authentication)
	args[0] = 26; args[1] = invented;
	gResult = invented; gCalls = 0;
	CHECK(callWith(sig, args) == invented, "the forward signal() changed the handler it returned");
	CHECK(gCalls == 1, "the forward callee was not called");
	// the forward ring took it: passing it back is accepted instead of replaced by a failed authentication
	gResult = 0;
	callWith(sig, args);
	CHECK(gSeen[1] == invented, "the forward ring did not take the value it handed out (this check would be vacuous)");
	// the reverse direction signs only function entries and its own ring: this value stays as it is
	memcpy(args, kS, sizeof(args));
	args[0] = invented;
	gResult = 0; gCalls = 0;
	callWith(set, args);
	CHECK(gCalls == 1, "the reverse callee was not called");
	CHECK(gSeen[0] == invented, "the reverse path signed a value that only the forward ring handed out (%llx)", (unsigned long long)gSeen[0]);
}

static void checkFunctionStarts()
{
	// deltas 0x10, 0x20, 0x08 give the starts 0x10, 0x30, 0x38; a zero delta ends the table
	const uint8_t blob[] = { 0x10, 0x20, 0x08, 0x00, 0x7f };
	CHECK(functionStartsContain(blob, sizeof(blob), 0x10) && functionStartsContain(blob, sizeof(blob), 0x30) && functionStartsContain(blob, sizeof(blob), 0x38), "a start was not found");
	CHECK(!functionStartsContain(blob, sizeof(blob), 0x0) && !functionStartsContain(blob, sizeof(blob), 0x11) && !functionStartsContain(blob, sizeof(blob), 0x34) && !functionStartsContain(blob, sizeof(blob), 0x3c), "a non-start was found");
	CHECK(!functionStartsContain(blob, sizeof(blob), 0x7f + 0x38), "an entry after the terminator was found");
	const uint8_t multi[] = { 0xb4, 0x24, 0x01, 0x00 };	// 0x1234, then 1: starts 0x1234, 0x1235
	CHECK(functionStartsContain(multi, sizeof(multi), 0x1234) && functionStartsContain(multi, sizeof(multi), 0x1235), "a multi-byte delta was misread");
	CHECK(!functionStartsContain(multi, sizeof(multi), 0x34), "a multi-byte delta was read as a single byte");
	const uint8_t truncated[] = { 0x10, 0x80 };
	CHECK(functionStartsContain(truncated, sizeof(truncated), 0x10) && !functionStartsContain(truncated, sizeof(truncated), 0x20), "a truncated blob was misread");
	const uint8_t endless[] = { 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x01 };
	CHECK(!functionStartsContain(endless, sizeof(endless), 0x10) && !functionStartsContain(endless, sizeof(endless), 0x40) && !functionStartsContain(endless, sizeof(endless), 0x2000), "an over-long ULEB was accepted");
	CHECK(!functionStartsContain(nullptr, 0, 0x10), "an empty blob has a start");
	// the running offset wraps past 2^64 and then reaches 0xfffffffffffffff8 by wrapped arithmetic; that is not a start
	const uint8_t wrapping[] = { 0xf0, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x01, 0x20, 0xe8, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x01, 0x00 };
	CHECK(!functionStartsContain(wrapping, sizeof(wrapping), 0xfffffffffffffff8ULL), "a table whose offsets overflow matched a wrapped offset");
}

static void checkArgPositions()
{
	// the dest of __cxa_throw is argument 2; the others pass; the result is not touched (a typeinfo pointer is data)
	Fn8 f = thunkFor("___cxa_throw");
	uint64_t args[8]; memcpy(args, kS, sizeof(args));
	args[0] = 0x0000000200002000ULL; args[1] = 0x0000000200003000ULL; args[2] = goodCode(4);
	gResult = 0x1234;
	const uint64_t r = callWith(f, args);
	CHECK(gSeen[2] == oracleSign(args[2], 0), "dest was not signed");
	CHECK(gSeen[0] == args[0] && gSeen[1] == args[1], "the object or the typeinfo changed");
	CHECK(r == 0x1234, "a result that is not a handler changed: %llx", (unsigned long long)r);
	// a row with two masked arguments: strstreambuf(this, alloc, free)
	f = thunkFor("__ZNSt3__112strstreambufC1EPFPvmEPFvS1_E");
	memcpy(args, kS, sizeof(args));
	args[0] = 0x0000000200002000ULL; args[1] = goodCode(5); args[2] = goodCode(6);
	callWith(f, args);
	CHECK(gSeen[0] == args[0], "this changed");
	CHECK(gSeen[1] == oracleSign(args[1], 0) && gSeen[2] == oracleSign(args[2], 0), "an alloc or free pointer was not signed");
	// a manipulator is argument 1
	f = thunkFor("__ZNSt3__113basic_ostreamIcNS_11char_traitsIcEEElsEPFRS3_S4_E");
	memcpy(args, kS, sizeof(args));
	args[0] = 0x0000000200002000ULL; args[1] = goodCode(7);
	callWith(f, args);
	CHECK(gSeen[0] == args[0] && gSeen[1] == oracleSign(args[1], 0), "the manipulator was not signed");
}

static void checkPolicy()
{
	CHECK(reverseAdaptedTarget("__ZSt13set_terminatePFvvE", 0x1234, false, &isEntry) == 0x1234, "an exporter that is plain was adapted");
	CHECK(reverseAdaptedTarget("_not_a_row", 0x1234, true, &isEntry) == 0x1234, "an unknown symbol was adapted");
	// no predicate: nothing is signed
	const uint64_t t = reverseAdaptedTarget("__ZSt15set_new_handlerPFvvE", (uint64_t)&fakeCallee, true, nullptr);
	CHECK(t != (uint64_t)&fakeCallee, "no thunk without a predicate");
	uint64_t args[8]; memcpy(args, kS, sizeof(args)); args[0] = goodCode(8);
	gResult = 0;
	callWith((Fn8)t, args);
	CHECK(gSeen[0] == args[0], "a pointer was signed with no predicate to vouch for it");
	// an unsupported row binds the target and warns
	gWarnings.clear();
	size_t n = 0; const ReverseRow* rows = reverseRows(&n);
	const char* unsupported = nullptr;
	for (size_t i = 0; i != n; ++i)
		if ( rows[i].status == AdapterStatus::Unsupported ) unsupported = rows[i].symbol;
	CHECK(unsupported != nullptr, "no unsupported row in the table");
	if ( unsupported ) {
		CHECK(reverseAdaptedTarget(unsupported, 0x1234, true, &isEntry) == 0x1234, "an unsupported row was adapted");
		CHECK(gWarnings.find(unsupported) != std::string::npos, "an unsupported row did not warn");
	}
	setAdapterMode(AdapterMode::Off);
	CHECK(reverseAdaptedTarget("__ZSt13set_terminatePFvvE", 0x1234, true, &isEntry) == 0x1234, "mode off still adapted");
	setAdapterMode(AdapterMode::On);
	// a thunk is made once per symbol and target
	CHECK(reverseAdaptedTarget("__ZSt13set_terminatePFvvE", (uint64_t)&fakeCallee, true, &isEntry) == reverseAdaptedTarget("__ZSt13set_terminatePFvvE", (uint64_t)&fakeCallee, true, &isEntry), "two thunks for one symbol and target");
}

// every supported row: the masked arguments that are entries are signed, nothing else changes, a handler result is authenticated
// and any other result passes through
static void checkEveryRow()
{
	size_t n = 0;
	const ReverseRow* rows = reverseRows(&n);
	int supported = 0;
	for (size_t r = 0; r != n; ++r) {
		const ReverseRow& row = rows[r];
		if ( row.status == AdapterStatus::Unsupported )
			continue;
		++supported;
		Fn8 f = thunkFor(row.symbol);
		uint64_t args[8]; memcpy(args, kS, sizeof(args));
		for (unsigned i = 0; i != 8; ++i)
			if ( (row.signMask >> i) & 1 )
				args[i] = goodCode(10 + i);
		gResult = row.authReturn ? oracleSign(goodCode(30), 0) : 0x5a5a;
		const uint64_t result = callWith(f, args);
		for (unsigned i = 0; i != 8; ++i) {
			const uint64_t want = ((row.signMask >> i) & 1) ? oracleSign(args[i], 0) : args[i];
			CHECK(gSeen[i] == want, "%s: argument %u is %llx, expected %llx", row.symbol, i, (unsigned long long)gSeen[i], (unsigned long long)want);
		}
		CHECK(result == (row.authReturn ? goodCode(30) : 0x5a5a), "%s: result %llx", row.symbol, (unsigned long long)result);
	}
	CHECK(supported == 23, "supported rows: %d", supported);
}

static void checkReport()
{
	gWarnings.clear();
	setAdapterMode(AdapterMode::Report);
	CHECK(reverseAdaptedTarget("_no_such_export", 0x1234, true, &isEntry) == 0x1234, "report mode changed a symbol with no row");
	CHECK(reverseAdaptedTarget("_no_such_export", 0x1234, true, &isEntry) == 0x1234, "report mode changed a symbol with no row (second time)");
	CHECK(gWarnings.find("_no_such_export") != std::string::npos, "report mode did not name a symbol with no row");
	CHECK(gWarnings.find("_no_such_export") == gWarnings.rfind("_no_such_export"), "report mode named a symbol twice");
	gWarnings.clear();
	CHECK(reverseAdaptedTarget("_no_such_export", 0x1234, false, &isEntry) == 0x1234 && gWarnings.empty(), "report mode named a plain exporter's symbol");
	setAdapterMode(AdapterMode::On);
	gWarnings.clear();
	CHECK(reverseAdaptedTarget("_another_export", 0x1234, true, &isEntry) == 0x1234 && gWarnings.empty(), "a symbol with no row was reported outside report mode");
}

static void checkThunkPage()
{
	const uint64_t t = reverseAdaptedTarget("__ZSt13set_terminatePFvvE", (uint64_t)&fakeCallee, true, &isEntry);
	FILE* maps = fopen("/proc/self/maps", "r");
	char line[512]; bool found = false, rx = false;
	while ( maps && fgets(line, sizeof(line), maps) ) {
		unsigned long lo, hi; char perms[8];
		if ( sscanf(line, "%lx-%lx %7s", &lo, &hi, perms) == 3 && t >= lo && t < hi ) { found = true; rx = strcmp(perms, "r-xp") == 0; }
	}
	if ( maps ) fclose(maps);
	CHECK(found && rx, "the thunk page is not r-x");
}

int main(int argc, char** argv)
{
	if ( argc >= 2 && strcmp(argv[1], "rows") == 0 ) {
		size_t n = 0; const ReverseRow* rows = reverseRows(&n);
		for (size_t i = 0; i != n; ++i)
			printf("%s %x %d %d %d\n", rows[i].symbol, rows[i].signMask, rows[i].authReturn, rows[i].argCount, (int)rows[i].status);
		return 0;
	}
	if ( argc >= 3 && strcmp(argv[1], "reverse-thunk") == 0 ) {
		const ReverseRow* row = findReverseRow(argv[2]);
		if ( row == nullptr )
			return 2;
		uint32_t w[24];
		const size_t n = emitReverseThunk(w, row, 0x1122334455667788ULL, &isEntry);
		printf("ROWADDR %016llx FORWARD_HELPER %016llx PREDICATE %016llx\n", (unsigned long long)(uint64_t)row, (unsigned long long)callThunkHelperAddress(), (unsigned long long)(uint64_t)&isEntry);
		for (size_t i = 0; i != n; ++i)
			printf("%08x\n", w[i]);
		return 0;
	}
	checkTable();
	checkSetHandler();
	checkGetters();
	checkReturnAuthentication();
	checkRoundTrip();
	checkPredicateIsolation();
	checkRingIsolation();
	checkFunctionStarts();
	checkArgPositions();
	checkEveryRow();
	checkPolicy();
	checkReport();
	checkThunkPage();
	printf("%d checks, %d failures\n", gChecks, gFailures);
	return gFailures == 0 ? 0 : 1;
}
