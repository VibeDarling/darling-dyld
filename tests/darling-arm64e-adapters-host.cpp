// Native driver of tests/darling-arm64e-adapters.rb: the real dyld3/DarlingArm64eAdapters.cpp built for this arm64
// host, with MachOLoaded.h, mach/machine.h and dyld::warn stubbed and the real signPointer extracted from
// dyld3/MachOLoaded.cpp. The expectations use the PAC instructions directly (pacia, autia, xpaci), not the module's
// own helpers. Modes: no argument runs the checks; `rows`, `auth-thunk MASK` and `call-thunk SYMBOL` print what the
// ruby side compares with an assembler.
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <string>

#include <signal.h>
#include <sys/mman.h>
#include <sys/resource.h>
#include <errno.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <unistd.h>
#include <vector>

#include "DarlingArm64eAdapters.h"

using namespace dyld3::darling;

static std::string gWarnings;
static bool gEcho;	// a child that is about to be killed has nowhere to keep its warnings but stderr
namespace dyld {
void warn(const char* format, ...)
{
	char line[512];
	va_list list;
	va_start(list, format);
	vsnprintf(line, sizeof(line), format, list);
	va_end(list);
	gWarnings += line;
	if ( gEcho )
		fputs(line, stderr);
}
}

// Every mapping or protection change of this process that asks for write and execute together is counted: the module's
// own calls reach these, and the checks below insist that there are none.
static int gWxCalls;
extern "C" void* mmap(void* addr, size_t length, int prot, int flags, int fd, off_t offset)
{
	if ( (prot & PROT_WRITE) && (prot & PROT_EXEC) )
		++gWxCalls;
	return (void*)syscall(SYS_mmap, addr, length, prot, flags, fd, offset);
}
extern "C" int mprotect(void* addr, size_t length, int prot)
{
	if ( (prot & PROT_WRITE) && (prot & PROT_EXEC) )
		++gWxCalls;
	return (int)syscall(SYS_mprotect, addr, length, prot);
}

static int gFailures, gChecks;
#define CHECK(cond, ...) do { ++gChecks; if (!(cond)) { ++gFailures; printf("FAIL %s:%d %s: ", __FILE__, __LINE__, #cond); printf(__VA_ARGS__); printf("\n"); } } while (0)

// ---------------------------------------------------------------- independent PAC oracle
__attribute__((target("arch=armv8.3-a"))) static uint64_t oracleSign(uint64_t p, uint64_t modifier) { asm("pacia %0, %1" : "+r"(p) : "r"(modifier)); return p; }
__attribute__((target("arch=armv8.3-a"))) static uint64_t oracleAuth(uint64_t p, uint64_t modifier) { asm("autia %0, %1" : "+r"(p) : "r"(modifier)); return p; }
__attribute__((target("arch=armv8.3-a"))) static uint64_t oracleStrip(uint64_t p) { asm("xpaci %0" : "+r"(p)); return p; }

// ---------------------------------------------------------------- a fake plain callee that records what it got
static uint64_t gSeen[8];
static int gCalls;
static uint64_t gFakeResult;
static void (*gHook)(const uint64_t* args);
static uint64_t fake8(uint64_t a0, uint64_t a1, uint64_t a2, uint64_t a3, uint64_t a4, uint64_t a5, uint64_t a6, uint64_t a7)
{
	const uint64_t a[8] = { a0, a1, a2, a3, a4, a5, a6, a7 };
	memcpy(gSeen, a, sizeof(a));
	++gCalls;
	if ( gHook )
		gHook(a);
	return gFakeResult;
}
typedef uint64_t (*Fn8)(uint64_t, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t);

static const uint64_t kSentinel[8] = { 0x1111111111111111, 0x2222222222222222, 0x3333333333333333, 0x4444444444444444,
									   0x5555555555555555, 0x6666666666666666, 0x7777777777777777, 0x0888888888888888 };

static uint64_t codeWithSignature(uint64_t modifier);
static uint64_t codeAddress(int n) { return 0x0000000100003000ULL + 0x40 * n; }

static std::vector<uint64_t> gThunkAddresses;
static Fn8 thunkFor(const char* symbol)
{
	const uint64_t t = adaptedTarget(symbol, (uint64_t)&fake8, false);
	gThunkAddresses.push_back(t);
	CHECK(t != (uint64_t)&fake8, "%s was not adapted", symbol);
	return (Fn8)t;
}

struct Block { void* isa; int32_t flags; int32_t reserved; void* invoke; void* descriptor; };
static const int32_t kHeap = 1 << 24, kGlobal = 1 << 28;
// A global block's literal lives in read-only memory and carries the signature that the arm64e image's own fixups gave it:
// built in a page that is made read-only, so that a write into it by the module crashes the test.
static const Block* gGlobalBlock;
static void makeGlobalBlock()
{
	Block* page = (Block*)mmap(nullptr, 4096, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANON, -1, 0);
	*page = { nullptr, kGlobal, 0, (void*)oracleSign(codeWithSignature((uint64_t)&page->invoke), (uint64_t)&page->invoke), nullptr };
	mprotect(page, 4096, PROT_READ);
	gGlobalBlock = page;
}

static Block* gSharedBlock;
static const char* gRefusedSymbol;
static void passSharedBlock() { ((Fn8)adaptedTarget(gRefusedSymbol, (uint64_t)&fake8, false))((uint64_t)gSharedBlock, (uint64_t)gSharedBlock, 0, 0, 0, 0, 0, 0); }
// a heap block in read-only memory: Block_copy of it is a retain, and a write into it by the module crashes the test
static const Block* gReadOnlyHeapBlock;
static void makeReadOnlyHeapBlock()
{
	Block* page = (Block*)mmap(nullptr, 4096, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANON, -1, 0);
	*page = { nullptr, kHeap, 0, (void*)oracleSign(codeWithSignature((uint64_t)&page->invoke), (uint64_t)&page->invoke), nullptr };
	mprotect(page, 4096, PROT_READ);
	gReadOnlyHeapBlock = page;
}

static uint64_t gBlockInvokeSeen;
static void snapshotBlock(const uint64_t* a) { const Block* b = (const Block*)a[1]; if (b) { gBlockInvokeSeen = (uint64_t)b->invoke; } }

static void checkPacWorks()
{
	// an address whose signatures for modifiers 0 and 1 differ and are not zero: with 7 PAC bits two signatures of one
	// address are equal about once in 128, and that must not make a check fail
	uint64_t p = codeAddress(1);
	while ( (oracleSign(p, 0) == p) || (oracleSign(p, 1) == oracleSign(p, 0)) )
		p += 0x40;
	const uint64_t s = oracleSign(p, 0);
	CHECK(s != p, "this host does not sign (no pointer authentication): the test cannot say anything");
	CHECK(oracleStrip(s) == p, "oracle strip");
	CHECK(oracleAuth(s, 0) == p, "oracle auth");
	CHECK(oracleAuth(s, 1) != p, "oracle auth with the wrong modifier must not give the pointer back");
}

// "r-xp" for the mapping that holds the address, or "unmapped"
static std::string permissionsOf(uint64_t address)
{
	FILE* maps = fopen("/proc/self/maps", "r");
	char line[512];
	std::string perms = "unmapped";
	while ( fgets(line, sizeof(line), maps) ) {
		unsigned long long lo, hi;
		char p[8];
		if ( sscanf(line, "%llx-%llx %7s", &lo, &hi, p) == 3 && address >= lo && address < hi )
			perms = p;
	}
	fclose(maps);
	return perms;
}

static bool anyWritableAndExecutableMapping()
{
	FILE* maps = fopen("/proc/self/maps", "r");
	char line[512];
	bool found = false;
	while ( fgets(line, sizeof(line), maps) ) {
		unsigned long long lo, hi;
		char p[8];
		if ( sscanf(line, "%llx-%llx %7s", &lo, &hi, p) == 3 && p[1] == 'w' && p[2] == 'x' )
			found = true;
	}
	fclose(maps);
	return found;
}

static void checkSeal()
{
	const size_t size = 16384;
	uint32_t* page = (uint32_t*)mmap(nullptr, size, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANON, -1, 0);
	page[0] = 0xD65F03C0;	// ret
	CHECK(permissionsOf((uint64_t)page) == "rw-p", "before the seal: %s", permissionsOf((uint64_t)page).c_str());
	CHECK(sealExecutablePage(page, size), "seal");
	CHECK(permissionsOf((uint64_t)page) == "r-xp", "after the seal: %s", permissionsOf((uint64_t)page).c_str());
	((void (*)())page)();
	// a write into a sealed page must not be possible
	fflush(stdout);
	pid_t pid = fork();
	if ( pid == 0 ) {
		signal(SIGSEGV, SIG_DFL);
		page[0] = 0;
		_exit(0);
	}
	int status = 0;
	waitpid(pid, &status, 0);
	CHECK(WIFSIGNALED(status) && (WTERMSIG(status) == SIGSEGV), "a write into a sealed page did not fault (status 0x%x)", status);
}

// after everything above has made its thunks
static void checkThunkPages()
{
	CHECK(gThunkAddresses.size() >= 8, "only %zu thunks were made", gThunkAddresses.size());
	for (uint64_t t : gThunkAddresses)
		CHECK(permissionsOf(t) == "r-xp", "thunk %llx is in a %s mapping", (unsigned long long)t, permissionsOf(t).c_str());
	CHECK(!anyWritableAndExecutableMapping(), "a writable and executable mapping exists in this process");
	CHECK(gWxCalls == 0, "%d mmap or mprotect calls asked for write and execute together", gWxCalls);
}

static void checkTable()
{
	size_t n = 0;
	const AdapterRow* rows = adapterRows(&n);
	const char* error = validateAdapterRows(rows, n);
	CHECK(error == nullptr, "built-in table: %s", error ? error : "");
	CHECK(n >= 100, "rows: %zu", n);

	auto bad = [](const AdapterRow r, const char* why) {
		AdapterRow two[2] = { { "_ok", 1, 0, 0, ReturnFix::None, 1, AdapterStatus::Probed, "e" }, r };
		CHECK(validateAdapterRows(two, 2) != nullptr, "a malformed table was accepted: %s", why);
	};
	bad({ "nounderscore", 1, 0, 0, ReturnFix::None, 1, AdapterStatus::Probed, "e" }, "no underscore");
	bad({ "_ok", 1, 0, 0, ReturnFix::None, 1, AdapterStatus::Probed, "e" }, "duplicate");
	bad({ "_a", 1, 0, 0, ReturnFix::None, 1, AdapterStatus::Probed, "" }, "no evidence");
	bad({ "_a", 0, 0, 0, ReturnFix::None, 1, AdapterStatus::Probed, "e" }, "no action");
	bad({ "_a", 4, 0, 0, ReturnFix::None, 2, AdapterStatus::Probed, "e" }, "mask beyond argCount");
	bad({ "_a", 1, 0, 0, ReturnFix::None, 9, AdapterStatus::Probed, "e" }, "nine arguments");
	bad({ "_a", 1, 0, 0, ReturnFix::None, 0, AdapterStatus::Probed, "e" }, "no argument count");
	bad({ "_a", 0, 3, 0, ReturnFix::None, 2, AdapterStatus::Probed, "e" }, "block argument beyond argCount");
	bad({ "_a", 0, 1, 1, ReturnFix::None, 2, AdapterStatus::Probed, "e" }, "block and struct together");
	bad({ "_a", 0, 0, 2, ReturnFix::None, 2, AdapterStatus::Probed, "e" }, "a struct argument with no old action after it");
	bad({ "_a", 1, 1, 0, ReturnFix::None, 2, AdapterStatus::Probed, "e" }, "block argument also stripped");
	bad({ "_a", 1, 0, 0, ReturnFix::None, 1, AdapterStatus::Unsupported, "e" }, "unsupported row with an action");
	bad({ "_a", 1, 0, 0, ReturnFix::None, 1, AdapterStatus::HandledElsewhere, "e" }, "handled-elsewhere row with an action");
}

// ---------------------------------------------------------------- helpers for the authentication checks
// The signature bits of a signed pointer: a copy with one of them flipped cannot authenticate
static uint64_t corrupted(uint64_t signedPointer)
{
	const uint64_t bits = signedPointer ^ oracleStrip(signedPointer);
	return signedPointer ^ (bits & -bits);
}

// a code address whose signature for this modifier is not zero, so that the unsigned pointer cannot authenticate by luck
static uint64_t codeWithSignature(uint64_t modifier)
{
	for (uint64_t p = codeAddress(1);; p += 0x40)
		if ( oracleSign(p, modifier) != p )
			return p;
}

static bool gFpac;
// functions whose address, signed with modifier 0, differs from the address: with the process's random key about one
// in 128 would sign to itself, and a "corrupted" copy of that is no corruption at all
static void touch0() { }
static void touch1() { }
static void touch2() { }
static void touch3() { }
static uint64_t touch()
{
	for (void (*f)() : { touch0, touch1, touch2, touch3 })
		if ( oracleSign((uint64_t)f, 0) != (uint64_t)f )
			return (uint64_t)f;
	return (uint64_t)touch0;
}
static uint64_t callArg0(uint64_t p, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t)
{
	((void (*)())p)();
	return 0;
}

// Does a failed authentication kill the process (FPAC) or return a pointer that faults when it is called?
static void detectFpac()
{
	fflush(stdout);
	pid_t pid = fork();
	if ( pid == 0 ) {
		signal(SIGSEGV, SIG_DFL);
		oracleAuth(corrupted(oracleSign(codeWithSignature(0), 0)), 0);
		_exit(0);
	}
	int status = 0;
	waitpid(pid, &status, 0);
	gFpac = WIFSIGNALED(status);
	printf("INFO this host %s a failed authentication\n", gFpac ? "faults at" : "survives");
}

// in a child: true when it ended with exit status 0, false when a signal killed it
static bool childSurvives(void (*body)())
{
	fflush(stdout);
	pid_t pid = fork();
	if ( pid == 0 ) {
		signal(SIGSEGV, SIG_DFL); signal(SIGBUS, SIG_DFL); signal(SIGILL, SIG_DFL);
		body();
		_exit(0);
	}
	int status = 0;
	waitpid(pid, &status, 0);
	return WIFEXITED(status) && (WEXITSTATUS(status) == 0);
}

// Runs body in a child with stderr in a pipe. Returns the wait status; out gets what the child wrote to stderr.
static int childOutput(void (*body)(), std::string& out)
{
	int fds[2];
	if ( pipe(fds) != 0 )
		return -1;
	fflush(stdout);
	pid_t pid = fork();
	if ( pid == 0 ) {
		close(fds[0]);
		dup2(fds[1], 2);
		gEcho = true;
		signal(SIGSEGV, SIG_DFL); signal(SIGBUS, SIG_DFL); signal(SIGILL, SIG_DFL); signal(SIGTRAP, SIG_DFL);
		body();
		_exit(0);
	}
	close(fds[1]);
	char buf[512];
	ssize_t n;
	out.clear();
	while ( (n = read(fds[0], buf, sizeof(buf))) > 0 )
		out.append(buf, n);
	close(fds[0]);
	int status = 0;
	waitpid(pid, &status, 0);
	return status;
}

static Fn8 gCallingThunk;
static void callGoodPointer() { gCallingThunk(oracleSign(touch(), 0), 0, 0, 0, 0, 0, 0, 0); }
static void callCorruptedPointer() { gCallingThunk(corrupted(oracleSign(touch(), 0)), 0, 0, 0, 0, 0, 0, 0); }

static void checkAuthRows()
{
	size_t n = 0;
	const AdapterRow* rows = adapterRows(&n);
	const uint64_t good = oracleSign(codeWithSignature(0), 0);
	const uint64_t plain = oracleStrip(good);
	int rowsRun = 0;
	for (size_t r = 0; r != n; ++r) {
		const AdapterRow& row = rows[r];
		if ( ((row.status != AdapterStatus::Probed) && (row.status != AdapterStatus::ShapeOnly)) || row.blockArg || row.structArg || (row.ret != ReturnFix::None) )
			continue;
		++rowsRun;
		Fn8 t = thunkFor(row.symbol);
		struct Case { uint64_t value; uint64_t want; const char* what; bool failsAuth; };
		const Case cases[] = {
			{ good, plain, "signed", false },
			{ 0, 0, "NULL", false }, { ~0ULL, ~0ULL, "-1", false }, { 1, 1, "1", false },
			{ plain, oracleAuth(plain, 0), "unsigned", true },
			{ 0x9234567812345678ULL, oracleAuth(0x9234567812345678ULL, 0), "garbage high-bit", true },
			{ oracleSign(plain, 0x1234), oracleAuth(oracleSign(plain, 0x1234), 0), "signed with another discriminator", true },
			{ corrupted(good), oracleAuth(corrupted(good), 0), "corrupted signature", true },
		};
		for (const Case& c : cases) {
			if ( c.failsAuth && gFpac )
				continue;	// the instruction itself would kill this process; the child checks below cover it
			uint64_t args[8];
			memcpy(args, kSentinel, sizeof(args));
			for (unsigned i = 0; i != 8; ++i)
				if ( (row.authMask >> i) & 1 )
					args[i] = c.value;
			gCalls = 0;
			gFakeResult = 0xabcdef;
			const uint64_t result = t(args[0], args[1], args[2], args[3], args[4], args[5], args[6], args[7]);
			CHECK(gCalls == 1, "%s: the target was called %d times", row.symbol, gCalls);
			CHECK(result == 0xabcdef, "%s: the result was changed", row.symbol);
			for (unsigned i = 0; i != 8; ++i) {
				const uint64_t want = ((row.authMask >> i) & 1) ? c.want : kSentinel[i];
				CHECK(gSeen[i] == want, "%s arg %u (%s): 0x%llx arrived as 0x%llx, want 0x%llx", row.symbol, i, c.what, (unsigned long long)c.value, (unsigned long long)gSeen[i], (unsigned long long)want);
				if ( c.failsAuth && ((row.authMask >> i) & 1) && (c.value == corrupted(good)) )
					CHECK(gSeen[i] != plain && gSeen[i] != oracleStrip(gSeen[i]), "%s arg %u: a corrupted signature came out usable (0x%llx)", row.symbol, i, (unsigned long long)gSeen[i]);
			}
		}
	}
	CHECK(rowsRun >= 20, "only %d authenticating rows ran", rowsRun);

	// the same thing as a call: the good pointer runs, the others kill the child
	const uint64_t target = (uint64_t)&callArg0;
	gCallingThunk = (Fn8)adaptedTarget("_atexit", target, false);
	gThunkAddresses.push_back((uint64_t)gCallingThunk);
	CHECK(childSurvives(callGoodPointer), "a signed pointer did not run through the thunk");
	CHECK(!childSurvives(callCorruptedPointer), "a pointer with a corrupted signature ran");
}

static void checkSignal()
{
	Fn8 t = thunkFor("_signal");
	const uint64_t handlerA = oracleSign(codeWithSignature(0), 0), handlerB = oracleSign(codeWithSignature(0) + 0x400, 0);
	const uint64_t plainA = oracleStrip(handlerA), plainB = oracleStrip(handlerB), other = codeAddress(20);

	// arm64e code installs A over SIG_DFL: the result 0 stays, A is remembered
	gFakeResult = 0;
	CHECK(t(30, handlerA, 0, 0, 0, 0, 0, 0) == 0, "signal: SIG_DFL came back changed");
	CHECK(gSeen[0] == 30 && gSeen[1] == plainA, "signal: arguments 30, 0x%llx", (unsigned long long)gSeen[1]);

	// installing B returns A, which arm64e code installed: it comes back signed IA, discriminator 0
	gFakeResult = plainA;
	uint64_t result = t(30, handlerB, 0, 0, 0, 0, 0, 0);
	CHECK(result != plainA && oracleAuth(result, 0) == plainA, "signal: the handler that arm64e code installed did not come back signed");

	// a value that arm64e code did not install is not signed, whatever it points at
	gFakeResult = other;
	CHECK(t(30, handlerA, 0, 0, 0, 0, 0, 0) == other, "signal: a handler nobody installed here was signed");
	gFakeResult = plainB;	// B was installed before the line above replaced it
	CHECK(t(30, handlerA, 0, 0, 0, 0, 0, 0) == plainB, "signal: a stale handler was signed");

	// the special values come back as they are
	for (uint64_t special : { 0ULL, 1ULL, ~0ULL }) {
		gFakeResult = special;
		CHECK(t(30, handlerA, 0, 0, 0, 0, 0, 0) == special, "signal: special value 0x%llx", (unsigned long long)special);
	}
	// SIG_IGN installed by arm64e code is remembered like a handler, and still comes back as 1
	gFakeResult = 0;
	t(30, 1, 0, 0, 0, 0, 0, 0);
	gFakeResult = 1;
	CHECK(t(30, handlerA, 0, 0, 0, 0, 0, 0) == 1, "signal: SIG_IGN that arm64e code installed came back signed");
	// SIG_ERR means nothing was installed: the next call must not sign the handler of the failed one
	gFakeResult = ~0ULL;
	t(31, handlerB, 0, 0, 0, 0, 0, 0);
	gFakeResult = plainB;
	CHECK(t(31, handlerA, 0, 0, 0, 0, 0, 0) == plainB, "signal: a handler whose installation failed was signed");
	// an out of range signal number is never remembered
	gFakeResult = 0;
	t(100, handlerB, 0, 0, 0, 0, 0, 0);
	gFakeResult = plainB;
	CHECK(t(100, handlerA, 0, 0, 0, 0, 0, 0) == plainB, "signal: out of range number");
	// a handler that does not authenticate is not remembered either
	if ( !gFpac ) {
		gFakeResult = 0;
		t(29, corrupted(handlerA), 0, 0, 0, 0, 0, 0);
		const uint64_t poisoned = gSeen[1];
		CHECK(poisoned != plainA && poisoned != oracleStrip(poisoned), "signal: a corrupted handler reached the callee usable");
		gFakeResult = poisoned;
		CHECK(t(29, handlerB, 0, 0, 0, 0, 0, 0) == poisoned, "signal: a handler that failed authentication was signed on its way back");
	}
	// SIG_IGN as the argument survives
	t(30, 1, 0, 0, 0, 0, 0, 0);
	CHECK(gSeen[1] == 1, "signal: SIG_IGN changed");
}

// a code address after `after` whose signature for the modifier is not zero: unsigned, it cannot authenticate by luck
static uint64_t codeWithSignatureAfter(uint64_t after, uint64_t modifier)
{
	for (uint64_t p = after;; p += 0x40)
		if ( oracleSign(p, modifier) != p )
			return p;
}

// A handler that plain code installed is handed to arm64e code unsigned; arm64e code that saves it and restores it passes
// it back as it got it. That works for exactly the values handed out, and a forged unsigned pointer still does not.
static void checkHandlerRoundTrip()
{
	Fn8 sig = thunkFor("_signal");
	Fn8 act = thunkFor("_sigaction");
	const uint64_t signedNew = oracleSign(codeWithSignature(0), 0);
	const uint64_t plainOld = codeWithSignatureAfter(0x0000000100008000ULL, 0);
	const uint64_t forged = codeWithSignatureAfter(0x0000000100009000ULL, 0);

	// signal(): plain code had installed plainOld, arm64e code gets it back unsigned and restores it
	gFakeResult = plainOld;
	CHECK(sig(20, signedNew, 0, 0, 0, 0, 0, 0) == plainOld, "round trip: a handler plain code installed came back changed");
	gFakeResult = 0;
	sig(20, plainOld, 0, 0, 0, 0, 0, 0);
	CHECK(gSeen[1] == plainOld, "round trip: the saved handler did not come back to signal() unchanged (0x%llx)", (unsigned long long)gSeen[1]);
	// a pointer that was never handed out and is not signed stays unusable
	if ( !gFpac ) {
		sig(20, forged, 0, 0, 0, 0, 0, 0);
		CHECK(gSeen[1] != forged && gSeen[1] == oracleAuth(forged, 0), "round trip: a forged unsigned pointer was accepted (0x%llx)", (unsigned long long)gSeen[1]);
	}

	// sigaction(): the old action that plain code left is written into oact; restored as act it still works
	struct Act { uint64_t handler; uint32_t mask; int32_t flags; };
	static Act old;
	static Act saved;
	old = { 0, 0, 0 };
	const uint64_t oldHandler = codeWithSignatureAfter(0x0000000100008000ULL + 0x40 * 7, 0);
	static uint64_t oldHandlerValue;
	oldHandlerValue = oldHandler;
	gHook = [](const uint64_t* a) { if (a[2]) { Act* o = (Act*)a[2]; *o = { oldHandlerValue, 0x11, 0x22 }; } if (a[1]) memcpy(&saved, (const void*)a[1], sizeof(saved)); };
	gFakeResult = 0;
	Act fresh = { signedNew, 0, 0 };
	act(21, (uint64_t)&fresh, (uint64_t)&old, 0, 0, 0, 0, 0);
	CHECK(old.handler == oldHandler, "round trip: the old action was changed on its way out");
	act(21, (uint64_t)&old, 0, 0, 0, 0, 0, 0);
	CHECK(saved.handler == oldHandler && saved.mask == 0x11 && saved.flags == 0x22, "round trip: the saved old action did not come back to sigaction() unchanged (0x%llx)", (unsigned long long)saved.handler);
	if ( !gFpac ) {
		Act forgedAct = { forged, 0, 0 };
		act(21, (uint64_t)&forgedAct, 0, 0, 0, 0, 0, 0);
		CHECK(saved.handler != forged && saved.handler == oracleAuth(forged, 0), "round trip: a forged unsigned handler in a struct was accepted");
	}
	gHook = nullptr;

	// The ring holds exactly the last 64: every one of them is accepted again, whatever slot the count had reached, and older
	// ones are refused. Shifting the start by 0..64 puts the wrap-around at every slot, so a ring that is a slot too long
	// or too short loses a handler in one of the rounds.
	if ( !gFpac ) {
		uint64_t next = 0x0000000200000000ULL;	// far from every other test's handlers: a value already in the ring is not entered twice
		auto fresh = [&]() { next = codeWithSignatureAfter(next + 0x40, 0); return next; };
		for (int shift = 0; shift <= 64; ++shift) {
			for (int i = 0; i != shift; ++i) {
				gFakeResult = fresh();
				sig(19, signedNew, 0, 0, 0, 0, 0, 0);
			}
			std::vector<uint64_t> handedOut;
			for (int i = 0; i != 64; ++i) {
				handedOut.push_back(fresh());
				gFakeResult = handedOut.back();
				sig(19, signedNew, 0, 0, 0, 0, 0, 0);
			}
			gFakeResult = 0;
			int refused = 0;
			for (uint64_t h : handedOut) {
				sig(19, h, 0, 0, 0, 0, 0, 0);
				refused += gSeen[1] != h;
			}
			CHECK(refused == 0, "round trip: %d of the last 64 handed out handlers were refused (shift %d)", refused, shift);
		}
		const uint64_t old = fresh();
		gFakeResult = old;
		sig(19, signedNew, 0, 0, 0, 0, 0, 0);
		for (int i = 0; i != 64; ++i) {
			gFakeResult = fresh();
			sig(19, signedNew, 0, 0, 0, 0, 0, 0);
		}
		gFakeResult = 0;
		sig(19, old, 0, 0, 0, 0, 0, 0);
		CHECK(gSeen[1] != old, "round trip: a handler that fell out of the ring was still accepted");
	}
}

// A value that plain code installed and that the ring then accepted is not a signature that arm64e code made: it is never
// remembered as installed, so it is never signed on its way back. (A pointer that came back from signal() unsigned,
// passed in again, installed and returned, used to come out signed IA, discriminator 0: a signing oracle for any value
// that plain code can plant.)
static void checkNoSigningOracle()
{
	Fn8 sig = thunkFor("_signal");
	Fn8 act = thunkFor("_sigaction");
	const uint64_t handlerA = oracleSign(codeWithSignature(0), 0);
	const uint64_t V = codeWithSignatureAfter(0x4142434440ULL, 0);
	struct Act { uint64_t handler; uint32_t mask; int32_t flags; };

	// plain code installed V (through _sigset, say: an unsupported row that binds the raw function)
	gFakeResult = V;
	CHECK(sig(30, handlerA, 0, 0, 0, 0, 0, 0) == V, "oracle: a plain handler came back changed");
	// arm64e code restores it: accepted through the ring, installed
	gFakeResult = 0;
	sig(30, V, 0, 0, 0, 0, 0, 0);
	CHECK(gSeen[1] == V, "oracle: the restore of V was not accepted");
	// and the next signal() returns it: it must not come out signed
	gFakeResult = V;
	CHECK(sig(30, handlerA, 0, 0, 0, 0, 0, 0) == V, "oracle: V, accepted through the ring, was signed IA with discriminator 0");

	// the same through sigaction: restored with V in a struct, then returned by signal()
	Act actV = { V, 0, 0 };
	gFakeResult = V;
	sig(29, handlerA, 0, 0, 0, 0, 0, 0);
	gFakeResult = 0;
	act(29, (uint64_t)&actV, 0, 0, 0, 0, 0, 0);
	gFakeResult = V;
	CHECK(sig(29, handlerA, 0, 0, 0, 0, 0, 0) == V, "oracle: V, installed by sigaction through the ring, was signed");

	// a handler that plain code planted after arm64e code had installed its own is not the recorded one any more
	gFakeResult = 0;
	sig(28, handlerA, 0, 0, 0, 0, 0, 0);
	gFakeResult = V;
	sig(28, handlerA, 0, 0, 0, 0, 0, 0);
	sig(28, V, 0, 0, 0, 0, 0, 0);
	gFakeResult = oracleStrip(handlerA);
	CHECK(sig(28, handlerA, 0, 0, 0, 0, 0, 0) == oracleStrip(handlerA), "oracle: a stale record signed a handler that plain code had put back");
}

// The old action is taken from the callee's private copy and copied out; memory that the caller, or another thread, can
// write while the call runs is not read again. The deterministic equivalent of the race: the callee writes the legitimate
// old handler into the copy it was given, and the "other thread" writes a forged one into the caller's memory during the
// call; what is remembered as handed out is the legitimate one.
static uint64_t* gCallerOld;
static uint64_t gLegitOld, gForgedOld;
static void raceOnOldAction(const uint64_t* a)
{
	if ( a[2] )
		((uint64_t*)a[2])[0] = gLegitOld;
	gCallerOld[0] = gForgedOld;
}

static void checkOldActionRace()
{
	Fn8 act = thunkFor("_sigaction");
	Fn8 sig = thunkFor("_signal");
	const uint64_t handlerA = oracleSign(codeWithSignature(0), 0);
	gLegitOld = codeWithSignatureAfter(0x0000000100020000ULL, 0);
	gForgedOld = codeWithSignatureAfter(0x0000000100030000ULL, 0);
	struct Act { uint64_t handler; uint32_t mask; int32_t flags; };
	Act fresh = { handlerA, 0, 0 };
	Act old = { 0, 0, 0 };
	gCallerOld = &old.handler;
	gHook = raceOnOldAction;
	gFakeResult = 0;
	act(27, (uint64_t)&fresh, (uint64_t)&old, 0, 0, 0, 0, 0);
	gHook = nullptr;
	CHECK(old.handler == gLegitOld, "race: the caller's old action is not what the callee wrote (0x%llx)", (unsigned long long)old.handler);
	CHECK(gSeen[2] != (uint64_t)&old, "race: the callee was given the caller's own old-action memory");
	if ( !gFpac ) {
		gFakeResult = 0;
		sig(27, gForgedOld, 0, 0, 0, 0, 0, 0);
		CHECK(gSeen[1] != gForgedOld, "race: a value written into the caller's memory during the call was accepted");
		sig(27, gLegitOld, 0, 0, 0, 0, 0, 0);
		CHECK(gSeen[1] == gLegitOld, "race: the legitimate old handler was refused");
	}
}

// the signal number is an int: dirty upper bits are not part of it, and numbers outside 1..31 are never remembered
static void checkSignalNumbers()
{
	Fn8 sig = thunkFor("_signal");
	Fn8 act = thunkFor("_sigaction");
	const uint64_t handlerA = oracleSign(codeWithSignature(0), 0), plainA = oracleStrip(handlerA);
	const uint64_t dirty = 0xdead00000000ULL;
	gFakeResult = 0;
	sig(dirty | 17, handlerA, 0, 0, 0, 0, 0, 0);
	gFakeResult = plainA;
	uint64_t r = sig(17, handlerA, 0, 0, 0, 0, 0, 0);
	CHECK(oracleAuth(r, 0) == plainA && r != plainA, "signal numbers: a number with dirty upper bits was not remembered as itself");
	gFakeResult = 0;
	sig(17, handlerA, 0, 0, 0, 0, 0, 0);
	gFakeResult = plainA;
	r = sig(dirty | 17, handlerA, 0, 0, 0, 0, 0, 0);
	CHECK(oracleAuth(r, 0) == plainA && r != plainA, "signal numbers: a lookup with dirty upper bits did not find the handler");
	struct Act { uint64_t handler; uint32_t mask; int32_t flags; };
	Act actA = { handlerA, 0, 0 };
	gFakeResult = 0;
	act(dirty | 16, (uint64_t)&actA, 0, 0, 0, 0, 0, 0);
	gFakeResult = plainA;
	r = sig(16, handlerA, 0, 0, 0, 0, 0, 0);
	CHECK(oracleAuth(r, 0) == plainA && r != plainA, "signal numbers: sigaction with dirty upper bits did not remember the handler");

	// outside 1..31 nothing is remembered, so nothing comes back signed, and nothing is written outside the table
	const uint64_t outside[] = { 0, 32, 33, 0xffffffffULL, ~0ULL, 0x80000000ULL, dirty | 32, dirty | 0xffffffffULL };
	for (uint64_t n : outside) {
		gFakeResult = 0;
		sig(n, handlerA, 0, 0, 0, 0, 0, 0);
		gFakeResult = plainA;
		const uint64_t back = sig(n, handlerA, 0, 0, 0, 0, 0, 0);
		CHECK(back == plainA, "signal numbers: 0x%llx was remembered", (unsigned long long)n);
	}
	gFakeResult = 0;
	sig(31, handlerA, 0, 0, 0, 0, 0, 0);
	gFakeResult = plainA;
	CHECK(oracleAuth(sig(31, handlerA, 0, 0, 0, 0, 0, 0), 0) == plainA, "signal numbers: 31 is the last valid one");

	// SIG_HOLD (5) is only for sigset, which has no adapter: here it is a pointer like any other and does not authenticate
	if ( !gFpac ) {
		sig(14, 5, 0, 0, 0, 0, 0, 0);
		CHECK(gSeen[1] == oracleAuth(5, 0) && ((oracleSign(5, 0) == 5) || (gSeen[1] != 5)), "signal numbers: SIG_HOLD reached the callee as a valid pointer");
	}
}

static Block gHeapResult;
static void checkBlockCopy()
{
	Fn8 t = thunkFor("__Block_copy");
	const uint64_t target = codeWithSignature(0);
	Block original = { nullptr, 0, 0, nullptr, nullptr };
	original.invoke = (void*)oracleSign(codeWithSignature((uint64_t)&original.invoke), (uint64_t)&original.invoke);
	const uint64_t plainTarget = oracleStrip((uint64_t)original.invoke);
	(void)target;

	// the plain Block_copy moves the literal and leaves the stale signature in the copy
	gHeapResult = original;
	gHeapResult.flags = kHeap;
	gFakeResult = (uint64_t)&gHeapResult;
	CHECK(t((uint64_t)&original, 0, 0, 0, 0, 0, 0, 0) == (uint64_t)&gHeapResult, "Block_copy: the block pointer changed");
	CHECK(oracleAuth((uint64_t)gHeapResult.invoke, (uint64_t)&gHeapResult.invoke) == plainTarget, "Block_copy: the copy's invoke is not signed for its own address (IA, address-diversified, discriminator 0)");
	CHECK(gHeapResult.flags == kHeap, "Block_copy: flags changed");
	// (the two signatures differ unless the PAC of the two addresses happens to be equal, about once in 128)
	CHECK(oracleSign(plainTarget, (uint64_t)&original.invoke) == oracleSign(plainTarget, (uint64_t)&gHeapResult.invoke) || (uint64_t)original.invoke != (uint64_t)gHeapResult.invoke, "Block_copy: the copy kept the stale signature");

	// the original's signature is checked first: a corrupted one is not turned into a valid signature for the copy
	Block bad = original;
	// signed for its own address and then corrupted: a signature made for another address would verify by luck about once in 128
	bad.invoke = (void*)corrupted(oracleSign(codeWithSignature((uint64_t)&bad.invoke), (uint64_t)&bad.invoke));
	gHeapResult = bad;
	gHeapResult.flags = kHeap;
	t((uint64_t)&bad, 0, 0, 0, 0, 0, 0, 0);
	CHECK(gHeapResult.invoke == bad.invoke, "Block_copy: a corrupted original was re-signed for the copy (0x%llx)", (unsigned long long)(uint64_t)gHeapResult.invoke);

	// so is an invoke that was never signed (a block that plain code made)
	Block unsignedBlock = { nullptr, 0, 0, nullptr, nullptr };
	unsignedBlock.invoke = (void*)codeWithSignature((uint64_t)&unsignedBlock.invoke);
	gHeapResult = unsignedBlock;
	gHeapResult.flags = kHeap;
	t((uint64_t)&unsignedBlock, 0, 0, 0, 0, 0, 0, 0);
	CHECK(gHeapResult.invoke == unsignedBlock.invoke, "Block_copy: an unsigned original was signed for the copy");

	// the same heap block returned (a retain, no copy): nothing is written, which the read-only page enforces
	gFakeResult = (uint64_t)gReadOnlyHeapBlock;
	CHECK(t((uint64_t)gReadOnlyHeapBlock, 0, 0, 0, 0, 0, 0, 0) == (uint64_t)gReadOnlyHeapBlock, "Block_copy: a retained block");

	// a block with copy and dispose helpers is refused before the plain Block_copy calls helpers it cannot call
	{
		Block withHelpers = original;
		withHelpers.flags = 1 << 25;
		*gSharedBlock = withHelpers;
		gRefusedSymbol = "__Block_copy";
		std::string message;
		const int status = childOutput(passSharedBlock, message);
		CHECK(WIFSIGNALED(status) && message.find("copy and dispose helpers") != std::string::npos, "Block_copy: helpers were not refused: '%s'", message.c_str());
	}

	// a global block comes back as it is (its literal is read-only), and NULL stays NULL
	CHECK(gGlobalBlock->invoke != (void*)oracleStrip((uint64_t)gGlobalBlock->invoke), "the global block of this test is not signed");
	const void* signedInvoke = gGlobalBlock->invoke;
	gFakeResult = (uint64_t)gGlobalBlock;
	CHECK(t((uint64_t)gGlobalBlock, 0, 0, 0, 0, 0, 0, 0) == (uint64_t)gGlobalBlock && gGlobalBlock->invoke == signedInvoke, "Block_copy: a global block was touched");
	gFakeResult = 0;
	CHECK(t(0, 0, 0, 0, 0, 0, 0, 0) == 0, "Block_copy: NULL");
}

// A heap block, or a block with helpers, is refused: the child dies with a message that names the symbol and the shim, and the
// block (in memory that parent and child share) is exactly as it was, so it is not corrupted for its other users.
static void checkRefusedBlocks()
{
	struct Case { const char* symbol; int32_t flags; const char* what; };
	const Case cases[] = {
		{ "_dispatch_async", kHeap, "a heap block" }, { "_dispatch_once", kHeap, "a heap block" },
		{ "_dispatch_async", 1 << 25, "a block with copy and dispose helpers" },
		{ "_dispatch_async", kHeap | (1 << 25), "a block with copy and dispose helpers" }, { "_dispatch_once", 1 << 25, "a block with copy and dispose helpers" },
	};
	for (const Case& c : cases) {
		*gSharedBlock = { nullptr, c.flags, 0, (void*)oracleSign(codeWithSignature((uint64_t)&gSharedBlock->invoke), (uint64_t)&gSharedBlock->invoke), nullptr };
		const Block before = *gSharedBlock;
		gRefusedSymbol = c.symbol;
		std::string message;
		const int status = childOutput(passSharedBlock, message);
		CHECK(WIFSIGNALED(status), "%s: %s was not refused (status 0x%x)", c.symbol, c.what, status);
		CHECK(message.find(c.symbol) != std::string::npos && message.find(c.what) != std::string::npos && message.find("option B") != std::string::npos, "%s: the refusal says '%s'", c.symbol, message.c_str());
		CHECK(memcmp(gSharedBlock, &before, sizeof(Block)) == 0, "%s: %s was rewritten before it was refused", c.symbol, c.what);
		// the block queued and passed again: still its own, still signed, because nothing ever rewrote it
		CHECK(gSharedBlock->invoke == before.invoke, "%s: the shared block lost its signature", c.symbol);
	}
}

static void checkDispatch()
{
	for (const char* name : { "_dispatch_async", "_dispatch_once" }) {
		Fn8 t = thunkFor(name);
		gFakeResult = 0;
		gHook = snapshotBlock;

		// a stack block: authenticated during the call, its own signature back afterwards
		Block stack = { nullptr, 0, 0, nullptr, nullptr };
		const uint64_t target = codeWithSignature((uint64_t)&stack.invoke);
		stack.invoke = (void*)oracleSign(target, (uint64_t)&stack.invoke);
		void* original = stack.invoke;
		t(0x1010, (uint64_t)&stack, 0, 0, 0, 0, 0, 0);
		CHECK(gSeen[0] == 0x1010 && gSeen[1] == (uint64_t)&stack, "%s: the arguments changed", name);
		CHECK(gBlockInvokeSeen == target, "%s: the callee saw invoke 0x%llx", name, (unsigned long long)gBlockInvokeSeen);
		CHECK(stack.invoke == original, "%s: the caller's stack block did not get its signature back", name);

		// a stack block with a corrupted signature reaches the callee unusable and is left as it was
		Block badStack = stack;
		badStack.invoke = (void*)corrupted(oracleSign(codeWithSignature((uint64_t)&badStack.invoke), (uint64_t)&badStack.invoke));
		void* badOriginal = badStack.invoke;
		if ( !gFpac ) {
			t(0x1010, (uint64_t)&badStack, 0, 0, 0, 0, 0, 0);
			CHECK(gBlockInvokeSeen != target && gBlockInvokeSeen != oracleStrip(gBlockInvokeSeen), "%s: a corrupted invoke reached the callee usable (0x%llx)", name, (unsigned long long)gBlockInvokeSeen);
			CHECK(badStack.invoke == badOriginal, "%s: a corrupted stack block was changed", name);
		}

		// the same stack block twice: the second call finds the signature the first one restored
		t(0x1010, (uint64_t)&stack, 0, 0, 0, 0, 0, 0);
		CHECK(gBlockInvokeSeen == target && stack.invoke == original, "%s: a second call with the same stack block", name);

		// a global block lives in read-only memory: the callee gets a mirror with the invoke authenticated, the literal is untouched
		const void* globalBefore = gGlobalBlock->invoke;
		t(0x1010, (uint64_t)gGlobalBlock, 0, 0, 0, 0, 0, 0);
		CHECK(gSeen[1] != (uint64_t)gGlobalBlock, "%s: a global block was passed on in place", name);
		const Block* mirror = (const Block*)gSeen[1];
		CHECK(mirror->flags == kGlobal && (uint64_t)mirror->invoke == oracleStrip((uint64_t)gGlobalBlock->invoke), "%s: mirror", name);
		CHECK(gGlobalBlock->invoke == globalBefore, "%s: the global literal was written", name);
		const uint64_t firstMirror = gSeen[1];
		t(0x1010, (uint64_t)gGlobalBlock, 0, 0, 0, 0, 0, 0);
		CHECK(gSeen[1] == firstMirror, "%s: a second call made a second mirror", name);

		// NULL block
		t(0x1010, 0, 0, 0, 0, 0, 0, 0);
		CHECK(gSeen[1] == 0, "%s: NULL block", name);
		gHook = nullptr;
	}
}

// A pointer that cannot be read or written never reaches the real call: both structs become (void*)-1, which the kernel
// answers with EFAULT every time, and nothing is installed. Here the real call is the fake, which sees what it is given.
static const uint64_t kInvalid = ~0ULL;
static uint64_t gInstalled;			// what the fake "kernel" installed, read from act when act is a pointer it may read
static void* gRacePage;
static void installLikeTheKernel(const uint64_t* a)
{
	if ( a[1] != 0 && a[1] != kInvalid )
		gInstalled = *(const uint64_t*)a[1];
}
// the second thread: the page becomes readable after the thunk has looked at it
static void mapAfterTheCheck(const uint64_t* a)
{
	if ( gRacePage ) {
		mprotect(gRacePage, 4096, PROT_READ | PROT_WRITE);
		((uint64_t*)gRacePage)[0] = 0x4141414141ULL;	// a forged handler
	}
	installLikeTheKernel(a);
}

static void checkSigactionFaults()
{
	Fn8 act = thunkFor("_sigaction");
	struct Act { uint64_t handler; uint32_t mask; int32_t flags; };
	const uint64_t handlerA = oracleSign(codeWithSignature(0), 0);
	Act good = { handlerA, 1, 2 };
	Act oldGood = { 0, 0, 0 };
	// a page that cannot be touched, a read-only page and the null page
	uint64_t* none = (uint64_t*)mmap(nullptr, 4096, PROT_NONE, MAP_PRIVATE | MAP_ANON, -1, 0);
	Act* readOnly = (Act*)mmap(nullptr, 4096, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANON, -1, 0);
	*readOnly = { 0x1111, 2, 3 };
	mprotect(readOnly, 4096, PROT_READ);
	const uint64_t bad[] = { (uint64_t)none, 0x10 };

	gHook = installLikeTheKernel;
	gFakeResult = 0xffffffffULL;	// -1: what the real call answers for EFAULT
	for (uint64_t b : bad) {
		gInstalled = 0;
		// invalid act, good old action: the real call gets -1 for both, and installs nothing
		uint64_t result = act(5, b, (uint64_t)&oldGood, 0, 0, 0, 0, 0);
		CHECK(gSeen[1] == kInvalid && gSeen[2] == kInvalid && (int)result == -1, "EFAULT: an unreadable act reached the real call as 0x%llx, old action 0x%llx", (unsigned long long)gSeen[1], (unsigned long long)gSeen[2]);
		CHECK(gInstalled == 0, "EFAULT: a handler was installed through an unreadable act");
		// good act, invalid old action: the act is not forwarded either, so nothing can be installed before the old action fails
		result = act(5, (uint64_t)&good, b, 0, 0, 0, 0, 0);
		CHECK(gSeen[1] == kInvalid && gSeen[2] == kInvalid && (int)result == -1 && gInstalled == 0, "EFAULT: an unwritable old action let the act through (0x%llx, installed 0x%llx)", (unsigned long long)gSeen[1], (unsigned long long)gInstalled);
		// both
		result = act(5, b, b, 0, 0, 0, 0, 0);
		CHECK(gSeen[1] == kInvalid && gSeen[2] == kInvalid && (int)result == -1, "EFAULT: invalid act and old action");
		// an unreadable act with no old action stays a query-shaped call with -1
		act(5, b, 0, 0, 0, 0, 0, 0);
		CHECK(gSeen[1] == kInvalid && gSeen[2] == 0, "EFAULT: an unreadable act with no old action");
	}
	// An old action that can be read but not written is refused the same way, and what it holds is untouched
	const Act before = *readOnly;
	gInstalled = 0;
	act(5, (uint64_t)&good, (uint64_t)readOnly, 0, 0, 0, 0, 0);
	CHECK(gSeen[1] == kInvalid && gSeen[2] == kInvalid && gInstalled == 0 && memcmp(readOnly, &before, sizeof(Act)) == 0, "EFAULT: a read-only old action");

	// The race: the page becomes readable between the thunk's check and the real call (here, while the real call runs). The
	// caller's pointer must not have been handed on, so the real call never reads the forged struct.
	gRacePage = none;
	gHook = mapAfterTheCheck;
	gInstalled = 0;
	act(5, (uint64_t)none, 0, 0, 0, 0, 0, 0);
	CHECK(gSeen[1] == kInvalid && gInstalled == 0, "race: the caller's page was handed to the real call (0x%llx, installed 0x%llx)", (unsigned long long)gSeen[1], (unsigned long long)gInstalled);
	gRacePage = nullptr;
	gHook = nullptr;
	mprotect(none, 4096, PROT_NONE);

	// a failed call leaves the caller's old action exactly as it was, whatever the callee wrote into the copy it was given
	Act untouched = { 0x7777, 0x88, 0x99 };
	static Act written;
	written = { 0x5555, 0x66, 0x77 };
	gHook = [](const uint64_t* a) { if (a[2]) memcpy((void*)a[2], &written, sizeof(written)); };
	gFakeResult = 0xffffffffULL;
	act(5, (uint64_t)&good, (uint64_t)&untouched, 0, 0, 0, 0, 0);
	CHECK(untouched.handler == 0x7777 && untouched.mask == 0x88 && untouched.flags == 0x99, "a failed sigaction changed the caller's old action (0x%llx)", (unsigned long long)untouched.handler);
	// and a successful one hands it back
	gFakeResult = 0;
	act(5, (uint64_t)&good, (uint64_t)&untouched, 0, 0, 0, 0, 0);
	CHECK(untouched.handler == 0x5555 && untouched.mask == 0x66 && untouched.flags == 0x77, "a successful sigaction did not hand back the old action");
	gHook = nullptr;
}

// no descriptor for the pipe: the call fails closed (both structs -1, so EFAULT), with a warning that says why
struct PipeAct { uint64_t handler; uint32_t mask; int32_t flags; };
static Fn8 gPipeThunk;
static PipeAct* gPipeAct;
static void withoutDescriptors()
{
	struct rlimit none = { 3, 3 };
	setrlimit(RLIMIT_NOFILE, &none);
	gFakeResult = 0;
	gPipeThunk(5, (uint64_t)gPipeAct, 0, 0, 0, 0, 0, 0);
	_exit(gSeen[1] == ~0ULL ? 0 : 1);
}

static void checkNoDescriptors()
{
	PipeAct act = { oracleSign(codeWithSignature(0), 0), 0, 0 };
	gPipeThunk = thunkFor("_sigaction");
	gPipeAct = &act;
	std::string message;
	const int status = childOutput(withoutDescriptors, message);
	CHECK(WIFEXITED(status) && WEXITSTATUS(status) == 0 && message.find("could not make a pipe") != std::string::npos, "no descriptors: status 0x%x, '%s'", status, message.c_str());
}

// The old action is signed like signal()'s result: only when it is the handler that arm64e code installed with a real
// signature. Plain code's handlers, and SIG_DFL and SIG_IGN, come back as they are.
static void checkOldActionSigning()
{
	Fn8 act = thunkFor("_sigaction");
	struct Act { uint64_t handler; uint32_t mask; int32_t flags; };
	const uint64_t handlerA = oracleSign(codeWithSignature(0), 0), plainA = oracleStrip(handlerA);
	const uint64_t handlerB = oracleSign(codeWithSignature(0) + 0x400, 0);
	const uint64_t plainOld = codeWithSignatureAfter(0x000000010000b000ULL, 0);
	static uint64_t oldWritten;
	gHook = [](const uint64_t* a) { if (a[2]) ((Act*)a[2])->handler = oldWritten; };
	gFakeResult = 0;

	// arm64e code installs A; the next call, installing B, reads A back: signed, and the chained call authenticates
	Act installA = { handlerA, 0, 0 }, installB = { handlerB, 0, 0 }, old = { 0, 0, 0 };
	oldWritten = 0;
	act(18, (uint64_t)&installA, 0, 0, 0, 0, 0, 0);
	oldWritten = plainA;
	act(18, (uint64_t)&installB, (uint64_t)&old, 0, 0, 0, 0, 0);
	CHECK(old.handler != plainA && oracleAuth(old.handler, 0) == plainA, "old action: the handler arm64e code installed came back unsigned (0x%llx)", (unsigned long long)old.handler);

	// plain code's handler comes back as it is, and the ring takes it
	oldWritten = plainOld;
	act(18, (uint64_t)&installA, (uint64_t)&old, 0, 0, 0, 0, 0);
	CHECK(old.handler == plainOld, "old action: a plain handler was signed (0x%llx)", (unsigned long long)old.handler);

	// SIG_DFL and SIG_IGN come back as they are, even for a signal that arm64e code has installed a handler on
	for (uint64_t special : { 0ULL, 1ULL }) {
		oldWritten = special;
		old.handler = 0xabc;
		act(18, (uint64_t)&installB, (uint64_t)&old, 0, 0, 0, 0, 0);
		CHECK(old.handler == special, "old action: special value %llu came back as 0x%llx", (unsigned long long)special, (unsigned long long)old.handler);
	}

	// A is recorded again by installing it; a handler that only the ring accepted is not: it is never signed
	oldWritten = 0;
	act(17, (uint64_t)&installA, 0, 0, 0, 0, 0, 0);
	Act viaRing = { plainOld, 0, 0 };
	act(17, (uint64_t)&viaRing, 0, 0, 0, 0, 0, 0);	// accepted through the ring, installed, recorded as 0
	oldWritten = plainOld;
	act(17, (uint64_t)&installB, (uint64_t)&old, 0, 0, 0, 0, 0);
	CHECK(old.handler == plainOld, "old action: a handler that only the ring accepted was signed (0x%llx)", (unsigned long long)old.handler);
	gHook = nullptr;
}

static void checkSigaction()
{
	Fn8 t = thunkFor("_sigaction");
	Fn8 sig = thunkFor("_signal");
	const uint64_t handler = oracleSign(codeWithSignature(0), 0);
	const uint64_t plainHandler = oracleStrip(handler);
	struct Act { uint64_t handler; uint32_t mask; int32_t flags; };
	Act act = { handler, 0xa5a5, 0x42 };
	uint64_t oact[2] = { 7, 7 };
	static Act seen;
	gHook = [](const uint64_t* a) { if (a[1]) memcpy(&seen, (const void*)a[1], sizeof(seen)); };
	// sigaction returns an int: the upper half of x0 is not its business
	gFakeResult = 0xdead00000000ULL;
	t(28, (uint64_t)&act, (uint64_t)oact, 0, 0, 0, 0, 0);
	CHECK(gSeen[0] == 28 && gSeen[2] != (uint64_t)oact, "sigaction: the signal number changed or the callee was given the caller's old-action memory");
	CHECK(gSeen[1] != (uint64_t)&act, "sigaction: the caller's struct was passed on in place");
	CHECK(seen.handler == plainHandler && seen.mask == 0xa5a5 && seen.flags == 0x42, "sigaction: handler 0x%llx mask 0x%x flags 0x%x", (unsigned long long)seen.handler, seen.mask, seen.flags);
	CHECK(act.handler == handler, "sigaction: the caller's struct changed");
	// what sigaction installed is what signal may sign when it hands it back
	gHook = nullptr;
	gFakeResult = plainHandler;
	const uint64_t back = sig(28, handler, 0, 0, 0, 0, 0, 0);
	CHECK(back != plainHandler && oracleAuth(back, 0) == plainHandler, "sigaction: the installed handler did not come back from signal() signed");
	// a handler with a corrupted signature reaches the callee unusable
	if ( !gFpac ) {
		Act badAct = { corrupted(handler), 0, 0 };
		gHook = [](const uint64_t* a) { if (a[1]) memcpy(&seen, (const void*)a[1], sizeof(seen)); };
		gFakeResult = 0;
		t(25, (uint64_t)&badAct, 0, 0, 0, 0, 0, 0);
		CHECK(seen.handler != plainHandler && seen.handler != oracleStrip(seen.handler), "sigaction: a corrupted handler reached the callee usable (0x%llx)", (unsigned long long)seen.handler);
		gHook = nullptr;
	}
	// a failed sigaction installs nothing
	gHook = [](const uint64_t* a) { if (a[1]) memcpy(&seen, (const void*)a[1], sizeof(seen)); };
	Act other = { oracleSign(codeWithSignature(0) + 0x800, 0), 0, 0 };
	gFakeResult = 0xffffffffULL;
	t(27, (uint64_t)&other, 0, 0, 0, 0, 0, 0);
	gHook = nullptr;
	gFakeResult = oracleStrip(other.handler);
	CHECK(sig(27, handler, 0, 0, 0, 0, 0, 0) == oracleStrip(other.handler), "sigaction: a handler whose installation failed was signed");
	// the caller's struct may be read-only, so the handler cannot be changed in place; SIG_DFL and SIG_IGN pass
	static const Act readOnlyAct = { 1, 1, 2 };
	gHook = [](const uint64_t* a) { if (a[1]) memcpy(&seen, (const void*)a[1], sizeof(seen)); };
	t(26, (uint64_t)&readOnlyAct, 0, 0, 0, 0, 0, 0);
	CHECK(seen.handler == 1, "sigaction: SIG_IGN in a read-only struct");
	t(26, 0, 0, 0, 0, 0, 0, 0);
	CHECK(gSeen[1] == 0 && gSeen[2] == 0, "sigaction: NULL act and oact");
	gHook = nullptr;
}

static void checkBind()
{
	gWarnings.clear();
	CHECK(adaptedTarget("_not_a_row", 0x1234, false) == 0x1234, "an unknown symbol was adapted");
	CHECK(adaptedTarget("_atexit", 0x1234, true) == 0x1234, "an arm64e target was adapted");
	CHECK(gWarnings.empty(), "unexpected warnings: %s", gWarnings.c_str());

	const uint64_t a = adaptedTarget("_atexit", 0x4000, false), b = adaptedTarget("_atexit", 0x4000, false), c = adaptedTarget("_atexit", 0x5000, false);
	CHECK(a != 0x4000 && a == b, "the same row and target must share one thunk");
	CHECK(c != a, "another target needs its own thunk");

	CHECK(adaptedTarget("__Unwind_Resume", 0x1234, false) == 0x1234 && gWarnings.empty(), "a handled-elsewhere row changed the binding or warned: '%s'", gWarnings.c_str());
	CHECK(adaptedTarget("_atexit_b", 0x1234, false) == 0x1234, "an unsupported row changed the binding");
	CHECK(gWarnings.find("_atexit_b") != std::string::npos && gWarnings.find("no adapter") != std::string::npos, "an unsupported row did not warn loudly: '%s'", gWarnings.c_str());

	setAdapterMode(AdapterMode::Off);
	CHECK(adaptedTarget("_atexit", 0x7000, false) == 0x7000, "the kill switch did not turn the adapters off");
	setAdapterMode(AdapterMode::On);
	CHECK(adaptedTarget("_atexit", 0x7000, false) != 0x7000, "the adapters did not come back");

	// report mode names a plain function with no row once, and never one that has a row (supported, unsupported or elsewhere)
	gWarnings.clear();
	setAdapterMode(AdapterMode::On);
	adaptedTarget("_report_me", 0x1234, false);
	CHECK(gWarnings.empty(), "a symbol with no row warned outside report mode: '%s'", gWarnings.c_str());
	setAdapterMode(AdapterMode::Report);
	CHECK(adaptedTarget("_report_me", 0x1234, false) == 0x1234 && gWarnings.find("_report_me") != std::string::npos && gWarnings.find("no row") != std::string::npos, "report mode did not name a symbol with no row: '%s'", gWarnings.c_str());
	gWarnings.clear();
	adaptedTarget("_report_me", 0x1234, false);
	adaptedTarget("_atexit", 0x4000, false);
	adaptedTarget("__Unwind_Resume", 0x1234, false);
	adaptedTarget("_unrelated", 0x1234, true);
	CHECK(gWarnings.empty(), "report mode named a symbol twice, one with a row or an arm64e target: '%s'", gWarnings.c_str());
	adaptedTarget("_report_me_too", 0x1234, false);
	CHECK(gWarnings.find("_report_me_too") != std::string::npos, "report mode did not name a second symbol");
	setAdapterMode(AdapterMode::Off);
	gWarnings.clear();
	adaptedTarget("_report_me_three", 0x1234, false);
	CHECK(gWarnings.empty(), "off mode warned");
	setAdapterMode(AdapterMode::On);
}

int main(int argc, char** argv)
{
	if ( (argc > 1) && (strcmp(argv[1], "rows") == 0) ) {
		size_t n;
		const AdapterRow* rows = adapterRows(&n);
		for (size_t i = 0; i != n; ++i)
			printf("ROW %s %u %u %u %d %u %d\n", rows[i].symbol, rows[i].authMask, rows[i].blockArg, rows[i].structArg, (int)rows[i].ret, rows[i].argCount, (int)rows[i].status);
		return 0;
	}
	if ( (argc > 2) && (strcmp(argv[1], "auth-thunk") == 0) ) {
		uint32_t w[40];
		const size_t n = emitAuthThunk(w, (uint8_t)strtoul(argv[2], nullptr, 0), 0x1122334455667788ULL);
		for (size_t i = 0; i != n; ++i)
			printf("%08x\n", w[i]);
		return 0;
	}
	if ( (argc > 2) && (strcmp(argv[1], "call-thunk") == 0) ) {
		const AdapterRow* row = findAdapterRow(argv[2]);
		if ( row == nullptr )
			return 2;
		uint32_t w[24];
		const size_t n = emitCallThunk(w, row, 0x1122334455667788ULL);
		printf("ROWADDR %016llx HELPER %016llx\n", (unsigned long long)(uint64_t)row, (unsigned long long)callThunkHelperAddress());
		for (size_t i = 0; i != n; ++i)
			printf("%08x\n", w[i]);
		return 0;
	}
	checkPacWorks();
	detectFpac();
	makeGlobalBlock();
	makeReadOnlyHeapBlock();
	gSharedBlock = (Block*)mmap(nullptr, 4096, PROT_READ | PROT_WRITE, MAP_SHARED | MAP_ANON, -1, 0);
	checkTable();
	checkAuthRows();
	checkSignal();
	checkBlockCopy();
	checkDispatch();
	checkRefusedBlocks();
	checkSigaction();
	checkSigactionFaults();
	checkNoDescriptors();
	checkOldActionSigning();
	checkHandlerRoundTrip();
	checkSignalNumbers();
	checkNoSigningOracle();
	checkOldActionRace();
	checkBind();
	checkSeal();
	checkThunkPages();
	printf("%s %d checks, %d failures\n", gFailures ? "FAIL" : "PASS", gChecks, gFailures);
	return gFailures ? 1 : 0;
}
