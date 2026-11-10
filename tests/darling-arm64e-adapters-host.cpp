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
#include <sys/syscall.h>
#include <sys/wait.h>
#include <unistd.h>
#include <vector>

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
	*page = { nullptr, kGlobal, 0, (void*)oracleSign(0x0000000100004000ULL, (uint64_t)&page->invoke), nullptr };
	mprotect(page, 4096, PROT_READ);
	gGlobalBlock = page;
}

// a heap block in read-only memory: Block_copy of it is a retain, and a write into it by the module crashes the test
static const Block* gReadOnlyHeapBlock;
static void makeReadOnlyHeapBlock()
{
	Block* page = (Block*)mmap(nullptr, 4096, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANON, -1, 0);
	*page = { nullptr, kHeap, 0, (void*)oracleSign(0x0000000100005000ULL, (uint64_t)&page->invoke), nullptr };
	mprotect(page, 4096, PROT_READ);
	gReadOnlyHeapBlock = page;
}

static uint64_t gBlockInvokeSeen;
static void snapshotBlock(const uint64_t* a) { const Block* b = (const Block*)a[1]; if (b) { gBlockInvokeSeen = (uint64_t)b->invoke; } }

static void checkPacWorks()
{
	const uint64_t p = codeAddress(1), s = oracleSign(p, 0);
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
static void touch() { }
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
		oracleAuth(corrupted(oracleSign(codeAddress(1), 0)), 0);
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

static Fn8 gCallingThunk;
static void callGoodPointer() { gCallingThunk(oracleSign((uint64_t)&touch, 0), 0, 0, 0, 0, 0, 0, 0); }
static void callCorruptedPointer() { gCallingThunk(corrupted(oracleSign((uint64_t)&touch, 0)), 0, 0, 0, 0, 0, 0, 0); }

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
	CHECK((uint64_t)original.invoke != (uint64_t)gHeapResult.invoke || (uint64_t)&original == (uint64_t)&gHeapResult, "Block_copy: the copy kept the stale signature");

	// the original's signature is checked first: a corrupted one is not turned into a valid signature for the copy
	Block bad = original;
	bad.invoke = (void*)corrupted((uint64_t)original.invoke);
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

	// a global block comes back as it is (its literal is read-only), and NULL stays NULL
	CHECK(gGlobalBlock->invoke != (void*)oracleStrip((uint64_t)gGlobalBlock->invoke), "the global block of this test is not signed");
	const void* signedInvoke = gGlobalBlock->invoke;
	gFakeResult = (uint64_t)gGlobalBlock;
	CHECK(t((uint64_t)gGlobalBlock, 0, 0, 0, 0, 0, 0, 0) == (uint64_t)gGlobalBlock && gGlobalBlock->invoke == signedInvoke, "Block_copy: a global block was touched");
	gFakeResult = 0;
	CHECK(t(0, 0, 0, 0, 0, 0, 0, 0) == 0, "Block_copy: NULL");
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
		badStack.invoke = (void*)corrupted((uint64_t)original);
		void* badOriginal = badStack.invoke;
		if ( !gFpac ) {
			t(0x1010, (uint64_t)&badStack, 0, 0, 0, 0, 0, 0);
			CHECK(gBlockInvokeSeen != target && gBlockInvokeSeen != oracleStrip(gBlockInvokeSeen), "%s: a corrupted invoke reached the callee usable (0x%llx)", name, (unsigned long long)gBlockInvokeSeen);
			CHECK(badStack.invoke == badOriginal, "%s: a corrupted stack block was changed", name);
		}

		// a heap block: authenticated for good (the callee keeps it)
		Block heap = { nullptr, kHeap, 0, nullptr, nullptr };
		heap.invoke = (void*)oracleSign(target, (uint64_t)&heap.invoke);
		t(0x1010, (uint64_t)&heap, 0, 0, 0, 0, 0, 0);
		CHECK(gBlockInvokeSeen == target && heap.invoke == (void*)target, "%s: heap block", name);

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
	CHECK(gSeen[0] == 28 && gSeen[2] == (uint64_t)oact, "sigaction: the other arguments changed");
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

	setAdaptersEnabled(false);
	CHECK(adaptedTarget("_atexit", 0x7000, false) == 0x7000, "the kill switch did not turn the adapters off");
	setAdaptersEnabled(true);
	CHECK(adaptedTarget("_atexit", 0x7000, false) != 0x7000, "the adapters did not come back");
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
		uint32_t w[20];
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
	checkTable();
	checkAuthRows();
	checkSignal();
	checkBlockCopy();
	checkDispatch();
	checkSigaction();
	checkBind();
	checkSeal();
	checkThunkPages();
	printf("%s %d checks, %d failures\n", gFailures ? "FAIL" : "PASS", gChecks, gFailures);
	return gFailures ? 1 : 0;
}
