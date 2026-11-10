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
	checkTable();
	checkAuthRows();
	checkBind();
	checkSeal();
	checkThunkPages();
	printf("%s %d checks, %d failures\n", gFailures ? "FAIL" : "PASS", gChecks, gFailures);
	return gFailures ? 1 : 0;
}
