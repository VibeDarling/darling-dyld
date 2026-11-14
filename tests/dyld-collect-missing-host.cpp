// Host check of dyld3/DarlingCollectMissing.cpp: the recorder, the thunks and the guard region, run natively on ARM64 Linux.
// dyld::halt is replaced by a stub that jumps back to the check, so a thunk is really entered, reaches the trap and halts.
#include "DarlingCollectMissing.h"

#include <assert.h>
#include <fcntl.h>
#include <setjmp.h>
#include <stdarg.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <unistd.h>
#include <string>
#include <vector>

using namespace dyld3::darling;

// What the recorder asks of the kernel is watched through these two wrappers (the executable's symbols win over libc's).
static const char* sWatchedPath = nullptr;
static int sWatchedOpenFlags = -1;
static bool sShortWrite = false;
extern "C" int open(const char* path, int flags, ...)
{
	va_list ap;
	va_start(ap, flags);
	const int mode = va_arg(ap, int);
	va_end(ap);
	if ( (sWatchedPath != nullptr) && (strcmp(path, sWatchedPath) == 0) )
		sWatchedOpenFlags = flags;
	return (int)syscall(SYS_openat, AT_FDCWD, path, flags, mode);
}
extern "C" ssize_t write(int fd, const void* buf, size_t n)
{
	if ( sShortWrite && (n > 1) )
		return (ssize_t)(n - 1);
	return (ssize_t)syscall(SYS_write, fd, buf, n);
}

static sigjmp_buf sJump;
static char sHaltMessage[1024];

namespace dyld {
void halt(const char* message)
{
	snprintf(sHaltMessage, sizeof(sHaltMessage), "%s", message);
	siglongjmp(sJump, 1);
}
}

static void* sFaultAddress;
static void onSegv(int, siginfo_t* info, void*)
{
	sFaultAddress = info->si_addr;
	siglongjmp(sJump, 2);
}

static int failures = 0;
#define CHECK(cond, ...) do { if ( cond ) { printf("CHECK ok: " __VA_ARGS__); printf("\n"); } else { printf("FAIL: " __VA_ARGS__); printf("\n"); ++failures; } } while (0)

static std::vector<std::string> readLines(const char* path)
{
	std::vector<std::string> lines;
	FILE* f = fopen(path, "r");
	if ( f == nullptr )
		return lines;
	char buf[4096];
	while ( fgets(buf, sizeof(buf), f) != nullptr ) {
		std::string s(buf);
		if ( !s.empty() && s.back() == '\n' )
			s.pop_back();
		lines.push_back(s);
	}
	fclose(f);
	return lines;
}

static std::vector<std::string> fields(const std::string& line)
{
	std::vector<std::string> out;
	size_t at = 0;
	for (;;) {
		size_t tab = line.find('\t', at);
		if ( tab == std::string::npos ) { out.push_back(line.substr(at)); break; }
		out.push_back(line.substr(at, tab - at));
		at = tab + 1;
	}
	return out;
}

static std::string mapsPermsOf(uintptr_t address)
{
	FILE* f = fopen("/proc/self/maps", "r");
	char buf[512];
	std::string perms = "unmapped";
	while ( (f != nullptr) && (fgets(buf, sizeof(buf), f) != nullptr) ) {
		unsigned long lo, hi;
		char p[8];
		if ( sscanf(buf, "%lx-%lx %7s", &lo, &hi, p) == 3 && address >= lo && address < hi )
			perms = p;
	}
	if ( f ) fclose(f);
	return perms;
}

// Calls `address` and returns what halt got, or "" when it came back (it must not).
static std::string callThunk(uintptr_t address)
{
	sHaltMessage[0] = '\0';
	if ( sigsetjmp(sJump, 1) == 0 ) {
		((void (*)(void))address)();
		return "";
	}
	return sHaltMessage;
}

// The arm64e call sequence: the pointer is signed with key IA, discriminator 0, as dyld signs a resolved import for an
// arm64e fixup, and called with blraaz. Returns "skipped" when the host does not run PAC instructions.
static std::string callThunkAuthenticated(uintptr_t address)
{
	sHaltMessage[0] = '\0';
	if ( sigsetjmp(sJump, 1) == 0 ) {
		register uint64_t target __asm__("x17") = address;
		__asm__ volatile("paciza x17\n\tblraaz x17" : "+r"(target) : : "x0", "x1", "x2", "x3", "x4", "x5", "x6", "x7", "x8", "x9", "x10", "x11", "x12", "x13", "x14", "x15", "x16", "x30", "memory", "cc");
		return "";
	}
	return sHaltMessage;
}

int main(int argc, char** argv)
{
	const char* out = argc > 1 ? argv[1] : "collect-out.txt";
	unlink(out);

	// 1. off by default: nothing recorded, nothing bound, no file
	CHECK(!collectMissingEnabled(), "disabled before enable");
	CHECK(collectMissingBind({ "/app/Test", "_x", "/lib/x.dylib", 1, false, BindKind::Lazy }) == 0, "bind returns 0 while disabled");
	CHECK(access(out, F_OK) != 0, "no file while disabled");
	collectMissingEnable("");
	CHECK(!collectMissingEnabled(), "an empty path does not enable");

	// 2. record
	collectMissingEnable(out);
	CHECK(collectMissingEnabled(), "enabled");
	const char* app = "/app/Test";
	const char* lib = "/usr/lib/libmissing.dylib";
	uintptr_t a = collectMissingBind({ app, "_missingFunctionA", lib, 2, false, BindKind::Lazy });
	uintptr_t b = collectMissingBind({ app, "_missingFunctionB", lib, 2, false, BindKind::NonLazy });
	uintptr_t c = collectMissingBind({ app, "_missingFunctionC", lib, 2, false, BindKind::Unknown });
	uintptr_t d = collectMissingBind({ app, "_kMissingData", lib, 2, false, BindKind::NonLazy });
	uintptr_t w = collectMissingBind({ app, "_weakMissing", lib, 2, true, BindKind::NonLazy });
	uintptr_t aAgain = collectMissingBind({ app, "_missingFunctionA", lib, 2, false, BindKind::Lazy });
	uintptr_t aOther = collectMissingBind({ "/usr/lib/libother.dylib", "_missingFunctionA", lib, 3, false, BindKind::Lazy });
	uintptr_t dLazy = collectMissingBind({ app, "_kMissingLazyData", lib, 2, false, BindKind::Lazy });
	CHECK(a && b && c && d && dLazy, "every strong import got an address");
	CHECK(w == 0, "a weak import binds 0");
	CHECK(a != b && b != c && a != c, "distinct functions get distinct addresses");
	CHECK(aAgain == a && aOther == a, "the same symbol gets the same address from every referrer");

	std::vector<std::string> lines = readLines(out);
	std::vector<std::string> records;
	std::string header;
	for (const std::string& l : lines) {
		if ( !l.empty() && l[0] == '#' ) header = l; else records.push_back(l);
	}
	char pidText[32];
	snprintf(pidText, sizeof(pidText), "pid=%d", (int)getpid());
	CHECK(header.find(std::string("# process ") + pidText + " regions thunk=0x") == 0, "region header line names the pid and the regions: %s", header.c_str());
	CHECK(records.size() == 7, "7 record lines (A, B, C, data, weak, A from another referrer, lazy data), got %zu", records.size());
	for (const std::string& r : records)
		CHECK(fields(r).size() == 9 && fields(r)[8] == std::to_string((int)getpid()), "9 fields, the last the pid: %s", r.c_str());
	for (const std::string& r : records)
		CHECK(r.find("0x") == std::string::npos, "no address in a record line");
	auto has = [&](const char* line) { const std::string want = std::string(line) + "\t" + std::to_string((int)getpid()); for (const std::string& r : records) if ( r == want ) return true; return false; };
	CHECK(has("/app/Test\t_missingFunctionA\t/usr/lib/libmissing.dylib\t2\tstrong\tlazy\ttrap\tT0"), "A: lazy trap slot 0");
	CHECK(has("/app/Test\t_missingFunctionB\t/usr/lib/libmissing.dylib\t2\tstrong\tnonlazy\ttrap\tT1"), "B: non-lazy trap slot 1");
	CHECK(has("/app/Test\t_missingFunctionC\t/usr/lib/libmissing.dylib\t2\tstrong\tchained\ttrap\tT2"), "C: chained trap slot 2");
	CHECK(has("/app/Test\t_kMissingData\t/usr/lib/libmissing.dylib\t2\tstrong\tnonlazy\tguard\tG0"), "data: guard slot 0");
	CHECK(has("/app/Test\t_weakMissing\t/usr/lib/libmissing.dylib\t2\tweak\tnonlazy\tzero\t-"), "weak: zero, no slot");
	CHECK(has("/usr/lib/libother.dylib\t_missingFunctionA\t/usr/lib/libmissing.dylib\t3\tstrong\tlazy\ttrap\tT0"), "same symbol, other referrer: its own line, shared slot");
	CHECK(has("/app/Test\t_kMissingLazyData\t/usr/lib/libmissing.dylib\t2\tstrong\tlazy\ttrap\tT3"), "a lazy bind is a function even when the name looks like data");

	// 3. the thunks: entered, they reach the trap, which halts naming the symbol
	CHECK(callThunk(a) == "a collected missing symbol was called: _missingFunctionA (referenced from /app/Test, expected in /usr/lib/libmissing.dylib)", "calling A halts naming A: %s", sHaltMessage);
	CHECK(callThunk(b).find("_missingFunctionB") != std::string::npos, "calling B halts naming B");
	CHECK(callThunk(c).find("_missingFunctionC") != std::string::npos, "calling C halts naming C");
	CHECK(callThunk(dLazy).find("_kMissingLazyData") != std::string::npos, "calling the lazy data-named import halts naming it");
	std::string signedCall = callThunkAuthenticated(a);
	CHECK(signedCall.find("_missingFunctionA") != std::string::npos, "an arm64e call (signed IA/0, blraaz) of A reaches the trap: %s", signedCall.c_str());

	// 4. the data guard faults exactly at its slot, on a read
	struct sigaction sa;
	memset(&sa, 0, sizeof(sa));
	sa.sa_sigaction = onSegv;
	sa.sa_flags = SA_SIGINFO | SA_NODEFER;
	sigaction(SIGSEGV, &sa, nullptr);
	sFaultAddress = nullptr;
	int read = 0;
	if ( sigsetjmp(sJump, 1) == 0 ) {
		read = (int)*(volatile long*)d;
		CHECK(false, "reading the guard returned %d instead of faulting", read);
	}
	CHECK(sFaultAddress == (void*)d, "reading the data guard faults at its own slot");

	// 5. the regions are never writable and executable at once
	CHECK(mapsPermsOf(a).substr(0, 3) == "r-x", "thunk region is r-x: %s", mapsPermsOf(a).c_str());
	CHECK(mapsPermsOf(d).substr(0, 3) == "---", "guard region has no access: %s", mapsPermsOf(d).c_str());

	// 6. the name test
	struct { const char* name; bool data; } names[] = {
		{ "_OBJC_CLASS_$_CABackdropLayer", true }, { "_OBJC_METACLASS_$_Foo", true }, { "_kCTFontUIFontDesignSerif", true },
		{ "_NSToolbarSidebarTrackingSeparatorItemIdentifier", true }, { "_NSFlowLayoutCommonRowHorizontalAlignmentKey", true },
		{ "_NSDirectionalEdgeInsetsZero", true }, { "_NSBackgroundColorAttributeName", true }, { "_NSWindowDidResizeNotification", true },
		{ "_CGContextGetLineDashCount", false }, { "_CTFontCopySampleLettersWithLanguages", false }, { "_NSAccessibilityPostNotification", false },
		{ "_NSAccessibilityPointInView", false }, { "_CGBitmapGetAlignedBytesPerRow", false }, { "_CGImageSourceCreateThumbnailAtIndex", false },
		{ "_CGContextSetCompositeOperation", false }, { "_CGFloatIsValid", false },
	};
	for (const auto& n : names)
		CHECK(collectMissingNameLooksLikeData(n.name) == n.data, "%s is %s", n.name, n.data ? "data" : "a function");

	// 7. signed ordinals, as the bind opcodes have them: -1 main executable, -2 flat lookup, 0 self
	std::string thunkBase = header.substr(header.find("thunk=") + 6, header.find(" guard=") - header.find("thunk=") - 6);
	const uintptr_t thunkRegion = (uintptr_t)strtoull(thunkBase.c_str(), nullptr, 16);
	collectMissingBind({ "/app/Test", "_mainExecutableImport", "/app/Test", -1, false, BindKind::Unknown });
	collectMissingBind({ "/app/Test", "_flatImport", "flat", -2, false, BindKind::Unknown });
	collectMissingBind({ "/app/Test", "_selfImport", "/app/Test", 0, false, BindKind::Unknown });
	lines = readLines(out);
	auto hasLine = [&](const char* line) { const std::string want = std::string(line) + "\t" + std::to_string((int)getpid()); for (const std::string& r : lines) if ( r == want ) return true; return false; };
	CHECK(hasLine("/app/Test\t_mainExecutableImport\t/app/Test\t-1\tstrong\tchained\ttrap\tT4"), "ordinal -1 (main executable) keeps its sign");
	CHECK(hasLine("/app/Test\t_flatImport\tflat\t-2\tstrong\tchained\ttrap\tT5"), "ordinal -2 (flat lookup) keeps its sign");
	CHECK(hasLine("/app/Test\t_selfImport\t/app/Test\t0\tstrong\tchained\ttrap\tT6"), "ordinal 0 (self) is 0");

	// 8. guards: one slot per symbol, each its own, the same symbol from another referrer shares it
	uintptr_t g1 = collectMissingBind({ app, "_kMissingData2", lib, 2, false, BindKind::NonLazy });
	uintptr_t g2 = collectMissingBind({ app, "_kMissingData3", lib, 2, false, BindKind::NonLazy });
	uintptr_t g1Again = collectMissingBind({ "/usr/lib/libother.dylib", "_kMissingData2", lib, 3, false, BindKind::NonLazy });
	CHECK(g1 != g2 && g1 != d && g2 != d, "every data symbol has its own guard slot");
	CHECK(g1Again == g1, "the same data symbol shares its guard slot across referrers");
	CHECK(g1 == d + 16 && g2 == d + 32, "guard slots are consecutive 16-byte slots");

	// 9. what the recorder asks of the kernel: close-on-exec and no symlink following; failures are loud
	{
		const char* path = "collect-watched.txt";
		unlink(path);
		sWatchedPath = path;
		sWatchedOpenFlags = -1;
		collectMissingEnable(path);
		collectMissingBind({ app, "_openFlagsProbe", lib, 2, false, BindKind::Lazy });
		CHECK(sWatchedOpenFlags >= 0 && (sWatchedOpenFlags & O_CLOEXEC) && (sWatchedOpenFlags & O_NOFOLLOW) && (sWatchedOpenFlags & O_APPEND),
		      "the output file is opened O_APPEND|O_CLOEXEC|O_NOFOLLOW (flags 0x%x)", sWatchedOpenFlags);
		sWatchedPath = nullptr;

		// a symlink as the output path is refused loudly and the target is left alone
		unlink("collect-target.txt");
		unlink("collect-link.txt");
		FILE* t = fopen("collect-target.txt", "w");
		fputs("untouched\n", t);
		fclose(t);
		symlink("collect-target.txt", "collect-link.txt");
		collectMissingEnable("collect-link.txt");
		sHaltMessage[0] = '\0';
		if ( sigsetjmp(sJump, 1) == 0 ) {
			collectMissingBind({ app, "_throughSymlink", lib, 2, false, BindKind::Lazy });
			CHECK(false, "a symlink as the output path was followed");
		}
		CHECK(std::string(sHaltMessage).find("cannot open the output file") != std::string::npos, "a symlink output path halts: %s", sHaltMessage);
		CHECK(readLines("collect-target.txt").size() == 1, "the symlink's target was not written");

		// an unopenable path halts, and so does a short write
		collectMissingEnable("/nonexistent-directory/collect.txt");
		sHaltMessage[0] = '\0';
		if ( sigsetjmp(sJump, 1) == 0 ) {
			collectMissingBind({ app, "_unopenable", lib, 2, false, BindKind::Lazy });
			CHECK(false, "an unopenable output path was ignored");
		}
		CHECK(std::string(sHaltMessage).find("cannot open the output file") != std::string::npos, "an unopenable output path halts: %s", sHaltMessage);
		collectMissingEnable("collect-short.txt");
		unlink("collect-short.txt");
		sShortWrite = true;
		sHaltMessage[0] = '\0';
		if ( sigsetjmp(sJump, 1) == 0 ) {
			collectMissingBind({ app, "_shortWrite", lib, 2, false, BindKind::Lazy });
			CHECK(false, "a short write was ignored");
		}
		sShortWrite = false;
		CHECK(std::string(sHaltMessage).find("cannot write the output file") != std::string::npos, "a short write halts: %s", sHaltMessage);
		collectMissingEnable(out);
	}

	// 10. the trap with a slot it has no symbol for names nothing and does not read out of bounds
	{
		uint64_t trap = 0;
		memcpy(&trap, (const void*)thunkRegion, sizeof(trap));
		sHaltMessage[0] = '\0';
		if ( sigsetjmp(sJump, 1) == 0 )
			((void (*)(uint64_t))(uintptr_t)trap)(1ULL << 40);
		CHECK(std::string(sHaltMessage).find("called: ?") != std::string::npos, "a slot out of range halts without a name: %s", sHaltMessage);
	}

	// 11. the capacity: 8192 functions and 8192 data symbols per process, the next one halts
	{
		auto fill = [&](const char* format, BindKind kind, size_t base, const char* what) {
			uintptr_t last = 0;
			size_t i = 0;
			std::string halted;
			for (; i < 9000; ++i) {
				char name[64];
				snprintf(name, sizeof(name), format, (int)i);
				sHaltMessage[0] = '\0';
				if ( sigsetjmp(sJump, 1) == 0 )
					last = collectMissingBind({ app, name, lib, 2, false, kind });
				else {
					halted = sHaltMessage;
					break;
				}
			}
			CHECK(halted.find("more than 8192") != std::string::npos, "%s: the 8193rd distinct symbol halts (%s)", what, halted.c_str());
			CHECK(last == base, "%s: the last symbol bound sits in the last slot", what);
		};
		fill("_capFunction%d", BindKind::Lazy, thunkRegion + 16 + 16 * 8191, "functions");
		const uintptr_t guardRegion = (uintptr_t)strtoull(header.c_str() + header.find("guard=") + 6, nullptr, 16);
		fill("_kCapData%d", BindKind::NonLazy, guardRegion + 16 * 8191, "data symbols");
	}

	printf(failures == 0 ? "RESULT ok\n" : "RESULT failed (%d)\n", failures);
	return failures == 0 ? 0 : 1;
}
