// Host check of dyld3/DarlingCollectMissing.cpp: the recorder, the thunks and the guard region, run natively on ARM64 Linux.
// dyld::halt is replaced by a stub that jumps back to the check, so a thunk is really entered, reaches the trap and halts.
#include "DarlingCollectMissing.h"

#include <assert.h>
#include <fcntl.h>
#include <setjmp.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>
#include <string>
#include <vector>

using namespace dyld3::darling;

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
	CHECK(header.find("# regions thunk=0x") == 0, "region header line: %s", header.c_str());
	CHECK(records.size() == 7, "7 record lines (A, B, C, data, weak, A from another referrer, lazy data), got %zu", records.size());
	for (const std::string& r : records)
		CHECK(fields(r).size() == 8, "8 fields: %s", r.c_str());
	for (const std::string& r : records)
		CHECK(r.find("0x") == std::string::npos, "no address in a record line");
	auto has = [&](const char* line) { for (const std::string& r : records) if ( r == line ) return true; return false; };
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

	printf(failures == 0 ? "RESULT ok\n" : "RESULT failed (%d)\n", failures);
	return failures == 0 ? 0 : 1;
}
