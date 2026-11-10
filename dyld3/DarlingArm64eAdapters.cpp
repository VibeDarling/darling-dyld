// DARLING arm64e compat: see DarlingArm64eAdapters.h.
#include "DarlingArm64eAdapters.h"

#include <string.h>
#include <sys/mman.h>


namespace dyld {
	extern void warn(const char* format, ...) __attribute__((format(printf, 1, 2)));
}

namespace dyld3 {
namespace darling {

#if defined(__aarch64__) || defined(__arm64__)

static const AdapterRow kRows[] = {
#include "DarlingArm64eAdapterRows.inc"
};

static bool sEnabled = true;

void setAdaptersEnabled(bool enabled)
{
	sEnabled = enabled;
}

const AdapterRow* adapterRows(size_t* count)
{
	*count = sizeof(kRows) / sizeof(kRows[0]);
	return kRows;
}

const AdapterRow* findAdapterRow(const char* symbol)
{
	for (const AdapterRow& row : kRows) {
		if ( strcmp(row.symbol, symbol) == 0 )
			return &row;
	}
	return nullptr;
}

const char* validateAdapterRows(const AdapterRow* rows, size_t count)
{
	for (size_t i = 0; i != count; ++i) {
		const AdapterRow& r = rows[i];
		if ( (r.symbol == nullptr) || (r.symbol[0] != '_') )
			return "a symbol is missing the Mach-O underscore";
		for (size_t j = 0; j != i; ++j) {
			if ( strcmp(rows[j].symbol, r.symbol) == 0 )
				return "a symbol has two rows";
		}
		if ( (r.evidence == nullptr) || (r.evidence[0] == '\0') )
			return "a row has no evidence";
		const bool acts = (r.authMask != 0) || (r.blockArg != 0) || (r.structArg != 0) || (r.ret != ReturnFix::None);
		if ( (r.status == AdapterStatus::Unsupported) || (r.status == AdapterStatus::HandledElsewhere) ) {
			if ( acts )
				return "a row without an adapter has an action";
			continue;
		}
		if ( !acts )
			return "a row does nothing";
		if ( (r.argCount == 0) || (r.argCount > 8) )
			return "a row takes no register argument or more than eight";
		if ( (r.authMask >> r.argCount) != 0 )
			return "a strip mask names an argument the row does not have";
		if ( (r.blockArg > r.argCount) || (r.structArg > r.argCount) )
			return "a block or struct argument is out of range";
		if ( (r.blockArg != 0) && (r.structArg != 0) )
			return "a row has both a block and a struct argument";
		if ( (r.blockArg != 0) && ((r.authMask >> (r.blockArg - 1)) & 1) )
			return "the block argument is also in the strip mask";
		if ( (r.structArg != 0) && ((r.authMask >> (r.structArg - 1)) & 1) )
			return "the struct argument is also in the strip mask";
	}
	return nullptr;
}

// ------------------------------------------------------------------------------------------ thunks

static void putLiteral(uint32_t* words, uint64_t value)
{
	words[0] = (uint32_t)value;
	words[1] = (uint32_t)(value >> 32);
}

// For each masked argument: leave 0, 1 and -1 alone, else autiza xN (key IA, zero discriminator); then a tail branch. No
// frame, no stack, the link register stays the caller's. x16 and the flags are scratch at a call boundary.
size_t emitAuthThunk(uint32_t* words, uint8_t authMask, uint64_t real)
{
	size_t n = 0;
	for (unsigned i = 0; i != 8; ++i) {
		if ( ((authMask >> i) & 1) == 0 )
			continue;
		words[n++] = 0x91000410 | (i << 5);		// add x16, xi, #1: 0, -1 and 1 become 1, 0 and 2
		words[n++] = 0xF1000A1F;				// cmp x16, #2
		words[n++] = 0x54000049;				// b.ls +8
		words[n++] = 0xDAC133E0 | i;			// autiza xi
	}
	words[n++] = 0x58000050;	// ldr x16, #8
	words[n++] = 0xD61F0200;	// br x16
	putLiteral(&words[n], real);	// 4 words per argument and two more: the literal is 8 aligned
	return n + 2;
}

// Thunks are never in a page that is writable and executable at once. Each new thunk gets its own page: mapped read-write,
// filled, flushed and sealed read-execute, and never written again. Thunks are made as images bind, so one shared page
// would have to be reopened for writing while other threads may already be running thunks in it. The cost is one page
// per distinct adapted symbol and target (at most one per table row in practice). The pool is the cache below, which
// holds the lock; it only ever grows, and a hit reads an entry that is complete and a sealed page.
static const size_t kThunkPageSize = 16384;		// the largest page size of the hosts (Asahi has 16 KiB)

struct ThunkEntry { const AdapterRow* row; uint64_t real; uint64_t thunk; };
static ThunkEntry sThunks[128];
static size_t sThunkCount;
// dyld's lock is held by every caller; this one also keeps a bind from another thread out of the cache and the page
static volatile int sThunkLock;

static void flushInstructionCache(void* start, size_t length)
{
	uint64_t ctr;
	__asm__ volatile("mrs %0, ctr_el0" : "=r"(ctr));
	const uintptr_t dline = 4UL << ((ctr >> 16) & 0xf);
	const uintptr_t iline = 4UL << (ctr & 0xf);
	const uintptr_t first = (uintptr_t)start, last = first + length;
	for (uintptr_t a = first & ~(dline - 1); a < last; a += dline)
		__asm__ volatile("dc cvau, %0" : : "r"(a) : "memory");
	__asm__ volatile("dsb ish" : : : "memory");
	for (uintptr_t a = first & ~(iline - 1); a < last; a += iline)
		__asm__ volatile("ic ivau, %0" : : "r"(a) : "memory");
	__asm__ volatile("dsb ish\n\tisb" : : : "memory");
}

bool sealExecutablePage(void* page, size_t length)
{
	flushInstructionCache(page, length);
	return mprotect(page, length, PROT_READ | PROT_EXEC) == 0;
}

// 0 when no page can be had
static uint64_t emitThunkLocked(const AdapterRow* row, uint64_t real)
{
	for (size_t i = 0; i != sThunkCount; ++i) {
		if ( (sThunks[i].row == row) && (sThunks[i].real == real) )
			return sThunks[i].thunk;
	}
	if ( sThunkCount == sizeof(sThunks) / sizeof(sThunks[0]) )
		return 0;
	uint32_t words[40];
	const size_t count = emitAuthThunk(words, row->authMask, real);
	void* page = mmap(nullptr, kThunkPageSize, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANON, -1, 0);
	if ( page == MAP_FAILED )
		return 0;
	memcpy(page, words, count * sizeof(uint32_t));
	if ( !sealExecutablePage(page, kThunkPageSize) ) {
		munmap(page, kThunkPageSize);
		return 0;
	}
	sThunks[sThunkCount++] = { row, real, (uint64_t)page };
	return (uint64_t)page;
}

static uint64_t emitThunk(const AdapterRow* row, uint64_t real)
{
	while ( __sync_lock_test_and_set(&sThunkLock, 1) ) { }
	const uint64_t thunk = emitThunkLocked(row, real);
	__sync_lock_release(&sThunkLock);
	return thunk;
}

// ------------------------------------------------------------------------------------------ bind time

uint64_t adaptedTarget(const char* symbol, uint64_t target, bool targetIsArm64e)
{
	if ( !sEnabled || targetIsArm64e )
		return target;
	const AdapterRow* row = findAdapterRow(symbol);
	if ( row == nullptr )
		return target;
	if ( row->status == AdapterStatus::HandledElsewhere )
		return target;
	if ( row->status == AdapterStatus::Unsupported ) {
		dyld::warn("arm64e adapters: %s is imported by an arm64e image and has no adapter (%s); calls with a signed pointer fault\n",
				   symbol, row->evidence);
		return target;
	}
	const uint64_t thunk = emitThunk(row, target);
	if ( thunk == 0 ) {
		dyld::warn("arm64e adapters: no room for a thunk for %s; it is bound unadapted and calls with a signed pointer fault\n", symbol);
		return target;
	}
	return thunk;
}

#else // not arm64: arm64e importers do not exist, so nothing is ever adapted

static const AdapterRow kRows[] = { { "_unused", 0, 0, 0, ReturnFix::None, 0, AdapterStatus::Unsupported, "not arm64" } };
void setAdaptersEnabled(bool) { }
const AdapterRow* adapterRows(size_t* count) { *count = 0; return kRows; }
const AdapterRow* findAdapterRow(const char*) { return nullptr; }
const char* validateAdapterRows(const AdapterRow*, size_t) { return nullptr; }
uint64_t adaptedTarget(const char*, uint64_t target, bool) { return target; }
size_t emitAuthThunk(uint32_t*, uint8_t, uint64_t) { return 0; }

#endif

} // namespace darling
} // namespace dyld3
