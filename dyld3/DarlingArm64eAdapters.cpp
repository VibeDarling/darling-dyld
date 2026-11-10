// DARLING arm64e compat: see DarlingArm64eAdapters.h.
#include "DarlingArm64eAdapters.h"

#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>

#include "MachOLoaded.h"

namespace dyld {
	extern void warn(const char* format, ...) __attribute__((format(printf, 1, 2)));
}

namespace dyld3 {
namespace darling {

#if defined(__aarch64__) || defined(__arm64__)

using AdapterSign = dyld3::MachOLoaded::ChainedFixupPointerOnDisk::Arm64e;

static const AdapterRow kRows[] = {
#include "DarlingArm64eAdapterRows.inc"
};

// A Block_literal_1. flags: 1<<24 BLOCK_NEEDS_FREE (heap), 1<<28 BLOCK_IS_GLOBAL.
struct BlockLiteral {
	void*		isa;
	int32_t		flags;
	int32_t		reserved;
	void*		invoke;
	void*		descriptor;
};
static_assert(sizeof(BlockLiteral) == 32, "block literal layout");
static const int32_t kBlockNeedsFree = 1 << 24;
static const int32_t kBlockHasCopyDispose = 1 << 25;
static const int32_t kBlockIsGlobal  = 1 << 28;

// The plain arm64 assembler of this build refuses the PAC mnemonics, so these are .inst words on x17 and x16.
// XPACI is only used to tell a pointer that authenticated (canonical, so stripping changes nothing) from one that did not.
static inline uint64_t stripCode(uint64_t pointer)
{
	uint64_t stripped;
	__asm__("mov x17, %1\n\t.inst 0xDAC143F1\n\tmov %0, x17" : "=r"(stripped) : "r"(pointer) : "x17");	// xpaci x17
	return stripped;
}

// AUTIA with the modifier in a register. Without FPAC a failed authentication returns a pointer with error bits and
// the later call through it faults; with FPAC the instruction itself faults.
static inline uint64_t authenticateIA(uint64_t pointer, uint64_t modifier)
{
	uint64_t result;
	__asm__("mov x17, %1\n\tmov x16, %2\n\t.inst 0xDAC11211\n\tmov %0, x17" : "=r"(result) : "r"(pointer), "r"(modifier) : "x16", "x17");	// autia x17, x16
	return result;
}

static inline bool authenticated(uint64_t result)
{
	return result == stripCode(result);
}

static inline bool isSpecialHandler(uint64_t value)
{
	// NULL, SIG_IGN, SIG_ERR: never signed, never authenticated
	return (value == 0) || (value == 1) || (value == ~0ULL);
}

static AdapterMode sMode = AdapterMode::On;

void setAdapterMode(AdapterMode mode)
{
	sMode = mode;
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
			return "an auth mask names an argument the row does not have";
		if ( (r.blockArg > r.argCount) || (r.structArg >= r.argCount) )
			return "a block argument is out of range, or a struct argument has no old-action argument after it";
		if ( (r.blockArg != 0) && (r.structArg != 0) )
			return "a row has both a block and a struct argument";
		if ( (r.blockArg != 0) && ((r.authMask >> (r.blockArg - 1)) & 1) )
			return "the block argument is also in the auth mask";
		if ( (r.structArg != 0) && ((r.authMask >> (r.structArg - 1)) & 1) )
			return "the struct argument is also in the auth mask";
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

static uint64_t callRow(uint64_t* regs, const AdapterRow* row, uint64_t real);

uint64_t callThunkHelperAddress()
{
	return (uint64_t)&callRow;
}

// Saves x0-x7 below a frame record, then helper(regs, row, real) does the work and returns the result in x0. Both
// directions use this template; the row is whichever table the helper reads.
static size_t emitCallThunkWith(uint32_t* words, const void* row, uint64_t real, uint64_t helper)
{
	static const uint32_t kTemplate[14] = {
		0xA9BB7BFD,		// stp x29, x30, [sp, #-80]!
		0x910003FD,		// mov x29, sp
		0xA90107E0,		// stp x0, x1, [sp, #16]
		0xA9020FE2,		// stp x2, x3, [sp, #32]
		0xA90317E4,		// stp x4, x5, [sp, #48]
		0xA9041FE6,		// stp x6, x7, [sp, #64]
		0x910043E0,		// add x0, sp, #16
		0x580000E1,		// ldr x1, row
		0x58000102,		// ldr x2, real
		0x58000130,		// ldr x16, helper
		0xD63F0200,		// blr x16
		0xA8C57BFD,		// ldp x29, x30, [sp], #80
		0xD65F03C0,		// ret
		0xD503201F,		// nop (the literals are 8 aligned)
	};
	memcpy(words, kTemplate, sizeof(kTemplate));
	putLiteral(&words[14], (uint64_t)row);
	putLiteral(&words[16], real);
	putLiteral(&words[18], helper);
	return 20;
}

size_t emitCallThunk(uint32_t* words, const AdapterRow* row, uint64_t real)
{
	return emitCallThunkWith(words, row, real, callThunkHelperAddress());
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
// Thunks are made by a bind or by dlsym, neither of which is async-signal-safe, so no signal handler can arrive on a thread
// that holds this lock and make one; it keeps concurrent binds and dlsym calls on other threads out of the cache. The
// calls that run through a thunk never touch it.
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
	const bool simple = (row->blockArg == 0) && (row->structArg == 0) && (row->ret == ReturnFix::None);
	const size_t count = simple ? emitAuthThunk(words, row->authMask, real) : emitCallThunk(words, row, real);
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

// ------------------------------------------------------------------------------------------ the call thunk's work

// The mirror of a global block: its literal can be read-only, so plain code gets a copy with the invoke authenticated.
// Global blocks are never freed, so the mirrors are kept, one per block address, and refreshed on every use.
struct Mirror { const BlockLiteral* original; BlockLiteral* copy; };
static Mirror sMirrors[256];
static size_t sMirrorCount;
static volatile int sMirrorLock;

static BlockLiteral* mirrorOfGlobalBlock(const BlockLiteral* block, uint64_t plainInvoke)
{
	while ( __sync_lock_test_and_set(&sMirrorLock, 1) ) { }
	BlockLiteral* copy = nullptr;
	for (size_t i = 0; i != sMirrorCount; ++i) {
		if ( sMirrors[i].original == block ) {
			copy = sMirrors[i].copy;
			break;
		}
	}
	if ( copy == nullptr ) {
		if ( sMirrorCount == sizeof(sMirrors) / sizeof(sMirrors[0]) ) {
			dyld::warn("arm64e adapters: more than %lu distinct global blocks passed to plain code\n", (unsigned long)(sizeof(sMirrors) / sizeof(sMirrors[0])));
			__builtin_trap();
		}
		copy = (BlockLiteral*)malloc(sizeof(BlockLiteral));
		sMirrors[sMirrorCount++] = { block, copy };
	}
	*copy = *block;
	copy->invoke = (void*)plainInvoke;
	__sync_lock_release(&sMirrorLock);
	return copy;
}

// The tables below are lock free: sigaction() is async-signal-safe, so a handler that calls signal() or sigaction() on a
// thread that is inside an adapter must not meet a lock that thread holds. Every slot is one aligned word, read and
// written with relaxed atomics, and a stale or lost entry only makes a pointer come back unsigned or be refused.

// The handler that each signal was last given through a signal or sigaction row, as plain code has it, and only when
// that handler really authenticated (a signature that arm64e code made); 0 when the last install was anything else. It
// is the one thing signal() signs on the way back.
//
// Every value this module signs gets signed by one of two paths, and each needs a real signature first:
//   1. signal() result R: signed only when R equals the table entry of its signal, which only a successful
//      authentication ever wrote (so R is a pointer that arm64e code signed itself, re-signed for the same code);
//   2. _Block_copy copy: its invoke is signed from the original's invoke, only when that authenticated at the original's
//      own address.
// A pointer that the ring below accepted (plain code's own value) is never recorded, so it is never signed. dlsym, the GOT
// override and the fixups sign or bind addresses that dyld itself resolved, not values that a caller supplies.
static const int32_t kSignalCount = 32;
static uint64_t sInstalledHandlers[kSignalCount];

// A signal number is an int: the upper half of its register is not part of it
static inline int32_t signalNumber(uint64_t reg)
{
	return (int32_t)reg;
}

static inline bool validSignal(int32_t sig)
{
	return (sig > 0) && (sig < kSignalCount);
}

// plainHandler is 0 for an install that did not authenticate (a ring-accepted value, SIG_DFL, SIG_IGN, garbage): the
// handler that was recorded before is no longer the installed one
static void recordInstalledHandler(int32_t sig, uint64_t plainHandler)
{
	if ( validSignal(sig) )
		__atomic_store_n(&sInstalledHandlers[sig], plainHandler, __ATOMIC_RELAXED);
}

static bool wasInstalledHere(int32_t sig, uint64_t handler)
{
	return validSignal(sig) && (__atomic_load_n(&sInstalledHandlers[sig], __ATOMIC_RELAXED) == handler);
}

// The plain handlers this module handed out unsigned (signal() results and sigaction old actions that arm64e code did
// not install through an adapter). Arm64e code that saves one and restores it passes it back as it got it, which does not
// authenticate; an exact match is accepted, nothing else that fails is, so this is no way to make a forged pointer pass.
// A ring: when it is full the oldest entry goes, and that handler can no longer be restored.
//
// The ring is lock free: one aligned word per slot, read and written with relaxed atomics. The two directions each keep their own.
static const unsigned kRingCount = 64;
struct PointerRing {
	uint64_t	slots[kRingCount];
	uint32_t	next;
};

static bool ringHolds(const PointerRing& ring, uint64_t pointer)
{
	if ( pointer == 0 )
		return false;
	for (unsigned i = 0; i != kRingCount; ++i) {
		if ( __atomic_load_n(&ring.slots[i], __ATOMIC_RELAXED) == pointer )
			return true;
	}
	return false;
}

static void ringAdd(PointerRing& ring, uint64_t pointer)
{
	const uint32_t slot = __atomic_fetch_add(&ring.next, 1, __ATOMIC_RELAXED) % kRingCount;
	__atomic_store_n(&ring.slots[slot], pointer, __ATOMIC_RELAXED);
}

static PointerRing sHandedOut;

static bool wasHandedOut(uint64_t pointer)
{
	return ringHolds(sHandedOut, pointer);
}

static void recordHandedOut(uint64_t plainHandler)
{
	if ( isSpecialHandler(plainHandler) || wasHandedOut(plainHandler) )
		return;
	ringAdd(sHandedOut, plainHandler);
}

// A handler argument: key IA, discriminator 0 (what paciza makes, and the compiler for a C function pointer). What does
// not authenticate stays unusable unless it is exactly a plain handler handed out above. genuine says that the signature
// was real: only then may the handler be remembered as one that arm64e code installed.
struct HandlerArg { uint64_t value; bool genuine; };

static HandlerArg authenticateHandler(uint64_t pointer)
{
	if ( isSpecialHandler(pointer) )
		return { pointer, false };
	const uint64_t result = authenticateIA(pointer, 0);
	if ( authenticated(result) )
		return { result, true };
	if ( wasHandedOut(pointer) )
		return { pointer, false };
	return { result, false };
}

// The real sigaction() returns EFAULT for a pointer it cannot read or write, and an adapter that touches the caller's
// structs must not crash instead. A pipe is a copy that the kernel does and that fails with EFAULT: write() reads the
// source, read() writes the destination. When it fails, the real call gets (void*)-1 for both structs, never the caller's
// pointer: the caller's memory could be mapped by another thread between the check and the call, and the real call would
// then read a struct that was neither copied nor authenticated. -1 is not a user address, so the kernel answers EFAULT
// every time, nothing is installed (the act copy-in fails first), and the answer carries the errno of the caller's libc;
// returning -1 from the thunk instead would set dyld's own errno, which is not the process's. The descriptors exist for
// the length of one copy; no memory is mapped or probed in any other way.
enum class Access { Ok, Fault, NoResource };

static Access copyThroughPipe(void* destination, const void* source, size_t length)
{
	int fds[2];
	if ( pipe(fds) != 0 )
		return Access::NoResource;
	const bool ok = (write(fds[1], source, length) == (ssize_t)length) && (read(fds[0], destination, length) == (ssize_t)length);
	close(fds[0]);
	close(fds[1]);
	return ok ? Access::Ok : Access::Fault;
}

static void warnNoDescriptors(const AdapterRow* row)
{
	dyld::warn("arm64e adapters: %s could not make a pipe to copy the caller's struct, so it fails with EFAULT\n", row->symbol);
}

// Rewriting a shared block would corrupt it for its other users, and the proxy block that would serve both needs an
// arm64e compiled shim: until then the call stops here, with the reason.
static void refuseBlock(const AdapterRow* row, const char* what)
{
	dyld::warn("arm64e adapters: %s was passed %s by an arm64e image; plain code cannot call it and rewriting it in place would corrupt it for its other users: this needs the arm64e shim (decision Q3 option B)\n", row->symbol, what);
	__builtin_trap();
}

typedef uint64_t (*Call8)(uint64_t, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t);

static uint64_t callRow(uint64_t* regs, const AdapterRow* row, uint64_t real)
{
	uint64_t a[8];
	memcpy(a, regs, sizeof(a));
	uint8_t genuine = 0;	// bit i: argument i was a real signature
	for (unsigned i = 0; i != 8; ++i) {
		if ( (row->authMask >> i) & 1 ) {
			const HandlerArg arg = authenticateHandler(a[i]);
			a[i] = arg.value;
			genuine |= (uint8_t)(arg.genuine << i);
		}
	}

	// An address-diversified invoke is authenticated with the address of its own field. A stack block is rewritten for the
	// call only (the callee copies it or runs it before it returns) and gets its signature back afterwards. A heap block
	// is shared: plain code needs its invoke unsigned and arm64e code needs it signed, and no rewrite serves both, so it
	// is refused. So is any block with copy or dispose helpers, whose pointers arm64e signs and plain code calls unsigned.
	void** restoreSlot = nullptr;
	void* restoreValue = nullptr;
	if ( (row->blockArg != 0) && (a[row->blockArg - 1] != 0) ) {
		BlockLiteral* block = (BlockLiteral*)a[row->blockArg - 1];
		const uint64_t plainInvoke = authenticateIA((uint64_t)block->invoke, (uint64_t)&block->invoke);
		if ( block->flags & kBlockIsGlobal ) {
			a[row->blockArg - 1] = (uint64_t)mirrorOfGlobalBlock(block, plainInvoke);
		}
		else {
			if ( block->flags & kBlockHasCopyDispose )
				refuseBlock(row, "a block with copy and dispose helpers");
			if ( block->flags & kBlockNeedsFree )
				refuseBlock(row, "a heap block");
			restoreSlot = &block->invoke;
			restoreValue = block->invoke;
			block->invoke = (void*)plainInvoke;
		}
	}

	// The callee gets private copies of both structs: the caller's can be read-only, and another thread can write to the
	// caller's memory while the call runs, so nothing is read from it again after the copy. The old action goes back to
	// the caller only when the call succeeded (a failed call leaves it as it was). When either struct cannot be copied
	// (or there is no descriptor for the pipe), the real call gets -1 for both and answers EFAULT.
	uint64_t structCopy[2];
	uint64_t oldCopy[2];
	bool actCopied = false, structGenuine = false, uncopyable = false;
	void* callerOld = nullptr;
	if ( (row->structArg != 0) && (a[row->structArg - 1] != 0) ) {
		const Access access = copyThroughPipe(structCopy, (const void*)a[row->structArg - 1], sizeof(structCopy));
		if ( access == Access::Ok ) {
			const HandlerArg arg = authenticateHandler(structCopy[0]);
			structCopy[0] = arg.value;
			structGenuine = arg.genuine;
			actCopied = true;
			a[row->structArg - 1] = (uint64_t)structCopy;
		}
		else {
			uncopyable = true;
			if ( access == Access::NoResource )
				warnNoDescriptors(row);
		}
	}
	if ( (row->structArg != 0) && (a[row->structArg] != 0) ) {
		// writable means that what is in it can be written back: the bytes are read and put back unchanged
		uint64_t current[2];
		void* old = (void*)a[row->structArg];
		const Access access = copyThroughPipe(current, old, sizeof(current));
		if ( (access == Access::Ok) && (copyThroughPipe(old, current, sizeof(current)) == Access::Ok) ) {
			callerOld = old;
			oldCopy[0] = oldCopy[1] = 0;
			a[row->structArg] = (uint64_t)oldCopy;
		}
		else {
			uncopyable = true;
			if ( access == Access::NoResource )
				warnNoDescriptors(row);
		}
	}
	if ( uncopyable ) {
		actCopied = false;
		callerOld = nullptr;
		if ( a[row->structArg - 1] != 0 )
			a[row->structArg - 1] = ~0ULL;
		if ( a[row->structArg] != 0 )
			a[row->structArg] = ~0ULL;
	}

	// Block_copy: the original's signature is checked before anything is signed for the copy
	uint64_t originalBlock = 0, originalInvoke = 0;
	if ( (row->ret == ReturnFix::ResignCopiedBlock) && (a[0] != 0) ) {
		const BlockLiteral* block = (const BlockLiteral*)a[0];
		if ( (block->flags & kBlockHasCopyDispose) && ((block->flags & kBlockIsGlobal) == 0) )
			refuseBlock(row, "a block with copy and dispose helpers");
		originalBlock = a[0];
		originalInvoke = authenticateIA((uint64_t)block->invoke, (uint64_t)&block->invoke);
	}

	// the handler that signal() replaces is looked up before this call records the new one
	uint64_t result = ((Call8)real)(a[0], a[1], a[2], a[3], a[4], a[5], a[6], a[7]);

	if ( restoreSlot != nullptr )
		*restoreSlot = restoreValue;
	const int32_t sig = signalNumber(a[0]);
	if ( (row->structArg != 0) && ((int)result == 0) ) {
		// sigaction succeeded. The old action holds the handler that was installed before. Like signal(), it is signed
		// only when it is the one that arm64e code installed with a real signature; any other (plain code's) goes back as it
		// is, and is remembered so that arm64e code can pass it back. This looks at the table before the new handler is
		// recorded in it.
		if ( callerOld != nullptr ) {
			if ( !isSpecialHandler(oldCopy[0]) ) {
				if ( wasInstalledHere(sig, oldCopy[0]) )
					oldCopy[0] = AdapterSign::signPointer(oldCopy[0], nullptr, false, 0, 0);
				else
					recordHandedOut(oldCopy[0]);
			}
			const Access access = copyThroughPipe(callerOld, oldCopy, sizeof(oldCopy));
			if ( access == Access::NoResource )
				warnNoDescriptors(row);
		}
		// the handler in act is the one installed, remembered only when its signature was real
		if ( actCopied )
			recordInstalledHandler(sig, structGenuine ? structCopy[0] : 0);
	}
	switch ( row->ret ) {
		case ReturnFix::None:
			break;
		case ReturnFix::SignInstalledHandler: {
			const bool failed = (result == ~0ULL);
			if ( !isSpecialHandler(result) ) {
				if ( wasInstalledHere(sig, result) )
					result = AdapterSign::signPointer(result, nullptr, false, 0, 0);
				else
					recordHandedOut(result);
			}
			if ( !failed )
				recordInstalledHandler(sig, ((genuine >> 1) & 1) ? a[1] : 0);
			break;
		}
		case ReturnFix::ResignCopiedBlock:
			// a copy was made when the result is another block than the argument (a global or heap block comes back as it is, and is not written); a failed authentication signs nothing
			if ( (originalBlock != 0) && (result != 0) && (result != originalBlock) && authenticated(originalInvoke) ) {
				BlockLiteral* copy = (BlockLiteral*)result;
				copy->invoke = (void*)AdapterSign::signPointer(originalInvoke, &copy->invoke, true, 0, 0);
			}
			break;
	}
	return result;
}

// ------------------------------------------------------------------------------------------ bind time

// report mode: a symbol is named once per direction, by a 64-bit FNV-1a hash (a name pointer may not outlive its image; a
// collision only loses a line of a diagnostic)
static uint64_t sReported[2048];
static unsigned sReportedCount;

static void reportMissingRow(const char* symbol, const char* binder, const char* bound)
{
	uint64_t hash = 1469598103934665603ULL;
	for (const char* c = binder; *c != '\0'; ++c)
		hash = (hash ^ (uint8_t)*c) * 1099511628211ULL;
	for (const char* c = symbol; *c != '\0'; ++c)
		hash = (hash ^ (uint8_t)*c) * 1099511628211ULL;
	for (unsigned i = 0; i != sReportedCount; ++i) {
		if ( sReported[i] == hash )
			return;
	}
	if ( sReportedCount == sizeof(sReported) / sizeof(sReported[0]) )
		return;
	sReported[sReportedCount++] = hash;
	dyld::warn("arm64e adapters: %s is bound by %s to %s and has no row\n", symbol, binder, bound);
}

uint64_t adaptedTarget(const char* symbol, uint64_t target, bool targetIsArm64e)
{
	if ( (sMode == AdapterMode::Off) || targetIsArm64e )
		return target;
	const AdapterRow* row = findAdapterRow(symbol);
	if ( row == nullptr ) {
		if ( sMode == AdapterMode::Report )
			reportMissingRow(symbol, "an arm64e image", "a plain function");
		return target;
	}
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
void setAdapterMode(AdapterMode) { }
const AdapterRow* adapterRows(size_t* count) { *count = 0; return kRows; }
const AdapterRow* findAdapterRow(const char*) { return nullptr; }
const char* validateAdapterRows(const AdapterRow*, size_t) { return nullptr; }
uint64_t adaptedTarget(const char*, uint64_t target, bool) { return target; }
size_t emitAuthThunk(uint32_t*, uint8_t, uint64_t) { return 0; }
size_t emitCallThunk(uint32_t*, const AdapterRow*, uint64_t) { return 0; }
uint64_t callThunkHelperAddress() { return 0; }

#endif

} // namespace darling
} // namespace dyld3
