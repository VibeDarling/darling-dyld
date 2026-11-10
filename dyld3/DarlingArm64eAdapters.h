// DARLING arm64e compat: callback-taking exports of Darling's plain arm64 libraries, as seen by arm64e importers.
//
// An arm64e image hands PAC-signed code pointers to a plain callee, which calls them with a plain BLR and faults
// (tests/arm64e-link/abi/README.md in the abi-probe branch). The loader knows at bind time that the importer is arm64e
// and that the resolved target is a plain image, so it binds a small thunk instead: it authenticates the signature on
// the way in (a pointer that does not authenticate stays unusable) and, for the few exports that hand a pointer back, signs
// it on the way out. A table of rows says which.
#ifndef DarlingArm64eAdapters_h
#define DarlingArm64eAdapters_h

#include <stddef.h>
#include <stdint.h>
#include <mach/machine.h>

namespace dyld3 {
namespace darling {

enum class AdapterStatus : uint8_t {
	Probed,				// an L2 ABI probe check runs this shape
	ShapeOnly,			// the prototype has the same shape as a probed row; not run itself
	HandledElsewhere,	// no thunk: the pointer is handled by another patch (evidence says which); no warning
	Unsupported			// the shape is known to matter and is not adapted; evidence says why
};

enum class ReturnFix : uint8_t {
	None,
	// signal(): argument 0 is the signal number. The handler installed through an adapter row is remembered per signal; the
	// result is signed IA, discriminator 0, only when it is that handler. SIG_DFL, SIG_IGN and SIG_ERR come back as they
	// are, and so does any other value (plain code installed it), so that a later authenticated call faults instead of
	// running a forged pointer. A handler that came back unsigned is accepted again when arm64e code passes it back.
	SignInstalledHandler,
	// _Block_copy(): when a copy was made, its invoke is signed for the copy's own address (IA, address diversified,
	// discriminator 0) from the original's invoke, which is authenticated first; a failed authentication leaves the copy as is.
	ResignCopiedBlock
};

// Argument numbers are counts from 0, one integer register each. Code pointers that arm64e code passes were signed with
// key IA and discriminator 0 by its compiler (L2 README: the pointers `hand` records, and check 19 calling one it signed
// that way): they are authenticated, so that a corrupted or unsigned pointer faults. 0, 1 and -1 pass unchanged (NULL
// destructors, SIG_DFL, SIG_IGN, SIG_ERR). The thunk path only exists for arm64e importers, which run on PAC hardware.
struct AdapterRow {
	const char*		symbol;			// Mach-O name, with the leading underscore
	uint8_t			authMask;		// bit i: argument i is a code pointer to authenticate
	uint8_t			blockArg;		// argument number + 1 of a block pointer whose invoke is authenticated, 0 for none (see Blocks below)
	uint8_t			structArg;		// argument number + 1 of a pointer to a struct whose first word is a signal handler, followed by the out struct of the old one (sigaction), 0 for none
	ReturnFix		ret;
	uint8_t			argCount;		// register arguments up to the last one the row touches; at most 8 (a call thunk takes no FP or stack arguments)
	AdapterStatus	status;
	const char*		evidence;		// the probe check or the reason; never empty
};

// Blocks. A stack block with plain captures and a global block run. A heap block, and any block with copy and dispose
// helpers (arm64e signs those pointers with the address of the descriptor field, and plain code calls them unsigned), make
// the adapter stop with SIGTRAP and a message naming the symbol and the arm64e shim. So dispatch_async or dispatch_once of
// a block that captures an object or a __block variable, or of a heap block, stops here; most Objective-C dispatch_async
// calls are in that group, and so is a heap block that the adapted _Block_copy made and that is then dispatched. That is
// deliberate: rewriting a shared block corrupts it for its other users, and a proxy block needs code compiled for arm64e.
// It is the concrete evidence that the arm64e shim (decision Q3 option B) is needed from L5.
//
// SIG_HOLD (5) is not special: only sigset takes it, and sigset has no adapter (an unsupported row).

inline bool cpusubtypeIsArm64e(cpu_subtype_t subtype)
{
	return (subtype & ~CPU_SUBTYPE_MASK) == CPU_SUBTYPE_ARM64E;
}

const AdapterRow* adapterRows(size_t* count);
const AdapterRow* findAdapterRow(const char* symbol);

// Why a table is malformed, or nullptr. Used on the built-in table by the host test and on synthetic ones.
const char* validateAdapterRows(const AdapterRow* rows, size_t count);

// What an arm64e importer should bind for `symbol` when the resolved target is at `target`: a thunk when the table has
// a row for it and the target is a plain image, otherwise `target`. An Unsupported row binds the target and warns.
// The caller has checked that the importer is arm64e. Interposing: an interposer's own address is not wrapped (the hook
// compares it with the target image); the replacee of an interpose tuple in an arm64e image binds to the same thunk as
// every other arm64e importer's reference to that symbol, so those match each other, but a plain image's direct reference
// is the raw function and is not interposed by an arm64e interposer (not tested under a guest). Safe to call from several threads (the thunk cache has its own lock).
uint64_t adaptedTarget(const char* symbol, uint64_t target, bool targetIsArm64e);

// ------------------------------------------------------------------------------------------ the opposite direction
//
// A PLAIN importer (Darling's libobjc, any non-arm64e image) binding an export of an ARM64E image (the shared cache's
// libc++ and libc++abi). The arm64e callee authenticates or re-signs the function pointers it is given (key IA, discriminator
// 0: the schema of a C function pointer, which the open-source libc++abi's re-sign into its __ptrauth fields authenticates its
// source with) and hands handlers back signed; plain code signs nothing and calls what it gets with a plain BLR. libobjc's
// std::set_terminate(&_objc_terminate) at init stored an unsigned pointer that __cxa_init_primary_exception then failed to
// authenticate, so every throw trapped. Only these binds get a thunk (the hooks in ImageLoaderMachOCompressed.cpp check that the
// importer is plain and the exporter arm64e; an arm64e importer binds the arm64e export directly, and an interposer's own
// address is never wrapped). It is on in the same cases as the forward direction: DYLD_DARLING_ARM64E_ADAPTERS=off turns it
// off and report names the exports with no row, and that variable is honoured only where the other loader environment
// variables that choose the shared cache are (dyld2.cpp).
//
// Result: a handler that comes back is AUTHENTICATED (IA, 0) and handed to plain code raw. One that does not authenticate stops
// the process with a message naming the symbol; 0, 1 and -1 pass. A signature is never stripped without being authenticated.
//
// Argument: a code pointer is signed (IA, 0) only when the predicate says it is a function entry of a loaded PLAIN image, or it
// is exactly a handler this module handed back before (a round trip: set_terminate(get_terminate())). 0, an address in an arm64e
// or cache image, a mid-function address, data and a value that already carries a signature are passed as they are, so the
// arm64e callee fails to authenticate them. An image with no function-starts table signs nothing.
//
// Residual trust. (1) A plain caller of a bound thunk can get any function entry of a plain image installed as a handler (a
// terminate handler, a destructor of a thrown object): it could call that entry itself, so this gives it no new reach, but the
// thunk is not a check that the entry is a sensible handler. (2) The entry check reads the image's mapped LINKEDIT without
// dyld's lock, like dladdr: a dlclose of that image during the call is a race. The lock is not taken: dladdr, which reads the
// same image list and LINKEDIT, takes none, and a thunk is called from arbitrary library code, where taking dyld's lock could
// deadlock a thread that already holds it.
//
// Not covered by a register thunk, and so not by this table: (a) vtables and typeinfo of plain code handed to the arm64e
// libc++abi (a plain image throwing a class through the cache's __cxa_throw: the cache's catch matching calls through plain,
// unsigned vtables; that needs a design decision, not a row); (b) plain code reading or writing the handler data exports
// (___cxa_terminate_handler, ___cxa_unexpected_handler, ___cxa_new_handler) directly; (c) dlsym by a plain caller, which returns
// the raw address; (d) arguments beyond register 8 or on the stack; (e) struct arguments: no row in this table copies a struct
// (money_get::__do_get, whose deleter lives in one, is an unsupported row).
struct ReverseRow {
	const char*		symbol;			// Mach-O name, with the leading underscore
	uint8_t			signMask;		// bit i: argument i is a code pointer to sign (IA, discriminator 0)
	bool			authReturn;		// the result is a handler: authenticate it (IA, 0) and hand plain code the raw pointer
	uint8_t			argCount;		// register arguments up to the last one the row touches, at most 8; 0 for a getter
	AdapterStatus	status;			// Probed, ShapeOnly or Unsupported (HandledElsewhere does not exist in this direction)
	const char*		evidence;		// never empty
};

// true when `address` may be signed for an arm64e callee: a function entry of a loaded plain image
typedef bool (*FunctionEntryPredicate)(uint64_t address);

const ReverseRow* reverseRows(size_t* count);
const ReverseRow* findReverseRow(const char* symbol);
const char* validateReverseRows(const ReverseRow* rows, size_t count);

// Whether `offset` (from the mach header of the image) is one of the function starts in an LC_FUNCTION_STARTS blob (ULEB128
// deltas from 0, ended by a zero delta). A malformed or truncated blob never matches what it does not plainly list.
bool functionStartsContain(const uint8_t* blob, size_t size, uint64_t offset);

// What a plain importer should bind for `symbol` when the resolved target is at `target` and the exporter is arm64e or not: a
// thunk when there is a supported row, otherwise `target` (an Unsupported row warns). isEntry is the predicate that the thunks
// consult; the loader passes the same one on every call.
uint64_t reverseAdaptedTarget(const char* symbol, uint64_t target, bool targetIsArm64e, FunctionEntryPredicate isEntry);

// DYLD_DARLING_ARM64E_ADAPTERS: off binds the raw targets, as before the adapters existed. report also warns, once per
// symbol, for every plain function an arm64e image binds that has no row at all (the way to find a callback-taking import
// that the table does not know; a symbol with a row never warns here).
enum class AdapterMode : uint8_t { Off, On, Report };
void setAdapterMode(AdapterMode mode);

// Flushes the instruction cache over the page and makes it read-execute. False when the protection change failed.
// Thunk pages are only ever writable before this and never after it.
bool sealExecutablePage(void* page, size_t length);

// The thunk bytes, exposed so a test can compare them with an assembler. All return the number of words written.
size_t emitAuthThunk(uint32_t* words, uint8_t authMask, uint64_t real);
size_t emitCallThunk(uint32_t* words, const AdapterRow* row, uint64_t real);
size_t emitReverseThunk(uint32_t* words, const ReverseRow* row, uint64_t real);
uint64_t callThunkHelperAddress();

} // namespace darling
} // namespace dyld3

#endif
