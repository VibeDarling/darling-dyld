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
	// result is signed IA, discriminator 0, only when it is that handler (or SIG_DFL, SIG_IGN, SIG_ERR). Any other value
	// is returned as plain code has it, so that a later authenticated call faults instead of running a forged pointer.
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
	uint8_t			blockArg;		// argument number + 1 of a block pointer whose invoke is authenticated, 0 for none
	uint8_t			structArg;		// argument number + 1 of a pointer to a struct whose first word is a signal handler (sigaction), 0 for none
	ReturnFix		ret;
	uint8_t			argCount;		// register arguments up to the last one the row touches; at most 8 (a call thunk takes no FP or stack arguments)
	AdapterStatus	status;
	const char*		evidence;		// the probe check or the reason; never empty
};

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
// The caller has checked that the importer is arm64e. Callers hold dyld's lock.
uint64_t adaptedTarget(const char* symbol, uint64_t target, bool targetIsArm64e);

// DYLD_DARLING_ARM64E_ADAPTERS=off: bind the raw targets, as before the adapters existed.
void setAdaptersEnabled(bool enabled);

// Flushes the instruction cache over the page and makes it read-execute. False when the protection change failed.
// Thunk pages are only ever writable before this and never after it.
bool sealExecutablePage(void* page, size_t length);

// The thunk bytes, exposed so a test can compare them with an assembler. Both return the number of words written.
size_t emitAuthThunk(uint32_t* words, uint8_t authMask, uint64_t real);

} // namespace darling
} // namespace dyld3

#endif
