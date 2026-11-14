// DARLING collect-missing mode (DARLING_DYLD_COLLECT_MISSING=<file>): instead of aborting at the first unresolved symbol,
// record every one that dyld meets (one line each, appended to the file as it is found) and bind something that fails loudly
// when it is used. A diagnostic for finding every name a set of apps needs at once; never on unless the variable is set.
#ifndef DarlingCollectMissing_h
#define DarlingCollectMissing_h

#include <stddef.h>
#include <stdint.h>

namespace dyld3 {
namespace darling {

enum class BindKind : uint8_t {
	Unknown,	// chained fixups carry no lazy bit
	Lazy,
	NonLazy
};

struct MissingImport {
	const char*	referrer;		// install name of the importing dylib, or the path of an app image
	const char*	symbol;			// Mach-O name, leading underscore included
	const char*	expectedIn;		// install name of the two-level library, or "flat" / "weak-lookup"
	long		ordinal;		// library ordinal of the bind
	bool		weak;			// weak import: dyld binds 0 for it with or without this mode
	BindKind	kind;
};

// Turns the mode on; `outputPath` is the file the lines are appended to. Called once, while the environment is read.
void collectMissingEnable(const char* outputPath);
bool collectMissingEnabled();

// Records one unresolved import and returns the address to bind: 0 for a weak import, else a thunk that halts with
// "a collected missing symbol was called: <name> ..." or, for a name that looks like data, an address in a region with no access.
uintptr_t collectMissingBind(const MissingImport& import);

// The name test that picks the guard region (a bind records no type, so this is a guess; see DESIGN notes in the .cpp).
bool collectMissingNameLooksLikeData(const char* symbol);

} // namespace darling
} // namespace dyld3

#endif
