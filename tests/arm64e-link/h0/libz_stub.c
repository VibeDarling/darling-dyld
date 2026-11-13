// LINK-ONLY STUB. NEVER INSTALL IT, LOAD IT OR RUN IT.
// It exists so ld64 can resolve symbols and record install name and versions
// for an executable under test. The real libz comes from the dyld shared cache
// at run time; a copy of this file on disk would shadow it. Every function
// traps (brk) so an accidental call fails loudly.
// The same template builds the libSystem stub (STUB_SYMBOLS differs).
#define STUB(name) void name(void) { __builtin_trap(); }
#include STUB_SYMBOLS
