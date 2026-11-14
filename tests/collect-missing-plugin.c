// A bundle linked with -bundle_loader against the full program: its import of collectMissingHostFunction is a bind with the
// main-executable ordinal (-1), which the run-time program (collect-missing-guest.c built without HOST_FULL) does not define.
extern int collectMissingHostFunction(void);
int pluginEntry(void) { return collectMissingHostFunction(); }
