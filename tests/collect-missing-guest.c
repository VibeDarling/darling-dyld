// Guest fixture for DARLING_DYLD_COLLECT_MISSING. The program is linked against collect-missing-full.c's library and run
// against collect-missing-stub.c's (same install name, same versions), so it imports three functions and one data symbol that
// the library at run time does not export. The data symbol is a non-lazy bind and the functions are lazy binds (plain arm64):
//   mode off: dyld ends the launch at the missing data symbol ("Symbol not found: _kCollectMissingData"), as before.
//   mode on:  all four are recorded, main runs, and the argument picks what it then does:
//             present  call the library function that exists: returns normally
//             a|b|c    call a missing function: halts with "a collected missing symbol was called: <name>"
//             data     read the missing data symbol: faults on the guard (SIGSEGV)
//             plugin   dlopen a bundle whose import of collectMissingHostFunction binds to this program (ordinal -1), then
//                      call it (HOST_FULL builds define the function; the run-time program does not)
//   The same program linked -flat_namespace (collect-missing-flat) records its imports with ordinal -2.
#include <dlfcn.h>
#include <stdio.h>
#include <string.h>

extern int collectMissingPresent(void);
extern int collectMissingFunctionA(void);
extern int collectMissingFunctionB(void);
extern int collectMissingFunctionC(void);
extern long kCollectMissingData;
#ifdef HOST_FULL
__attribute__((used)) int collectMissingHostFunction(void) { return 5; }
#endif

int main(int argc, char** argv)
{
	setbuf(stdout, NULL);
	const char* what = (argc > 1) ? argv[1] : "present";
	printf("REACHED main %s\n", what);
	if ( strcmp(what, "present") == 0 )
		return (collectMissingPresent() == 7) ? 0 : 3;
	if ( strcmp(what, "a") == 0 )
		return collectMissingFunctionA();
	if ( strcmp(what, "b") == 0 )
		return collectMissingFunctionB();
	if ( strcmp(what, "c") == 0 )
		return collectMissingFunctionC();
	if ( strcmp(what, "data") == 0 )
		return (int)kCollectMissingData;
	if ( strcmp(what, "plugin") == 0 ) {
		void* bundle = dlopen("@executable_path/collect-missing-plugin.bundle", RTLD_NOW);
		printf(bundle ? "plugin loaded\n" : "plugin not loaded\n");
		int (*entry)(void) = bundle ? (int (*)(void))dlsym(bundle, "pluginEntry") : NULL;
		return entry ? entry() : 6;
	}
	return 4;
}
