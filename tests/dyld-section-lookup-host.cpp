// Native driver of tests/dyld-section-lookup-signing.rb: runs setDyldFuncLookup and what it stores, extracted from
// src/ImageLoaderMachO.cpp, on an ARM64 Linux host with pointer authentication. The oracle is what an arm64e libdyld does with the
// __dyld section (ldr x8, [slot + 8]; blraaz x8 for the lookup, then autiza on the address it returns), executed against what
// the extracted code stored.
// Exit 0 when every check passed, 1 when one failed, 77 when this host cannot sign pointers.
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <stddef.h>
#include <signal.h>
#include <sys/auxv.h>
#include <sys/wait.h>
#include <unistd.h>

struct macho_header { uint32_t magic; int32_t cputype; int32_t cpusubtype; uint32_t filetype, ncmds, sizeofcmds, flags, reserved; };
#include "DarlingArm64eAdapters.h"

struct ProgramVars { const void* mh; int* NXArgcPtr; const char*** NXArgvPtr; const char*** environPtr; const char** __prognamePtr; };

static void* fakeImplementation(void) { return nullptr; }
extern "C" int _dyld_func_lookup(const char* name, void** address)
{
	if ( name[0] == 'k' ) {
		*address = (void*)&fakeImplementation;
		return 1;
	}
	*address = nullptr;
	return 0;
}

#include "extracted.inc"

#define CHECK(condition) do { if ( !(condition) ) { printf("FAIL line %d: %s\n", __LINE__, #condition); ++failures; } } while (0)
static int failures;

__attribute__((target("arch=armv8.3-a"))) static uint64_t signIA(uint64_t p, uint64_t m) { __asm__("pacia %0, %1" : "+r"(p) : "r"(m)); return p; }
__attribute__((target("arch=armv8.3-a"))) static uint64_t authIA(uint64_t p, uint64_t m) { __asm__("autia %0, %1" : "+r"(p) : "r"(m)); return p; }
__attribute__((target("arch=armv8.3-a"))) static uint64_t strip(uint64_t p) { __asm__("xpaci %0" : "+r"(p)); return p; }

// libdyld's __dyld_func_lookup on arm64e: the pointer from the section is called with blraaz
__attribute__((target("arch=armv8.3-a"))) static int callLikeArm64eLibdyld(void* lookup, const char* name, void** address)
{
	register uint64_t result __asm__("x0") = (uint64_t)name;
	register void** arg1 __asm__("x1") = address;
	register void* fn __asm__("x8") = lookup;
	__asm__ volatile("blraaz x8" : "+r"(result), "+r"(arg1), "+r"(fn)
		:: "x2", "x3", "x4", "x5", "x6", "x7", "x9", "x10", "x11", "x12", "x13", "x14", "x15", "x16", "x17", "x30", "memory", "cc");
	return (int)result;
}
// what it does with the address: autiza (the oracle; a failed authentication kills the process on this host)
__attribute__((target("arch=armv8.3-a"))) static uint64_t autiza(uint64_t p) { __asm__ volatile("autiza %0" : "+r"(p)); return p; }

// 0: the sequence found the implementation and authenticated it, 1: it ran and got something else, 2: the process died of a signal
static int arm64eLookup(void* lookup, const char* name, bool expectFound)
{
	fflush(stdout);
	const pid_t child = fork();
	if ( child == 0 ) {
		signal(SIGSEGV, SIG_DFL); signal(SIGBUS, SIG_DFL); signal(SIGILL, SIG_DFL); signal(SIGTRAP, SIG_DFL);
		void* address = (void*)0x77;
		const int found = callLikeArm64eLibdyld(lookup, name, &address);
		if ( !expectFound )
			_exit((found == 0 && address == nullptr) ? 0 : 1);
		_exit((found == 1 && autiza((uint64_t)address) == (uint64_t)&fakeImplementation) ? 0 : 1);
	}
	int status = 0;
	waitpid(child, &status, 0);
	return WIFSIGNALED(status) ? 2 : WEXITSTATUS(status);
}
static void* storedFor(int32_t cputype, int32_t cpusubtype, uint64_t sectionSize = sizeof(DATAdyld))
{
	macho_header mh = { 0xfeedfacf, cputype, cpusubtype, 0, 0, 0, 0, 0 };
	DATAdyld dd = {};
	setDyldFuncLookup(&dd, sectionSize, &mh);
	return dd.dyldFuncLookup;
}

int main()
{
	if ( (getauxval(AT_HWCAP) & (1UL << 30)) == 0 ) {
		printf("SKIP: no pointer authentication\n");
		return 77;
	}
	const uint64_t rawLookup = (uint64_t)&_dyld_func_lookup;
	CHECK(signIA((uint64_t)&fakeImplementation, 0) != (uint64_t)&fakeImplementation);
	CHECK(signIA((uint64_t)&dyldFuncLookupSigned, 0) != (uint64_t)&dyldFuncLookupSigned);

	// every header that an arm64e image can carry: the ptrauth ABI bits live in the flag byte of the subtype
	const int32_t arm64eSubtypes[] = { 2, (int32_t)0x80000002, (int32_t)0x81000002 };
	for ( int32_t subtype : arm64eSubtypes ) {
		void* stored = storedFor(0x0100000c, subtype);
		// the pointer: IA, discriminator 0, to the wrapper
		CHECK((uint64_t)stored == signIA((uint64_t)&dyldFuncLookupSigned, 0));
		CHECK(strip((uint64_t)stored) != rawLookup);
		// the call and the result, as arm64e libdyld does them
		CHECK(arm64eLookup(stored, "known", true) == 0);
		CHECK(arm64eLookup(stored, "unknown", false) == 0);
	}
	// what dyld stored before this fix faults in the call, and a signed pointer to the raw lookup faults in the result
	CHECK(arm64eLookup((void*)rawLookup, "known", true) != 0);
	CHECK(arm64eLookup((void*)signIA(rawLookup, 0), "known", true) != 0);

	// every other image gets the raw function, called with a plain branch, and plain addresses back
	const struct { int32_t cputype, cpusubtype; } others[] = {
		{ 0x0100000c, 0 }, { 0x0100000c, 1 }, { 0x0100000c, (int32_t)0x80000000 }, { 0x0100000c, 3 },
		{ 0x01000007, 2 },	// x86_64 with an arm64e-looking subtype
		{ 0x0200000c, 2 },	// arm64_32
	};
	for ( const auto& o : others ) {
		void* stored = storedFor(o.cputype, o.cpusubtype);
		CHECK((uint64_t)stored == rawLookup);
		void* address = nullptr;
		CHECK(((int (*)(const char*, void**))stored)("known", &address) == 1 && address == (void*)&fakeImplementation);
	}

	// the section must have room for the lookup slot: dyld writes nothing past a short section
	CHECK(storedFor(0x0100000c, 2, offsetof(DATAdyld, dyldFuncLookup)) == nullptr);
	CHECK(storedFor(0x0100000c, 2, offsetof(DATAdyld, dyldFuncLookup) + sizeof(void*)) != nullptr);

	printf(failures == 0 ? "RESULT ok\n" : "RESULT failed\n");
	return failures == 0 ? 0 : 1;
}
