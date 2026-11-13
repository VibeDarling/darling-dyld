// Native driver of tests/check-tlv-thunk-signing.rb: runs the code extracted from src/threadLocalVariables.c on an ARM64
// Linux host with pointer authentication. Not a Mach-O loader: the image is a synthetic one in memory.
// Exit 0 when every check passed, 1 when one failed, 77 when this host cannot sign pointers.
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <signal.h>
#include <sys/auxv.h>
#include <sys/wait.h>
#include <unistd.h>

// the values of <mach/machine.h> and <mach-o/loader.h> that the extracted code uses
#define CPU_TYPE_X86_64 0x01000007
#define CPU_TYPE_ARM64 0x0100000c
#define CPU_TYPE_ARM64_32 0x0200000c
#define CPU_SUBTYPE_MASK 0xff000000
#define CPU_SUBTYPE_PTRAUTH_ABI 0x80000000
#define CPU_SUBTYPE_ARM64_ALL 0
#define CPU_SUBTYPE_ARM64_V8 1
#define CPU_SUBTYPE_ARM64E 2
#define CPU_SUBTYPE_X86_64_ALL 3
#define LC_SEGMENT_COMMAND 0x19
#define SECTION_TYPE 0xff
#define S_THREAD_LOCAL_VARIABLES 0x13
#define S_THREAD_LOCAL_REGULAR 0x11
#define S_THREAD_LOCAL_ZEROFILL 0x12
// the layout of struct mach_header_64, segment_command_64 and section_64
struct mach_header { uint32_t magic; int32_t cputype; int32_t cpusubtype; uint32_t filetype, ncmds, sizeofcmds, flags, reserved; };
typedef struct mach_header macho_header;
struct load_command { uint32_t cmd, cmdsize; };
typedef struct { uint32_t cmd, cmdsize; char segname[16]; uint64_t vmaddr, vmsize, fileoff, filesize; int32_t maxprot, initprot; uint32_t nsects, flags; } macho_segment_command;
typedef struct { char sectname[16], segname[16]; uint64_t addr, size; uint32_t offset, align, reloff, nreloc, flags, reserved1, reserved2, reserved3; } macho_section;
typedef struct TLVDescriptor TLVDescriptor;
struct TLVDescriptor { void* (*thunk)(struct TLVDescriptor*); unsigned long key, offset; };

#define CHECK(condition) do { if ( !(condition) ) { printf("FAIL line %d: %s\n", __LINE__, #condition); ++failures; } } while (0)
static int failures;

__attribute__((noinline)) void* tlv_get_addr(TLVDescriptor* d) { return (char*)d + 0x40; }   // what a plain call can tell apart
static void tlv_free(void* storage) { (void)storage; }
static bool tlv_image_uses_cache_v2(const struct mach_header* mh) { (void)mh; return false; }
static void tlv_set_key_for_image(const struct mach_header* mh, pthread_key_t key) { (void)mh; (void)key; }

#include "extracted.inc"

__attribute__((target("arch=armv8.3-a"))) static uint64_t signIA(uint64_t p, uint64_t m) { __asm__("pacia %0, %1" : "+r"(p) : "r"(m)); return p; }
__attribute__((target("arch=armv8.3-a"))) static uint64_t signIB(uint64_t p, uint64_t m) { __asm__("pacib %0, %1" : "+r"(p) : "r"(m)); return p; }
__attribute__((target("arch=armv8.3-a"))) static uint64_t signDA(uint64_t p, uint64_t m) { __asm__("pacda %0, %1" : "+r"(p) : "r"(m)); return p; }
__attribute__((target("arch=armv8.3-a"))) static uint64_t strip(uint64_t p) { __asm__("xpaci %0" : "+r"(p)); return p; }

// The call an arm64e compiler emits at a thread-local access (read from an arm64e executable that ld64 linked from
// compiler output): ldr x8, [descriptor]; mov x0, descriptor; blraaz x8.
__attribute__((target("arch=armv8.3-a"))) static void* callLikeArm64e(const TLVDescriptor* d)
{
	void* result;
	__asm__ volatile("ldr x8, [%1]\n\tmov x0, %1\n\tblraaz x8\n\tmov %0, x0" : "=r"(result) : "r"(d)
		: "x0", "x1", "x2", "x3", "x4", "x5", "x6", "x7", "x8", "x9", "x10", "x11", "x12", "x13", "x14", "x15", "x16", "x17", "x30", "memory", "cc");
	return result;
}
// the call a plain image makes
static void* callPlain(const TLVDescriptor* d) { return d->thunk((TLVDescriptor*)d); }

// 0: the call returned tlv_get_addr's result, 1: it returned something else, 2: the process died of a signal
static int outcome(void* (*call)(const TLVDescriptor*), const TLVDescriptor* d)
{
	fflush(stdout);
	const pid_t child = fork();
	if ( child == 0 ) {
		signal(SIGSEGV, SIG_DFL); signal(SIGBUS, SIG_DFL); signal(SIGILL, SIG_DFL);
		_exit(call(d) == (char*)d + 0x40 ? 0 : 1);
	}
	int status = 0;
	waitpid(child, &status, 0);
	return WIFSIGNALED(status) ? 2 : WEXITSTATUS(status);
}

static struct mach_header headerFor(int32_t cputype, int32_t cpusubtype) { struct mach_header h = {0xfeedfacf, cputype, cpusubtype, 0, 0, 0, 0, 0}; return h; }
static uint64_t thunkFor(int32_t cputype, int32_t cpusubtype) { struct mach_header h = headerFor(cputype, cpusubtype); return (uint64_t)tlv_thunk_for_image(&h); }

// A signature that equals the right one by luck (1 in 2^PAC bits per wrong scheme) would make a negative control pass
// vacuously, and keys are new for every exec: so pick a process whose keys keep every control meaningful.
static bool controlsAreMeaningful(void)
{
	const uint64_t raw = (uint64_t)tlv_get_addr;
	const uint64_t right = signIA(raw, 0);
	return right != raw && signIB(raw, 0) != right && signDA(raw, 0) != right && signIA(raw, 1) != right && signIA(raw, (uint64_t)&right) != right;
}

int main(int argc, char** argv)
{
	if ( !(getauxval(AT_HWCAP) & (1UL << 30)) ) { puts("this host has no pointer authentication"); return 77; }
	if ( !controlsAreMeaningful() ) {
		const char* retries = getenv("TLV_TEST_RETRIES");
		const int n = retries ? atoi(retries) : 0;
		if ( n >= 64 ) { puts("no process with usable keys in 64 tries"); return 1; }
		char text[16]; snprintf(text, sizeof text, "%d", n + 1);
		setenv("TLV_TEST_RETRIES", text, 1);
		execv("/proc/self/exe", argv);
		perror("execv"); return 1;
	}
	(void)argc;
	const uint64_t raw = (uint64_t)tlv_get_addr;
	const uint64_t right = signIA(raw, 0);
	TLVDescriptor d = { 0, 0, 0 };

	// The oracle itself: the arm64e call sequence accepts IA with discriminator 0 and nothing else.
	d.thunk = (void* (*)(TLVDescriptor*))right;
	CHECK(outcome(callLikeArm64e, &d) == 0);
	d.thunk = (void* (*)(TLVDescriptor*))raw;
	CHECK(outcome(callLikeArm64e, &d) == 2);									// unsigned: what libdyld stored before
	d.thunk = (void* (*)(TLVDescriptor*))signIB(raw, 0);
	CHECK(outcome(callLikeArm64e, &d) == 2);
	d.thunk = (void* (*)(TLVDescriptor*))signDA(raw, 0);
	CHECK(outcome(callLikeArm64e, &d) == 2);
	d.thunk = (void* (*)(TLVDescriptor*))signIA(raw, 1);
	CHECK(outcome(callLikeArm64e, &d) == 2);
	d.thunk = (void* (*)(TLVDescriptor*))signIA(raw, (uint64_t)&d.thunk);		// address diversity
	CHECK(outcome(callLikeArm64e, &d) == 2);
	d.thunk = (void* (*)(TLVDescriptor*))raw;
	CHECK(outcome(callPlain, &d) == 0);

	// tlv_thunk_for_image
#ifdef __arm64__
	const uint64_t signedForArm64e = right;
#else
	const uint64_t signedForArm64e = raw;											// built for another architecture: nothing to sign
#endif
	CHECK(thunkFor(CPU_TYPE_ARM64, CPU_SUBTYPE_ARM64E) == signedForArm64e);
	CHECK(thunkFor(CPU_TYPE_ARM64, CPU_SUBTYPE_ARM64E | CPU_SUBTYPE_PTRAUTH_ABI) == signedForArm64e);
	CHECK(thunkFor(CPU_TYPE_ARM64, CPU_SUBTYPE_ARM64E | 0x01000000) == signedForArm64e);
	CHECK(strip(thunkFor(CPU_TYPE_ARM64, CPU_SUBTYPE_ARM64E)) == raw);
	CHECK(thunkFor(CPU_TYPE_ARM64, CPU_SUBTYPE_ARM64_ALL) == raw);
	CHECK(thunkFor(CPU_TYPE_ARM64, CPU_SUBTYPE_ARM64_V8) == raw);
	CHECK(thunkFor(CPU_TYPE_ARM64, CPU_SUBTYPE_ARM64_ALL | CPU_SUBTYPE_PTRAUTH_ABI) == raw);
	CHECK(thunkFor(CPU_TYPE_X86_64, CPU_SUBTYPE_X86_64_ALL) == raw);
	CHECK(thunkFor(CPU_TYPE_X86_64, CPU_SUBTYPE_ARM64E) == raw);					// the same subtype number under another cputype
	CHECK(thunkFor(CPU_TYPE_ARM64_32, CPU_SUBTYPE_ARM64E) == raw);
	CHECK(thunkFor(0, 0) == raw);

	// A synthetic image with two thread-local descriptors reaches the stores of tlv_initialize_descriptors: each image kind
	// gets the thunk its own call sequence accepts, in every descriptor.
	struct { struct mach_header h; macho_segment_command seg; macho_section sect; TLVDescriptor vars[2]; } image;
	const struct { int32_t cputype, cpusubtype; bool arm64e; } kinds[] = {
		{ CPU_TYPE_ARM64, CPU_SUBTYPE_ARM64E, true },
		{ CPU_TYPE_ARM64, CPU_SUBTYPE_ARM64E | CPU_SUBTYPE_PTRAUTH_ABI, true },
		{ CPU_TYPE_ARM64, CPU_SUBTYPE_ARM64_ALL, false },
		{ CPU_TYPE_X86_64, CPU_SUBTYPE_X86_64_ALL, false },
	};
	for (unsigned k = 0; k != sizeof kinds / sizeof kinds[0]; ++k) {
		memset(&image, 0, sizeof image);
		image.vars[0].key = image.vars[1].key = ~0UL;
		image.h = headerFor(kinds[k].cputype, kinds[k].cpusubtype);
		image.h.ncmds = 1; image.h.sizeofcmds = sizeof image.seg + sizeof image.sect;
		image.seg.cmd = LC_SEGMENT_COMMAND; image.seg.cmdsize = sizeof image.seg + sizeof image.sect; image.seg.nsects = 1;
		image.seg.vmaddr = 0; image.seg.filesize = sizeof image;
		image.sect.flags = S_THREAD_LOCAL_VARIABLES;
		image.sect.addr = (uint64_t)&image.vars[0] - (uint64_t)&image;			// mh minus vmaddr is the slide
		image.sect.size = sizeof image.vars;
		tlv_initialize_descriptors(&image.h);
		for (int i = 0; i != 2; ++i) {
			CHECK(image.vars[i].key != ~0UL);
			CHECK((uint64_t)image.vars[i].thunk == (kinds[k].arm64e ? signedForArm64e : raw));
			if ( kinds[k].arm64e && signedForArm64e != raw )
				CHECK(outcome(callLikeArm64e, &image.vars[i]) == 0);
			else
				CHECK(outcome(callPlain, &image.vars[i]) == 0);
		}
	}
	printf(failures ? "RESULT failed (%d)\n" : "RESULT ok\n", failures);
	return failures != 0;
}
