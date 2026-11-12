// The values of <mach/machine.h> and <mach-o/loader.h> that the extracted code uses, shared by the host and the
// ptrauth_calls unit of tests/check-tlv-thunk-signing.rb.
#include <stdint.h>

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
// test-only flag bit the image kind loop sets on a synthetic image that declares itself a cache-v2 image
#define TLV_TEST_CACHE_V2 0x80000000
// the layout of struct mach_header_64, segment_command_64 and section_64
struct mach_header { uint32_t magic; int32_t cputype; int32_t cpusubtype; uint32_t filetype, ncmds, sizeofcmds, flags, reserved; };
typedef struct mach_header macho_header;
struct load_command { uint32_t cmd, cmdsize; };
typedef struct { uint32_t cmd, cmdsize; char segname[16]; uint64_t vmaddr, vmsize, fileoff, filesize; int32_t maxprot, initprot; uint32_t nsects, flags; } macho_segment_command;
typedef struct { char sectname[16], segname[16]; uint64_t addr, size; uint32_t offset, align, reloff, nreloc, flags, reserved1, reserved2, reserved3; } macho_section;
typedef struct TLVDescriptor TLVDescriptor;
struct TLVDescriptor { void* (*thunk)(struct TLVDescriptor*); unsigned long key, offset; };
