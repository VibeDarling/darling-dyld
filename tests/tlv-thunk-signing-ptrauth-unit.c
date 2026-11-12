// The ptrauth_calls half of tests/check-tlv-thunk-signing.rb: the extracted tlv_thunk_for_image built for a target whose
// compiler signs every function pointer (clang -target aarch64-linux-pauthtest), linked into the plain host driver. The
// host cannot run a ptrauth_calls build as a whole, so this unit exposes only what it checks: what the code stores for an
// image of a given cputype and subtype, and the unsigned address of the tlv_get_addr it points at.
#include <ptrauth.h>
#include <stdbool.h>
#include "tlv-thunk-signing-macho.h"

__attribute__((noinline)) void* tlv_get_addr(TLVDescriptor* d) { return (char*)d + 0x40; }

#include <extracted.inc>

void* unit_thunk_for_image(int32_t cputype, int32_t cpusubtype)
{
	struct mach_header h = {0xfeedfacf, cputype, cpusubtype, 0, 0, 0, 0, 0};
	return tlv_thunk_for_image(&h);
}

uint64_t unit_raw_tlv_get_addr(void)
{
	return (uint64_t)ptrauth_strip((void*)tlv_get_addr, ptrauth_key_function_pointer);
}
