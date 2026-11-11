// DARLING: the dyld4 objc callback interface over a loader that speaks the old (v1) callback shapes.
//
// libdyld builds dyld3/APIs.cpp and the dyld executable builds src/dyldAPIs.cpp, and neither links the
// other's object, so the translation from v2-v4 callbacks to the old-shape ones lives here, text shared
// by both. Each translation unit holds its own state() and registers the old-shape thunks with its own
// loader (AllImages::setObjCNotifiers, dyld::registerObjCNotifiers); whichever loader is driving calls
// the thunks, the other's copy is never used.
//
// The v4 callback pointers arrive ptrauth-signed by the arm64e libobjc with key IB, address diversity
// and a string discriminator (open-source dyld_priv.h: `__ptrauth(ptrauth_key_process_dependent_code, 1,
// ptrauth_string_discriminator("_dyld_objc_notify_mapped4"))`, and likewise for init3, unmapped2 and
// patch_class2). This tree is plain arm64, where the assembler refuses the PAC mnemonics and
// `__has_feature(ptrauth_calls)` is false, so the signatures are read, authenticated and stripped here by
// hand, and the block this loader hands libobjc is signed by hand as well.
#ifndef DarlingObjCCallbacks_h
#define DarlingObjCCallbacks_h

#include <stddef.h>
#include <stdint.h>
#include <mach-o/dyld_priv.h>

// loader.h carries this when it is the SDK's; dyld2.cpp keeps the same fallback for MH_HAS_OBJC.
#ifndef MH_DYLIB_IN_CACHE
  #define MH_DYLIB_IN_CACHE 0x80000000
#endif

namespace dyld3 {
namespace darling {

#if defined(__aarch64__) || defined(__arm64__)

// The instruction words of the mnemonics this target refuses, as DarlingArm64eAdapters.cpp:45-63 records
// them (assembled for arm64e-apple-darwin, read back with llvm-objdump). They are HINTs on a CPU without
// pointer authentication, where a signature is already a plain pointer.
static inline uint64_t stripSignedPointer(uint64_t pointer)
{
	uint64_t stripped;
	__asm__("mov x17, %1\n\t.inst 0xDAC143F1\n\tmov %0, x17" : "=r"(stripped) : "r"(pointer) : "x17");	// xpaci x17
	return stripped;
}

// AUTIB (key IB) with the modifier in a register, for a v4 callback field.
static inline uint64_t authenticateCallback(uint64_t pointer, uint64_t modifier)
{
	uint64_t result;
	__asm__("mov x17, %1\n\tmov x16, %2\n\t.inst 0xDAC11611\n\tmov %0, x17" : "=r"(result) : "r"(pointer), "r"(modifier) : "x16", "x17");	// autib x17, x16
	return result;
}

// AUTIA (key IA), the key libclosure uses for a block's invoke field.
static inline uint64_t authenticateBlockInvoke(uint64_t invoke, uint64_t fieldAddress)
{
	uint64_t result;
	__asm__("mov x17, %1\n\tmov x16, %2\n\t.inst 0xDAC11211\n\tmov %0, x17" : "=r"(result) : "r"(invoke), "r"(fieldAddress) : "x16", "x17");	// autia x17, x16
	return result;
}

// PACIA (key IA), address-diversified against the invoke field, the shape of libclosure's
// _Block_set_function_pointer.
static inline uint64_t signBlockInvoke(uint64_t invoke, uint64_t fieldAddress)
{
	uint64_t result;
	__asm__("mov x17, %1\n\tmov x16, %2\n\t.inst 0xDAC10211\n\tmov %0, x17" : "=r"(result) : "r"(invoke), "r"(fieldAddress) : "x16", "x17");	// pacia x17, x16
	return result;
}

#else

// No pointer authentication on this CPU: nothing signs, nothing authenticates.
static inline uint64_t stripSignedPointer(uint64_t pointer) { return pointer; }
static inline uint64_t authenticateCallback(uint64_t pointer, uint64_t) { return pointer; }
static inline uint64_t authenticateBlockInvoke(uint64_t invoke, uint64_t) { return invoke; }
static inline uint64_t signBlockInvoke(uint64_t invoke, uint64_t) { return invoke; }

#endif

// An authentication that succeeded leaves a canonical pointer, so stripping it changes nothing; a failed
// one leaves the error code in the top bits, which xpaci keeps. This is the check clang emits.
static inline bool signatureAuthenticated(uint64_t value)
{
	return value == stripSignedPointer(value);
}

// A v4 callback field's modifier: the field's address with the string discriminator in the top 16 bits,
// which is what clang emits (`mov x16, &field; movk x16, #disc, lsl #48`). Values from our own compiler,
// one per field.
static inline uint64_t callbackModifier(uint64_t fieldAddress, uint16_t discriminator)
{
	return (fieldAddress & 0x0000FFFFFFFFFFFFULL) | ((uint64_t)discriminator << 48);
}

static const uint16_t kMappedDiscriminator    = 0xd15a;	// "_dyld_objc_notify_mapped4"
static const uint16_t kInitDiscriminator      = 0x4b12;	// "_dyld_objc_notify_init3"
static const uint16_t kUnmappedDiscriminator  = 0x4840;	// "_dyld_objc_notify_unmapped2"
static const uint16_t kPatchDiscriminator     = 0x318c;	// "_dyld_objc_notify_patch_class2"

// The block libobjc is handed with a v3/v4 mapped call and calls back when it remaps a class or protocol
// reference. libobjc only loads `invoke` and never copies the block, so the struct is built by hand
// (darlingObjCCallbacks notes: isa null, flags 0). `invoke` is signed against its own field address.
struct ObjCBlockLayout {
	void*		isa;
	int32_t		flags;
	int32_t		reserved;
	uint64_t	invoke;
	const void*	descriptor;
};
static_assert(sizeof(ObjCBlockLayout) == 32, "block literal layout");

typedef void (*ObjCBlockInvoke)(void* block, uint32_t objcImageIndex);

// One of libobjc's enumeration blocks (_dyld_for_each_objc_class/_protocol). arm64e libclosure signs its
// invoke, so a plain branch through it reaches a non-canonical address. Strip the signature and call
// through the caller's block, whose captures the invoke still finds where it left them; nothing is
// copied or released, so the block runtime's helpers are never reached. `isa` is never read.
typedef void (*ObjCEnumerationInvoke)(const ObjCBlockLayout* block, void* objectPtr, bool isLoaded, bool* stop);

static inline void callObjCEnumerationBlock(const void* blockPtr, void* objectPtr, bool isLoaded, bool* stop)
{
	const ObjCBlockLayout* block = (const ObjCBlockLayout*)blockPtr;
	((ObjCEnumerationInvoke)(uintptr_t)stripSignedPointer(block->invoke))(block, objectPtr, isLoaded, stop);
}

struct ObjCCallbackState {
	const char*						error		= nullptr;	// why registration failed, for the caller to halt with
	uintptr_t						version		= 0;
	_dyld_objc_notify_mapped2		mapped2		= nullptr;
	_dyld_objc_notify_mapped3		mapped3		= nullptr;
	_dyld_objc_notify_init2			init2		= nullptr;
	_dyld_objc_notify_unmapped		unmapped	= nullptr;
	_dyld_objc_notify_patch_class	patches		= nullptr;
	ObjCBlockInvoke					markImageMutableInvoke = nullptr;
	ObjCBlockLayout					markImageMutable = { nullptr, 0, 0, 0, nullptr };

	// Stores the callbacks the struct names. Returns false and sets `error` for a version other than 2-4
	// and for a v4 field that does not authenticate (a zeroed or forged signature). Versions 2 and 3 are
	// unsigned and are stored as they arrive.
	bool registerCallbacks(const struct _dyld_objc_callbacks* callbacks)
	{
		if ( callbacks == nullptr ) {
			error = "dyld: _dyld_objc_register_callbacks() got a null callbacks struct\n";
			return false;
		}
		const uintptr_t callbacksVersion = callbacks->version;
		if ( callbacksVersion == 2 ) {
			const struct _dyld_objc_callbacks_v2* v2 = (const struct _dyld_objc_callbacks_v2*)callbacks;
			mapped2  = v2->mapped;
			init2    = v2->init;
			unmapped = v2->unmapped;
			patches  = v2->patches;
		}
		else if ( callbacksVersion == 3 ) {
			const struct _dyld_objc_callbacks_v3* v3 = (const struct _dyld_objc_callbacks_v3*)callbacks;
			mapped3  = v3->mapped;
			init2    = v3->init;
			unmapped = v3->unmapped;
			patches  = v3->patches;
		}
		else if ( callbacksVersion == 4 ) {
			const struct _dyld_objc_callbacks_v4* v4 = (const struct _dyld_objc_callbacks_v4*)callbacks;
			uint64_t fieldMapped = 0, fieldInit = 0, fieldUnmapped = 0, fieldPatches = 0;
			if ( !authenticateField(reinterpret_cast<uintptr_t>(v4->mapped), &v4->mapped, kMappedDiscriminator, fieldMapped)
			  || !authenticateField(reinterpret_cast<uintptr_t>(v4->init), &v4->init, kInitDiscriminator, fieldInit)
			  || !authenticateField(reinterpret_cast<uintptr_t>(v4->unmapped), &v4->unmapped, kUnmappedDiscriminator, fieldUnmapped)
			  || !authenticateField(reinterpret_cast<uintptr_t>(v4->patches), &v4->patches, kPatchDiscriminator, fieldPatches) ) {
				error = "dyld: _dyld_objc_register_callbacks() v4 callback did not authenticate\n";
				return false;
			}
			mapped3  = reinterpret_cast<_dyld_objc_notify_mapped3>(fieldMapped);
			init2    = reinterpret_cast<_dyld_objc_notify_init2>(fieldInit);
			unmapped = reinterpret_cast<_dyld_objc_notify_unmapped>(fieldUnmapped);
			patches  = reinterpret_cast<_dyld_objc_notify_patch_class>(fieldPatches);
		}
		else {
			error = "dyld: _dyld_objc_register_callbacks() got an unsupported version\n";
			return false;
		}
		version = callbacksVersion;
		return true;
	}

	// Hands the batch to the registered mapped callback, as _dyld_objc_notify_mapped_info entries whose
	// refs-optimized bit is set for images the shared cache serves: libobjc takes its preoptimized class
	// path only then, and the cache's own tables are what _dyld_for_each_objc_class answers from.
	// Large batches go out in chunks, which the interface allows (a dlopen notify is a batch of one).
	void notifyMapped(unsigned count, const char* const* paths, const struct mach_header* const* mhs)
	{
		static const unsigned kMaxBatch = 64;
		if ( count == 0 )
			return;
		// The old notifiers tolerate a callback the runtime did not provide; so does this.
		if ( (version >= 3) ? (mapped3 == nullptr) : (mapped2 == nullptr) )
			return;
		if ( version >= 3 )
			markImageMutable.invoke = signBlockInvoke((uint64_t)(uintptr_t)markImageMutableInvoke, (uint64_t)(uintptr_t)&markImageMutable.invoke);
		for ( unsigned base = 0; base < count; base += kMaxBatch ) {
			const unsigned batch = (count - base < kMaxBatch) ? count - base : kMaxBatch;
			_dyld_objc_notify_mapped_info infos[kMaxBatch];
			for ( unsigned i = 0; i < batch; ++i ) {
				infos[i].mh = mhs[base + i];
				infos[i].path = paths[base + i];
				infos[i].sectionLocationMetadata = nullptr;
				infos[i].dyldObjCRefsOptimized = (mhs[base + i]->flags & MH_DYLIB_IN_CACHE) ? 1 : 0;
				infos[i].flags = 0;
			}
			if ( version >= 3 )
				mapped3(batch, infos, (_dyld_objc_mark_image_mutable)&markImageMutable);
			else
				mapped2(batch, infos);
		}
	}

	void notifyInit(const char* path, const struct mach_header* mh) const
	{
		if ( init2 == nullptr )
			return;
		_dyld_objc_notify_mapped_info info;
		info.mh = mh;
		info.path = path;
		info.sectionLocationMetadata = nullptr;
		info.dyldObjCRefsOptimized = (mh->flags & MH_DYLIB_IN_CACHE) ? 1 : 0;
		info.flags = 0;
		init2(&info);
	}

	void notifyUnmapped(const char* path, const struct mach_header* mh) const
	{
		if ( unmapped != nullptr )
			unmapped(path, mh);
	}

private:
	// Authenticates one v4 field and stores its plain value in `stored`. An all-zero field is null, which
	// stands as null: a callback the runtime did not provide is not a signature failure.
	bool authenticateField(uintptr_t signedValue, const volatile void* field, uint16_t discriminator, uint64_t& stored)
	{
		if ( signedValue == 0 ) {
			stored = 0;
			return true;
		}
		const uint64_t modifier = callbackModifier(reinterpret_cast<uintptr_t>(field), discriminator);
		const uint64_t authenticated = authenticateCallback(signedValue, modifier);
		if ( !signatureAuthenticated(authenticated) )
			return false;
		stored = stripSignedPointer(authenticated);
		return true;
	}
};

// The one state of this translation unit.
static inline ObjCCallbackState& objcCallbackState()
{
	static ObjCCallbackState state;
	return state;
}

// The old shapes this translation unit registers with its loader; they forward to the state above.
static void objcMappedThunk(unsigned count, const char* const paths[], const struct mach_header* const mhs[])
{
	objcCallbackState().notifyMapped(count, paths, mhs);
}

static void objcInitThunk(const char* path, const struct mach_header* mh)
{
	objcCallbackState().notifyInit(path, mh);
}

static void objcUnmappedThunk(const char* path, const struct mach_header* mh)
{
	objcCallbackState().notifyUnmapped(path, mh);
}

} // namespace darling
} // namespace dyld3

#endif
