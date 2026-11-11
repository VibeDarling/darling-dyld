// Local declarations of the dyld4 objc surface and the libobjc entry points the L5 test uses.
// No SDK headers: the Darling SDK's header symlinks do not resolve outside its build tree, and the
// in-tree dyld_priv.h only declares these when the loader is built (the test is a guest image that
// imports them from libdyld). Shapes follow include/mach-o/dyld_priv.h and include/objc-shared-cache.h,
// both read at HEAD; the kind order of the section lookup is part of the interface.
#ifndef L5_DECL_H
#define L5_DECL_H

#include "abi_decl.h"   // the POSIX types and calls; abi_decl.h is guarded against a second include

#ifndef __has_feature
#define __has_feature(x) 0
#endif

#ifndef ABI_NATIVE
typedef __UINT64_TYPE__ uint64_t;   // abi_decl.h's guest branch stops at uint32_t

// The loaded-bit reader of check 02 (objc_headeropt_rw_t, include/objc-shared-cache.h): cache content,
// so a stride smaller than an entry reads nothing.
struct l5_header_info_rw {
    uint64_t isLoaded           : 1,
             allClassesRealized : 1,
             next               : 62;
};
struct l5_headeropt_rw {
    uint32_t count;
    uint32_t entsize;
    struct l5_header_info_rw headers[0];
};

// The mach header is only ever used as an address and a flags word here; its layout matters only to
// the split cache's own reader.
struct l5_mach_header {
    uint32_t magic, cputype, cpusubtype, filetype, ncmds, sizeofcmds, flags, reserved;
};

struct l5_dl_info {
    const char *dli_fname;
    void       *dli_fbase;
    const char *dli_sname;
    void       *dli_saddr;
};

extern int dladdr(const void *, struct l5_dl_info *);
extern void *dlopen(const char *, int);
#define L5_RTLD_NOW 2
extern int access(const char *, int);
#define L5_F_OK 0

extern const void *_dyld_get_shared_cache_range(size_t *length);

// dyld4 objc SPIs (F14). The callback interface is version 4: four plain fields that the cache's
// arm64e libobjc fills with ptrauth-signed pointers, which this test signs the same way.
typedef struct _dyld_section_location_info_s *l5_section_location_info_t;

enum l5_section_location_kind {
    l5_section_text_swift5_protos                   = 0x0,
    l5_section_text_swift5_proto,
    l5_section_text_swift5_types,
    l5_section_text_swift5_replace,
    l5_section_text_swift5_replace2,
    l5_section_text_swift5_ac_funcs,
    l5_section_objc_image_info,
    l5_section_data_sel_refs,
    l5_section_data_msg_refs,
    l5_section_data_class_refs,
    l5_section_data_super_refs,
    l5_section_data_protocol_refs,
    l5_section_data_class_list,
    l5_section_data_non_lazy_class_list,
    l5_section_data_stub_list,
    l5_section_data_category_list,
    l5_section_data_category_list2,
    l5_section_data_non_lazy_category_list,
    l5_section_data_protocol_list,
    l5_section_data_objc_fork_ok,
    l5_section_data_raw_isa,
    l5_section_count,
};

struct l5_section_info_result {
    void  *buffer;
    size_t bufferSize;
};

extern uint32_t _dyld_objc_class_count(void);
extern const void *_dyld_for_objc_header_opt_ro(void);
extern void *_dyld_for_objc_header_opt_rw(void);
extern struct l5_section_info_result _dyld_lookup_section_info(const struct l5_mach_header *mh,
                                                               l5_section_location_info_t handle,
                                                               enum l5_section_location_kind kind);
extern const struct l5_mach_header *_dyld_get_dlopen_image_header(void *handle);
struct l5_objc_callbacks {
    uintptr_t version;
};
extern void _dyld_objc_register_callbacks(const struct l5_objc_callbacks *callbacks);

// The v4 callbacks and the batch a mapped notification carries (dyld_priv.h). The refs-optimized bit
// is bit 0 of the word after sectionLocationMetadata; the loader sets it for cache-served images.
struct l5_mapped_info {
    const struct l5_mach_header *mh;
    const char                  *path;
    void                        *sectionLocationMetadata;
    uint32_t                     dyldObjCRefsOptimized : 1,
                                 flags                 : 31;
};
#define L5_REFS_OPTIMIZED(info) ((info)->dyldObjCRefsOptimized != 0)

typedef void (^l5_mark_image_mutable)(uint32_t objcImageIndex);
typedef void (*l5_mapped3)(unsigned count, const struct l5_mapped_info infos[],
                           l5_mark_image_mutable markMutable);
typedef void (*l5_init2)(const struct l5_mapped_info *info);
typedef void (*l5_unmapped)(const char *path, const struct l5_mach_header *mh);
typedef void (*l5_patches)(const struct l5_mach_header *originalMH, void *originalClass,
                           const struct l5_mach_header *replacementMH, const void *replacementClass);

struct l5_objc_callbacks_v4 {
    uintptr_t  version;
    l5_mapped3 mapped;     // signed IB, "_dyld_objc_notify_mapped4"
    l5_init2   init;       // signed IB, "_dyld_objc_notify_init3"
    l5_unmapped unmapped;  // signed IB, "_dyld_objc_notify_unmapped2"
    l5_patches patches;    // signed IB, "_dyld_objc_notify_patch_class2"
};

// The callback fields are ptrauth-signed the way the arm64e libobjc signs them: IB, address
// diversification against the field, and a string discriminator. A plain build stores the plain
// pointer; the loader treats an unsigned field as a signature failure only on an arm64e host, where
// it could not have been produced by this test's compiler anyway.
#if __has_feature(ptrauth_intrinsics)
#define L5_SIGN_CALLBACK(fn, field, name)                                                     \
    ((void *)__builtin_ptrauth_sign_unauthenticated(                                          \
        (void *)(fn), 1 /* ptrauth_key_process_dependent_code, IB */,                         \
        __builtin_ptrauth_blend_discriminator((void *)(field),                                \
                                              __builtin_ptrauth_string_discriminator(name))))
#else
#define L5_SIGN_CALLBACK(fn, field, name) ((void *)(fn))
#endif

// libobjc entry points (objc/runtime.h, libobjc.A's exports). Messages go through objc_msgSend, which
// this file declares with no prototype and every call casts.
typedef void (*l5_imp)(void);
extern void *objc_getClass(const char *name);
extern const char *class_getName(void *cls);
extern void *class_createInstance(void *cls, size_t extraBytes);
extern void *objc_allocateClassPair(void *superclass, const char *name, size_t extraBytes);
extern void objc_registerClassPair(void *cls);
extern signed char class_addMethod(void *cls, void *sel, l5_imp imp, const char *types);
extern void *class_getSuperclass(void *cls);
extern void *sel_registerName(const char *name);
extern void object_dispose(void *obj);
extern void *objc_msgSend(void);

// The commpage gives check 08 its two characterisation reads (F8).
#define L5_COMMPAGE_BASE 0xfffffc000ULL
#define L5_COMMPAGE_D0 0xd0
#define L5_COMMPAGE_D8 0xd8
#endif   // ABI_NATIVE

#endif   // L5_DECL_H
