// The section a _dyld_section_location_kind names, found in an image's own load commands. Shared by the
// dyld and libdyld copies of _dyld_lookup_section_info, which link into different images.
#ifndef __OBJC_SECTION_INFO_H__
#define __OBJC_SECTION_INFO_H__

#include <stdint.h>
#include <string.h>
#include <mach-o/dyld_priv.h>
#include <mach-o/loader.h>

// The section each kind names, in _dyld_section_location_kind order. Darwin fills SectionLocations from the
// same image sections; matching by section name is enough because these occur at most once per image.
static const char* const kObjCSectionNames[] = {
    "__swift5_protos", "__swift5_proto", "__swift5_types", "__swift5_replace", "__swift5_replace2", "__swift5_ac_funcs",
    "__objc_imageinfo", "__objc_selrefs", "__objc_msgrefs", "__objc_classrefs", "__objc_superrefs",
    "__objc_protorefs", "__objc_classlist", "__objc_nlclslist", "__objc_stublist", "__objc_catlist",
    "__objc_catlist2", "__objc_nlcatlist", "__objc_protolist", "__objc_fork_ok", "__objc_rawisa",
};
static_assert(sizeof(kObjCSectionNames)/sizeof(kObjCSectionNames[0]) == _dyld_section_location_count,
              "one section name per _dyld_section_location_kind");

// Calls visit on every LC_SEGMENT_64 that lies entirely inside the image's sizeofcmds command area, stopping
// when visit returns false. A command that overruns the area, or a segment command too short for the fields
// it describes, ends the walk: the header is malformed and its sections are not to be trusted.
template <typename F>
static inline void forEachSegmentCommand(const mach_header_64* hdr, F visit)
{
    const uint8_t* cmdStart = (const uint8_t*)hdr + sizeof(mach_header_64);
    for (uint32_t i = 0, off = 0; i != hdr->ncmds; ++i) {
        if ( hdr->sizeofcmds - off < sizeof(load_command) )
            return;
        const load_command* lc = (const load_command*)(cmdStart + off);
        if ( (lc->cmdsize < sizeof(load_command)) || (lc->cmdsize > hdr->sizeofcmds - off) )
            return;
        if ( (lc->cmd == LC_SEGMENT_64) && (lc->cmdsize >= sizeof(segment_command_64)) ) {
            if ( !visit((const segment_command_64*)lc) )
                return;
        }
        off += lc->cmdsize;
    }
}

// Offsets are relative to the mach header: the header sits at the vmaddr of the segment mapped from file
// offset 0, and every other mapping keeps its vmaddr distance from it, so addr - that base is the in-memory offset.
static inline struct _dyld_section_info_result lookupObjCSectionInfo(const struct mach_header* mh,
                                                                     enum _dyld_section_location_kind kind)
{
    if ( (unsigned)kind >= (unsigned)_dyld_section_location_count )
        return { nullptr, (size_t)-1 };
    const mach_header_64* hdr = (const mach_header_64*)mh;
    uint64_t imageVMBase = 0;
    bool haveVMBase = false;
    forEachSegmentCommand(hdr, [&](const segment_command_64* seg) {
        if ( seg->fileoff == 0 ) {
            imageVMBase = seg->vmaddr;
            haveVMBase = true;
            return false;
        }
        return true;
    });
    if ( !haveVMBase )
        return { nullptr, 0 };
    const char* name = kObjCSectionNames[kind];
    struct _dyld_section_info_result found = { nullptr, 0 };
    forEachSegmentCommand(hdr, [&](const segment_command_64* seg) {
        if ( seg->nsects > (seg->cmdsize - sizeof(segment_command_64))/sizeof(section_64) )
            return true;
        const section_64* sect = (const section_64*)((const uint8_t*)seg + sizeof(segment_command_64));
        for (uint32_t s = 0; s != seg->nsects; ++s) {
            // A 16-byte sectname has no terminator; compare within the field, not past it.
            if ( strncmp(sect[s].sectname, name, sizeof(sect[s].sectname)) == 0 ) {
                found = { (uint8_t*)mh + (sect[s].addr - imageVMBase), (size_t)sect[s].size };
                return false;
            }
        }
        return true;
    });
    return found;
}

#endif // __OBJC_SECTION_INFO_H__
