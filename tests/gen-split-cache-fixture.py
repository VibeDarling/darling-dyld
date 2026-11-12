#!/usr/bin/env python3
"""Deterministic synthetic split dyld shared cache for host tests. Synthetic data only, no Apple content.

Usage: python3 -I tests/gen-split-cache-fixture.py OUTDIR [--base 0x180000000] [--variant NAME]

Writes OUTDIR/cache (main), OUTDIR/cache.01 (text), OUTDIR/cache.02.dylddata (data with slide info v5)
and OUTDIR/manifest.txt, which holds the values the tests expect. The variants "patch" and "patch_high" (the same with the GOT above 4 GiB) add a fourth file,
cache.03.patch: three more images, a coalesced GOT mapping (DATA_CONST, read-only) and a version-4 patch info. The offsets below are written
independently of dyld_cache_format.h so that the header's static_asserts are checked against them.
"""
import argparse
import hashlib
import os
import struct
import sys

PAGE = 0x4000
STUB_SLOT_OFF = 3 * PAGE + 0x100 + 8 * 2   # entry 2 of the page-3 matrix: IA, address diversity, diversity 0
REGION_SIZE = 0x40000
INSTALL_NAME = b"/usr/lib/libmini.dylib"
OBJC_NAME = b"/usr/lib/libobjc.A.dylib"

# dyld_cache_header offsets
H_MAGIC, H_MAPPING_OFF, H_MAPPING_CNT, H_IMAGES_OFF, H_IMAGES_CNT = 0x00, 0x10, 0x14, 0x18, 0x1C
H_CODESIG_OFF, H_CODESIG_SIZE, H_UUID, H_PLATFORM = 0x28, 0x30, 0x58, 0xD8
H_REGION_START, H_REGION_SIZE, H_TRIE_SIZE = 0xE0, 0xE8, 0x110
H_MAPSLIDE_OFF, H_MAPSLIDE_CNT = 0x138, 0x13C
H_SUBCACHE_OFF, H_SUBCACHE_CNT = 0x188, 0x18C
H_IMAGES_OFF_SPLIT, H_IMAGES_CNT_SPLIT = 0x1C0, 0x1C4
HEADER_SIZE = 0x228

VARIANTS = [
    "valid", "bad_uuid", "bad_vm_offset", "main_overlap", "sub_overlap", "short_sub_file",
    "suffix_slash", "main_not_split", "bad_mapping_offset", "bad_codesig", "sig_before_eof", "sig_inside_mapping", "main_mapping_offset", "main_wrong_start", "image_table_outside",
    "sub_first_mapping_offset", "bad_alignment", "sub_bad_magic", "sub_bad_platform", "sub_wx_prot", "sub_bad_prot_bits",
    "main_wx", "slide_outside_file", "sub_outside_region", "chain_start_unaligned", "main_count_mismatch", "page_starts_range",
    "page_starts_truncated", "chain_leaves_page", "chain_start_outside", "unknown_slide_version",
    "target_outside_region", "bad_page_size", "auth_target_outside_region", "no_auth", "patch", "patch_high",
    "objc", "objc_no_ro", "objc_no_ptrs", "objc_short_ro", "objc_mid_ro", "objc_edge_ro",
]

# __objc_opt_ro section sizes shorter than sizeof(objc_opt::objc_opt_t), 0x30 for version 16. objc_mid_ro sits
# between the version-15 size (0x20) and 0x30: a check against the old size would accept it. objc_edge_ro is
# one byte short of the struct.
OBJC_RO_SIZES = {"objc_short_ro": 2, "objc_mid_ro": 0x28, "objc_edge_ro": 0x2F}


def uuid_for(name):
    return hashlib.sha256(b"split-cache-fixture/" + name.encode()).digest()[:16]


def header(region_start, region_size, magic=b"dyld_v1  arm64e", platform=1):
    # As in a real cache: the main file carries the region, each sub-cache file carries its own
    # first mapping address as sharedRegionStart and a size of 0.
    h = bytearray(HEADER_SIZE)
    h[H_MAGIC:H_MAGIC + len(magic)] = magic
    struct.pack_into("<I", h, H_PLATFORM, platform)
    struct.pack_into("<Q", h, H_REGION_START, region_start)
    struct.pack_into("<Q", h, H_REGION_SIZE, region_size)
    return h


def plain(runtime_offset, high8=0, nxt=0):
    return runtime_offset | (high8 << 34) | (nxt << 52)


def auth(runtime_offset, diversity, addr_div, key_is_data, nxt=0):
    return runtime_offset | (diversity << 34) | (addr_div << 50) | (key_is_data << 51) | (nxt << 52) | (1 << 63)


PATCH_VM = 0x40000          # cache.03.patch: text, GOT and patch-info mappings
PATCH_VM_HIGH = 0x100040000  # variant patch_high: the GOT lies 4 GiB or more above the cache base (cacheOffsetHi != 0)
PATCH_SUFFIX = b".03.patch"
PATCH_IMAGES = [            # index 1.. (index 0 is libmini); each header sits in its own page of the text mapping
    "/usr/lib/system/libexpa.dylib", "/usr/lib/system/libexpb.dylib", "/usr/lib/libclient.dylib",
]
# Exports per exporter image index: (name, implementation offset from the exporter's header, kind)
PATCH_EXPORTS = {
    1: [("_alpha", 0x1000, 0), ("_beta", 0x1040, 7), ("_gamma", 0x1080, 0), ("_delta_data", 0x2000, 0), ("_plain_only", 0x1100, 0)],
    2: [("_bravo", 0x1000, 0), ("_charlie", 0x1010, 0), ("_unexplained", 0x1020, 0)],
}


def flags_word(auth_, high7=0, bit8=0, addend=0, addr_div=0, key_data=0, disc=0):
    f = 1 if auth_ else 0
    f |= high7 << 1 | bit8 << 8
    if auth_:
        f |= addend << 9 | addr_div << 14 | key_data << 15 | disc << 16
    else:
        f |= addend << 9
    return f


# GOT locations in table order: (slot index in the GOT page, exporter, symbol, flags fields)
PATCH_GOT = [
    (0, 1, "_alpha", dict(auth_=1, addr_div=1)),
    (1, 1, "_beta", dict(auth_=1, key_data=1, disc=1)),
    (2, 1, "_gamma", dict(auth_=1, addr_div=1, disc=0xFFFF)),
    (3, 1, "_gamma", dict(auth_=1, addr_div=1, key_data=1, addend=3)),
    (4, 1, "_gamma", dict(auth_=1, bit8=1, disc=0x1234)),
    (5, 1, "_delta_data", dict(auth_=0, high7=0x20, addend=5)),
    (6, 1, "_delta_data", dict(auth_=0, addend=100)),
    (7, 2, "_bravo", dict(auth_=1, addr_div=1, key_data=1, disc=0xFFFF)),
    (8, 2, "_charlie", dict(auth_=1, addend=31)),
    (9, 2, "_unexplained", dict(auth_=1, high7=1)),      # an authenticated pointer has no high7: refused
]
# Client (plain table) locations: (slot offset in the plain page, exporter, symbol, client image index, flags fields)
PATCH_PLAIN = [
    (0x10, 1, "_plain_only", 3, dict(auth_=0)),
    (0x18, 1, "_alpha", 3, dict(auth_=1, addr_div=1)),
    (0x20, 1, "_alpha", 3, dict(auth_=0)),
    (0x28, 2, "_bravo", 3, dict(auth_=1, addr_div=1, key_data=1)),
]
GOT_SLOT_OFF = 0x40         # slot i of the GOT page is at GOT_SLOT_OFF + 8 * i
CONTROL_OFFS = (0x200, 0x208)   # chain entries in the GOT mapping that the patch info does not list


def build_patch(base, value_add, rt, image0_addr, image0_path, patch_vm):
    """The extra sub-cache file plus what the main file and the manifest need. Layout written independently of the C header."""
    text_addr = base + patch_vm
    got_addr = text_addr + 4 * PAGE
    plain_page = got_addr + PAGE
    blob_addr = got_addr + 3 * PAGE
    image_addr = {0: image0_addr}
    for i in range(1, 4):
        image_addr[i] = text_addr + i * PAGE
    paths = {0: image0_path, 1: PATCH_IMAGES[0], 2: PATCH_IMAGES[1], 3: PATCH_IMAGES[2]}
    slot_addr = lambda k: got_addr + GOT_SLOT_OFF + 8 * k

    # exports: absolute index = position in the flat array, slices per exporter
    exports, export_slice, export_index = [], {}, {}
    for img in range(4):
        start = len(exports)
        for name, impl, kind in PATCH_EXPORTS.get(img, []):
            export_index[(img, name)] = len(exports)
            exports.append((img, name, impl, kind))
        export_slice[img] = (start, len(exports) - start)
    names, name_off = bytearray(b"\0"), {}
    for _, name, _, _ in exports:
        name_off[name] = len(names)
        names += name.encode() + b"\0"

    # plain table: clients -> clientExports -> locations, grouped per exporter then client
    clients, client_exports, locations, client_slice = [], [], [], {}
    for img in range(4):
        cstart = len(clients)
        by_client = {}
        for off, exp, sym, client, fl in PATCH_PLAIN:
            if exp == img:
                by_client.setdefault(client, []).append((off, sym, fl))
        for client, items in by_client.items():
            ce_start = len(client_exports)
            for sym in dict.fromkeys(i[1] for i in items):
                l_start = len(locations)
                for off, s2, fl in items:
                    if s2 == sym:
                        locations.append((plain_page + off - image_addr[client], flags_word(**fl)))
                client_exports.append((export_index[(img, sym)], l_start, len(locations) - l_start))
            clients.append((client, ce_start, len(client_exports) - ce_start))
        client_slice[img] = (cstart, len(clients) - cstart)

    # GOT table: per exporter, per symbol (first-appearance order), its locations are contiguous
    got_clients, got_exports, got_locs = [], [], []
    for img in range(4):
        gstart = len(got_exports)
        entries = [g for g in PATCH_GOT if g[1] == img]
        for sym in dict.fromkeys(g[2] for g in entries):
            l_start = len(got_locs)
            for k, _, s2, fl in entries:
                if s2 == sym:
                    off = slot_addr(k) - base
                    got_locs.append((off & 0xFFFFFFFF, off >> 32, flags_word(**fl), 0))
            got_exports.append((export_index[(img, sym)], l_start, len(got_locs) - l_start))
        got_clients.append((gstart, len(got_exports) - gstart))
    # the table order of GOT locations must equal PATCH_GOT order for the manifest to be simple
    assert [g[0] for g in PATCH_GOT] == sorted(g[0] for g in PATCH_GOT)

    # patch info blob: header (152 bytes) then the arrays, each 4-byte aligned
    blob = bytearray(152)
    arrays = {}

    def put(name, count, data):
        while len(blob) % 4:
            blob.append(0)
        arrays[name] = (blob_addr + len(blob), count)
        blob.extend(data)
        blob.extend(bytes(16))      # slack: a count one too high stays inside the blob and does not overlap the next array

    put("patchTable", 4, b"".join(struct.pack("<IIII", *client_slice[i], *export_slice[i]) for i in range(4)))
    put("imageExports", len(exports), b"".join(struct.pack("<II", impl, kind << 28 | name_off[name]) for _, name, impl, kind in exports))
    put("clients", len(clients), b"".join(struct.pack("<III", *c) for c in clients))
    put("clientExports", len(client_exports), b"".join(struct.pack("<III", *c) for c in client_exports))
    put("locations", len(locations), b"".join(struct.pack("<II", *l) for l in locations))
    put("gotClients", 4, b"".join(struct.pack("<II", *g) for g in got_clients))
    put("gotClientExports", len(got_exports), b"".join(struct.pack("<III", *g) for g in got_exports))
    put("gotLocations", len(got_locs), b"".join(struct.pack("<IIII", *g) for g in got_locs))
    put("exportNames", len(names), bytes(names))
    order = ["patchTable", "imageExports", "clients", "clientExports", "locations", "exportNames", "gotClients", "gotClientExports", "gotLocations"]
    struct.pack_into("<II", blob, 0, 4, 0)
    for n, name in enumerate(order):
        struct.pack_into("<QQ", blob, 8 + 16 * n, *arrays[name])
    assert len(blob) <= 3 * PAGE

    # GOT mapping content: page 0 slots, page 1 client slots, page 2 control slots, all chained
    data = bytearray(3 * PAGE)
    for slot in range(0, len(data) // 8):
        struct.pack_into("<Q", data, slot * 8, 0x2222222200000000 + slot)
    chains = {0: [], 1: [], 2: []}
    impl_of = {(e[0], e[1]): e[2] for e in exports}

    def cache_target(exp, sym):
        return image_addr[exp] + impl_of[(exp, sym)] - base      # slide info targets are offsets from the cache base

    def chain_entry(fl, target, nxt):
        a = flags_word(**fl)
        if a & 1:
            return auth(rt(target), (a >> 16), (a >> 14) & 1, (a >> 15) & 1, nxt)
        return plain(rt(target), 0, nxt)

    for k, exp, sym, fl in PATCH_GOT:
        chains[0].append((GOT_SLOT_OFF + 8 * k, chain_entry(fl, cache_target(exp, sym), 1)))
    for off, exp, sym, client, fl in PATCH_PLAIN:
        chains[1].append((off, chain_entry(fl, cache_target(exp, sym), 1)))
    for n, off in enumerate(CONTROL_OFFS):
        chains[2].append((off, auth(rt(image_addr[1] + 0x1200 + 0x40 * n - base), 0x0777, 1, 0, 1)))
    starts, slots_in_chains = [], 0
    for page in range(3):
        items = sorted(chains[page])
        for n, (off, raw) in enumerate(items):
            if n + 1 == len(items):
                raw &= ~(0x7FF << 52)
            struct.pack_into("<Q", data, page * PAGE + off, raw)
        starts.append(items[0][0])
        slots_in_chains += len(items)
    n_auth = sum(1 for page in chains.values() for _, raw in page if raw >> 63)
    slide = struct.pack("<IIIIQ", 5, PAGE, 3, 0, value_add) + struct.pack("<3H", *starts)

    # the file: header page + 3 text pages | GOT mapping (3 pages) | blob mapping (3 pages) | slide info
    h = header(text_addr, 0)
    h[H_UUID:H_UUID + 16] = uuid_for("sub3")
    struct.pack_into("<II", h, H_MAPPING_OFF, HEADER_SIZE, 3)
    struct.pack_into("<II", h, H_MAPSLIDE_OFF, 0x280, 3)
    text = bytearray(4 * PAGE)
    text[:HEADER_SIZE] = h
    for i in range(1, 4):   # a bare mach_header_64 per image: magic, arm64, dylib
        struct.pack_into("<IIIIIIII", text, i * PAGE, 0xFEEDFACF, 0x0100000C, 0x80000002, 6, 0, 0, 0, 0)
    slide_off = 10 * PAGE
    f = bytearray(10 * PAGE) + slide
    f[:4 * PAGE] = text
    f[4 * PAGE:7 * PAGE] = data
    f[7 * PAGE:7 * PAGE + len(blob)] = blob
    f[0x280:0x280 + 3 * 56] = (
        struct.pack("<QQQQQQII", text_addr, 4 * PAGE, 0, 0, 0, 0, 5, 5)
        + struct.pack("<QQQQQQII", got_addr, 3 * PAGE, 4 * PAGE, slide_off, len(slide), 4 | 1, 3, 1)   # CONST_DATA | AUTH_DATA, read-only
        + struct.pack("<QQQQQQII", blob_addr, 3 * PAGE, 7 * PAGE, 0, 0, 0, 1, 1))
    struct.pack_into("<Q", f, H_CODESIG_OFF, len(f))

    lines = ["patchinfo 0x%x %d" % (blob_addr, len(blob))]
    for name in order:
        lines.append("parray %s 0x%x %d" % ((name,) + arrays[name]))
    lines.append("pgotmap 0x%x 0x%x" % (got_addr, 3 * PAGE))
    for i in range(4):
        lines.append("pimage %d 0x%x %s" % (i, image_addr[i], paths[i]))
    for name, (img, sym, impl, kind) in [(e[1], e) for e in exports]:
        lines.append("pexport %d %s 0x%x %d" % (img, name, impl, kind))
    for k, exp, sym, fl in PATCH_GOT:
        f_ = flags_word(**fl)
        explained = 0 if (fl.get("auth_") and fl.get("high7")) else 1
        lines.append("pgot 0x%x %d %s 0x%x %d %d %d %d %d %d %d %d" % (
            slot_addr(k), exp, sym, f_, fl.get("auth_", 0), fl.get("addr_div", 0), fl.get("key_data", 0),
            fl.get("disc", 0), fl.get("addend", 0), fl.get("high7", 0), fl.get("bit8", 0), explained))
    for off, exp, sym, client, fl in PATCH_PLAIN:
        lines.append("pplain 0x%x %d %s %d 0x%x" % (plain_page + off, exp, sym, client, flags_word(**fl)))
    for off in CONTROL_OFFS:
        lines.append("pcontrol 0x%x" % (got_addr + 2 * PAGE + off))
    entry = struct.pack("<16sQ32s", uuid_for("sub3"), patch_vm, PATCH_SUFFIX)
    images = [(image_addr[i], paths[i]) for i in range(1, 4)]
    return dict(file=bytes(f), entry=entry, images=images, lines=lines, blob_addr=blob_addr, blob_size=len(blob),
                pages=3, plain=slots_in_chains - n_auth, auth=n_auth, mappings=3)


def libobjc_macho(addr, with_ro, with_ptrs, ro_size=0x30):
    """A bare version-16 libobjc: one 152-byte segment command per section, written with the same pack
    formats as the libmini image. The __objc_opt_ro content is a version-16 objc_opt_t prefix; ro_size
    can make the section shorter than the struct the accessor reads."""
    img = bytearray(0x200)
    ncmds = int(with_ro) + int(with_ptrs)
    struct.pack_into("<IIIIIIII", img, 0, 0xFEEDFACF, 0x0100000C, 0x80000002, 6, ncmds, 152 * ncmds, 0, 0)
    off = 32
    ro_addr = ptrs_addr = 0
    if with_ro:
        ro_addr = addr + 0x180
        sect = struct.pack("<16s16sQQIIIIIIII", b"__objc_opt_ro", b"__TEXT", ro_addr, ro_size, 0x980, 3, 0, 0, 0, 0, 0, 0)
        struct.pack_into("<II16sQQQQIIII", img, off, 0x19, 152, b"__TEXT", addr, 0x200, 0x800, 0x200, 5, 5, 1, 0)
        img[off + 72:off + 152] = sect
        struct.pack_into("<II", img, 0x180, 16, 6)     # version, flags
        off += 152
    if with_ptrs:
        ptrs_addr = addr + 0x1C0
        sect = struct.pack("<16s16sQQIIIIIIII", b"__objc_opt_ptrs", b"__DATA", ptrs_addr, 8, 0x9C0, 3, 0, 0, 0, 0, 0, 0)
        struct.pack_into("<II16sQQQQIIII", img, off, 0x19, 152, b"__DATA", ptrs_addr, 8, 0x9C0, 8, 3, 3, 1, 0)
        img[off + 72:off + 152] = sect
        struct.pack_into("<Q", img, 0x1C0, 0x8000000000000123)
    return bytes(img), ro_addr, ptrs_addr


def build(base, variant):
    files = {}
    v = variant
    patch = v in ("patch", "patch_high")
    with_objc = v in ("objc", "objc_no_ro", "objc_no_ptrs", "objc_short_ro", "objc_mid_ro", "objc_edge_ro")
    patch_vm = PATCH_VM_HIGH if v == "patch_high" else PATCH_VM
    region_size = patch_vm + 0x40000 if patch else REGION_SIZE
    # Real caches have value_add == region start; the fixture offsets it so that code which ignored
    # value_add would produce wrong targets.
    value_add_delta = 0x4000
    value_add = base + value_add_delta

    def rt(target_offset):
        return target_offset - value_add_delta

    # ---- sub-cache .01: one text mapping that starts with the file's own header, then the Mach-O header
    text_addr = base + 0x8000
    image_addr = text_addr + PAGE
    macho = bytearray(PAGE)
    lc_name = INSTALL_NAME + b"\0"
    lc_size = (24 + len(lc_name) + 7) & ~7
    struct.pack_into("<IIIIIIII", macho, 0, 0xFEEDFACF, 0x0100000C, 0x80000002, 6, 2, lc_size + 152, 0, 0)
    struct.pack_into("<IIIIII", macho, 32, 0xD, lc_size, 24, 2, 0x10000, 0x10000)
    macho[32 + 24:32 + 24 + len(lc_name)] = lc_name
    # A __TEXT segment with one 16-byte __auth_stubs entry, the arm64e stub shape
    # (adrp x17; add x17, x17, #lo12; ldr x16, [x17]; braa x16, x17) loading from the matrix slot whose entry is
    # IA, address-diversified, diversity 0 (the shape real stubs have; see tests/real-cache-check.rb).
    stub_addr = image_addr + 0x400
    got_slot = base + 0x10000 + STUB_SLOT_OFF
    pages = ((got_slot >> 12) - (stub_addr >> 12)) & 0x1FFFFF
    stub = struct.pack("<IIII", 0x90000000 | ((pages & 3) << 29) | ((pages >> 2) << 5) | 17,
                       0x91000231 | ((got_slot & 0xFFF) << 10), 0xF9400230, 0xD71F0A11)
    sect = struct.pack("<16s16sQQIIIIIIII", b"__auth_stubs", b"__TEXT", stub_addr, len(stub), 0x400, 2, 0, 0, 0x80000408, 0, 16, 0)
    struct.pack_into("<II16sQQQQIIII", macho, 32 + lc_size, 0x19, 152, b"__TEXT", image_addr, PAGE, 0, PAGE, 5, 5, 1, 0)
    macho[32 + lc_size + 72:32 + lc_size + 152] = sect
    macho[0x400:0x400 + len(stub)] = stub
    # An optional second image in the same text page: a fake version-16 libobjc with the two
    # sections the cache accessors read.
    objc_addr = image_addr + 0x800
    objc_ro_addr = objc_ptrs_addr = 0
    if with_objc:
        objc_img, objc_ro_addr, objc_ptrs_addr = libobjc_macho(objc_addr, v != "objc_no_ro", v != "objc_no_ptrs",
                                                               OBJC_RO_SIZES.get(v, 0x30))
        # A section shorter than objc_opt_t must be ignored, so the expected result is absent.
        if v in OBJC_RO_SIZES:
            objc_ro_addr = 0
        macho[0x800:0x800 + len(objc_img)] = objc_img
    sub1_addr = {"sub_overlap": text_addr - 0x4000, "sub_outside_region": base + REGION_SIZE}.get(v, text_addr)
    h1 = header(sub1_addr, 0,
                magic=b"dyld_v1   arm64" if v == "sub_bad_magic" else b"dyld_v1  arm64e",
                platform=2 if v == "sub_bad_platform" else 1)
    sub1_uuid = uuid_for("sub1")
    h1[H_UUID:H_UUID + 16] = sub1_uuid
    struct.pack_into("<II", h1, H_MAPPING_OFF, HEADER_SIZE, 1)
    struct.pack_into("<II", h1, H_MAPSLIDE_OFF, 0x280, 1)
    f1 = bytearray(2 * PAGE)
    f1[:HEADER_SIZE] = h1
    sub1_size = 0x5000 if v == "bad_alignment" else 2 * PAGE
    sub1_offset = PAGE if v == "sub_first_mapping_offset" else 0
    if v == "sub_first_mapping_offset":
        sub1_size = PAGE
    max_prot1 = {"sub_wx_prot": 7, "sub_bad_prot_bits": 0x9}.get(v, 5)
    f1[0x280:0x280 + 56] = struct.pack("<QQQQQQII", sub1_addr, sub1_size, sub1_offset, 0, 0, 0, max_prot1, 5)
    f1[PAGE:2 * PAGE] = macho
    struct.pack_into("<Q", f1, H_CODESIG_OFF, len(f1))
    if v == "short_sub_file":
        f1 = f1[:PAGE + 0x100]
    files["cache.01"] = bytes(f1)

    # ---- sub-cache .02.dylddata: the data mapping starts with the file's header page (no chains),
    # then three data pages; slide info v5 follows the mapping in the file
    data_addr = base + 0x10000
    npages = 4
    chain = {
        # page 1: plain, auth (DA, address diversity), plain with high8, auth (IA)
        PAGE + 0x10: plain(rt(0xC000), 0, 2),
        PAGE + 0x20: auth(rt(0xC040), 0x1234, 1, 1, 1),
        PAGE + 0x28: plain(rt(0x10040), 0x80, 4),
        PAGE + 0x48: auth(rt(0xC100), 0x0042, 0, 0, 0),
    }
    if v == "no_auth":
        chain[PAGE + 0x20] = plain(rt(0xC040), 0, 1)
        chain[PAGE + 0x48] = plain(rt(0xC100), 0, 0)
    # page 3 (auth_target_outside_region: its first entry is out of range, after the page-1 slots were already signed):
    # every key x address-diversity x diversity edge (0 and 0xffff), as one chain of 8 entries
    matrix = [(key, addr_div, div) for key in (0, 1) for addr_div in (0, 1) for div in (0, 0xFFFF)]
    assert matrix[2] == (0, 1, 0)
    for i, (key, addr_div, div) in enumerate([] if v == "no_auth" else matrix):
        target = rt(REGION_SIZE + 0x4000) if (v == "auth_target_outside_region" and i == 0) else rt(0xC200 + 0x40 * i)
        chain[3 * PAGE + 0x100 + 8 * i] = auth(target, div, addr_div, key, 1 if i + 1 < len(matrix) else 0)
    last = {2 * PAGE + 0x3FF8: plain(rt(0x4010), 0, 0)}  # page 2: a one-entry chain in the last slot
    if v == "chain_leaves_page":
        last[2 * PAGE + 0x3FF8] = plain(rt(0x4010), 0, 1)
    if v == "target_outside_region":
        chain[PAGE + 0x10] = plain(rt(REGION_SIZE + 0x4000), 0, 2)
    data = bytearray(npages * PAGE)
    for slot in range(PAGE // 8, len(data) // 8):
        struct.pack_into("<Q", data, slot * 8, 0x1111111100000000 + slot)
    for off, raw in list(chain.items()) + list(last.items()):
        struct.pack_into("<Q", data, off, raw)
    slots = {}
    for off in (PAGE + 0x18, 3 * PAGE, 3 * PAGE + 0xF8):
        slots[data_addr + off] = struct.unpack_from("<Q", data, off)[0]

    starts = [0xFFFF, 0x10, 0x3FF8, 0xFFFF if v == "no_auth" else 0x100]
    count = npages
    version = 5
    page_size = PAGE
    if v == "page_starts_range":
        starts.append(0xFFFF)
        count = 5
    if v == "page_starts_truncated":
        count = 0x7FFFFFFF
    if v == "chain_start_outside":
        starts[1] = PAGE
    if v == "chain_start_unaligned":
        starts[1] = 0x14
    if v == "unknown_slide_version":
        version = 4
    if v == "bad_page_size":
        page_size = 0x3000
    slide = struct.pack("<IIIIQ", version, page_size, count, 0, value_add) + struct.pack("<%dH" % len(starts), *starts)

    h2 = header(data_addr, 0)
    h2[H_UUID:H_UUID + 16] = uuid_for("sub2")
    struct.pack_into("<II", h2, H_MAPPING_OFF, HEADER_SIZE, 1)
    struct.pack_into("<II", h2, H_MAPSLIDE_OFF, 0x280, 1)
    data[:HEADER_SIZE] = h2
    slide_off = len(data) + (0x1000 if v == "slide_outside_file" else 0)
    data[0x280:0x280 + 56] = struct.pack("<QQQQQQII", data_addr, len(data), 0, slide_off, len(slide), 1, 3, 3)
    f2 = bytearray(data) + (b"" if v == "slide_outside_file" else slide)
    struct.pack_into("<Q", f2, H_CODESIG_OFF, len(f2))
    files["cache.02.dylddata"] = bytes(f2)

    # ---- main file: header, one text mapping, sub-cache array, image table, path
    main_len = 2 * PAGE
    m = bytearray(main_len)
    h = header(base, region_size)
    h[H_UUID:H_UUID + 16] = uuid_for("main")
    mappings = [(base, main_len, 0, 7 if v == "main_wx" else 5, 5)]
    if v == "main_overlap":
        mappings.append((base + PAGE, PAGE, PAGE, 5, 5))
    if v == "main_count_mismatch":
        mappings = [(base, PAGE, 0, 5, 5), (base + PAGE, PAGE, PAGE, 5, 5)]
    if v == "sig_before_eof":
        mappings = [(base, PAGE, 0, 5, 5)]      # unsigned bytes follow the signature blob
    if v == "main_mapping_offset":
        mappings = [(base, PAGE, PAGE, 5, 5)]
    if v == "main_wrong_start":
        mappings = [(base + PAGE, PAGE, 0, 5, 5)]
    map_off = 0x3FF8 if v == "bad_mapping_offset" else HEADER_SIZE
    slide_count = 1 if v == "main_count_mismatch" else len(mappings)
    struct.pack_into("<II", h, H_MAPPING_OFF, map_off, len(mappings))
    struct.pack_into("<II", h, H_MAPSLIDE_OFF, 0x280, slide_count)
    extra = None
    if patch:
        extra = build_patch(base, value_add, rt, image_addr, INSTALL_NAME.decode(), patch_vm)
        struct.pack_into("<QQ", h, 0x98, extra["blob_addr"], extra["blob_size"])
    struct.pack_into("<II", h, H_SUBCACHE_OFF, 0x300, 3 if patch else 2)
    struct.pack_into("<II", h, H_IMAGES_OFF_SPLIT, main_len - 16 if v == "image_table_outside" else 0x400,
                     0 if v == "main_not_split" else (1 + len(extra["images"]) if patch else 1) + (1 if with_objc else 0))
    struct.pack_into("<I", h, H_TRIE_SIZE, 0)
    sig_off, sig_size = main_len + (0x1000 if v == "bad_codesig" else 0), 0
    if v == "sig_before_eof":
        sig_off, sig_size = 0x6000, 0x100       # ends before EOF, after the only mapping
    if v == "sig_inside_mapping":
        sig_off, sig_size = 0x7000, 0x1000      # ends at EOF, but the mapping covers it
    struct.pack_into("<QQ", h, H_CODESIG_OFF, sig_off, sig_size)
    m[:HEADER_SIZE] = h
    if v != "bad_mapping_offset":
        for i, (a, s, fo, mx, ip) in enumerate(mappings):
            m[HEADER_SIZE + 32 * i:HEADER_SIZE + 32 * (i + 1)] = struct.pack("<QQQII", a, s, fo, mx, ip)
    for i, (a, s, fo, mx, ip) in enumerate(mappings[:slide_count]):
        m[0x280 + 56 * i:0x280 + 56 * (i + 1)] = struct.pack("<QQQQQQII", a, s, fo, 0, 0, 0, mx, ip)
    suffix1 = b"/x" if v == "suffix_slash" else b".01"
    uuid1 = uuid_for("sub1")
    uuid2 = uuid_for("bad") if v == "bad_uuid" else uuid_for("sub2")
    vm1 = sub1_addr - base + (0x4000 if v == "bad_vm_offset" else 0)
    m[0x300:0x300 + 56] = struct.pack("<16sQ32s", uuid1, vm1, suffix1)
    m[0x300 + 56:0x300 + 112] = struct.pack("<16sQ32s", uuid2, 0x10000, b".02.dylddata")
    if patch:
        m[0x300 + 112:0x300 + 168] = extra["entry"]
    path_off = 0x500
    m[0x400:0x420] = struct.pack("<QQQII", image_addr, 0, 0, path_off, 0)
    m[path_off:path_off + len(INSTALL_NAME) + 1] = INSTALL_NAME + b"\0"
    if with_objc:
        m[0x420:0x440] = struct.pack("<QQQII", objc_addr, 0, 0, 0x600, 0)
        m[0x600:0x600 + len(OBJC_NAME) + 1] = OBJC_NAME + b"\0"
    if patch:
        files["cache.03.patch"] = extra["file"]
        next_path = path_off + 0x20
        for i, (addr, path) in enumerate(extra["images"]):
            m[0x420 + 32 * i:0x440 + 32 * i] = struct.pack("<QQQII", addr, 0, 0, next_path, 0)
            m[next_path:next_path + len(path) + 1] = path.encode() + b"\0"
            next_path += (len(path) + 8) & ~7
    files["cache"] = bytes(m)

    # ---- values the tests expect after mapping
    expect = []
    auth_lines = []
    plain_n = auth_n = 0
    for off, raw in sorted(list(chain.items()) + list(last.items())):
        if raw >> 63:
            auth_n += 1
            auth_lines.append("auth 0x%x 0x%x %d %d 0x%x 0x%x" % (
                data_addr + off, value_add + (raw & (2 ** 34 - 1)), (raw >> 51) & 1, (raw >> 50) & 1, (raw >> 34) & 0xFFFF, raw))
        else:
            plain_n += 1
            expect.append((data_addr + off, (value_add + (raw & (2 ** 34 - 1))) | (((raw >> 34) & 0xFF) << 56)))
    manifest = ["base 0x%x" % base,
                "image 0x%x %s" % (image_addr, INSTALL_NAME.decode())]
    if with_objc:
        manifest.append("objc 0x%x 0x%x 0x%x" % (objc_addr, objc_ro_addr, objc_ptrs_addr))
    manifest += [
                "stats files=%d mappings=%d pages=%d plain=%d auth=%d" % (
                    4 if patch else 3, 6 if patch else 3, len([x for x in starts if x != 0xFFFF]) + (extra["pages"] if patch else 0),
                    plain_n + (extra["plain"] if patch else 0), auth_n + (extra["auth"] if patch else 0)),
                "region 0x%x 0x%x" % (base, region_size)]
    if patch:
        manifest += extra["lines"]
    manifest += auth_lines
    manifest += ["expect 0x%x 0x%x" % (a, val) for a, val in expect]
    manifest += ["untouched 0x%x 0x%x" % (a, val) for a, val in sorted(slots.items())]
    return files, "\n".join(manifest) + "\n"


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("outdir")
    ap.add_argument("--base", default="0x180000000")
    ap.add_argument("--variant", default="valid", choices=VARIANTS)
    a = ap.parse_args()
    base = int(a.base, 0)
    if base % PAGE:
        sys.exit("base must be 16 KiB aligned")
    files, manifest = build(base, a.variant)
    os.makedirs(a.outdir, exist_ok=True)
    for name, content in files.items():
        with open(os.path.join(a.outdir, name), "wb") as f:
            f.write(content)
    with open(os.path.join(a.outdir, "manifest.txt"), "w") as f:
        f.write(manifest)


if __name__ == "__main__":
    main()
