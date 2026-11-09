#!/usr/bin/env python3
"""Deterministic synthetic split dyld shared cache for host tests. Synthetic data only, no Apple content.

Usage: python3 -I tests/gen-split-cache-fixture.py OUTDIR [--base 0x180000000] [--variant NAME]

Writes OUTDIR/cache (main), OUTDIR/cache.01 (text), OUTDIR/cache.02.dylddata (data with slide info v5)
and OUTDIR/manifest.txt, which holds the values the tests expect. The offsets below are written
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
    "target_outside_region", "bad_page_size", "auth_target_outside_region", "no_auth",
]


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


def build(base, variant):
    files = {}
    v = variant
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
    h = header(base, REGION_SIZE)
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
    struct.pack_into("<II", h, H_SUBCACHE_OFF, 0x300, 2)
    struct.pack_into("<II", h, H_IMAGES_OFF_SPLIT, main_len - 16 if v == "image_table_outside" else 0x400,
                     0 if v == "main_not_split" else 1)
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
    path_off = 0x500
    m[0x400:0x420] = struct.pack("<QQQII", image_addr, 0, 0, path_off, 0)
    m[path_off:path_off + len(INSTALL_NAME) + 1] = INSTALL_NAME + b"\0"
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
                "image 0x%x %s" % (image_addr, INSTALL_NAME.decode()),
                "stats files=3 mappings=3 pages=%d plain=%d auth=%d" % (len([x for x in starts if x != 0xFFFF]), plain_n, auth_n),
                "region 0x%x 0x%x" % (base, REGION_SIZE)]
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
