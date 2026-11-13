#!/usr/bin/env python3
"""Tests for emit_tsd_sites.py on a synthetic split cache (synthetic data only, no Apple content).

Usage: python3 -I tests/darling-tsd/emit_test.py EMITTER.py [KEEP_DIR]
KEEP_DIR, when given, receives the table emitted from the fixture (fixture.tsdsites).
"""
import importlib.util
import os
import shutil
import struct
import sys
import tempfile

BASE = 0x180000000
TEXT = BASE + 0x4000            # address of the text mapping (sub-cache .01)
UUID_MAIN = bytes(range(1, 17))
UUID_SUB = bytes(range(101, 117))
NOP, MRS, LSR12 = 0xD503201F, 0xD53BD060, 0xD34CFC00
AND_X3_X3_NOT7 = 0x927DF063     # and x3, x3, #~7


def macho(sections, vmaddr, vmsize):
    """A 64-bit mach header with one __TEXT segment. sections: [(name, addr, size, flags)]."""
    cmd = struct.pack("<II16sQQQQiiII", 0x19, 72 + 80 * len(sections), b"__TEXT", vmaddr, vmsize, 0, vmsize, 5, 5, len(sections), 0)
    for name, addr, size, flags in sections:
        cmd += struct.pack("<16s16sQQIIIIIIII", name, b"__TEXT", addr, size, 0, 2, 0, 0, flags, 0, 0, 0)
    return struct.pack("<IIIIIIII", 0xFEEDFACF, 0x0100000C, 0x80000002, 6, 1, len(cmd), 0, 0) + cmd


def words(*values):
    return struct.pack("<%dI" % len(values), *values)


def header(uuid, region_start):
    h = bytearray(0x228)
    h[0:15] = b"dyld_v1  arm64e"
    h[0x58:0x68] = uuid
    struct.pack_into("<Q", h, 0xE0, region_start)
    return h


def build_fixture(directory):
    sub = bytearray(0x4000)
    sub[0:0x228] = header(UUID_SUB, TEXT)
    struct.pack_into("<II", sub, 0x138, 0x280, 1)
    sub[0x280:0x280 + 56] = struct.pack("<QQQQQQII", TEXT, 0x4000, 0, 0, 0, 0, 5, 5)
    A, B, C, D = TEXT + 0x400, TEXT + 0x1000, TEXT + 0x1800, TEXT + 0x1910
    TI = 0x80000400
    # A: every shape of site, a mrs word in __const, and a misaligned match
    sub[0x400:0x400 + 0x300] = bytes(0x300)
    code = [NOP] * 32
    code[1] = MRS | 9
    code[3], code[4] = MRS | 0, LSR12 | (0 << 5) | 0
    code[5] = MRS | 31
    code[6], code[7] = MRS | 3, AND_X3_X3_NOT7
    code[10], code[11] = MRS | 4, LSR12 | (5 << 5) | 5      # shift of another register: still a plain TSD read
    code[12], code[13] = MRS | 7, 0xD34CFC00 + (1 << 10) | (7 << 5) | 7     # lsr #13: not the CPU number
    code[8], code[9] = 0x3BD06100, 0x000000D5               # bytes 00 61 d0 3b d5 00 00 00: a match one byte off alignment
    sub[0x400 + 0x200:0x400 + 0x200 + 128] = words(*code)
    sub[0x400 + 0x2C0:0x400 + 0x2C0 + 4] = words(MRS | 10)     # in __const: data, not code
    sub[0x400:0x400 + 32 + 72 + 160] = macho([(b"__text", A + 0x200, 0x80, TI), (b"__const", A + 0x2C0, 0x10, 0)], A, 0x300)
    # B: one site, then a gap whose middle holds a non-zero word, so the usable gap starts after it
    sub[0x1000:0x1000 + 32 + 72 + 80] = macho([(b"__text", B + 0x100, 0x40, TI)], B, 0x200)
    sub[0x1100:0x1104] = words(MRS | 20)
    sub[0x1300:0x1304] = words(0xDEADBEEF)
    # C: the site is the last word of its section; the next image is 16 bytes after C's text (too small for a veneer)
    sub[0x1800:0x1800 + 32 + 72 + 80] = macho([(b"__text", C + 0x80, 0x20, TI)], C, 0x100)
    sub[0x1800 + 0x9C:0x1800 + 0xA4] = words(MRS | 5, LSR12 | (5 << 5) | 5)     # the shift after the section's end is not part of the site
    # D: last image of the mapping, its gap runs to the end of the mapping
    sub[0x1910:0x1910 + 32 + 72 + 80] = macho([(b"__text", D + 0x80, 0x20, TI)], D, 0x100)

    main = bytearray(0x4000)
    main[0:0x228] = header(UUID_MAIN, BASE)
    struct.pack_into("<II", main, 0x138, 0x280, 1)
    main[0x280:0x280 + 56] = struct.pack("<QQQQQQII", BASE, 0x4000, 0, 0, 0, 0, 1, 1)
    struct.pack_into("<II", main, 0x188, 0x300, 1)
    main[0x300:0x300 + 56] = struct.pack("<16sQ32s", UUID_SUB, 0x4000, b".01")
    # E: an image in the main file's read-only mapping; veneers cannot live there
    E = BASE + 0x2000
    main[0x2000:0x2000 + 32 + 72 + 80] = macho([(b"__text", E + 0x100, 0x20, 0x80000400)], E, 0x200)
    struct.pack_into("<II", main, 0x1C0, 0x1000, 5)
    for i, address in enumerate([D, A, E, C, B]):      # unsorted on purpose
        main[0x1000 + 32 * i:0x1000 + 32 * i + 8] = struct.pack("<Q", address)
    path = os.path.join(directory, "cache")
    open(path, "wb").write(main)
    open(path + ".01", "wb").write(sub)
    return path, (A, B, C, D, E)


def read_table(data):
    """An independent reader: (uuid, gaps, images, sites)."""
    assert data[:8] == b"DTSDSIT1"
    gap_count, image_count, site_count, reserved = struct.unpack_from("<IIII", data, 24)
    assert reserved == 0 and len(data) == 40 + 16 * gap_count + 16 * image_count + 4 * site_count
    gaps = [struct.unpack_from("<QQ", data, 40 + 16 * i) for i in range(gap_count)]
    off = 40 + 16 * gap_count
    images = [struct.unpack_from("<QII", data, off + 16 * i) for i in range(image_count)]
    off += 16 * image_count
    sites = struct.unpack_from("<%dI" % site_count, data, off)
    return data[8:24], gaps, images, sites


def site(offset, reg, kind):
    return ((offset >> 2) << 6) | (kind << 5) | reg


def check(condition, message):
    if not condition:
        print("FAIL: " + message)
        raise SystemExit(1)


def main():
    spec = importlib.util.spec_from_file_location("emit_tsd_sites", sys.argv[1])
    emitter = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(emitter)
    checks = 0
    with tempfile.TemporaryDirectory() as directory:
        path, (A, B, C, D, E) = build_fixture(directory)
        output = os.path.join(directory, "out.tsdsites")
        check(emitter.main(["emit", path, output]) == 0, "emitter failed")
        uuid, gaps, images, sites = read_table(open(output, "rb").read())
        check(uuid == UUID_MAIN, "uuid is the main file's")
        expected_sites = [site(0x204, 9, 0), site(0x20C, 0, 1), site(0x214, 31, 0), site(0x218, 3, 0), site(0x228, 4, 0), site(0x230, 7, 0),
                          site(0x100, 20, 0), site(0x9C, 5, 0)]
        check(list(sites) == expected_sites, "sites: %r" % (list(sites),))
        check(images == [(E - BASE, 0, 0), (A - BASE, 0, 6), (B - BASE, 6, 1), (C - BASE, 7, 1), (D - BASE, 8, 0)], "images: %r" % (images,))
        want_gaps = [(A + 0x300 - BASE, 0x1000 - 0x700), (0x1304 + TEXT - BASE, 0x1800 - 0x1304), (D + 0x100 - BASE, 0x4000 - 0x1A10)]
        check(gaps == want_gaps, "gaps: %r want %r" % (gaps, want_gaps))
        checks += 5
        if len(sys.argv) > 2:
            os.makedirs(sys.argv[2], exist_ok=True)
            shutil.copy(output, os.path.join(sys.argv[2], "fixture.tsdsites"))

        # refusals
        sub = open(path + ".01", "rb").read()
        bad = bytearray(sub); bad[0x58] ^= 1
        open(path + ".01", "wb").write(bad)
        try:
            emitter.main(["emit", path, output]); check(False, "a sub-cache with another uuid is refused")
        except emitter.CacheError:
            checks += 1
        bad = bytearray(sub); bad[0x400:0x404] = b"\0\0\0\0"
        open(path + ".01", "wb").write(bad)
        try:
            emitter.main(["emit", path, output]); check(False, "an image without a mach header is refused")
        except emitter.CacheError:
            checks += 1
        open(path + ".01", "wb").write(sub)
        main_bytes = bytearray(open(path, "rb").read()); main_bytes[0x300 + 24:0x300 + 28] = b"/x\0\0"
        open(path, "wb").write(main_bytes)
        try:
            emitter.main(["emit", path, output]); check(False, "a suffix with a slash is refused")
        except emitter.CacheError:
            checks += 1
    print("%d checks, 0 failures" % checks)


if __name__ == "__main__":
    main()
