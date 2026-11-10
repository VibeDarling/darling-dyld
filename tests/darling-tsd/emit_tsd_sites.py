#!/usr/bin/env python3
"""Emit the TSD site table (see dyld3/DarlingTSDIslands.h) for a split dyld shared cache.

Usage: python3 -I tests/darling-tsd/emit_tsd_sites.py MAIN_CACHE_FILE OUTPUT [--summary]

Reads the main cache file and its sub-cache files (named by the sub-cache array) read-only, decodes the instruction
sections of every image for `mrs Xt, TPIDRRO_EL0`, and records the zero padding after each image's text where veneers can
live. Nothing from the cache is copied into the output beyond offsets, registers and the main file's UUID.
"""
import bisect
import mmap
import os
import re
import struct
import sys

# dyld_cache_header offsets (dyld3/shared-cache/dyld_cache_format.h)
H_UUID, H_MAPSLIDE_OFF, H_MAPSLIDE_CNT, H_SUBCACHE_OFF, H_SUBCACHE_CNT = 0x58, 0x138, 0x13C, 0x188, 0x18C
H_IMAGES_OFF_SPLIT, H_IMAGES_CNT_SPLIT = 0x1C0, 0x1C4
H_REGION_START = 0xE0
VM_PROT_EXECUTE = 4
S_INSTRUCTION_ATTRS = 0x80000400    # S_ATTR_PURE_INSTRUCTIONS | S_ATTR_SOME_INSTRUCTIONS
LC_SEGMENT_64 = 0x19
MRS_PATTERN = re.compile(rb"[\x60-\x7f]\xd0\x3b\xd5")   # mrs Xt, TPIDRRO_EL0 = 0xD53BD060 | Rt, little endian
LSR_12 = 0xD34CFC00                                      # lsr Xd, Xd, #12 (with Rd = Rn)
KIND_TSD, KIND_CPU = 0, 1
MIN_GAP = 20                                             # one veneer


class CacheError(Exception):
    pass


class Cache:
    def __init__(self, main_path):
        self.files = []
        self.mappings = []          # (address, size, file index, file offset, init prot)
        main = self._open(main_path)
        self.uuid = bytes(main[H_UUID:H_UUID + 16])
        self.base = struct.unpack_from("<Q", main, H_REGION_START)[0]
        map_off, map_cnt = struct.unpack_from("<II", main, H_MAPSLIDE_OFF)
        self._read_mappings(0, main, map_off, map_cnt)
        sub_off, sub_cnt = struct.unpack_from("<II", main, H_SUBCACHE_OFF)
        for i in range(sub_cnt):
            uuid, vm_offset, suffix = struct.unpack_from("<16sQ32s", main, sub_off + 56 * i)
            name = suffix.split(b"\0")[0].decode()
            if not name or "/" in name:
                raise CacheError("bad sub-cache suffix")
            data = self._open(main_path + name)
            if bytes(data[H_UUID:H_UUID + 16]) != uuid:
                raise CacheError("sub-cache %s does not match the main file" % name)
            off, cnt = struct.unpack_from("<II", data, H_MAPSLIDE_OFF)
            self._read_mappings(len(self.files) - 1, data, off, cnt)
        self.mappings.sort()
        self.starts = [m[0] for m in self.mappings]
        off, cnt = struct.unpack_from("<II", main, H_IMAGES_OFF_SPLIT)
        self.image_addresses = sorted(struct.unpack_from("<Q", main, off + 32 * i)[0] for i in range(cnt))

    def _open(self, path):
        with open(path, "rb") as handle:
            data = mmap.mmap(handle.fileno(), 0, access=mmap.ACCESS_READ)
        self.files.append(data)
        return data

    def _read_mappings(self, file_index, data, offset, count):
        for i in range(count):
            address, size, file_offset, _, _, _, _, init_prot = struct.unpack_from("<QQQQQQII", data, offset + 56 * i)
            self.mappings.append((address, size, file_index, file_offset, init_prot))

    def mapping_of(self, address):
        i = bisect.bisect_right(self.starts, address) - 1
        if i < 0 or address >= self.mappings[i][0] + self.mappings[i][1]:
            return None
        return self.mappings[i]

    def view(self, address, length):
        """(file data, file offset) of [address, address+length), which must lie inside one mapping."""
        m = self.mapping_of(address)
        if m is None or address + length > m[0] + m[1]:
            raise CacheError("range 0x%x+0x%x is not inside one mapping" % (address, length))
        return self.files[m[2]], m[3] + (address - m[0])


def image_layout(cache, mh):
    """(sections, segments) of the image at `mh`: instruction sections and (vmaddr, vmsize) of every segment."""
    data, off = cache.view(mh, 32)
    magic, _, _, _, ncmds, sizeofcmds = struct.unpack_from("<IIIIII", data, off)[:6]
    if magic != 0xFEEDFACF:
        raise CacheError("image at 0x%x has no mach header" % mh)
    data, off = cache.view(mh, 32 + sizeofcmds)
    sections, segments = [], []
    cursor = off + 32
    for _ in range(ncmds):
        cmd, size = struct.unpack_from("<II", data, cursor)
        if cmd == LC_SEGMENT_64:
            name, vmaddr, vmsize, _, _, _, _, nsects, _ = struct.unpack_from("<16sQQQQiiII", data, cursor + 8)
            segments.append((vmaddr, vmsize))
            for k in range(nsects):
                sect = cursor + 72 + 80 * k
                sectname, _, addr, ssize, _, _, _, _, flags = struct.unpack_from("<16s16sQQIIIII", data, sect)
                if flags & S_INSTRUCTION_ATTRS:
                    sections.append((addr, ssize))
        cursor += size
    return sections, segments


def scan_sections(cache, mh, sections):
    """Sorted [(offset from mh, register, kind)] for every mrs TPIDRRO_EL0 in the instruction sections."""
    sites = []
    for addr, size in sections:
        size &= ~3
        data, off = cache.view(addr, size)
        for match in MRS_PATTERN.finditer(data, off, off + size):
            pos = match.start()
            if (pos - off) % 4:
                continue
            word = struct.unpack_from("<I", data, pos)[0]
            reg = word & 31
            kind = KIND_TSD
            if pos + 8 <= off + size and reg != 31:
                following = struct.unpack_from("<I", data, pos + 4)[0]
                if following == LSR_12 | (reg << 5) | reg:
                    kind = KIND_CPU
            sites.append((addr + (pos - off) - mh, reg, kind))
    return sorted(sites)


def zero_tail(cache, start, end):
    """The longest 4-byte aligned all-zero run that ends at `end` and begins at or after `start`."""
    start = (start + 3) & ~3
    if end - start < MIN_GAP:
        return None
    data, off = cache.view(start, end - start)
    chunk = bytes(data[off:off + end - start])
    stripped = chunk.rstrip(b"\0")
    first = (start + len(stripped) + 3) & ~3
    return (first, end - first) if end - first >= MIN_GAP else None


def build_table(cache):
    base = cache.base
    images, gaps, all_sites = [], [], []
    stats = {"images": 0, "sites": 0, "cpu": 0, "gaps": 0, "gap_bytes": 0, "gaps_trimmed": 0}
    for index, mh in enumerate(cache.image_addresses):
        sections, segments = image_layout(cache, mh)
        sites = scan_sections(cache, mh, sections)
        records = []
        for offset, reg, kind in sites:
            if offset >= 1 << 28:
                raise CacheError("site at 0x%x is more than 256 MiB into its image" % (mh + offset))
            records.append(((offset >> 2) << 6) | (kind << 5) | reg)
        images.append((mh - base, len(all_sites), len(records)))
        all_sites.extend(records)
        stats["images"] += 1
        stats["sites"] += len(records)
        stats["cpu"] += sum(1 for _, _, k in sites if k == KIND_CPU)

        # padding: after the image's text, up to the next image or the end of the mapping
        mapping = cache.mapping_of(mh)
        if mapping is None or not mapping[4] & VM_PROT_EXECUTE:
            continue
        end_of_mapping = mapping[0] + mapping[1]
        text_end = max([a + s for a, s in segments if mapping[0] <= a < end_of_mapping] + [mh])
        limit = end_of_mapping
        if index + 1 < len(cache.image_addresses) and cache.image_addresses[index + 1] < end_of_mapping:
            limit = cache.image_addresses[index + 1]
        if text_end >= limit:
            continue
        tail = zero_tail(cache, text_end, limit)
        if tail is None:
            continue
        stats["gaps_trimmed"] += tail[0] > ((text_end + 3) & ~3)
        gaps.append((tail[0] - base, tail[1]))
        stats["gaps"] += 1
        stats["gap_bytes"] += tail[1]
    gaps.sort()
    out = bytearray(b"DTSDSIT1" + cache.uuid)
    out += struct.pack("<IIII", len(gaps), len(images), len(all_sites), 0)
    for g in gaps:
        out += struct.pack("<QQ", *g)
    for im in images:
        out += struct.pack("<QII", *im)
    out += struct.pack("<%dI" % len(all_sites), *all_sites)
    return bytes(out), stats


def main(argv):
    if len(argv) < 3:
        sys.stderr.write(__doc__)
        return 2
    cache = Cache(argv[1])
    table, stats = build_table(cache)
    with open(argv[2], "wb") as handle:
        handle.write(table)
    if "--summary" in argv:
        print("images %(images)d, sites %(sites)d (cpu-index %(cpu)d), gaps %(gaps)d (%(gap_bytes)d bytes, %(gaps_trimmed)d trimmed)" % stats)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
