#!/usr/bin/env python3
"""Host-only arm64e link recipe: clang objects, caps byte cleared, in-tree ld64.

Compiling with clang's arm64e target stamps the Mach-O object cpusubtype with a
versioned-ABI "caps" byte (0x80000002). The in-tree cctools-port ld64 does not
know it and refuses the object as plain arm64. Clearing the byte (0x00000002)
makes ld64 link real arm64e output, and -fixup_chains gives authenticated
chained fixups. clang has no flag that omits the byte, so the object is patched.

Usage:
  arm64e_link.py build --out FILE [--kind dylib|exe] [options] SRC.c...
  arm64e_link.py patch IN.o OUT.o
  arm64e_link.py verify FILE [--kind dylib|exe]
  arm64e_link.py dump FILE            (JSON)
ld64 comes from --ld64 or the LD64 environment variable. Run with python3 -I.
"""
import argparse
import json
import os
import shutil
import struct
import subprocess
import sys
import tempfile

MH_MAGIC_64 = 0xFEEDFACF
CPU_TYPE_ARM64 = 0x0100000C
CPU_SUBTYPE_ARM64E = 0x2
CAPS_MASK = 0xFF000000
CAPS_ARM64E_VERSIONED = 0x80000000
MH_OBJECT, MH_EXECUTE, MH_DYLIB = 1, 2, 6

LC_SEGMENT_64 = 0x19
LC_SYMTAB = 0x2
LC_ID_DYLIB = 0xD
LC_LOAD_DYLIB = 0xC
LC_LOAD_WEAK_DYLIB = 0x80000018
LC_REEXPORT_DYLIB = 0x8000001F
LC_LOAD_UPWARD_DYLIB = 0x80000023
LC_LAZY_LOAD_DYLIB = 0x20
LC_DYLD_INFO = 0x22
LC_DYLD_INFO_ONLY = 0x80000022
LC_DYLD_CHAINED_FIXUPS = 0x80000034
LC_BUILD_VERSION = 0x32
LC_MAIN = 0x80000028
DYLIB_ORDINAL_CMDS = (LC_LOAD_DYLIB, LC_LOAD_WEAK_DYLIB, LC_REEXPORT_DYLIB,
                      LC_LOAD_UPWARD_DYLIB, LC_LAZY_LOAD_DYLIB)
PLATFORM_MACOS = 1

DYLD_CHAINED_PTR_ARM64E = 1
CHAIN_STRIDE = 8
PAGE_START_NONE = 0xFFFF
PAGE_START_MULTI = 0x8000
KEYS = ("IA", "IB", "DA", "DB")

DEFAULT_TARGET = "arm64e-apple-macos13"
# -undefined dynamic_lookup made ld64 emit lib_ordinal -1 (main executable)
# instead of a flat lookup, so the recipe never passes it.
FORBIDDEN_LD_ARGS = ("dynamic_lookup",)


class RecipeError(Exception):
    pass


# ---------------------------------------------------------------- object patch

def patch_object(data):
    """Return a copy of a clang arm64e object with the caps byte cleared."""
    if len(data) < 32:
        raise RecipeError("object too short for a Mach-O header (%d bytes)" % len(data))
    magic, cputype, cpusubtype, filetype = struct.unpack_from("<IIII", data, 0)
    if magic != MH_MAGIC_64:
        raise RecipeError("not a 64-bit little-endian Mach-O (magic 0x%08x)" % magic)
    if filetype != MH_OBJECT:
        raise RecipeError("not a relocatable object (filetype %d)" % filetype)
    if cputype != CPU_TYPE_ARM64:
        raise RecipeError("cputype 0x%08x is not ARM64 (0x%08x)" % (cputype, CPU_TYPE_ARM64))
    expected = CAPS_ARM64E_VERSIONED | CPU_SUBTYPE_ARM64E
    if cpusubtype != expected:
        raise RecipeError(
            "cpusubtype 0x%08x is not arm64e with the expected caps byte (0x%08x); "
            "refusing to patch" % (cpusubtype, expected))
    out = bytearray(data)
    struct.pack_into("<I", out, 8, cpusubtype & ~CAPS_MASK)
    return bytes(out)


def patch_file(src, dst):
    if os.path.exists(dst) and os.path.samefile(src, dst):
        raise RecipeError("refusing to patch %s in place" % src)
    with open(src, "rb") as f:
        data = f.read()
    try:
        patched = patch_object(data)
    except RecipeError as e:
        raise RecipeError("%s: %s" % (src, e))
    with open(dst, "wb") as f:
        f.write(patched)


# --------------------------------------------------------------- Mach-O parser

class MachO:
    """Minimal 64-bit Mach-O reader; every bounds problem raises RecipeError."""

    def __init__(self, data, name="<buffer>"):
        self.data = data
        self.name = name
        self.segments = []
        self.dylibs = []          # (command, path) in ordinal order
        self.install_name = None
        self.install_versions = None   # (current, compatibility) of LC_ID_DYLIB
        self.dylib_versions = []       # (current, compatibility), parallel to dylibs
        self.commands = []             # every load command id, in file order
        self.entry_offset = None       # LC_MAIN entryoff
        self.symtab = None
        self.chained = None       # (dataoff, datasize)
        self.dyld_info = None
        self.build_platform = None
        self.build_versions = None     # (minos, sdk) of LC_BUILD_VERSION
        self._parse()

    def err(self, msg):
        raise RecipeError("%s: %s" % (self.name, msg))

    def u(self, fmt, off):
        try:
            return struct.unpack_from(fmt, self.data, off)
        except struct.error:
            self.err("read of %s at 0x%x past end of file (size 0x%x)" % (fmt, off, len(self.data)))

    def _parse(self):
        magic, self.cputype, self.cpusubtype, self.filetype, ncmds, sizeofcmds, self.flags, _ = \
            self.u("<IIIIIIII", 0)
        if magic != MH_MAGIC_64:
            self.err("not a 64-bit little-endian Mach-O (magic 0x%08x)" % magic)
        off = 32
        end = 32 + sizeofcmds
        if end > len(self.data):
            self.err("load commands (0x%x bytes) exceed the file" % sizeofcmds)
        for _ in range(ncmds):
            if off + 8 > end:
                self.err("load command table overruns sizeofcmds")
            cmd, cmdsize = self.u("<II", off)
            if cmdsize < 8 or cmdsize % 8 or off + cmdsize > end:
                self.err("bad load command size 0x%x at 0x%x" % (cmdsize, off))
            self.commands.append(cmd)
            self._command(cmd, cmdsize, off)
            off += cmdsize
        if off != end:
            self.err("load commands end at 0x%x, header says 0x%x" % (off, end))

    def _cstr(self, off, limit):
        raw = self.data[off:limit]
        nul = raw.find(b"\0")
        if nul < 0:
            self.err("unterminated string at 0x%x" % off)
        return raw[:nul].decode("utf-8", "replace")

    def _fixed_name(self, off):
        # char[16] fields carry no NUL when the name is exactly 16 characters long
        return self.data[off:off + 16].split(b"\0", 1)[0].decode("utf-8", "replace")

    def _command(self, cmd, cmdsize, off):
        if cmd == LC_SEGMENT_64:
            name = self._fixed_name(off + 8)
            vmaddr, vmsize, fileoff, filesize, _mp, _ip, nsects, _fl = self.u("<QQQQIIII", off + 24)
            if 72 + nsects * 80 > cmdsize:
                self.err("segment %s: %d sections overrun the command" % (name, nsects))
            sections = []
            for i in range(nsects):
                so = off + 72 + i * 80
                sect = self._fixed_name(so)
                saddr, ssize = self.u("<QQ", so + 32)
                sections.append({"name": sect, "addr": saddr, "size": ssize})
            self.segments.append({"name": name, "vmaddr": vmaddr, "vmsize": vmsize,
                                  "fileoff": fileoff, "filesize": filesize, "sections": sections})
        elif cmd in DYLIB_ORDINAL_CMDS or cmd == LC_ID_DYLIB:
            nameoff = self.u("<I", off + 8)[0]
            if nameoff >= cmdsize:
                self.err("dylib command name offset 0x%x outside the command" % nameoff)
            path = self._cstr(off + nameoff, off + cmdsize)
            versions = self.u("<II", off + 16)
            if cmd == LC_ID_DYLIB:
                self.install_name = path
                self.install_versions = versions
            else:
                self.dylibs.append((cmd, path))
                self.dylib_versions.append(versions)
        elif cmd == LC_SYMTAB:
            self.symtab = self.u("<IIII", off + 8)
        elif cmd == LC_DYLD_CHAINED_FIXUPS:
            if self.chained is not None:
                self.err("more than one LC_DYLD_CHAINED_FIXUPS")
            self.chained = self.u("<II", off + 8)
        elif cmd in (LC_DYLD_INFO, LC_DYLD_INFO_ONLY):
            if cmdsize < 48:
                self.err("LC_DYLD_INFO command is %d bytes, expected 48" % cmdsize)
            self.dyld_info = self.u("<10I", off + 8)
        elif cmd == LC_MAIN:
            self.entry_offset = self.u("<Q", off + 8)[0]
        elif cmd == LC_BUILD_VERSION:
            self.build_platform = self.u("<I", off + 8)[0]
            self.build_versions = self.u("<II", off + 12)

    # -- addresses
    def image_base(self):
        for s in self.segments:
            if s["fileoff"] == 0 and s["filesize"] > 0:
                return s["vmaddr"]
        self.err("no segment maps file offset 0")

    def segment_of(self, vmaddr):
        for s in self.segments:
            if s["vmaddr"] <= vmaddr < s["vmaddr"] + s["vmsize"]:
                return s
        return None

    def section_of(self, vmaddr):
        seg = self.segment_of(vmaddr)
        if seg:
            for sec in seg["sections"]:
                if sec["addr"] <= vmaddr < sec["addr"] + sec["size"]:
                    return "%s,%s" % (seg["name"], sec["name"])
        return None

    def read_vm(self, vmaddr, size):
        seg = self.segment_of(vmaddr)
        if seg is None:
            self.err("address 0x%x is in no segment" % vmaddr)
        rel = vmaddr - seg["vmaddr"]
        if rel + size > seg["filesize"]:
            self.err("0x%x..0x%x is beyond the file-backed part of %s" %
                     (vmaddr, vmaddr + size, seg["name"]))
        start = seg["fileoff"] + rel
        if start + size > len(self.data):
            self.err("0x%x maps past the end of the file" % vmaddr)
        return self.data[start:start + size]

    # -- symbols
    def symbols(self):
        """Defined, non-debug symbols as {name: vmaddr} (names keep their underscore)."""
        if self.symtab is None:
            return {}
        symoff, nsyms, stroff, strsize = self.symtab
        if stroff + strsize > len(self.data) or symoff + nsyms * 16 > len(self.data):
            self.err("symbol table outside the file")
        out = {}
        for i in range(nsyms):
            n_strx, n_type, n_sect, _desc, n_value = struct.unpack_from("<IBBHQ", self.data, symoff + i * 16)
            if n_type & 0xE0 or (n_type & 0x0E) != 0x0E or n_strx >= strsize:
                continue
            out[self._cstr(stroff + n_strx, stroff + strsize)] = n_value
        return out

    # -- chained fixups
    def chained_fixups(self):
        if self.chained is None:
            self.err("no LC_DYLD_CHAINED_FIXUPS")
        dataoff, datasize = self.chained
        if datasize < 28 or dataoff + datasize > len(self.data):
            self.err("chained fixups blob 0x%x+0x%x outside the file" % (dataoff, datasize))
        blob = self.data[dataoff:dataoff + datasize]

        def b(fmt, off):
            try:
                return struct.unpack_from(fmt, blob, off)
            except struct.error:
                self.err("chained fixups read at 0x%x past the blob" % off)

        version, starts_off, imports_off, symbols_off, nimports, imports_format, symbols_format = \
            b("<7I", 0)
        if version != 0:
            self.err("chained fixups version %d, expected 0" % version)
        if symbols_format != 0:
            self.err("symbols_format %d (compressed) unsupported" % symbols_format)
        imports = self._imports(blob, b, imports_off, symbols_off, nimports, imports_format)

        seg_count = b("<I", starts_off)[0]
        if seg_count != len(self.segments):
            self.err("chained starts cover %d segments, the file has %d" % (seg_count, len(self.segments)))
        base = self.image_base()
        starts, fixups = [], []
        for i in range(seg_count):
            rel = b("<I", starts_off + 4 + 4 * i)[0]
            if rel == 0:
                continue
            so = starts_off + rel
            size, page_size, ptr_fmt, seg_off, max_ptr, page_count = b("<IHHQIH", so)
            if ptr_fmt != DYLD_CHAINED_PTR_ARM64E:
                self.err("segment %s pointer_format %d, expected %d (DYLD_CHAINED_PTR_ARM64E)" %
                         (self.segments[i]["name"], ptr_fmt, DYLD_CHAINED_PTR_ARM64E))
            if size < 22 + 2 * page_count:
                self.err("segment %s starts record (%d bytes) too small for %d pages" %
                         (self.segments[i]["name"], size, page_count))
            seg = self.segments[i]
            if base + seg_off != seg["vmaddr"]:
                self.err("segment %s segment_offset 0x%x does not match vmaddr 0x%x" %
                         (seg["name"], seg_off, seg["vmaddr"]))
            pages = [b("<H", so + 22 + 2 * p)[0] for p in range(page_count)]
            starts.append({"segment": seg["name"], "page_size": page_size, "pointer_format": ptr_fmt,
                           "segment_offset": seg_off, "page_count": page_count, "page_starts": pages})
            self._walk_segment(seg, page_size, pages, imports, fixups)
        return {"version": version, "imports_format": imports_format, "imports": imports,
                "starts": starts, "fixups": fixups}

    def _imports(self, blob, b, imports_off, symbols_off, count, fmt):
        out = []
        for i in range(count):
            if fmt == 1:
                v = b("<I", imports_off + 4 * i)[0]
                ordinal, weak, noff, addend = v & 0xFF, (v >> 8) & 1, v >> 9, 0
            elif fmt == 2:
                v, addend = b("<Ii", imports_off + 8 * i)
                ordinal, weak, noff = v & 0xFF, (v >> 8) & 1, v >> 9
            elif fmt == 3:
                v, addend = b("<Qq", imports_off + 16 * i)
                ordinal, weak, noff = v & 0xFFFF, (v >> 16) & 1, v >> 32
            else:
                self.err("imports_format %d unsupported" % fmt)
            # dyld treats only values above 0xF0 (0xFFF0) as special ordinals
            if fmt != 3 and ordinal > 0xF0:
                ordinal -= 0x100
            elif fmt == 3 and ordinal > 0xFFF0:
                ordinal -= 0x10000
            raw = blob[symbols_off + noff:]
            nul = raw.find(b"\0")
            if nul < 0:
                self.err("import %d name is not terminated" % i)
            out.append({"ordinal": ordinal, "weak": bool(weak), "addend": addend,
                        "name": raw[:nul].decode("utf-8", "replace"), "lib": self._ordinal_path(ordinal)})
        return out

    def _ordinal_path(self, ordinal):
        if ordinal == 0:
            return self.install_name
        if ordinal < 0:
            return None
        if ordinal > len(self.dylibs):
            self.err("import lib ordinal %d but only %d dylibs are loaded" % (ordinal, len(self.dylibs)))
        return self.dylibs[ordinal - 1][1]

    def _walk_segment(self, seg, page_size, pages, imports, fixups):
        for p, start in enumerate(pages):
            if start == PAGE_START_NONE:
                continue
            if start & PAGE_START_MULTI:
                self.err("segment %s page %d uses multi-start chains, unsupported" % (seg["name"], p))
            if start >= page_size:
                self.err("segment %s page %d start 0x%x beyond the page" % (seg["name"], p, start))
            page_base = seg["vmaddr"] + p * page_size
            addr = page_base + start
            index = 0
            seen = set()
            while True:
                if addr in seen:
                    self.err("fixup chain loops at 0x%x" % addr)
                seen.add(addr)
                if not page_base <= addr < page_base + page_size:
                    self.err("fixup chain leaves page %d of %s at 0x%x" % (p, seg["name"], addr))
                if addr % 8:
                    self.err("misaligned fixup at 0x%x" % addr)
                value = struct.unpack("<Q", self.read_vm(addr, 8))[0]
                fix = self._decode(value, imports)
                fix.update({"vmaddr": addr, "segment": seg["name"], "section": self.section_of(addr),
                            "page": p, "chain_index": index})
                fixups.append(fix)
                if fix["next"] == 0:
                    break
                addr += fix["next"] * CHAIN_STRIDE
                index += 1

    def _decode(self, v, imports):
        auth, bind = (v >> 63) & 1, (v >> 62) & 1
        nxt = (v >> 51) & 0x7FF
        fix = {"auth": bool(auth), "next": nxt, "raw": "0x%016x" % v}
        if bind:
            ordinal = v & 0xFFFF
            if (v >> 16) & 0xFFFF:
                self.err("bind with nonzero reserved bits: 0x%016x" % v)
            if ordinal >= len(imports):
                self.err("bind ordinal %d beyond %d imports" % (ordinal, len(imports)))
            imp = imports[ordinal]
            fix.update({"kind": "auth_bind" if auth else "bind", "import_index": ordinal,
                        "import": imp["name"], "lib": imp["lib"], "lib_ordinal": imp["ordinal"]})
            if auth:
                fix["addend"] = imp["addend"]
            else:
                addend = (v >> 32) & 0x7FFFF
                if addend & 0x40000:
                    addend -= 0x80000
                fix["addend"] = addend + imp["addend"]
        elif auth:
            fix.update({"kind": "auth_rebase", "target": v & 0xFFFFFFFF})
        else:
            fix.update({"kind": "rebase", "target": v & ((1 << 43) - 1), "high8": (v >> 43) & 0xFF})
        if auth:
            fix.update({"diversity": (v >> 32) & 0xFFFF, "addr_div": bool((v >> 48) & 1),
                        "key": KEYS[(v >> 49) & 3]})
        return fix


# ---------------------------------------------------------------------- verify

def version_str(v):
    """Mach-O packed dylib version (xxxx.yy.zz) as text."""
    return "%d.%d.%d" % (v >> 16, (v >> 8) & 0xFF, v & 0xFF)


def load_macho(path):
    try:
        with open(path, "rb") as f:
            return MachO(f.read(), path)
    except OSError as e:
        raise RecipeError("cannot read %s: %s" % (path, e))


def verify_output(path, kind=None):
    """Check a linked file is arm64e with chained fixups; return the decode."""
    m = load_macho(path)
    if m.cputype != CPU_TYPE_ARM64:
        raise RecipeError("%s: cputype 0x%08x is not ARM64" % (path, m.cputype))
    if m.cpusubtype != CPU_SUBTYPE_ARM64E:
        raise RecipeError("%s: cpusubtype 0x%08x is not arm64e (0x%08x)" %
                          (path, m.cpusubtype, CPU_SUBTYPE_ARM64E))
    want = {"dylib": MH_DYLIB, "exe": MH_EXECUTE}.get(kind)
    if kind is not None and want is None:
        raise RecipeError("unknown kind %r" % kind)
    if want is not None and m.filetype != want:
        raise RecipeError("%s: filetype %d, expected %d for %s" % (path, m.filetype, want, kind))
    if m.build_platform != PLATFORM_MACOS:
        raise RecipeError("%s: build platform %r is not macOS" % (path, m.build_platform))
    if kind == "dylib" and not m.install_name:
        raise RecipeError("%s: dylib has no LC_ID_DYLIB" % path)
    if m.chained is None:
        raise RecipeError("%s: no LC_DYLD_CHAINED_FIXUPS (was -fixup_chains passed?)" % path)
    if m.dyld_info is not None and any(m.dyld_info[i] for i in (1, 3, 5, 7)):
        raise RecipeError("%s: LC_DYLD_INFO carries rebase/bind opcodes next to chained fixups" % path)
    decoded = m.chained_fixups()
    for imp in decoded["imports"]:
        if imp["ordinal"] < 0:
            raise RecipeError("%s: import %s has special lib ordinal %d (main executable or flat "
                              "lookup), not a real dylib" % (path, imp["name"], imp["ordinal"]))
    return m, decoded


def dump(path):
    m, decoded = verify_output(path)
    base = m.image_base()
    return {
        "file": os.path.basename(path), "cputype": m.cputype, "cpusubtype": m.cpusubtype,
        "filetype": m.filetype, "image_base": base, "install_name": m.install_name,
        "load_dylibs": [p for _c, p in m.dylibs],
        "load_dylib_versions": [[version_str(v) for v in vs] for vs in m.dylib_versions],
        "install_versions": [version_str(v) for v in m.install_versions] if m.install_versions else None,
        "entry_offset": m.entry_offset,
        "build_versions": [version_str(v) for v in m.build_versions] if m.build_versions else None, "segments": m.segments,
        "symbols": m.symbols(), "chained": decoded,
    }


# ----------------------------------------------------------------------- build

def run(cmd, verbose, timeout=300):
    if verbose:
        print("+ " + " ".join(cmd), file=sys.stderr)
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
    except FileNotFoundError:
        raise RecipeError("cannot execute %s" % cmd[0])
    except subprocess.TimeoutExpired:
        raise RecipeError("%s timed out after %ds" % (cmd[0], timeout))
    if r.returncode != 0:
        raise RecipeError("%s failed (exit %d):\n%s%s" % (os.path.basename(cmd[0]), r.returncode, r.stdout, r.stderr))
    return r


def reject_forbidden(*arg_lists):
    for a in (a for args in arg_lists for a in args):
        if any(bad in a for bad in FORBIDDEN_LD_ARGS):
            raise RecipeError("linker argument %r is not allowed in the arm64e recipe" % a)


def link_command(ld64, objects, out, kind, min_os, sdk, install_name, entry,
                 libs, lib_dirs, extra):
    cmd = [ld64, "-arch", "arm64e", "-fixup_chains", "-platform_version", "macos", min_os, sdk]
    if kind == "dylib":
        cmd.append("-dylib")
    if install_name:
        cmd += ["-install_name", install_name]
    if entry:
        cmd += ["-e", entry]
    for d in lib_dirs:
        cmd.append("-L" + d)
    cmd += extra + objects + libs + ["-o", out]
    return cmd


def build(sources, out, kind="dylib", target=DEFAULT_TARGET, clang=None, cflags=(), ld64=None,
          min_os="13.0", sdk="13.0", install_name=None, entry=None,
          libs=(), lib_dirs=(), ld_args=(), workdir=None, verbose=False):
    ld64 = ld64 or os.environ.get("LD64")
    if not ld64:
        raise RecipeError("no linker: pass --ld64 or set LD64 to the in-tree ld64 binary")
    if not (os.path.isfile(ld64) and os.access(ld64, os.X_OK)):
        raise RecipeError("LD64 %r is not an executable file" % ld64)
    if kind not in ("dylib", "exe"):
        raise RecipeError("kind must be dylib or exe, not %r" % kind)
    if not sources:
        raise RecipeError("no source files")
    clang = clang or os.environ.get("CLANG", "clang")
    reject_forbidden(ld_args, libs, lib_dirs)
    own_workdir = workdir is None
    if own_workdir:
        workdir = tempfile.mkdtemp(prefix="arm64e-link-")
    else:
        os.makedirs(workdir, exist_ok=True)
    partial = out + ".partial"
    try:
        objects = []
        for i, src in enumerate(sources):
            stem = "%d_%s" % (i, os.path.splitext(os.path.basename(src))[0])
            raw, patched = os.path.join(workdir, stem + ".raw.o"), os.path.join(workdir, stem + ".o")
            run([clang, "--target=" + target, "-c"] + list(cflags) + [src, "-o", raw], verbose)
            patch_file(raw, patched)
            objects.append(patched)
        cmd = link_command(ld64, objects, partial, kind, min_os, sdk, install_name, entry,
                           list(libs), list(lib_dirs), list(ld_args))
        run(cmd, verbose)
        if not os.path.isfile(partial) or os.path.getsize(partial) == 0:
            raise RecipeError("ld64 reported success but %s is missing or empty" % partial)
        result = verify_output(partial, kind)
        os.replace(partial, out)
        return result
    finally:
        if os.path.exists(partial):
            os.remove(partial)
        if own_workdir:
            shutil.rmtree(workdir)


def main(argv):
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    sub = ap.add_subparsers(dest="cmd", required=True)
    b = sub.add_parser("build")
    b.add_argument("sources", nargs="+")
    b.add_argument("--out", required=True)
    b.add_argument("--kind", choices=("dylib", "exe"), default="dylib")
    b.add_argument("--target", default=DEFAULT_TARGET)
    b.add_argument("--clang")
    b.add_argument("--cflag", action="append", default=[], dest="cflags")
    b.add_argument("--ld64")
    b.add_argument("--min-os", default="13.0")
    b.add_argument("--sdk", default="13.0")
    b.add_argument("--install-name")
    b.add_argument("--entry")
    b.add_argument("--lib", action="append", default=[], help="-lNAME or a path to a dylib/stub")
    b.add_argument("--lib-dir", action="append", default=[])
    b.add_argument("--ld-arg", action="append", default=[], dest="ld_args")
    b.add_argument("--workdir")
    b.add_argument("-v", "--verbose", action="store_true")
    p = sub.add_parser("patch")
    p.add_argument("src")
    p.add_argument("dst")
    v = sub.add_parser("verify")
    v.add_argument("file")
    v.add_argument("--kind", choices=("dylib", "exe"))
    d = sub.add_parser("dump")
    d.add_argument("file")
    a = ap.parse_args(argv)
    try:
        if a.cmd == "build":
            _m, dec = build(a.sources, a.out, a.kind, a.target, a.clang, a.cflags, a.ld64, a.min_os,
                            a.sdk, a.install_name, a.entry, a.lib, a.lib_dir,
                            a.ld_args, a.workdir, a.verbose)
            print("OK %s: %d fixups, %d imports" % (a.out, len(dec["fixups"]), len(dec["imports"])))
        elif a.cmd == "patch":
            patch_file(a.src, a.dst)
        elif a.cmd == "verify":
            _m, dec = verify_output(a.file, a.kind)
            print("OK %s: %d fixups, %d imports" % (a.file, len(dec["fixups"]), len(dec["imports"])))
        else:
            json.dump(dump(a.file), sys.stdout, indent=1, sort_keys=True)
            print()
    except (RecipeError, OSError) as e:
        print("arm64e_link: error: %s" % e, file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
