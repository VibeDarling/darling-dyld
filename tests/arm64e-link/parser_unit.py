"""Parser checks on synthetic data for cases no toy can produce.

Run with python3 -I; ARM64E_LINK_SCRIPT selects another copy of arm64e_link.py.
"""
import importlib.util
import os
import struct
import sys

sys.dont_write_bytecode = True
script = os.environ.get("ARM64E_LINK_SCRIPT") or os.path.join(os.path.dirname(os.path.abspath(__file__)), "arm64e_link.py")
spec = importlib.util.spec_from_file_location("arm64e_link", script)
mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mod)

failures = 0


def check(desc, ok):
    global failures
    print(("PASS " if ok else "FAIL ") + desc)
    failures += 0 if ok else 1


def bare(dylibs=()):
    m = mod.MachO.__new__(mod.MachO)
    m.data, m.name, m.install_name = b"", "synthetic", "/self"
    m.dylibs = [(mod.LC_LOAD_DYLIB, "/lib%d" % i) for i in range(len(dylibs))] if dylibs else []
    return m


def imports_of(m, words, fmt, names=b"sym\0"):
    pack = {1: "<I", 3: "<Qq"}[fmt]
    blob = b"".join(struct.pack(pack, *w) if fmt == 3 else struct.pack(pack, w) for w in words) + names
    reader = lambda f, o: struct.unpack_from(f, blob, o)
    size = {1: 4, 3: 16}[fmt]
    return m._imports(blob, reader, 0, size * len(words), len(words), fmt)


# a bind ordinal above 255 must keep all 16 bits
imports = [{"name": "sym%d" % i, "lib": "/l", "ordinal": 1, "addend": 0} for i in range(400)]
fix = bare()._decode((1 << 62) | 300, imports)
check("bind ordinal 300 selects import 300", fix["import_index"] == 300 and fix["import"] == "sym300")
fix = bare()._decode((1 << 62) | (1 << 32) | 5, imports)
check("plain bind addend decodes as a signed 19-bit value", fix["addend"] == 1)
fix = bare()._decode((1 << 62) | (0x7FFFF << 32), imports)
check("plain bind addend -1", fix["addend"] == -1)

# special lib ordinals start above 0xF0 (0xFFF0 for format 3); 0xF0 itself is a real ordinal
m = bare(range(0xFFF0))
name_off = 0  # all words point at "sym"
one = lambda ordinal: imports_of(m, [ordinal | (name_off << 9)], 1)[0]["ordinal"]
check("format 1 ordinal 0xF0 stays 240", one(0xF0) == 0xF0)
check("format 1 ordinal 0xF1 is special (-15)", one(0xF1) == -15)
check("format 1 ordinal 0xFF is -1 (main executable)", one(0xFF) == -1)
three = lambda ordinal: imports_of(m, [(ordinal | (0 << 32), 0)], 3)[0]["ordinal"]
check("format 3 ordinal 0xFFF0 stays 65520", three(0xFFF0) == 0xFFF0)
check("format 3 ordinal 0xFFFF is -1", three(0xFFFF) == -1)

# format 3 keeps a 32-bit name offset and a weak flag
far = imports_of(m, [(1 | (1 << 16) | (0x10005 << 32), -8)], 3, names=b"\0" * 0x10000 + b"junk\0far\0")[0]
check("format 3 name offset above 0xFFFF", far["name"] == "far")
check("format 3 weak flag and addend", far["weak"] and far["addend"] == -8 and far["ordinal"] == 1)

# a 16-character name has no NUL inside its char[16] field
m = bare()
m.data = b"__toy_sixteen_ab" + b"__DATA\0\0\0\0\0\0\0\0\0\0"
check("16-character name is read in full", m._fixed_name(0) == "__toy_sixteen_ab")
check("short name stops at its NUL", m._fixed_name(16) == "__DATA")

sys.exit(1 if failures else 0)
