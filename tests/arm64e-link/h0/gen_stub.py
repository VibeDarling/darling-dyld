#!/usr/bin/env python3
"""Turn a symbol list (one C name per line, # comments) into STUB(name) lines for libz_stub.c.

Usage: python3 -I gen_stub.py SYMBOLS.txt OUT.inc
       python3 -I gen_stub.py --objects OUT.txt OBJ...

A symbol list can also come from objects: undefined_names() lists what Mach-O objects reference and
define nowhere (the l4 test builds its libc++ and libc++abi stubs from that). The --objects form
writes exactly that list as a symbols file, which is what the l5 test uses to turn its own imports
into its libobjc link-only stub.
"""
import re
import subprocess
import sys

IDENT = re.compile(r"[A-Za-z_][A-Za-z0-9_]*\Z")


def read_symbols(path):
    names = []
    with open(path) as f:
        for n, line in enumerate(f, 1):
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            if not IDENT.match(line):
                raise ValueError("%s:%d: %r is not a C identifier" % (path, n, line))
            if line in names:
                raise ValueError("%s:%d: duplicate symbol %s" % (path, n, line))
            names.append(line)
    if not names:
        raise ValueError("%s: no symbols" % path)
    return names


def nm_names(path, *flags):
    """C names (the Mach-O leading underscore removed) that `llvm-nm flags path` lists."""
    out = subprocess.run(["llvm-nm", *flags, path], capture_output=True, text=True, check=True).stdout
    names = set()
    for line in out.splitlines():
        fields = line.split()
        if not fields or line.rstrip().endswith(":"):
            continue
        if not fields[-1].startswith("_"):
            raise ValueError("%s: symbol %r has no leading underscore" % (path, fields[-1]))
        names.add(fields[-1][1:])
    return names


def exported_names(path):
    """C names a dylib exports: global symbols that are defined (an address) or indirect (`I _memchr
    (indirect for __platform_memchr)`, how libsystem_c re-exports platform routines under C names)."""
    names = set()
    out = subprocess.run(["llvm-nm", "-g", path], capture_output=True, text=True, check=True).stdout
    for line in out.splitlines():
        m = re.match(r"\s*(?:[0-9a-f]+\s+)?([A-Za-z])\s+(\S+)", line)
        if not m:
            continue
        kind, name = m.groups()
        defined = line.lstrip()[0] in "0123456789abcdef" and kind not in "Uu"
        if (defined or kind in "Ii") and name.startswith("_"):
            names.add(name[1:])
    return names


def undefined_names(objects):
    """C names referenced by the objects and defined by none of them (sorted)."""
    undefined, defined = set(), set()
    for obj in objects:
        undefined |= nm_names(obj, "-u")
        defined |= nm_names(obj, "-g", "--defined-only")
    return sorted(undefined - defined)


def write_symbols(names, out, comment):
    with open(out, "w") as f:
        f.write("# %s\n" % comment)
        for name in names:
            f.write(name + "\n")


def write_inc(names, out):
    with open(out, "w") as f:
        for name in names:
            f.write("STUB(%s)\n" % name)


if __name__ == "__main__":
    argv = sys.argv[1:]
    try:
        if len(argv) >= 3 and argv[0] == "--objects":
            write_symbols(undefined_names(argv[2:]), argv[1],
                          "C names the objects reference and define nowhere (gen_stub --objects)")
        elif len(argv) == 2:
            write_inc(read_symbols(argv[0]), argv[1])
        else:
            sys.exit(__doc__)
    except (ValueError, OSError) as e:
        sys.exit("gen_stub: %s" % e)
