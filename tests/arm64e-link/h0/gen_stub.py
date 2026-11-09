#!/usr/bin/env python3
"""Turn a symbol list (one C name per line, # comments) into STUB(name) lines for libz_stub.c.

Usage: python3 -I gen_stub.py SYMBOLS.txt OUT.inc
"""
import re
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


def write_inc(names, out):
    with open(out, "w") as f:
        for name in names:
            f.write("STUB(%s)\n" % name)


if __name__ == "__main__":
    if len(sys.argv) != 3:
        sys.exit(__doc__)
    try:
        write_inc(read_symbols(sys.argv[1]), sys.argv[2])
    except (ValueError, OSError) as e:
        sys.exit("gen_stub: %s" % e)
