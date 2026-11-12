#!/usr/bin/env python3
"""Name the function behind every `pc_in=` / `lr_in=` of a guest log of the ABI probe.

  symbolize_faults.py LOG [--map GUESTPREFIX=HOSTPREFIX ...]

The probe prints `pc_in=<image path>+0x<offset>` (and lr_in) without calling into dyld. This
resolves the offset against the nearest preceding symbol of the image, read with llvm-nm on the
host, adding the image's __TEXT vmaddr to the offset. Guest paths under /Volumes/SystemRoot are mapped to the host root by default. Run with
python3 -I. Images that cannot be read are reported as such, never guessed.
"""
import bisect
import re
import subprocess
import sys

DEFAULT_MAP = [("/Volumes/SystemRoot", "")]
FIELD = re.compile(r"\b(pc|lr)_in=(\S+)\+0x([0-9a-f]+)")


def host_path(path, maps):
    for guest, host in maps:
        if path.startswith(guest):
            return host + path[len(guest):]
    return path


def text_base(path):
    """vmaddr of __TEXT (0 for the dylibs of Darling's build, 0x100000000 for an executable)."""
    try:
        out = subprocess.run(["llvm-objdump", "--macho", "--private-headers", path], capture_output=True,
                             text=True, check=True).stdout
    except (OSError, subprocess.CalledProcessError):
        return None
    m = re.search(r"segname __TEXT\s+vmaddr 0x([0-9a-f]+)", out)
    return int(m.group(1), 16) if m else None


def load_symbols(path):
    base = text_base(path)
    if base is None:
        return None
    try:
        out = subprocess.run(["llvm-nm", "-n", "--defined-only", path], capture_output=True, text=True,
                             check=True).stdout
    except (OSError, subprocess.CalledProcessError):
        return None
    addrs, names = [], []
    for line in out.splitlines():
        parts = line.split(None, 2)
        if len(parts) == 3 and re.fullmatch(r"[0-9a-fA-F]+", parts[0]):
            addrs.append(int(parts[0], 16))
            names.append(parts[2])
    return addrs, names, base


def main(argv):
    if not argv or argv[0].startswith("-"):
        print(__doc__, file=sys.stderr)
        return 2
    maps = list(DEFAULT_MAP)
    log = argv[0]
    rest = argv[1:]
    while rest:
        if rest[0] != "--map" or len(rest) < 2 or "=" not in rest[1]:
            print(__doc__, file=sys.stderr)
            return 2
        maps.insert(0, tuple(rest[1].split("=", 1)))
        rest = rest[2:]
    cache = {}
    with open(log) as f:
        for line in f:
            m_check = re.search(r"FAULT check=(\d+)", line)
            if not m_check:
                continue
            parts = []
            for which, image, off in FIELD.findall(line):
                path = host_path(image, maps)
                if path not in cache:
                    cache[path] = load_symbols(path)
                syms = cache[path]
                if syms is None:
                    parts.append("%s=%s+0x%s (symbols unreadable)" % (which, image.rsplit("/", 1)[-1], off))
                    continue
                addrs, names, base = syms
                off_i = int(off, 16) + base
                i = bisect.bisect_right(addrs, off_i) - 1
                where = "%s+0x%x" % (names[i], off_i - addrs[i]) if i >= 0 else "before the first symbol"
                parts.append("%s=%s %s" % (which, image.rsplit("/", 1)[-1], where))
            print("check %s: %s" % (m_check.group(1), "  ".join(parts)))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
