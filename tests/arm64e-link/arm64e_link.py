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
ld64 comes from --ld64 or the LD64 environment variable. Run with python3 -I.
"""
import argparse
import os
import struct
import subprocess
import sys

MH_MAGIC_64 = 0xFEEDFACF
CPU_TYPE_ARM64 = 0x0100000C
CPU_SUBTYPE_ARM64E = 0x2
CAPS_MASK = 0xFF000000
CAPS_ARM64E_VERSIONED = 0x80000000
MH_OBJECT = 1

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


def link_command(ld64, objects, out, kind, min_os, sdk, install_name, entry,
                 no_implicit, libs, lib_dirs, extra):
    for a in extra:
        if any(bad in a for bad in FORBIDDEN_LD_ARGS):
            raise RecipeError("linker argument %r is not allowed in the arm64e recipe" % a)
    cmd = [ld64, "-arch", "arm64e", "-fixup_chains", "-platform_version", "macos", min_os, sdk]
    if kind == "dylib":
        cmd.append("-dylib")
    if install_name:
        cmd += ["-install_name", install_name]
    if entry:
        cmd += ["-e", entry]
    if no_implicit:
        cmd.append("-no_implicit_dylibs")
    for d in lib_dirs:
        cmd.append("-L" + d)
    cmd += extra + objects + libs + ["-o", out]
    return cmd


def build(sources, out, kind="dylib", target=DEFAULT_TARGET, clang=None, cflags=(), ld64=None,
          min_os="13.0", sdk="13.0", install_name=None, entry=None, no_implicit=False,
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
    workdir = workdir or os.path.dirname(os.path.abspath(out))
    objects = []
    for i, src in enumerate(sources):
        stem = "%d_%s" % (i, os.path.splitext(os.path.basename(src))[0])
        raw, patched = os.path.join(workdir, stem + ".raw.o"), os.path.join(workdir, stem + ".o")
        run([clang, "--target=" + target, "-c"] + list(cflags) + [src, "-o", raw], verbose)
        patch_file(raw, patched)
        objects.append(patched)
    cmd = link_command(ld64, objects, out, kind, min_os, sdk, install_name, entry,
                       no_implicit, list(libs), list(lib_dirs), list(ld_args))
    run(cmd, verbose)
    if not os.path.isfile(out) or os.path.getsize(out) == 0:
        raise RecipeError("ld64 reported success but %s is missing or empty" % out)


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
    b.add_argument("--no-implicit-dylibs", action="store_true")
    b.add_argument("--lib", action="append", default=[], help="-lNAME or a path to a dylib/stub")
    b.add_argument("--lib-dir", action="append", default=[])
    b.add_argument("--ld-arg", action="append", default=[], dest="ld_args")
    b.add_argument("--workdir")
    b.add_argument("-v", "--verbose", action="store_true")
    p = sub.add_parser("patch")
    p.add_argument("src")
    p.add_argument("dst")
    a = ap.parse_args(argv)
    try:
        if a.cmd == "build":
            build(a.sources, a.out, a.kind, a.target, a.clang, a.cflags, a.ld64, a.min_os,
                  a.sdk, a.install_name, a.entry, a.no_implicit_dylibs, a.lib, a.lib_dir,
                  a.ld_args, a.workdir, a.verbose)
            print("OK %s" % a.out)
        else:
            patch_file(a.src, a.dst)
    except (RecipeError, OSError) as e:
        print("arm64e_link: error: %s" % e, file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
