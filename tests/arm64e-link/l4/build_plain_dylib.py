#!/usr/bin/env python3
"""Build and structurally check l4_plain.dylib: a plain arm64 dylib that imports std::set_terminate and
std::get_terminate from the shared cache's libc++ (link-only stub), so that the arm64e probe can drive the
dyld reverse adapters (z1..z8 of l4_checks.cpp) from real plain code. Needs LD64 and SDKROOT like build_l4.py.

  build_plain_dylib.py build --out DIR    # DIR/l4_plain.dylib, next to the probe executables
  build_plain_dylib.py check DYLIB
Run with python3 -I.
"""
import argparse
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.dont_write_bytecode = True
sys.path[:0] = [HERE, os.path.join(ROOT, "abi"), os.path.join(ROOT, "h0"), ROOT]
import arm64e_link as rec  # noqa: E402
import build_abi  # noqa: E402
import build_h0  # noqa: E402
import gen_stub  # noqa: E402

IMPORTS = ["_ZSt13set_terminatePFvvE", "_ZSt13get_terminatev"]
INSTALL_NAME = "/usr/lib/l4_plain.dylib"
DEPENDENCIES = ["/usr/lib/libc++.1.dylib", "/usr/lib/libSystem.B.dylib"]
EXPORTS = {"_plain_set_terminate", "_plain_get_terminate", "_plain_entry", "_plain_data"}


def build(out_dir):
    os.makedirs(out_dir, exist_ok=True)
    sdk = build_abi.sdk_libs()
    symbols = os.path.join(out_dir, "symbols-libcxx-plain.txt")
    gen_stub.write_symbols(IMPORTS, symbols, "C++ names l4_plain.c imports")
    stub = build_h0.build_stub("libc++", out_dir, symbols, build_abi.build_plain)
    out = os.path.join(out_dir, "l4_plain.dylib")
    build_abi.build_plain([os.path.join(HERE, "l4_plain.c")], out, kind="dylib",
                          cflags=["-ffreestanding", "-fno-builtin", "-fno-stack-protector", "-O0", "-isysroot", sdk,
                                  "-Wno-incompatible-sysroot"],
                          install_name=INSTALL_NAME, libs=[stub, "-lSystem"], ld_args=["-syslibroot", sdk])
    return out


def check(path):
    """Problems with the plain dylib; empty means it passed. It must be plain arm64: the point of the checks is that the
    code calling the cache is not arm64e."""
    try:
        m = rec.load_macho(path)
    except rec.RecipeError as e:
        return [str(e)]
    problems = []
    if m.filetype != rec.MH_DYLIB or m.cputype != rec.CPU_TYPE_ARM64:
        problems.append("not an arm64 dylib")
    if m.cpusubtype != 0:
        problems.append("cpusubtype 0x%x is not plain arm64 (0)" % m.cpusubtype)
    if m.install_name != INSTALL_NAME:
        problems.append("install name %r" % m.install_name)
    if m.chained is None:
        problems.append("no LC_DYLD_CHAINED_FIXUPS")
    deps = [p for _c, p in m.dylibs]
    if deps != DEPENDENCIES:
        problems.append("dependencies %s, expected %s (system paths, never a stub's build path)" % (deps, DEPENDENCIES))
    if not EXPORTS <= set(m.symbols()):
        problems.append("missing exports %s" % sorted(EXPORTS - set(m.symbols())))
    pac = build_abi.text_words(path)
    if pac:
        problems.append("plain arm64 dylib contains PAC instructions %s" % pac)
    return problems


def main(argv):
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    sub = ap.add_subparsers(dest="cmd", required=True)
    b = sub.add_parser("build")
    b.add_argument("--out", required=True)
    c = sub.add_parser("check")
    c.add_argument("dylib")
    a = ap.parse_args(argv)
    try:
        if a.cmd == "build":
            out = build(a.out)
            problems = check(out)
        else:
            out = a.dylib
            problems = check(out)
        if problems:
            raise rec.RecipeError("structural checks failed:\n  " + "\n  ".join(problems))
        print("OK %s" % out)
    except (rec.RecipeError, ValueError, OSError) as e:
        print("build_plain_dylib: error: %s" % e, file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
