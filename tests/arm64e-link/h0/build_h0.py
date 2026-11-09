#!/usr/bin/env python3
"""Build and structurally check the H0 test executable and its link-only stubs.

  build_h0.py build --out DIR [--libsystem stub|sdk] [--libz-symbols FILE]
  build_h0.py check EXE [--expected FILE]

LD64 (in-tree ld64) comes from the environment; --libsystem sdk also needs SDKROOT.
The default links a link-only libSystem stub (see README.md for why); sdk links
the SDK's libSystem.dylib and exists to show both give the same import table.
Nothing is executed and the stubs are never installed. Run with python3 -I.
"""
import argparse
import json
import os
import struct
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
sys.dont_write_bytecode = True
sys.path[:0] = [HERE, os.path.dirname(HERE)]
import arm64e_link as rec  # noqa: E402  (the 3.3a recipe, reused as is)
import gen_stub  # noqa: E402

CFLAGS = ["-ffreestanding", "-fno-builtin", "-fno-stack-protector", "-O1"]
BRK_1 = 0xD4200020  # what __builtin_trap() compiles to on arm64

# name: (install name, symbol list, compat, current, output file)
STUBS = {
    "libz": ("/usr/lib/libz.1.dylib", "libz_symbols.txt", "1.0.0", "1.2.12", "libz.1.linkonly.dylib"),
    "libsystem": ("/usr/lib/libSystem.B.dylib", "libsystem_symbols.txt", "1.0.0", "1351.0.0",
                  "libSystem.B.linkonly.dylib"),
}


def build_stub(which, out_dir, symbols_file=None):
    install, symbols, compat, current, fname = STUBS[which]
    names = gen_stub.read_symbols(symbols_file or os.path.join(HERE, symbols))
    out = os.path.join(out_dir, fname)
    with tempfile.TemporaryDirectory(prefix="h0-stub-") as tmp:
        inc = os.path.join(tmp, "symbols.inc")
        gen_stub.write_inc(names, inc)
        rec.build([os.path.join(HERE, "libz_stub.c")], out, kind="dylib",
                  cflags=CFLAGS + ['-DSTUB_SYMBOLS="%s"' % inc], install_name=install,
                  ld_args=["-compatibility_version", compat, "-current_version", current])
    return out


def build_exe(out_dir, libz, libsystem, sdkroot=None):
    out = os.path.join(out_dir, "h0_zlib_main")
    # libz before libSystem: the order clang's driver gives (-lz, then the implicit -lSystem)
    if libsystem == "sdk":
        libs = [libz, "-lSystem"]
        ld_args = ["-syslibroot", sdkroot]
    else:
        libs, ld_args = [libz, libsystem], []
    rec.build([os.path.join(HERE, "h0_zlib_main.c")], out, kind="exe", cflags=CFLAGS,
              entry="_main", libs=libs, ld_args=ld_args)
    return out


def build_all(out_dir, mode="stub", libz_symbols=None):
    sdkroot = None
    if mode == "sdk":
        sdkroot = os.environ.get("SDKROOT")
        if not sdkroot or not os.path.isdir(sdkroot):
            raise rec.RecipeError("--libsystem sdk needs SDKROOT set to the SDK root")
    elif mode != "stub":
        raise rec.RecipeError("libsystem mode must be stub or sdk, not %r" % mode)
    os.makedirs(out_dir, exist_ok=True)
    libz = build_stub("libz", out_dir, libz_symbols)
    libsystem = build_stub("libsystem", out_dir) if mode == "stub" else "sdk"
    return {"libz": libz, "libsystem": libsystem, "exe": build_exe(out_dir, libz, libsystem, sdkroot)}


# ---------------------------------------------------------------------- checks

def check_stub(path, which, symbols_file=None):
    """Problems with a link-only stub: install name, versions, exports, trap bodies."""
    install, symbols, compat, current, _ = STUBS[which]
    want = {"_" + n for n in gen_stub.read_symbols(symbols_file or os.path.join(HERE, symbols))}
    problems = []
    try:
        m = rec.load_macho(path)
    except rec.RecipeError as e:
        return [str(e)]
    if (m.cputype, m.cpusubtype, m.filetype) != (rec.CPU_TYPE_ARM64, rec.CPU_SUBTYPE_ARM64E, rec.MH_DYLIB):
        problems.append("%s is not an arm64e dylib" % path)
    if m.install_name != install:
        problems.append("install name %r, expected %r" % (m.install_name, install))
    got = tuple(rec.version_str(v) for v in m.install_versions or ())
    if got != (current, compat):
        problems.append("versions (current, compat) %r, expected %r" % (got, (current, compat)))
    if m.dylibs:
        problems.append("stub depends on %r, expected no dependencies" % [p for _c, p in m.dylibs])
    syms = m.symbols()
    if set(syms) != want:
        problems.append("exports differ: missing %s, unexpected %s" %
                        (sorted(want - set(syms)), sorted(set(syms) - want)))
    for name, addr in sorted(syms.items()):
        try:
            insn = struct.unpack("<I", m.read_vm(addr, 4))[0]
        except rec.RecipeError as e:
            problems.append(str(e))
            continue
        if insn != BRK_1:
            problems.append("%s does not start with brk #1 (0x%08x)" % (name, insn))
    return problems


def check_exe(path, expected_file=None):
    """Problems with the test executable against expected.json; empty means it passed."""
    with open(expected_file or os.path.join(HERE, "expected.json")) as f:
        exp = json.load(f)
    try:
        m, dec = rec.verify_output(path, "exe")  # arm64e, macOS, chained fixups, walkable chains
    except rec.RecipeError as e:
        return [str(e)]
    problems = []
    if m.dyld_info is not None or rec.LC_DYLD_INFO in m.commands or rec.LC_DYLD_INFO_ONLY in m.commands:
        problems.append("LC_DYLD_INFO present")
    if m.entry_offset is None:
        problems.append("no LC_MAIN")
    else:
        text = next((s for s in m.segments if s["name"] == "__TEXT"), None)
        if text is None or not 0 < m.entry_offset < text["filesize"]:
            problems.append("LC_MAIN entryoff 0x%x is outside __TEXT" % m.entry_offset)
    cmds = [c for c, _p in m.dylibs]
    if any(c != rec.LC_LOAD_DYLIB for c in cmds):
        problems.append("dependencies must all be plain LC_LOAD_DYLIB, got %s" % [hex(c) for c in cmds])
    got = [{"path": p, "compat": rec.version_str(v[1])} for (_c, p), v in zip(m.dylibs, m.dylib_versions)]
    if got != exp["load_dylibs"]:
        problems.append("dependencies %s, expected %s" % (got, exp["load_dylibs"]))
    ordinal_of = {d["path"]: i + 1 for i, d in enumerate(exp["load_dylibs"])}
    want = {i["name"]: ordinal_of[i["lib"]] for i in exp["imports"]}
    imports = {}
    for imp in dec["imports"]:
        if imp["name"] in imports:
            problems.append("import %s listed twice" % imp["name"])
        imports[imp["name"]] = imp["ordinal"]
    if imports != want:
        problems.append("imports differ: missing %s, unexpected %s, wrong ordinal %s" % (
            sorted(set(want) - set(imports)), sorted(set(imports) - set(want)),
            sorted(n for n in set(want) & set(imports) if want[n] != imports[n])))
    ab = exp["auth_bind"]
    bound = []
    for f in dec["fixups"]:
        if f["kind"] != "auth_bind":
            problems.append("fixup at 0x%x is %s, expected only auth_bind" % (f["vmaddr"], f["kind"]))
            continue
        bound.append(f["import"])
        if (f["key"], f["addr_div"], f["diversity"]) != (ab["key"], ab["addr_div"], ab["diversity"]):
            problems.append("%s auth bind is key %s addr_div %s diversity %d" %
                            (f["import"], f["key"], f["addr_div"], f["diversity"]))
        if f["section"] != "__DATA_CONST,__auth_got":
            problems.append("%s bind lives in %s, expected __auth_got" % (f["import"], f["section"]))
        if f["lib_ordinal"] != want.get(f["import"]):
            problems.append("%s bound to ordinal %d, expected %s" % (f["import"], f["lib_ordinal"], want.get(f["import"])))
    if sorted(bound) != sorted(want):
        problems.append("auth binds %s, expected one per expected import" % sorted(bound))
    return problems


def report(path):
    m, dec = rec.verify_output(path, "exe")
    print("%s: arm64e executable, LC_MAIN entryoff 0x%x" % (os.path.basename(path), m.entry_offset or 0))
    for (_c, p), v in zip(m.dylibs, m.dylib_versions):
        print("  LC_LOAD_DYLIB %s (current %s, compat %s)" % (p, rec.version_str(v[0]), rec.version_str(v[1])))
    for f in dec["fixups"]:
        print("  %-14s ordinal %d %-14s %s addr_div=%s diversity=%d" % (
            f["section"].split(",")[1], f["lib_ordinal"], f["import"], f["key"], f["addr_div"], f["diversity"]))


def main(argv):
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    sub = ap.add_subparsers(dest="cmd", required=True)
    b = sub.add_parser("build")
    b.add_argument("--out", required=True)
    b.add_argument("--libsystem", choices=("stub", "sdk"), default="stub")
    b.add_argument("--libz-symbols")
    c = sub.add_parser("check")
    c.add_argument("exe")
    c.add_argument("--expected")
    a = ap.parse_args(argv)
    try:
        if a.cmd == "build":
            paths = build_all(a.out, a.libsystem, a.libz_symbols)
            problems = check_stub(paths["libz"], "libz", a.libz_symbols)
            if a.libsystem == "stub":
                problems += check_stub(paths["libsystem"], "libsystem")
            problems += check_exe(paths["exe"])
            if problems:
                raise rec.RecipeError("structural checks failed:\n  " + "\n  ".join(problems))
            report(paths["exe"])
            print("OK %s" % paths["exe"])
        else:
            problems = check_exe(a.exe, a.expected)
            if problems:
                raise rec.RecipeError("structural checks failed:\n  " + "\n  ".join(problems))
            report(a.exe)
            print("OK %s" % a.exe)
    except (rec.RecipeError, ValueError, OSError) as e:
        print("build_h0: error: %s" % e, file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
