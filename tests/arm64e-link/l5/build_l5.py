#!/usr/bin/env python3
"""Build and structurally check the L5 test: an arm64e executable linked against a link-only stub
of /usr/lib/libobjc.A.dylib and the Darling SDK's libSystem family.

  build_l5.py build --out DIR               # needs LD64 and SDKROOT (the Darling SDK root)
  build_l5.py check EXE [--prefix DIR]      # structural checks; --prefix also proves no stub was installed
  build_l5.py native --out EXE [--hash-skew N]   # the same harness on the host (not Mach-O)

The stub's symbols come from the compiled test's own undefined names, split against the SDK's
libSystem exports and the checked-in libobjc import list (l5_imports.txt), so the stub and the link
cannot go stale silently: a new import fails the build until the list or the test changes. Nothing
is executed and the stub is never installed (see ../h0/README.md on link-only stubs). Run with
python3 -I.
"""
import argparse
import os
import struct
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.dont_write_bytecode = True
sys.path[:0] = [HERE, os.path.join(ROOT, "abi"), os.path.join(ROOT, "h0"), os.path.join(ROOT, "l4"), ROOT]
import arm64e_link as rec  # noqa: E402  (the 3.3a recipe, reused as is)
import build_abi  # noqa: E402  (SDK paths and the PAC instruction scan)
import build_h0  # noqa: E402  (the stub compile flags and the trap-body check constant)
import build_l4  # noqa: E402  (the SDK export reader and the libSystem family glob)
import gen_stub  # noqa: E402

SOURCES = [os.path.join(HERE, "l5_test.c")]
L5_IMPORTS = os.path.join(HERE, "l5_imports.txt")
OBJC, LIBSYSTEM = "/usr/lib/libobjc.A.dylib", "/usr/lib/libSystem.B.dylib"
DEPENDENCIES = [OBJC, LIBSYSTEM]
ORDINAL = {OBJC: 1, LIBSYSTEM: 2}
OBJC_COMPAT, OBJC_CURRENT = "1.0.0", "228.0.0"   # the cache libobjc's version (T0's measured facts)
STUB_FILE = "libobjc.A.linkonly.dylib"
LINKER_PROVIDED = {"__dso_handle"}               # defined by ld64 in every image, not by a library
ARM64E_LD_ARGS = ["-init_offsets"]               # signed __mod_init_func pointers would be called raw
# imports the checks exist to exercise: name -> the library that must bind it
REQUIRED_IMPORTS = {
    LIBSYSTEM: ["__dyld_objc_class_count", "__dyld_for_objc_header_opt_ro",
                "__dyld_for_objc_header_opt_rw", "__dyld_get_dlopen_image_header",
                "__dyld_lookup_section_info", "__dyld_objc_register_callbacks",
                "__dyld_get_shared_cache_range", "_dladdr"],
    OBJC: ["_objc_getClass", "_objc_msgSend", "_objc_allocateClassPair", "_class_addMethod",
           "_object_dispose", "_object_getClass", "_sel_registerName"],
}


def cflags(sdk):
    return ["-ffreestanding", "-fno-builtin", "-fno-stack-protector", "-O1", "-I",
            os.path.join(ROOT, "abi"), "-isysroot", sdk, "-Wno-incompatible-sysroot",
            "-Wno-unused-command-line-argument"]


def compile_objects(sdk, workdir):
    """A plain compile of the source, only to read its undefined names."""
    obj = os.path.join(workdir, "l5_test.o")
    rec.run([os.environ.get("CLANG", "clang"), "--target=arm64e-apple-macos13", "-c"] +
            cflags(sdk) + [SOURCES[0], "-o", obj], False)
    return [obj]


def partition(undefined, declared, system_names):
    """Split the undefined names into (libSystem, libobjc stub). Anything else, and a declared
    import the test no longer references, is an error: the two lists are the test's contract."""
    system, objc, unknown = [], [], []
    for n in undefined:
        if n in LINKER_PROVIDED:
            continue
        if n in system_names:
            system.append(n)
        elif n in declared:
            objc.append(n)
        else:
            unknown.append(n)
    stale = sorted(set(declared) - set(undefined))
    if unknown:
        raise rec.RecipeError("names neither the SDK's libSystem nor l5_imports.txt provides (add to "
                              "l5_imports.txt if libobjc exports it): %s" % ", ".join(unknown))
    if stale:
        raise rec.RecipeError("l5_imports.txt lists names the test no longer references: %s"
                              % ", ".join(stale))
    return system, objc


def build_objc_stub(out_dir, names):
    """The link-only libobjc stub. Mirrors build_h0.build_stub's recipe; h0's stub table has no
    libobjc row, and h0 is not this task's to change."""
    sub = os.path.join(out_dir, "stubs-arm64e")
    os.makedirs(sub, exist_ok=True)
    symbols = os.path.join(sub, "symbols-libobjc.txt")
    gen_stub.write_symbols(names, symbols, "C names the l5 test imports from %s" % OBJC)
    inc = os.path.join(sub, "symbols.inc")
    gen_stub.write_inc(names, inc)
    out = os.path.join(sub, STUB_FILE)
    rec.build([os.path.join(ROOT, "h0", "libz_stub.c")], out, kind="dylib",
              cflags=build_h0.CFLAGS + ['-DSTUB_SYMBOLS="%s"' % inc], install_name=OBJC,
              ld_args=["-compatibility_version", OBJC_COMPAT, "-current_version", OBJC_CURRENT])
    return out, symbols


def build_probe(out_dir):
    sdk = build_abi.sdk_libs()
    with tempfile.TemporaryDirectory(prefix="l5-objects-") as tmp:
        undefined = gen_stub.undefined_names(compile_objects(sdk, tmp))
    declared = set(gen_stub.read_symbols(L5_IMPORTS))
    system, objc = partition(undefined, declared, build_l4.sdk_exports(sdk))
    stub, symbols = build_objc_stub(out_dir, objc)
    out = os.path.join(out_dir, "l5_probe")
    rec.build(SOURCES, out, kind="exe", cflags=cflags(sdk), entry="_main",
              libs=[stub, "-lSystem"], ld_args=["-syslibroot", sdk] + ARM64E_LD_ARGS)
    return out, stub, symbols, system, objc


def build_native(out, hash_skew=0):
    flags = ["-DABI_NATIVE", "-O1", "-I", os.path.join(ROOT, "abi")]
    if hash_skew:
        flags.append("-DL5_HASH_SKEW=%d" % hash_skew)
    rec.run([os.environ.get("CLANG", "clang")] + flags + [SOURCES[0], "-pthread", "-o", out], False)
    return out


# ---------------------------------------------------------------------- checks

def check_stub(path, symbols):
    """Problems with the libobjc stub: arm64e dylib, its install name, no dependencies, exactly the
    symbols the test needs, each a trap body. The install name is what the executable records."""
    want = {"_" + n for n in gen_stub.read_symbols(symbols)}
    m = rec.load_macho(path)
    problems = []
    if (m.cputype, m.cpusubtype, m.filetype) != (rec.CPU_TYPE_ARM64, rec.CPU_SUBTYPE_ARM64E, rec.MH_DYLIB):
        problems.append("stub is not an arm64e dylib")
    if m.install_name != OBJC:
        problems.append("stub install name %r, expected %r" % (m.install_name, OBJC))
    got = tuple(rec.version_str(v) for v in m.install_versions or ())
    if got != (OBJC_CURRENT, OBJC_COMPAT):
        problems.append("stub versions (current, compat) %r, expected %r"
                        % (got, (OBJC_CURRENT, OBJC_COMPAT)))
    if m.dylibs:
        problems.append("stub depends on %r, expected no dependencies" % [p for _c, p in m.dylibs])
    syms = m.symbols()
    if set(syms) != want:
        problems.append("stub exports differ: missing %s, unexpected %s"
                        % (sorted(want - set(syms)), sorted(set(syms) - want)))
    for name, addr in sorted(syms.items()):
        insn = struct.unpack("<I", m.read_vm(addr, 4))[0]
        if insn != build_h0.BRK_1:
            problems.append("%s does not start with brk #1 (0x%08x)" % (name, insn))
    return problems


def check_exe(path, prefix=None):
    """Problems with the built probe; empty means it passed. `prefix` adds the proof that no
    link-only stub was installed into the private prefix."""
    problems = []
    try:
        m, dec = rec.verify_output(path, "exe")
    except rec.RecipeError as e:
        return [str(e)]
    if m.filetype != rec.MH_EXECUTE or m.cputype != rec.CPU_TYPE_ARM64:
        problems.append("not an arm64 executable")
    if m.cpusubtype != rec.CPU_SUBTYPE_ARM64E:
        problems.append("cpusubtype 0x%x is not arm64e" % m.cpusubtype)
    if m.dyld_info is not None:
        problems.append("LC_DYLD_INFO present next to chained fixups")
    deps = [p for _c, p in m.dylibs]
    if deps != DEPENDENCIES:
        problems.append("dependencies %s, expected %s" % (deps, DEPENDENCIES))
    sections = {s["name"] for seg in m.segments for s in seg["sections"]}
    if "__mod_init_func" in sections:
        problems.append("__mod_init_func holds signed pointers dyld would call raw")
    pac = build_abi.text_words(path)
    if not (pac.get("pacibsp") or pac.get("paciasp")):
        problems.append("no pacibsp/paciasp (return addresses unsigned?)")
    if not (pac.get("blraaz", 0) + pac.get("blraa", 0)):
        problems.append("no authenticated call (function pointers unsigned?)")
    kinds = {f["kind"] for f in dec["fixups"]}
    if "auth_bind" not in kinds:
        problems.append("no authenticated bind in an arm64e executable")
    problems += check_imports({i["name"]: i["ordinal"] for i in dec["imports"]})
    if prefix is not None:
        problems += check_prefix(prefix)
    return problems


def check_imports(names):
    """Every import binds to the library that exports it, and every import the test needs is there."""
    problems = []
    sdk = build_abi.sdk_libs()
    declared = {"_" + n for n in gen_stub.read_symbols(L5_IMPORTS)}
    system_names = build_l4.sdk_exports(sdk)
    for lib, wanted in REQUIRED_IMPORTS.items():
        for n in wanted:
            if names.get(n) != ORDINAL[lib]:
                problems.append("import %s not bound from %s (ordinal %s)" % (n, lib, names.get(n)))
    for n, ordinal in sorted(names.items()):
        c = n[1:]
        want = ORDINAL[OBJC] if n in declared else ORDINAL[LIBSYSTEM] if c in system_names else None
        if want is None:
            problems.append("import %s is exported by no known library" % n)
        elif want != ordinal:
            problems.append("import %s bound with ordinal %d, expected %d" % (n, ordinal, want))
    missing = declared - set(names)
    if missing:
        problems.append("declared libobjc imports not bound: %s" % ", ".join(sorted(missing)))
    return problems


def is_link_stub(path):
    """A stub by its structure, whatever its name: a dylib with no dependencies whose every export
    is a trap body. The prefix's real libobjc has thousands of exports and links dependencies."""
    try:
        m = rec.load_macho(path)
    except (rec.RecipeError, OSError):
        return False
    if m.filetype != rec.MH_DYLIB or m.dylibs:
        return False
    syms = m.symbols()
    if not syms or len(syms) > 64:
        return False
    for addr in syms.values():
        try:
            if struct.unpack("<I", m.read_vm(addr, 4))[0] != build_h0.BRK_1:
                return False
        except rec.RecipeError:
            return False
    return True


def check_prefix(prefix):
    """The link-only stub must never reach the private prefix, under any name. An unreadable
    directory is an error, not a silently weakened check."""
    if not os.path.isdir(prefix):
        raise rec.RecipeError("--prefix %s is not a directory" % prefix)

    def unreadable(e):
        raise rec.RecipeError("cannot walk %s: %s" % (prefix, e))

    problems = []
    for dirpath, _dirnames, filenames in os.walk(prefix, onerror=unreadable):
        for f in filenames:
            path = os.path.join(dirpath, f)
            if "linkonly" in f.lower() or f == STUB_FILE:
                problems.append("link-only stub named in the prefix: %s" % path)
            elif is_link_stub(path):
                problems.append("link-only stub under another name in the prefix: %s" % path)
    return problems


def main(argv):
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    sub = ap.add_subparsers(dest="cmd", required=True)
    b = sub.add_parser("build")
    b.add_argument("--out", required=True)
    c = sub.add_parser("check")
    c.add_argument("exe")
    c.add_argument("--prefix")
    n = sub.add_parser("native")
    n.add_argument("--out", required=True)
    n.add_argument("--hash-skew", type=int, default=0)
    a = ap.parse_args(argv)
    try:
        if a.cmd == "native":
            print("OK %s" % build_native(a.out, a.hash_skew))
        elif a.cmd == "build":
            os.makedirs(a.out, exist_ok=True)
            exe, stub, symbols, system, objc = build_probe(a.out)
            problems = check_stub(stub, symbols) + check_exe(exe)
            if problems:
                raise rec.RecipeError("structural checks failed:\n  " + "\n  ".join(problems))
            print("OK %s (imports: %d libSystem, %d libobjc) stub=%s"
                  % (exe, len(system), len(objc), stub))
        else:
            problems = check_exe(a.exe, a.prefix)
            if problems:
                raise rec.RecipeError("structural checks failed:\n  " + "\n  ".join(problems))
            print("OK %s" % a.exe)
    except (rec.RecipeError, ValueError, OSError) as e:
        print("build_l5: error: %s" % e, file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
