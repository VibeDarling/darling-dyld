#!/usr/bin/env python3
"""Build the L5 libRosetta disk stub and an empty libswiftCore stand-in and install them into a Darling runtime root.

  build_l5_prefix.py stub --out FILE                # build + check libRosetta.dylib (needs LD64)
  build_l5_prefix.py install --root DIR [--stub FILE] [--ld64 PATH]
  build_l5_prefix.py precheck --root DIR

ROOT is a runtime root as it appears inside the guest: a DARLING_INSTALL_PREFIX copy
(<build>/prefix/libexec/darling) or a DPREFIX. The stub is installed at usr/lib/libRosetta.dylib, so
the cache's libobjc binds to disk instead of the cache's libRosetta. usr/lib/swift/libswiftCore.dylib
becomes an empty plain-arm64 dylib with the real file's install name and versions: libobjc only
LC_LOADs libswiftCore (it imports nothing from it), and Darling's real plain-arm64 libswiftCore hands
the cache's arm64e libobjc unsigned hook pointers, which trap. install builds both files before
writing either, replaces libswiftCore only when it is absent, a git-lfs pointer or an earlier
stand-in (anything else is refused, never overwritten), and runs precheck at the end; precheck fails
loud on anything but the stand-in, including the real 17 MB dylib. Run with python3 -I.
"""
import argparse
import os
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
sys.dont_write_bytecode = True
sys.path[:0] = [os.path.dirname(HERE)]
import arm64e_link as rec  # noqa: E402  (the 3.3a recipe, reused as is)

STUB_SOURCE = "rosetta_stub.c"
STUB_INSTALL_NAME = "/usr/lib/libRosetta.dylib"
STUB_EXPORTS = {"_rosetta_is_current_process_translated", "_objc_thread_get_rip"}
SWIFT_INSTALL_NAME = "/usr/lib/swift/libswiftCore.dylib"
# the real file's LC_ID_DYLIB values, as (current, compatibility)
SWIFT_VERSIONS = (0x00000000, 0x00010000)
SWIFT_TARGET = "arm64-apple-macos13"
LFS_PREFIX = b"version https://git-lfs"
LFS_POINTER_MAX = 1024
# the load commands ld64 emits for an empty dylib; anything else (initializers, LC_MAIN, an exports trie,
# a thread state) could run or export something. Dylib dependencies have their own check.
STANDIN_COMMANDS = {
    rec.LC_SEGMENT_64, rec.LC_ID_DYLIB, rec.LC_DYLD_INFO_ONLY, rec.LC_SYMTAB, rec.LC_BUILD_VERSION,
    0xB,         # LC_DYSYMTAB
    0x1B,        # LC_UUID
    0x2A,        # LC_SOURCE_VERSION
    0x2C,        # LC_ENCRYPTION_INFO_64
    0x1E,        # LC_SEGMENT_SPLIT_INFO
    0x26,        # LC_FUNCTION_STARTS
    0x29,        # LC_DATA_IN_CODE
}
STANDIN_SEGMENTS = {"__TEXT", "__LINKEDIT"}


def stub_path(root):
    return os.path.join(root, STUB_INSTALL_NAME.lstrip("/"))


def swift_path(root):
    return os.path.join(root, SWIFT_INSTALL_NAME.lstrip("/"))


def problems_stub(path):
    try:
        m = rec.load_macho(path)
    except rec.RecipeError as e:
        return [str(e)]
    out = []
    if (m.cputype, m.cpusubtype, m.filetype) != (
            rec.CPU_TYPE_ARM64, rec.CPU_SUBTYPE_ARM64E, rec.MH_DYLIB):
        out.append("%s is not an arm64e dylib" % path)
    if m.install_name != STUB_INSTALL_NAME:
        out.append("install name %r, expected %r" % (m.install_name, STUB_INSTALL_NAME))
    if m.dylibs:
        out.append("stub depends on %r, expected no dependencies" % [p for _c, p in m.dylibs])
    syms = m.symbols()
    if set(syms) != STUB_EXPORTS:
        out.append("exports differ: missing %s, unexpected %s" %
                   (sorted(STUB_EXPORTS - set(syms)), sorted(set(syms) - STUB_EXPORTS)))
    return out


# One entry per structural property of the stand-in; each returns its problems. A dict so the host
# test can drop one check at a time and see its bad dylib slip through.
def _standin_cpu(m):
    if (m.cputype, m.cpusubtype) != (rec.CPU_TYPE_ARM64, 0):
        return ["cpu type/subtype 0x%x/0x%x, expected plain arm64 0x%x/0x0" %
                (m.cputype, m.cpusubtype, rec.CPU_TYPE_ARM64)]
    return []


def _standin_filetype(m):
    return [] if m.filetype == rec.MH_DYLIB else ["filetype %d is not a dylib" % m.filetype]


def _standin_install_name(m):
    if m.install_name != SWIFT_INSTALL_NAME:
        return ["install name %r, expected %r" % (m.install_name, SWIFT_INSTALL_NAME)]
    return []


def _standin_versions(m):
    if m.install_versions != SWIFT_VERSIONS:
        return ["(current, compatibility) version %s, expected %s" % (
            None if m.install_versions is None else tuple(rec.version_str(v) for v in m.install_versions),
            tuple(rec.version_str(v) for v in SWIFT_VERSIONS))]
    return []


def _standin_exports(m):
    out = []
    if m.symbols():
        out.append("defines symbols %s, expected none" % sorted(m.symbols())[:5])
    if m.dyld_info and m.dyld_info[9]:
        out.append("carries an export trie, expected none")
    return out


def _standin_fixups(m):
    """Rebase, bind, weak-bind and lazy-bind data in LC_DYLD_INFO make dyld do work at load."""
    names = ("rebase", "bind", "weak bind", "lazy bind")
    sizes = [m.dyld_info[i] for i in (1, 3, 5, 7)] if m.dyld_info else []
    return ["carries %s data, expected none" % n for n, z in zip(names, sizes) if z]


def _standin_dylibs(m):
    return ["depends on %r, expected no dependencies" % [p for _c, p in m.dylibs]] if m.dylibs else []


def _standin_sections(m):
    """Only __TEXT and __LINKEDIT, holding at most an empty __TEXT,__text: this rejects __objc_*,
    __swift5_* and initializer sections alike."""
    bad = ["%s,%s" % (seg["name"], sec["name"]) for seg in m.segments for sec in seg["sections"]
           if (seg["name"], sec["name"], sec["size"]) != ("__TEXT", "__text", 0)]
    out = ["has %d sections other than an empty __TEXT,__text, among them %s" % (len(bad), bad[:5])] if bad else []
    extra = [seg["name"] for seg in m.segments if seg["name"] not in STANDIN_SEGMENTS]
    return out + (["has segments %s, expected only %s" % (extra, sorted(STANDIN_SEGMENTS))] if extra else [])


def _standin_commands(m):
    extra = sorted(set(m.commands) - STANDIN_COMMANDS - set(rec.DYLIB_ORDINAL_CMDS))
    return ["has load commands %s that ld64 does not emit for an empty dylib" % [hex(c) for c in extra]] if extra else []


STANDIN_CHECKS = {
    "cpu": _standin_cpu, "filetype": _standin_filetype, "install-name": _standin_install_name,
    "versions": _standin_versions, "exports": _standin_exports, "fixups": _standin_fixups,
    "dylibs": _standin_dylibs,
    "sections": _standin_sections, "commands": _standin_commands,
}


def problems_standin(path):
    if os.path.islink(path) or not os.path.isfile(path):
        return ["%s is missing or not a regular file" % path]
    try:
        m = rec.load_macho(path)
    except rec.RecipeError as e:
        return ["not a Mach-O dylib: %s" % e]
    return ["%s: %s: %s" % (path, name, p) for name, check in STANDIN_CHECKS.items() for p in check(m)]


def swift_overwrite_problem(path):
    """None when install may replace path: absent, a git-lfs pointer, or an earlier stand-in."""
    if not os.path.lexists(path):
        return None
    if os.path.isfile(path) and os.path.getsize(path) <= LFS_POINTER_MAX:
        with open(path, "rb") as f:
            if f.read(len(LFS_PREFIX)) == LFS_PREFIX:
                return None
    if os.path.isfile(path) and not problems_standin(path):
        return None
    return ("%s is not a git-lfs pointer or a stand-in this tool built; move it aside "
            "(for example to %s.keep) and rerun" % (path, os.path.basename(path)))


def build_stub(out, ld64=None):
    rec.build([os.path.join(HERE, STUB_SOURCE)], out, kind="dylib", install_name=STUB_INSTALL_NAME,
              cflags=["-ffreestanding", "-fno-builtin", "-O1"], ld64=ld64)
    problems = problems_stub(out)
    if problems:
        raise SystemExit("built stub has problems: " + "; ".join(problems))


def build_standin(out, ld64=None):
    """An empty plain-arm64 dylib built the way the guest build's ld64 builds one (no arm64e recipe)."""
    ld64 = ld64 or os.environ.get("LD64")
    if not ld64 or not (os.path.isfile(ld64) and os.access(ld64, os.X_OK)):
        raise SystemExit("no linker: pass --ld64 or set LD64 to the in-tree ld64 binary (got %r)" % ld64)
    clang = os.environ.get("CLANG", "clang")
    partial = out + ".partial"
    try:
        with tempfile.TemporaryDirectory(prefix="l5-swiftcore-") as tmp:
            src, obj = os.path.join(tmp, "empty.c"), os.path.join(tmp, "empty.o")
            open(src, "w").close()
            rec.run([clang, "--target=" + SWIFT_TARGET, "-c", src, "-o", obj], False)
            rec.run([ld64, "-dylib", "-arch", "arm64", "-platform_version", "macos", "13.0", "13.0",
                     "-install_name", SWIFT_INSTALL_NAME, "-compatibility_version", "1.0.0",
                     "-current_version", "0.0.0", obj, "-o", partial], False)
        problems = problems_standin(partial)
        if problems:
            raise SystemExit("built stand-in has problems: " + "; ".join(problems))
        os.replace(partial, out)
    finally:
        if os.path.exists(partial):
            os.remove(partial)


def write_bytes(data, dst):
    """Replace dst atomically, so a hard link to dst keeps the old bytes."""
    d = os.path.dirname(dst)
    os.makedirs(d, exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=d, prefix=".l5-")
    try:
        with os.fdopen(fd, "wb") as f:
            f.write(data)
        os.chmod(tmp, 0o755)
        os.replace(tmp, dst)
    except BaseException:
        if os.path.exists(tmp):
            os.remove(tmp)
        raise


def precheck(root, out=sys.stdout):
    problems = problems_stub(stub_path(root)) + problems_standin(swift_path(root))
    if problems:
        raise SystemExit("PRECHECK FAILED:\n  " + "\n  ".join(problems))
    out.write("precheck: %s exports %s\n" % (stub_path(root), " ".join(sorted(STUB_EXPORTS))))
    out.write("precheck: %s is the empty stand-in (%s, no exports, no dependencies)\n" %
              (swift_path(root), SWIFT_INSTALL_NAME))


def install(root, stub=None, ld64=None):
    refused = swift_overwrite_problem(swift_path(root))
    if refused:
        raise SystemExit("refusing to replace libswiftCore: " + refused)
    with tempfile.TemporaryDirectory(prefix="l5-prefix-") as tmp:
        standin = os.path.join(tmp, "libswiftCore.dylib")
        build_standin(standin, ld64=ld64)
        if stub is None:
            stub = os.path.join(tmp, os.path.basename(STUB_INSTALL_NAME))
            build_stub(stub, ld64=ld64)
        else:
            problems = problems_stub(stub)
            if problems:
                raise SystemExit("bad stub: " + "; ".join(problems))
        for src, dst in ((stub, stub_path(root)), (standin, swift_path(root))):
            with open(src, "rb") as f:
                write_bytes(f.read(), dst)
    precheck(root)


def main(argv):
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    sub = ap.add_subparsers(dest="cmd", required=True)
    s = sub.add_parser("stub")
    s.add_argument("--out", required=True)
    s.add_argument("--ld64")
    i = sub.add_parser("install")
    i.add_argument("--root", required=True)
    i.add_argument("--stub")
    i.add_argument("--ld64")
    p = sub.add_parser("precheck")
    p.add_argument("--root", required=True)
    a = ap.parse_args(argv)
    if a.cmd == "stub":
        build_stub(a.out, a.ld64)
        print("built", a.out)
    elif a.cmd == "install":
        install(a.root, a.stub, a.ld64)
    else:
        precheck(a.root)


if __name__ == "__main__":
    main(sys.argv[1:])
