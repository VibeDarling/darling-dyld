#!/usr/bin/env python3
"""Build the L5 libRosetta disk stub and install it with libswiftCore into a Darling runtime root.

  build_l5_prefix.py stub --out FILE                # build + check libRosetta.dylib (needs LD64)
  build_l5_prefix.py install --root DIR --swift-source FILE [--stub FILE] [--ld64 PATH]
  build_l5_prefix.py precheck --root DIR --swift-source FILE

ROOT is a runtime root as it appears inside the guest: a DARLING_INSTALL_PREFIX copy
(<build>/prefix/libexec/darling) or a DPREFIX. The stub is installed at usr/lib/libRosetta.dylib, so
the cache's libobjc binds to disk instead of the cache's libRosetta; the swift source's real dylib
replaces the git-lfs pointer at usr/lib/swift/libswiftCore.dylib. install validates the captured
bytes before writing them and runs precheck at the end; precheck fails loud on anything a pointer
file would satisfy. Run with python3 -I.
"""
import argparse
import hashlib
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
# the one dylib the build's git-lfs pointer stands in for; a different one is not this task's input
SWIFT_SHA256 = "30b5c17c4605133b01d265bdd5801b9eec43a3a751f0951a49c3dda23c34348a"
SWIFT_SIZE = 17429376
LFS_PREFIX = b"version https://git-lfs"


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


def problems_swift_bytes(data, name):
    if len(data) != SWIFT_SIZE:
        return ["%s is %d bytes, expected %d (a git-lfs pointer?)" % (name, len(data), SWIFT_SIZE)]
    if data.startswith(LFS_PREFIX):
        return ["%s is a git-lfs pointer, not the dylib" % name]
    sha = hashlib.sha256(data).hexdigest()
    if sha != SWIFT_SHA256:
        return ["%s sha256 %s, expected %s" % (name, sha, SWIFT_SHA256)]
    return []


def problems_swift(path):
    if not os.path.isfile(path):
        return ["%s is missing" % path]
    with open(path, "rb") as f:
        return problems_swift_bytes(f.read(), path)


def build_stub(out, ld64=None):
    rec.build([os.path.join(HERE, STUB_SOURCE)], out, kind="dylib", install_name=STUB_INSTALL_NAME,
              cflags=["-ffreestanding", "-fno-builtin", "-O1"], ld64=ld64)
    problems = problems_stub(out)
    if problems:
        raise SystemExit("built stub has problems: " + "; ".join(problems))


def write_bytes(data, dst):
    os.makedirs(os.path.dirname(dst), exist_ok=True)
    with open(dst, "wb") as f:
        f.write(data)
    os.chmod(dst, 0o755)


def precheck(root, swift_source, out=sys.stdout):
    problems = problems_stub(stub_path(root)) + problems_swift(swift_path(root)) + problems_swift(swift_source)
    if problems:
        raise SystemExit("PRECHECK FAILED:\n  " + "\n  ".join(problems))
    out.write("precheck: %s exports %s\n" % (stub_path(root), " ".join(sorted(STUB_EXPORTS))))
    out.write("precheck: %s is %d bytes, sha256 %s\n" % (swift_path(root), SWIFT_SIZE, SWIFT_SHA256))


def install(root, swift_source, stub=None, ld64=None):
    with open(swift_source, "rb") as f:
        swift = f.read()
    problems = problems_swift_bytes(swift, swift_source)
    if problems:
        raise SystemExit("bad swift source: " + "; ".join(problems))
    if stub is None:
        with tempfile.TemporaryDirectory(prefix="l5-stub-") as tmp:
            stub = os.path.join(tmp, os.path.basename(STUB_INSTALL_NAME))
            build_stub(stub, ld64=ld64)
            with open(stub, "rb") as f:
                write_bytes(f.read(), stub_path(root))
    else:
        problems = problems_stub(stub)
        if problems:
            raise SystemExit("bad stub: " + "; ".join(problems))
        with open(stub, "rb") as f:
            write_bytes(f.read(), stub_path(root))
    write_bytes(swift, swift_path(root))
    precheck(root, swift_source)


def main(argv):
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    sub = ap.add_subparsers(dest="cmd", required=True)
    s = sub.add_parser("stub")
    s.add_argument("--out", required=True)
    s.add_argument("--ld64")
    i = sub.add_parser("install")
    i.add_argument("--root", required=True)
    i.add_argument("--swift-source", required=True)
    i.add_argument("--stub")
    i.add_argument("--ld64")
    p = sub.add_parser("precheck")
    p.add_argument("--root", required=True)
    p.add_argument("--swift-source", required=True)
    a = ap.parse_args(argv)
    if a.cmd == "stub":
        build_stub(a.out, a.ld64)
        print("built", a.out)
    elif a.cmd == "install":
        install(a.root, a.swift_source, a.stub, a.ld64)
    else:
        precheck(a.root, a.swift_source)


if __name__ == "__main__":
    main(sys.argv[1:])
