"""Host test of build_l5_prefix.py's libswiftCore stand-in: structural precheck, install safety.

Run with python3 -I. Synthetic Mach-O files need nothing else; the cases that build the stand-in with
the real linker run when LD64 is set and SKIP otherwise. REAL_LIBSWIFTCORE (default
~/src/darling/src/external/swift/libswiftCore.dylib when it exists) adds Darling's real file.
"""
import importlib.util
import os
import struct
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
sys.dont_write_bytecode = True
spec = importlib.util.spec_from_file_location("build_l5_prefix", os.path.join(HERE, "build_l5_prefix.py"))
bp = importlib.util.module_from_spec(spec)
spec.loader.exec_module(bp)

LD64 = os.environ.get("LD64", "")
REAL = os.environ.get("REAL_LIBSWIFTCORE") or os.path.expanduser("~/src/darling/src/external/swift/libswiftCore.dylib")
failures = 0


def check(desc, ok, detail=""):
    global failures
    print(("PASS " if ok else "FAIL ") + desc + ("" if ok else ": %s" % detail))
    failures += 0 if ok else 1


def skip(desc):
    print("SKIP " + desc)


def pad8(b):
    return b + b"\0" * (-len(b) % 8)


def dylib_cmd(cmd, path, cur, compat):
    name = pad8(path.encode() + b"\0")
    return struct.pack("<IIIIII", cmd, 24 + len(name), 24, 2, cur, compat) + name


def macho(cputype=0x0100000C, cpusubtype=0, filetype=6, install=bp.SWIFT_INSTALL_NAME,
          cur=0, compat=0x10000, deps=(), sections=(), symbols=(), dyld_sizes=(0, 0, 0, 0, 0), extra_cmds=(), segments=()):
    """A minimal 64-bit Mach-O dylib with just the load commands the parser reads."""
    cmds = [dylib_cmd(0xD, install, cur, compat)]
    cmds += [dylib_cmd(0xC, d, 0x10000, 0x10000) for d in deps]
    segs = {}
    for g, s, *sz in sections:
        segs.setdefault(g, []).append(struct.pack("<16s16sQQIIIIIIII", s.encode(), g.encode(), 0, sz[0] if sz else 0,
                                                  0, 0, 0, 0, 0, 0, 0, 0))
    for g in segments:
        segs.setdefault(g, [])
    for g, secs in (segs or {"__TEXT": []}).items():
        cmds.append(struct.pack("<II16sQQQQIIII", 0x19, 72 + 80 * len(secs), g.encode(), 0, 0, 0, 0, 3, 3,
                                len(secs), 0) + b"".join(secs))
    strtab = b"\0" + b"".join(s.encode() + b"\0" for s in symbols)
    nlist, off = b"", 1
    for s in symbols:
        nlist += struct.pack("<IBBHQ", off, 0x0F, 1, 0, 0x1000)
        off += len(s) + 1
    body = nlist + pad8(strtab)
    hdr_len = 32 + sum(len(c) for c in cmds) + 24 + 48 + 16 * len(extra_cmds)
    cmds.append(struct.pack("<IIIIII", 0x2, 24, hdr_len, len(symbols), hdr_len + len(nlist), len(strtab)))
    cmds.append(struct.pack("<II10I", 0x80000022, 48, 0, dyld_sizes[0], 0, dyld_sizes[1], 0, dyld_sizes[2], 0,
                            dyld_sizes[3], 0, dyld_sizes[4]))
    cmds += [struct.pack("<IIII", c, 16, 0, 0) for c in extra_cmds]
    blob = b"".join(cmds)
    return struct.pack("<IIIIIIII", 0xFEEDFACF, cputype, cpusubtype, filetype, len(cmds), len(blob), 0, 0) \
        + blob + body


def fat_slice(path, cputype):
    with open(path, "rb") as f:
        data = f.read()
    magic, n = struct.unpack_from(">II", data, 0)
    if magic != 0xCAFEBABE:
        return data
    for i in range(n):
        ct, _st, off, size, _al = struct.unpack_from(">iiIII", data, 8 + 20 * i)
        if ct & 0xFFFFFFFF == cputype:
            return data[off:off + size]
    raise SystemExit("no slice for cputype 0x%x in %s" % (cputype, path))


def write(d, name, data):
    p = os.path.join(d, name)
    with open(p, "wb") as f:
        f.write(data)
    return p


# name of the one check each variant must trip -> the variant
VARIANTS = {
    "arm64e": ("cpu", dict(cpusubtype=2)),
    "x86_64": ("cpu", dict(cputype=0x01000007)),
    "executable": ("filetype", dict(filetype=2)),
    "wrong install name": ("install-name", dict(install="/usr/lib/swift/libswiftCore2.dylib")),
    "wrong current version": ("versions", dict(cur=0x10000)),
    "wrong compatibility version": ("versions", dict(compat=0x20000)),
    "exported symbol": ("exports", dict(symbols=("_swift_retain",))),
    "export trie in LC_DYLD_INFO": ("exports", dict(dyld_sizes=(0, 0, 0, 0, 8))),
    "rebase data": ("fixups", dict(dyld_sizes=(8, 0, 0, 0, 0))),
    "bind data": ("fixups", dict(dyld_sizes=(0, 8, 0, 0, 0))),
    "weak bind data": ("fixups", dict(dyld_sizes=(0, 0, 8, 0, 0))),
    "lazy bind data": ("fixups", dict(dyld_sizes=(0, 0, 0, 8, 0))),
    "LC_DYLD_EXPORTS_TRIE": ("commands", dict(extra_cmds=(0x80000033,))),
    "dependency": ("dylibs", dict(deps=("/usr/lib/libSystem.B.dylib",))),
    "__objc_ section": ("sections", dict(sections=(("__DATA", "__objc_imageinfo"),))),
    "__swift5_ section": ("sections", dict(sections=(("__TEXT", "__swift5_types"),))),
    "__mod_init_func section": ("sections", dict(sections=(("__DATA", "__mod_init_func"),))),
    "non-empty __text": ("sections", dict(sections=(("__TEXT", "__text", 4),))),
    "LC_ROUTINES_64": ("commands", dict(extra_cmds=(0x1A,))),
    "LC_ROUTINES": ("commands", dict(extra_cmds=(0x11,))),
    "LC_MAIN": ("commands", dict(extra_cmds=(0x80000028,))),
    "LC_UNIXTHREAD": ("commands", dict(extra_cmds=(0x5,))),
    "a __DATA segment": ("sections", dict(sections=(("__DATA", "__text"),))),
    "a sectionless extra segment": ("sections", dict(segments=("__EXTRA",))),
}

with tempfile.TemporaryDirectory(prefix="l5-prefix-unit-") as tmp:
    good = write(tmp, "good", macho())
    check("a synthetic stand-in passes every check", bp.problems_standin(good) == [], bp.problems_standin(good))
    check("the check table names the nine properties", sorted(bp.STANDIN_CHECKS) == sorted(
        {"cpu", "filetype", "install-name", "versions", "exports", "fixups", "dylibs", "sections", "commands"}))
    empty_text = write(tmp, "empty-text", macho(sections=(("__TEXT", "__text"),)))
    check("an empty __TEXT,__text (what ld64 emits) passes", bp.problems_standin(empty_text) == [])

    for desc, (name, kw) in VARIANTS.items():
        p = write(tmp, "bad", macho(**kw))
        got = bp.problems_standin(p)
        check("%s fails the %s check and no other" % (desc, name),
              got != [] and all(": %s: " % name in g for g in got), got)
        saved = bp.STANDIN_CHECKS[name]
        bp.STANDIN_CHECKS[name] = lambda m: []
        slipped = bp.problems_standin(p)
        bp.STANDIN_CHECKS[name] = saved
        check("mutation: without the %s check, %s passes" % (name, desc), slipped == [], slipped)

    real_like = write(tmp, "real-like", macho(symbols=("_swift_retain",), deps=("/usr/lib/libSystem.B.dylib",),
                                              sections=(("__TEXT", "__swift5_types"), ("__DATA", "__objc_classlist"))))
    got = bp.problems_standin(real_like)
    check("a dylib with the real file's name and versions but its contents fails exports, dylibs and sections",
          sorted({g.split(": ")[1] for g in got}) == ["dylibs", "exports", "sections"], got)
    pointer = write(tmp, "pointer", b"version https://git-lfs.github.com/spec/v1\noid sha256:%s\nsize 17429376\n" % (b"3" * 64))
    check("a git-lfs pointer fails", bp.problems_standin(pointer) != [])
    check("an empty file fails", bp.problems_standin(write(tmp, "empty", b"")) != [])
    check("a truncated stand-in fails", bp.problems_standin(write(tmp, "trunc", macho()[:40])) != [])
    check("a missing file fails", bp.problems_standin(os.path.join(tmp, "nope")) != [])
    os.symlink(good, os.path.join(tmp, "link"))
    check("a symlink to a good stand-in fails (the tool never writes one)", bp.problems_standin(os.path.join(tmp, "link")) != [])
    if os.path.isfile(REAL):
        check("Darling's real libswiftCore (the fat 17 MB file) fails", bp.problems_standin(REAL) != [])
        thin = write(tmp, "real-arm64", fat_slice(REAL, bp.rec.CPU_TYPE_ARM64))
        got = bp.problems_standin(thin)
        check("its arm64 slice has the stand-in's name and versions but fails exports, dylibs, sections and commands",
              sorted({g.split(": ")[1] for g in got}) == ["commands", "dylibs", "exports", "sections"], got)
    else:
        skip("the real libswiftCore is not at %s" % REAL)

    # overwrite policy: only an absent file, a git-lfs pointer or an earlier stand-in may be replaced
    check("install may create an absent libswiftCore", bp.swift_overwrite_problem(os.path.join(tmp, "absent")) is None)
    check("install may replace a git-lfs pointer", bp.swift_overwrite_problem(pointer) is None)
    check("install may replace an earlier stand-in", bp.swift_overwrite_problem(good) is None)
    check("install refuses a real-like dylib", bp.swift_overwrite_problem(real_like) is not None)
    check("install refuses a symlink", bp.swift_overwrite_problem(os.path.join(tmp, "link")) is not None)
    check("install refuses a directory", bp.swift_overwrite_problem(tmp) is not None)
    check("install refuses an unrelated file", bp.swift_overwrite_problem(write(tmp, "other", b"x" * 2000)) is not None)
    check("install refuses a large file that merely starts like a git-lfs pointer",
          bp.swift_overwrite_problem(write(tmp, "biglfs", bp.LFS_PREFIX + b"x" * 5000)) is not None)

    root = os.path.join(tmp, "root")
    dst = bp.swift_path(root)
    os.makedirs(os.path.dirname(dst))
    keep = macho(symbols=("_swift_retain",))
    write(os.path.dirname(dst), os.path.basename(dst), keep)
    r = subprocess.run([sys.executable, "-I", os.path.join(HERE, "build_l5_prefix.py"), "install", "--root", root],
                       capture_output=True, text=True, env={k: v for k, v in os.environ.items() if k != "LD64"})
    with open(dst, "rb") as f:
        untouched = f.read() == keep
    check("install over a non-stand-in exits nonzero, says so, and leaves the file and the stub path alone",
          r.returncode != 0 and "refusing to replace libswiftCore" in (r.stderr + r.stdout) and untouched
          and not os.path.exists(bp.stub_path(root)), r.stderr)

    if LD64:
        os.environ["LD64"] = LD64
        built = os.path.join(tmp, "built")
        try:
            bp.build_standin(built, ld64=LD64)
        except SystemExit as e:
            check("a stand-in built by the tool passes", False, e)
            sys.exit(1)
        check("a stand-in built by the tool passes", bp.problems_standin(built) == [], bp.problems_standin(built))
        check("the tool's build leaves no .partial file", not os.path.exists(built + ".partial"))

        root2 = os.path.join(tmp, "root2")
        d2 = bp.swift_path(root2)
        os.makedirs(os.path.dirname(d2))
        write(os.path.dirname(d2), "libswiftCore.dylib", open(pointer, "rb").read())
        tool = [sys.executable, "-I", os.path.join(HERE, "build_l5_prefix.py")]
        r = subprocess.run(tool + ["install", "--root", root2], capture_output=True, text=True)
        check("install replaces a git-lfs pointer, then precheck passes", r.returncode == 0
              and bp.problems_standin(d2) == [], r.stderr + r.stdout)
        link = os.path.join(tmp, "second-name")
        os.link(d2, link)
        before = open(link, "rb").read()
        r = subprocess.run(tool + ["install", "--root", root2], capture_output=True, text=True)
        check("install over an earlier stand-in succeeds and does not rewrite a hard link's inode",
              r.returncode == 0 and open(link, "rb").read() == before and os.stat(d2).st_nlink == 1, r.stderr)
        root3 = os.path.join(tmp, "root3")
        r = subprocess.run(tool + ["install", "--root", root3, "--stub", good], capture_output=True, text=True)
        check("install with a --stub that is not the libRosetta stub exits nonzero and writes nothing",
              r.returncode != 0 and "bad stub" in r.stderr and not os.path.exists(root3), r.stderr)
        check("the standalone precheck passes", subprocess.run(tool + ["precheck", "--root", root2],
                                                               capture_output=True).returncode == 0)
        os.remove(d2)
        write(os.path.dirname(d2), "libswiftCore.dylib", macho(symbols=("_swift_retain",)))
        r = subprocess.run(tool + ["precheck", "--root", root2], capture_output=True, text=True)
        check("precheck fails when libswiftCore exports a symbol", r.returncode != 0 and "exports" in r.stderr, r.stderr)
        os.remove(d2)
        r = subprocess.run(tool + ["precheck", "--root", root2], capture_output=True, text=True)
        check("precheck fails when libswiftCore is missing", r.returncode != 0 and "missing" in r.stderr, r.stderr)
        write(os.path.dirname(d2), "libswiftCore.dylib", open(built, "rb").read())
        os.remove(bp.stub_path(root2))
        r = subprocess.run(tool + ["precheck", "--root", root2], capture_output=True, text=True)
        check("precheck still fails on a missing libRosetta stub", r.returncode != 0 and "libRosetta" in r.stderr, r.stderr)
    else:
        skip("builds with the real linker (set LD64)")

sys.exit(1 if failures else 0)
