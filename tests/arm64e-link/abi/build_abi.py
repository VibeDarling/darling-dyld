#!/usr/bin/env python3
"""Build and structurally check the ABI probe: an arm64e executable (3.3a recipe) and the same
source as a plain arm64 control.

  build_abi.py build --out DIR      # needs LD64 and SDKROOT (the Darling SDK root)
  build_abi.py check EXE ARCH       # ARCH is arm64e or arm64

Both executables link the Darling SDK's libSystem (a plain arm64 dylib) and a link-only stub for
/usr/lib/libc++abi.dylib built for the same architecture. Nothing is executed; the stub is never
installed (see ../h0/README.md). Run with python3 -I.
"""
import argparse
import os
import struct
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
sys.dont_write_bytecode = True
sys.path[:0] = [HERE, os.path.dirname(HERE), os.path.join(os.path.dirname(HERE), "h0")]
import arm64e_link as rec  # noqa: E402  (the 3.3a recipe, reused as is)
import gen_stub  # noqa: E402  (h0's symbol list reader)

CFLAGS = ["-ffreestanding", "-fno-builtin", "-fno-stack-protector", "-O1", "-fblocks", "-fexceptions",
          "-nostdinc++", "-Wno-unused-command-line-argument"]
SOURCES = ["abi_harness.c", "abi_checks.c", "abi_cxx.cpp"]
STUB_TEMPLATE = os.path.join(os.path.dirname(HERE), "h0", "libz_stub.c")
CXXABI = "/usr/lib/libc++abi.dylib"
ARCHS = ("arm64e", "arm64")
# arm64e variants that remove kinds of signing from the whole executable (mutation probes for the
# C++ checks, where no source-level strip exists): name -> (extra compile flags, also rewrite every
# authenticated bind outside __auth_got as a plain bind). noret: return addresses unsigned.
# noret_unsigned: that plus the personality GOT slot and the typeinfo vtable pointers unsigned.
# nosign: that plus no function-pointer or vtable-pointer signing in the code the compiler emits.
VARIANTS = {
    "noret": (["-fno-ptrauth-returns"], False),
    "noret_unsigned": (["-fno-ptrauth-returns"], True),
    "nosign": (["-fno-ptrauth-returns", "-fno-ptrauth-calls"], True),
}
AUTH_GOT = "__DATA_CONST,__auth_got"
# calls into the plain libs the probe is about; every one must be imported
REQUIRED_IMPORTS = {
    "libSystem": ["_atexit", "___cxa_atexit", "_pthread_key_create", "_pthread_create", "_pthread_once",
                  "_qsort", "_dispatch_async", "_dispatch_once", "__dyld_register_func_for_add_image",
                  "__Unwind_Resume", "__NSConcreteStackBlock", "__NSConcreteGlobalBlock", "_sigaction"],
    "libc++abi": ["___cxa_throw", "___gxx_personality_v0", "__ZTIi",
                  "__ZTVN10__cxxabiv120__si_class_type_infoE"],
}
# arm64e return-address and function-pointer instructions; a plain build has none
PAC_WORDS = {0xD503233F: "paciasp", 0xD503237F: "pacibsp", 0xD50323BF: "autiasp", 0xD50323FF: "autibsp",
             0xD65F0BFF: "retaa", 0xD65F0FFF: "retab"}


# clang would take SDKROOT as its own sysroot (and warn that it is the wrong platform); only the
# linker needs it, so it is read once and removed from the environment the tools inherit.
SDKROOT = os.environ.pop("SDKROOT", None)


def sdk_libs():
    sdk = SDKROOT
    if not sdk or not os.path.isdir(sdk):
        raise rec.RecipeError("set SDKROOT to the Darling SDK root (its usr/lib/libSystem.dylib is linked)")
    return sdk


def plain_link(objects, out, kind, install_name, libs, ld_args, entry):
    ld64 = os.environ.get("LD64")
    if not ld64 or not (os.path.isfile(ld64) and os.access(ld64, os.X_OK)):
        raise rec.RecipeError("set LD64 to the in-tree ld64 binary")
    cmd = [ld64, "-arch", "arm64", "-fixup_chains", "-platform_version", "macos", "13.0", "13.0"]
    cmd += ["-dylib"] if kind == "dylib" else []
    cmd += ["-install_name", install_name] if install_name else []
    cmd += ["-e", entry] if entry else []
    rec.run(cmd + list(ld_args) + objects + list(libs) + ["-o", out], False)


def build_plain(sources, out, kind="exe", cflags=(), install_name=None, entry=None, libs=(), ld_args=()):
    """The control: the arm64e recipe's steps without the caps byte patch, for -arch arm64."""
    with tempfile.TemporaryDirectory(prefix="abi-plain-") as tmp:
        objects = []
        for i, src in enumerate(sources):
            obj = os.path.join(tmp, "%d.o" % i)
            rec.run([os.environ.get("CLANG", "clang"), "--target=arm64-apple-macos13", "-c"] + list(cflags) +
                    [src, "-o", obj], False)
            objects.append(obj)
        plain_link(objects, out, kind, install_name, libs, ld_args, entry)


def build_cxxabi_stub(arch, out_dir):
    out = os.path.join(out_dir, "libc++abi.%s.linkonly.dylib" % arch)
    names = gen_stub.read_symbols(os.path.join(HERE, "libcxxabi_symbols.txt"))
    with tempfile.TemporaryDirectory(prefix="abi-stub-") as tmp:
        inc = os.path.join(tmp, "symbols.inc")
        gen_stub.write_inc(names, inc)
        flags = ["-ffreestanding", "-fno-builtin", "-fno-stack-protector", "-O1", '-DSTUB_SYMBOLS="%s"' % inc]
        versions = ["-compatibility_version", "1.0.0", "-current_version", "1.0.0"]
        if arch == "arm64e":
            rec.build([STUB_TEMPLATE], out, kind="dylib", cflags=flags, install_name=CXXABI, ld_args=versions)
        else:
            build_plain([STUB_TEMPLATE], out, kind="dylib", cflags=flags, install_name=CXXABI, ld_args=versions)
    return out


def unsign_data_binds(path):
    """Rewrite, in place, each authenticated bind outside __auth_got as a plain bind to the same
    import (ordinal and addend kept, chain link kept). Returns the import names of the rewritten
    slots. The __auth_got entries stay signed because the arm64e call stubs authenticate them."""
    m, dec = rec.verify_output(path, "exe")
    data = bytearray(m.data)
    names = []
    for f in dec["fixups"]:
        if f["kind"] != "auth_bind" or f["section"] == AUTH_GOT:
            continue
        seg = m.segment_of(f["vmaddr"])
        off = seg["fileoff"] + f["vmaddr"] - seg["vmaddr"]
        word = struct.unpack_from("<Q", data, off)[0]
        if not (word >> 63) & 1 or not (word >> 62) & 1:
            raise rec.RecipeError("fixup at 0x%x is not an authenticated bind" % f["vmaddr"])
        word &= ~((1 << 63) | (0x7FFFF << 32))      # clear auth and diversity/address-diversity/key
        struct.pack_into("<Q", data, off, word)
        names.append(f["import"])
    with open(path, "wb") as fh:
        fh.write(data)
    return names


def build_probe(arch, out_dir, variant=None):
    sdk = sdk_libs()
    stub = build_cxxabi_stub(arch, out_dir)
    out = os.path.join(out_dir, "abi_probe_" + arch + ("_" + variant if variant else ""))
    cflags = CFLAGS + (VARIANTS[variant][0] if variant else [])
    srcs = [os.path.join(HERE, s) for s in SOURCES]
    libs, ld_args = ["-lSystem", stub], ["-syslibroot", sdk]
    if arch == "arm64e":
        rec.build(srcs, out, kind="exe", cflags=cflags, entry="_main", libs=libs, ld_args=ld_args)
    else:
        build_plain(srcs, out, kind="exe", cflags=cflags, entry="_main", libs=libs, ld_args=ld_args)
    if variant and VARIANTS[variant][1]:
        unsign_data_binds(out)
    return out, stub


# ---------------------------------------------------------------------- checks

def text_words(path):
    """Counts of the PAC instruction words (aligned 4-byte scan of the whole file)."""
    with open(path, "rb") as f:
        data = f.read()
    counts = {}
    for off in range(0, len(data) - 3, 4):
        w = struct.unpack_from("<I", data, off)[0]
        if w in PAC_WORDS:
            counts[PAC_WORDS[w]] = counts.get(PAC_WORDS[w], 0) + 1
    return counts


def import_names(m, arch, path):
    if arch == "arm64e":
        _m, dec = rec.verify_output(path, "exe")
        return {i["name"]: i["ordinal"] for i in dec["imports"]}, dec
    return None, None


def check_exe(path, arch, variant=None):
    """Problems with a built probe executable; empty means it passed."""
    problems = []
    try:
        m = rec.load_macho(path)
        names, dec = import_names(m, arch, path)
    except rec.RecipeError as e:
        return [str(e)]
    if m.filetype != rec.MH_EXECUTE or m.cputype != rec.CPU_TYPE_ARM64:
        problems.append("not an arm64 executable")
    if arch == "arm64e":
        if m.cpusubtype != rec.CPU_SUBTYPE_ARM64E:
            problems.append("cpusubtype 0x%x is not arm64e" % m.cpusubtype)
        kinds = {f["kind"] for f in dec["fixups"]}
        if "auth_bind" not in kinds:
            problems.append("no authenticated bind in an arm64e executable")
    elif m.cpusubtype != 0:
        problems.append("control cpusubtype 0x%x is not plain arm64 (0)" % m.cpusubtype)
    if m.chained is None:
        problems.append("no LC_DYLD_CHAINED_FIXUPS")
    if m.dyld_info is not None and any(m.dyld_info[i] for i in (1, 3, 5, 7)):
        problems.append("LC_DYLD_INFO carries rebase/bind opcodes next to chained fixups")
    deps = [p for _c, p in m.dylibs]
    if deps != ["/usr/lib/libSystem.B.dylib", CXXABI]:
        problems.append("dependencies %s, expected libSystem.B then libc++abi" % deps)
    pac = text_words(path)
    signs_returns = bool(pac.get("pacibsp") or pac.get("paciasp"))
    if arch == "arm64e" and variant not in VARIANTS and not signs_returns:
        problems.append("arm64e executable has no pacibsp/paciasp (return addresses unsigned?)")
    if variant in VARIANTS and signs_returns:
        problems.append("variant %s still signs return addresses %s" % (variant, pac))
    if arch == "arm64" and pac:
        problems.append("plain arm64 control contains PAC instructions %s" % pac)
    if dec is not None and variant and VARIANTS[variant][1]:
        left = [f["import"] for f in dec["fixups"] if f["kind"] == "auth_bind" and f["section"] != AUTH_GOT]
        if left:
            problems.append("authenticated binds outside __auth_got remain in %s: %s" % (variant, left))
        if not any(f["kind"] == "bind" and f.get("import") == "___gxx_personality_v0" for f in dec["fixups"]):
            problems.append("personality slot is not a plain bind in %s" % variant)
    if variant is None and dec is not None and not any(
            f["kind"] == "auth_bind" and f["import"] == "___gxx_personality_v0" for f in dec["fixups"]):
        problems.append("arm64e probe lacks the signed personality slot the C++ checks are about")
    if names is not None:
        for lib, wanted in REQUIRED_IMPORTS.items():
            ordinal = {"libSystem": 1, "libc++abi": 2}[lib]
            for n in wanted:
                if names.get(n) != ordinal:
                    problems.append("import %s not bound from %s (ordinal %s)" % (n, lib, names.get(n)))
    return problems


def main(argv):
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    sub = ap.add_subparsers(dest="cmd", required=True)
    b = sub.add_parser("build")
    b.add_argument("--out", required=True)
    c = sub.add_parser("check")
    c.add_argument("exe")
    c.add_argument("arch", choices=ARCHS)
    c.add_argument("--variant", choices=sorted(VARIANTS))
    a = ap.parse_args(argv)
    try:
        if a.cmd == "build":
            os.makedirs(a.out, exist_ok=True)
            for arch, variant in [(x, None) for x in ARCHS] + [("arm64e", v) for v in VARIANTS]:
                exe, _stub = build_probe(arch, a.out, variant)
                problems = check_exe(exe, arch, variant)
                if problems:
                    raise rec.RecipeError("%s structural checks failed:\n  %s" % (arch, "\n  ".join(problems)))
                print("OK %s" % exe)
        else:
            problems = check_exe(a.exe, a.arch, a.variant)
            if problems:
                raise rec.RecipeError("structural checks failed:\n  " + "\n  ".join(problems))
            print("OK %s" % a.exe)
    except (rec.RecipeError, ValueError, OSError) as e:
        print("build_abi: error: %s" % e, file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
