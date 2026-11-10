#!/usr/bin/env python3
"""Build and structurally check the L4 C++ test: an arm64e executable (3.3a recipe) and the same
sources as a plain arm64 control, both linked against link-only stubs of libc++ and libc++abi.

  build_l4.py build --out DIR      # needs LD64, SDKROOT (Darling SDK root), LIBCXX_INCLUDE
  build_l4.py check EXE ARCH       # ARCH is arm64e or arm64
  build_l4.py native --out EXE [--checks FILE] [--cxx g++]   # the same checks on the host (not Mach-O)

LIBCXX_INCLUDE is the directory of Darling's libc++ headers (the guest build's
src/external/libcxx/include, LLVM 15.0.7). The stubs are generated from the undefined names of the
compiled objects: every C++ runtime name a source references is exported by exactly one stub, so
the stubs follow the test and cannot go stale. Nothing is executed; the stubs are never installed
(see ../h0/README.md). Run with python3 -I.
"""
import argparse
import glob
import os
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.dont_write_bytecode = True
sys.path[:0] = [HERE, os.path.join(ROOT, "abi"), os.path.join(ROOT, "h0"), ROOT]
import arm64e_link as rec  # noqa: E402  (the 3.3a recipe, reused as is)
import build_abi  # noqa: E402  (plain-arm64 link steps and the PAC instruction scan)
import build_h0  # noqa: E402  (the link-only stub builder)
import gen_stub  # noqa: E402

SOURCES = [os.path.join(ROOT, "abi", "abi_harness.c"), os.path.join(HERE, "l4_checks.cpp")]
ARCHS = ("arm64e", "arm64")
LIBCXX, LIBCXXABI, LIBSYSTEM = "/usr/lib/libc++.1.dylib", "/usr/lib/libc++abi.dylib", "/usr/lib/libSystem.B.dylib"
DEPENDENCIES = [LIBCXX, LIBCXXABI, LIBSYSTEM]   # the order clang's driver gives, then ordinals 1, 2, 3
ORDINAL = {LIBCXX: 1, LIBCXXABI: 2, LIBSYSTEM: 3}
LINKER_PROVIDED = {"__dso_handle"}              # defined by ld64 in every image, not by a library
# the main program's static initialisers: an arm64e __mod_init_func holds signed pointers that
# Darling's dyld calls raw, so the arm64e link converts them to 32-bit offsets (as the cache's
# images already are)
ARM64E_LD_ARGS = ["-init_offsets"]
# imports the checks exist to exercise: name -> the library that must bind it
REQUIRED_IMPORTS = {
    LIBCXX: ["__ZNSt3__14coutE", "__ZNSt3__16locale7classicEv", "__ZNSt3__16thread4joinEv", "__ZNSt3__19to_stringEi"],
    LIBCXXABI: ["___cxa_throw", "___gxx_personality_v0", "___cxa_begin_catch", "___cxa_guard_acquire",
                "___cxa_guard_release", "___cxa_guard_abort", "___dynamic_cast", "___cxa_allocate_exception",
                "__ZTIi", "__ZTVN10__cxxabiv120__si_class_type_infoE"],
    LIBSYSTEM: ["__tlv_atexit", "___cxa_atexit", "_atexit", "_exit", "_pthread_create", "_dladdr", "_fork",
                "__dyld_get_shared_cache_range", "__Unwind_Resume"],
}
SDK_EXPORT_LIBS = ["usr/lib/libSystem.dylib", "usr/lib/system/*.dylib"]


def cflags(variant, libcxx_include, sdk):
    return ["-ffreestanding", "-fno-builtin", "-fno-stack-protector", "-O1", "-fexceptions", "-nostdinc++",
            "-isystem", libcxx_include, "-isysroot", sdk, "-Wno-incompatible-sysroot",
            "-Wno-unused-command-line-argument", '-DABI_VARIANT="%s"' % variant]


def libcxx_include_dir():
    d = os.environ.get("LIBCXX_INCLUDE")
    if not d or not os.path.isfile(os.path.join(d, "__config_site")):
        raise rec.RecipeError("set LIBCXX_INCLUDE to Darling's libc++ header directory (it holds __config_site)")
    return d


def sdk_exports(sdk):
    """C names the Darling SDK's libSystem family exports (what ld64 resolves from -lSystem)."""
    names = set()
    for pattern in SDK_EXPORT_LIBS:
        for path in sorted(glob.glob(os.path.join(sdk, pattern))):
            names |= gen_stub.exported_names(path)
    if not names:
        raise rec.RecipeError("no exports found under %s: is SDKROOT the Darling SDK root?" % sdk)
    return names


def partition(undefined, abi_names, system_names):
    """Split the undefined names into (libSystem, libc++abi, libc++); anything else is an error."""
    system, abi, cxx, unknown = [], [], [], []
    for n in undefined:
        if n in LINKER_PROVIDED:
            continue
        if n in system_names:
            system.append(n)
        elif n in abi_names:
            abi.append(n)
        elif n.startswith("_Z"):
            cxx.append(n)
        else:
            unknown.append(n)
    if unknown:
        raise rec.RecipeError("names no library is known to export (not in libSystem, not libc++abi, not a C++ "
                              "mangled name): %s" % ", ".join(unknown))
    return system, abi, cxx


def compile_objects(arch, libcxx_include, sdk, workdir):
    """Plain compiles of the sources, only to read their undefined names."""
    objects = []
    for i, src in enumerate(SOURCES):
        obj = os.path.join(workdir, "%d.o" % i)
        rec.run([os.environ.get("CLANG", "clang"), "--target=%s-apple-macos13" % arch, "-c"] +
                cflags(arch, libcxx_include, sdk) + [src, "-o", obj], False)
        objects.append(obj)
    return objects


def build_stubs(arch, out_dir, undefined, sdk):
    abi_names = set(gen_stub.read_symbols(os.path.join(HERE, "libcxxabi_exports.txt")))
    _system, abi, cxx = partition(undefined, abi_names, sdk_exports(sdk))
    sub = os.path.join(out_dir, "stubs-" + arch)
    os.makedirs(sub, exist_ok=True)
    builder = None if arch == "arm64e" else build_abi.build_plain
    stubs = {}
    for which, names, install in (("libc++", cxx, LIBCXX), ("libc++abi", abi, LIBCXXABI)):
        symbols = os.path.join(sub, "symbols-%s.txt" % which)
        gen_stub.write_symbols(names, symbols, "C names the l4 objects reference that %s exports" % install)
        stubs[install] = (build_h0.build_stub(which, sub, symbols, builder), symbols)
    return stubs


def build_probe(arch, out_dir):
    sdk, inc = build_abi.sdk_libs(), libcxx_include_dir()
    with tempfile.TemporaryDirectory(prefix="l4-objects-") as tmp:
        undefined = gen_stub.undefined_names(compile_objects(arch, inc, sdk, tmp))
    stubs = build_stubs(arch, out_dir, undefined, sdk)
    out = os.path.join(out_dir, "l4_probe_" + arch)
    libs = [stubs[LIBCXX][0], stubs[LIBCXXABI][0], "-lSystem"]
    ld_args = ["-syslibroot", sdk]
    if arch == "arm64e":
        rec.build(SOURCES, out, kind="exe", cflags=cflags(arch, inc, sdk), entry="_main", libs=libs,
                  ld_args=ld_args + ARM64E_LD_ARGS)
    else:
        build_abi.build_plain(SOURCES, out, kind="exe", cflags=cflags(arch, inc, sdk), entry="_main", libs=libs,
                              ld_args=ld_args)
    return out, stubs


def build_native(out, checks=None, cxx="g++"):
    """The same sources on the host, against the host's C++ library: it validates the checks, which
    the host cannot run as Mach-O. `checks` replaces l4_checks.cpp (the harness mutation probes)."""
    with tempfile.TemporaryDirectory(prefix="l4-native-") as tmp:
        harness = os.path.join(tmp, "harness.o")
        rec.run([os.environ.get("CLANG", "clang"), "-DABI_NATIVE", '-DABI_VARIANT="native"', "-O1",
                 "-I", os.path.join(ROOT, "abi"), "-c", SOURCES[0], "-o", harness], False)
        obj = os.path.join(tmp, "checks.o")
        rec.run([cxx, "-std=c++17", "-O1", "-I", HERE, "-c", checks or SOURCES[1], "-o", obj], False)
        rec.run([cxx, harness, obj, "-pthread", "-o", out], False)
    return out


# ---------------------------------------------------------------------- checks

def check_exe(path, arch):
    """Problems with a built probe executable; empty means it passed."""
    problems = []
    try:
        m = rec.load_macho(path)
        _m, dec = rec.verify_output(path, "exe") if arch == "arm64e" else (None, None)
    except rec.RecipeError as e:
        return [str(e)]
    if m.filetype != rec.MH_EXECUTE or m.cputype != rec.CPU_TYPE_ARM64:
        problems.append("not an arm64 executable")
    if arch == "arm64e":
        if m.cpusubtype != rec.CPU_SUBTYPE_ARM64E:
            problems.append("cpusubtype 0x%x is not arm64e" % m.cpusubtype)
    elif m.cpusubtype != 0:
        problems.append("control cpusubtype 0x%x is not plain arm64 (0)" % m.cpusubtype)
    if m.chained is None:
        problems.append("no LC_DYLD_CHAINED_FIXUPS")
    if m.dyld_info is not None and any(m.dyld_info[i] for i in (1, 3, 5, 7)):
        problems.append("LC_DYLD_INFO carries rebase/bind opcodes next to chained fixups")
    deps = [p for _c, p in m.dylibs]
    if deps != DEPENDENCIES:
        problems.append("dependencies %s, expected %s (system paths, never a stub's build path)" % (deps, DEPENDENCIES))
    sections = {s["name"] for seg in m.segments for s in seg["sections"]}
    if arch == "arm64e":
        if "__init_offsets" not in sections or "__mod_init_func" in sections:
            problems.append("static initialisers are not __init_offsets (signed __mod_init_func would be called raw)")
    pac = build_abi.text_words(path)
    signs_returns = bool(pac.get("pacibsp") or pac.get("paciasp"))
    if arch == "arm64e" and not signs_returns:
        problems.append("arm64e executable has no pacibsp/paciasp (return addresses unsigned?)")
    if arch == "arm64e" and not (pac.get("blraaz", 0) + pac.get("blraa", 0)):
        problems.append("arm64e executable has no authenticated call (function pointers unsigned?)")
    if arch == "arm64" and pac:
        problems.append("plain arm64 control contains PAC instructions %s" % pac)
    if dec is not None:
        kinds = {f["kind"] for f in dec["fixups"]}
        if "auth_bind" not in kinds:
            problems.append("no authenticated bind in an arm64e executable")
        names = {i["name"]: i["ordinal"] for i in dec["imports"]}
        problems += check_imports(names)
    return problems


def check_imports(names):
    """Every import is bound to the library that exports it, and the tested ones are present."""
    problems = []
    sdk = build_abi.sdk_libs()
    abi_names = set(gen_stub.read_symbols(os.path.join(HERE, "libcxxabi_exports.txt")))
    system_names = sdk_exports(sdk)
    for lib, wanted in REQUIRED_IMPORTS.items():
        for n in wanted:
            if names.get(n) != ORDINAL[lib]:
                problems.append("import %s not bound from %s (ordinal %s)" % (n, lib, names.get(n)))
    for n, ordinal in sorted(names.items()):
        c = n[1:]
        want = (ORDINAL[LIBSYSTEM] if c in system_names else
                ORDINAL[LIBCXXABI] if c in abi_names else
                ORDINAL[LIBCXX] if c.startswith("_Z") else None)
        if want is None:
            problems.append("import %s is exported by no known library" % n)
        elif want != ordinal:
            problems.append("import %s bound with ordinal %d, expected %d" % (n, ordinal, want))
    return problems


def main(argv):
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    sub = ap.add_subparsers(dest="cmd", required=True)
    b = sub.add_parser("build")
    b.add_argument("--out", required=True)
    c = sub.add_parser("check")
    c.add_argument("exe")
    c.add_argument("arch", choices=ARCHS)
    n = sub.add_parser("native")
    n.add_argument("--out", required=True)
    n.add_argument("--checks")
    n.add_argument("--cxx", default="g++")
    a = ap.parse_args(argv)
    try:
        if a.cmd == "native":
            print("OK %s" % build_native(a.out, a.checks, a.cxx))
        elif a.cmd == "build":
            os.makedirs(a.out, exist_ok=True)
            for arch in ARCHS:
                exe, stubs = build_probe(arch, a.out)
                problems = check_exe(exe, arch)
                for install, (stub, symbols) in stubs.items():
                    which = "libc++abi" if install == LIBCXXABI else "libc++"
                    problems += build_h0.check_stub(stub, which, symbols, None if arch == "arm64e" else 0)
                if problems:
                    raise rec.RecipeError("%s structural checks failed:\n  %s" % (arch, "\n  ".join(problems)))
                print("OK %s" % exe)
        else:
            problems = check_exe(a.exe, a.arch)
            if problems:
                raise rec.RecipeError("structural checks failed:\n  " + "\n  ".join(problems))
            print("OK %s" % a.exe)
    except (rec.RecipeError, ValueError, OSError) as e:
        print("build_l4: error: %s" % e, file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
