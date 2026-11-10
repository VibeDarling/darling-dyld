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
import build_h0  # noqa: E402  (h0's link-only stub builder)

CFLAGS = ["-ffreestanding", "-fno-builtin", "-fno-stack-protector", "-O1", "-fblocks", "-fexceptions",
          "-nostdinc++", "-Wno-unused-command-line-argument"]
SOURCES = ["abi_harness.c", "abi_checks.c", "abi_cxx.cpp"]
CXXABI = "/usr/lib/libc++abi.dylib"
ARCHS = ("arm64e", "arm64")
# arm64e variants that remove kinds of signing from the whole executable (mutation probes for the
# C++ checks, where no source-level strip exists): name -> (extra compile flags, rewrite every
# authenticated bind outside __auth_got as a plain bind, put the vtable address point offset back on
# the typeinfo vtable binds). noret: return addresses unsigned. noret_unsigned: that plus the
# personality GOT slot and the typeinfo vtable pointers unsigned. noret_unsigned_addend: that plus
# the +16 the in-tree ld64 drops from authenticated binds (README, check 13). nosign: no signed
# return addresses, function or vtable pointers from the compiler.
VARIANTS = {
    "noret": (["-fno-ptrauth-returns"], False, False),
    "noret_unsigned": (["-fno-ptrauth-returns"], True, False),
    "noret_unsigned_addend": (["-fno-ptrauth-returns"], True, True),
    "nosign": (["-fno-ptrauth-returns", "-fno-ptrauth-calls"], True, False),
}
VTABLE_PREFIX = "__ZTV"
VTABLE_ADDRESS_POINT = 16     # Itanium C++ ABI: two pointers (offset-to-top, typeinfo) precede it
AUTH_GOT = "__DATA_CONST,__auth_got"
# calls into the plain libs the probe is about; every one must be imported
REQUIRED_IMPORTS = {
    "libSystem": ["_atexit", "___cxa_atexit", "_pthread_key_create", "_pthread_create", "_pthread_once",
                  "_qsort", "_dlsym", "_dispatch_async", "_dispatch_once", "__dyld_register_func_for_add_image",
                  "__Unwind_Resume", "__NSConcreteStackBlock", "__NSConcreteGlobalBlock", "_sigaction"],
    "libc++abi": ["___cxa_throw", "___gxx_personality_v0", "__ZTIi",
                  "__ZTVN10__cxxabiv120__si_class_type_infoE", "___cxa_allocate_exception"],
}
# arm64e return-address and function-pointer instructions; a plain build has none
PAC_WORDS = {0xD503233F: "paciasp", 0xD503237F: "pacibsp", 0xD50323BF: "autiasp", 0xD50323FF: "autibsp",
             0xD65F0BFF: "retaa", 0xD65F0FFF: "retab"}
# (mask, value, name): pointer signing and authenticated calls with a register operand
PAC_PATTERNS = [(0xFFFFFFE0, 0xDAC123E0, "paciza"), (0xFFFFFC1F, 0xD63F081F, "blraaz"),
                (0xFFFFFC00, 0xD73F0800, "blraa")]


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
    """The link-only libc++abi stub for `arch`, through h0's stub builder (same template)."""
    sub = os.path.join(out_dir, "libcxxabi-" + arch)
    os.makedirs(sub, exist_ok=True)
    builder = None if arch == "arm64e" else build_plain
    return build_h0.build_stub("libc++abi", sub, os.path.join(HERE, "libcxxabi_symbols.txt"), builder)


def unsign_data_binds(path, restore_vtable_addend=False):
    """Rewrite, in place, each authenticated bind outside __auth_got as a plain bind to the same
    import (ordinal and chain link kept; the in-tree ld64 keeps no addend on an authenticated bind,
    so the inline addend is 0, or the vtable address point for a vtable import when
    `restore_vtable_addend`). Returns the import names of the rewritten slots. The __auth_got entries stay signed because the arm64e call stubs authenticate them."""
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
        if restore_vtable_addend and f["import"].startswith(VTABLE_PREFIX):
            word |= VTABLE_ADDRESS_POINT << 32        # the plain bind's 19-bit inline addend
        struct.pack_into("<Q", data, off, word)
        names.append(f["import"])
    with open(path, "wb") as fh:
        fh.write(data)
    return names


def build_probe(arch, out_dir, variant=None):
    sdk = sdk_libs()
    stub = build_cxxabi_stub(arch, out_dir)
    out = os.path.join(out_dir, "abi_probe_" + arch + ("_" + variant if variant else ""))
    cflags = CFLAGS + (VARIANTS[variant][0] if variant else []) + [
        '-DABI_VARIANT="%s"' % (variant or arch)]
    srcs = [os.path.join(HERE, s) for s in SOURCES]
    libs, ld_args = ["-lSystem", stub], ["-syslibroot", sdk]
    if arch == "arm64e":
        rec.build(srcs, out, kind="exe", cflags=cflags, entry="_main", libs=libs, ld_args=ld_args)
    else:
        build_plain(srcs, out, kind="exe", cflags=cflags, entry="_main", libs=libs, ld_args=ld_args)
    if variant and VARIANTS[variant][1]:
        unsign_data_binds(out, VARIANTS[variant][2])
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
        for mask, value, name in PAC_PATTERNS:
            if w & mask == value:
                counts[name] = counts.get(name, 0) + 1
    return counts


def import_names(m, arch, path):
    if arch == "arm64e":
        _m, dec = rec.verify_output(path, "exe")
        return {i["name"]: i["ordinal"] for i in dec["imports"]}, dec
    return None, None


# --------------------------------------------------- DWARF-mode fixture (checks 29-32)
# The fixture's claims are structural: the linker gives _dwarf_frame_call DWARF mode, and its FDE
# says what the frame does in the convention open-source libunwind reads - the CIE's B augmentation
# (B key) and the FDE's first instruction DW_CFA_AARCH64_negate_ra_state (RA sign state set).

def _section(m, segname, secname):
    for s in m.segments:
        if s["name"] == segname:
            for sec in s["sections"]:
                if sec["name"] == secname:
                    return sec
    return None


def _u32(data, off):
    return struct.unpack_from("<I", data, off)[0]


def _uleb(data, off):
    v = shift = 0
    while off < len(data):
        b = data[off]; off += 1
        v |= (b & 0x7F) << shift
        if not b & 0x80:
            return v, off
        shift += 7
    raise rec.RecipeError("truncated ULEB128")


def _cstr(data, off):
    end = data.index(b"\0", off)
    return data[off:end].decode("ascii", "replace"), end + 1


def _cie_augmentation(cie):
    """(augmentation string, FDE pointer encoding or None) of a CIE at bytes cie."""
    if cie[8] not in (1, 3, 4):
        raise rec.RecipeError("unexpected CIE version %d" % cie[8])
    aug, off = _cstr(cie, 9)
    _code, off = _uleb(cie, off)      # code alignment
    _data, off = _uleb(cie, off)      # data alignment (SLEB; the width is what matters)
    _ret, off = _uleb(cie, off)       # return address register
    enc = None
    if aug.startswith("z"):
        alen, off = _uleb(cie, off)
        data_end, p = off + alen, off
        for ch in aug[1:]:
            if ch == "R":
                enc = cie[p]; p += 1
            elif ch == "L":
                p += 1
            elif ch == "P":
                p += 1
                # an encoded personality pointer; our fixture has none, so stop rather than guess
                break
        off = data_end
    return aug, enc, off


def compact_encoding(m, func_addr):
    """The compact-unwind encoding of func_addr from __TEXT,__unwind_info, or raise."""
    sec = _section(m, "__TEXT", "__unwind_info")
    if sec is None:
        raise rec.RecipeError("no __TEXT,__unwind_info")
    ui = m.read_vm(sec["addr"], sec["size"])
    if _u32(ui, 0) != 1:
        raise rec.RecipeError("unexpected __unwind_info version %d" % _u32(ui, 0))
    index_off, index_count = _u32(ui, 20), _u32(ui, 24)
    func_off, first, second = func_addr - m.image_base(), None, None
    for i in range(index_count):
        foff, page = struct.unpack_from("<II", ui, index_off + i * 12)
        if foff <= func_off:
            first, second = foff, page
        else:
            break
    if second is None:
        raise rec.RecipeError("_dwarf_frame_call is below the first unwind index entry")
    kind = _u32(ui, second)
    if kind == 2:                                    # UNWIND_SECOND_LEVEL_REGULAR
        # regular second-level offsets are absolute (from the image base)
        page_off, count = struct.unpack_from("<HH", ui, second + 4)
        for i in range(count):
            foff, enc = struct.unpack_from("<II", ui, second + page_off + i * 8)
            if foff == func_off:
                return enc
        raise rec.RecipeError("no compact-unwind entry for _dwarf_frame_call")
    if kind == 3:                                    # UNWIND_SECOND_LEVEL_COMPRESSED
        # compressed second-level offsets are relative to the first-level entry's functionOffset;
        # an encoding index below the common count selects the section's common encodings
        page_target = func_off - first
        page_off, count, enc_off, _n = struct.unpack_from("<HHHH", ui, second + 4)
        common_off, common_count = _u32(ui, 4), _u32(ui, 8)
        for i in range(count):
            word = _u32(ui, second + page_off + i * 4)
            if word & 0xFFFFFF == page_target:
                eidx = word >> 24
                if eidx < common_count:
                    return _u32(ui, common_off + eidx * 4)
                return _u32(ui, second + enc_off + (eidx - common_count) * 4)
        raise rec.RecipeError("no compact-unwind entry for _dwarf_frame_call")
    raise rec.RecipeError("unknown second-level unwind page kind %d" % kind)


def dwarf_fde_cfi(m, func_addr):
    """(CIE augmentation, first FDE instruction opcode) of the FDE for func_addr."""
    sec = _section(m, "__TEXT", "__eh_frame")
    if sec is None:
        raise rec.RecipeError("no __TEXT,__eh_frame")
    eh = m.read_vm(sec["addr"], sec["size"])
    off = 0
    while off + 4 <= len(eh):
        length = _u32(eh, off)
        if length == 0:
            break
        if length == 0xFFFFFFFF:
            raise rec.RecipeError("64-bit .eh_frame length in a 32-bit fixture")
        body = off + 4
        cie_ptr = _u32(eh, body)
        if cie_ptr:
            cie_off = body - cie_ptr
            aug, enc, _cie_len = _cie_augmentation(eh[cie_off:])
            p = body + 4
            field_addr = sec["addr"] + p
            if enc == 0x10:                          # DW_EH_PE_pcrel | DW_EH_PE_absptr
                init = (struct.unpack_from("<Q", eh, p)[0] + field_addr) & 0xFFFFFFFFFFFFFFFF
                p += 8 + 8                           # initial location and address range
            elif enc == 0x1B:                        # DW_EH_PE_pcrel | DW_EH_PE_sdata4
                init = (struct.unpack_from("<i", eh, p)[0] + field_addr) & 0xFFFFFFFFFFFFFFFF
                p += 4 + 4
            elif enc is None:
                raise rec.RecipeError("CIE has no FDE pointer encoding")
            else:
                raise rec.RecipeError("unhandled FDE pointer encoding 0x%x" % enc)
            if init == func_addr:
                if aug.startswith("z"):
                    alen, p = _uleb(eh, p)
                    p += alen
                return aug, eh[p]
        off = body + length
    raise rec.RecipeError("no FDE for _dwarf_frame_call")


def dwarf_mode_problems(m):
    """Problems with the reference build's DWARF-mode fixture; empty means it is as claimed."""
    sym = m.symbols().get("_dwarf_frame_call")
    if sym is None:
        return ["no _dwarf_frame_call symbol"]
    problems = []
    try:
        enc = compact_encoding(m, sym)
        if enc & 0x0F000000 != 0x03000000:          # UNWIND_ARM64_MODE_MASK / _MODE_DWARF
            problems.append("_dwarf_frame_call is not in DWARF mode (compact encoding 0x%08x)" % enc)
        aug, opcode = dwarf_fde_cfi(m, sym)
        if "B" not in aug:
            problems.append("the CIE augmentation %r does not mark the B key (B)" % aug)
        if opcode != 0x2D:                          # DW_CFA_AARCH64_negate_ra_state
            problems.append("the FDE's first instruction is 0x%02x, not DW_CFA_AARCH64_negate_ra_state" % opcode)
    except rec.RecipeError as e:
        problems.append(str(e))
    return problems



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
    # nosign keeps the harness's explicit sign intrinsics (a few paciza) but no authenticated call
    auth_calls = pac.get("blraaz", 0) + pac.get("blraa", 0)
    if variant == "nosign" and auth_calls:
        problems.append("nosign still authenticates calls through function pointers %s" % pac)
    if arch == "arm64e" and variant != "nosign" and not auth_calls:
        problems.append("arm64e probe has no authenticated call (function pointers unsigned?)")
    if dec is not None and variant in ("nosign", "noret_unsigned_addend"):
        vt = [f for f in dec["fixups"] if f.get("import", "").startswith(VTABLE_PREFIX) and
              f["section"] != AUTH_GOT]
        if not vt:
            problems.append("no typeinfo vtable bind found in %s" % variant)
        for f in vt:
            if f["kind"] != "bind" or f["addend"] != VTABLE_ADDRESS_POINT:
                problems.append("%s: %s is %s with addend %s, expected a plain bind with addend %d" %
                                (variant, f["import"], f["kind"], f["addend"], VTABLE_ADDRESS_POINT))
    if dec is not None and variant and VARIANTS[variant][1]:
        left = [f["import"] for f in dec["fixups"] if f["kind"] == "auth_bind" and f["section"] != AUTH_GOT]
        if left:
            problems.append("authenticated binds outside __auth_got remain in %s: %s" % (variant, left))
        if not any(f["kind"] == "bind" and f.get("import") == "___gxx_personality_v0" for f in dec["fixups"]):
            problems.append("personality slot is not a plain bind in %s" % variant)
    if variant is None and dec is not None and not any(
            f["kind"] == "auth_bind" and f["import"] == "___gxx_personality_v0" for f in dec["fixups"]):
        problems.append("arm64e probe lacks the signed personality slot the C++ checks are about")
    if arch == "arm64e" and variant is None:
        problems.extend(dwarf_mode_problems(m))
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
