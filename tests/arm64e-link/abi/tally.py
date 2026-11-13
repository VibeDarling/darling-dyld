#!/usr/bin/env python3
"""Tally the RESULT lines of guest logs of the ABI probe per (variant, mutate) and check.

  tally.py LOG...        # run with python3 -I

Columns come from the `ABI-PROBE ... variant=V [config=C] ... mutate=M` header of each run (the l4 probe adds
config=, which is appended to the column name). Logs without a
SUMMARY for every run (an incomplete boot) are listed and skipped.
"""
import collections
import re
import sys


HEAD = r"ABI-PROBE .*set=(\w+) mutate=(\d) variant=(\S+)(?: config=(\w+))?"


def main(paths):
    tab = collections.defaultdict(lambda: collections.defaultdict(collections.Counter))
    names, zero_pac, mismatches, boots = {}, collections.Counter(), 0, 0
    for path in paths:
        text = open(path, errors="replace").read()
        heads = re.findall("^" + HEAD, text, re.M)
        if not heads or text.count("SUMMARY") != len(heads):
            print("INCOMPLETE", path)
            continue
        boots += 1
        col = None
        for line in text.splitlines():
            m = re.match(HEAD, line)
            if m:
                col = (m.group(3) + ("/" + m.group(4) if m.group(4) else "") + (" mutate" if m.group(2) == "1" else ""),
                       m.group(1))
                continue
            m = re.match(r"RESULT (\d+) (\S+) (ok|faulted|hung|failed)(.*)", line)
            if m:
                n = int(m.group(1))
                names[(col[1], n)] = m.group(2)
                tab[col][n][m.group(3)] += 1
                zero_pac[col] += "pac_field_was_zero=yes" in m.group(4)
                mismatches += "EXPECT-MISMATCH" in m.group(4)
    print("complete boots: %d of %d, selftest EXPECT-MISMATCH lines: %d" % (boots, len(paths), mismatches))
    for sset in ("checks", "selftest"):
        cols = sorted(c for c in tab if c[1] == sset)
        print("\n[%s]" % sset)
        print("%-40s" % "check" + "".join("%-26s" % c[0] for c in cols))
        for n in sorted(k[1] for k in names if k[0] == sset):
            row = "%02d %-37s" % (n, names[(sset, n)])
            for c in cols:
                cnt = tab[c][n]
                row += "%-26s" % ", ".join("%d %s" % (cnt[k], k) for k in ("ok", "faulted", "hung", "failed") if cnt[k])
            print(row)
    print("\npac_field_was_zero=yes lines per column:", {c[0]: v for c, v in zero_pac.items() if v})
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]) if len(sys.argv) > 1 else print(__doc__))
