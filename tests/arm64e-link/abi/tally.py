#!/usr/bin/env python3
"""Tally the RESULT lines of guest logs of the ABI probe per (variant, mutate) and check.

  tally.py LOG...        # run with python3 -I

Columns come from the `ABI-PROBE ... variant=V ... mutate=M` header of each run. Logs without a
SUMMARY for every run (an incomplete boot) are listed and skipped.
"""
import collections
import re
import sys


def main(paths):
    tab = collections.defaultdict(lambda: collections.defaultdict(collections.Counter))
    names, zero_pac, mismatches, collisions, boots = {}, collections.Counter(), 0, 0, 0
    for path in paths:
        text = open(path, errors="replace").read()
        heads = re.findall(r"^ABI-PROBE .*set=(\w+) mutate=(\d) variant=(\S+)", text, re.M)
        if not heads or text.count("SUMMARY") != len(heads):
            print("INCOMPLETE", path)
            continue
        boots += 1
        col = None
        for line in text.splitlines():
            m = re.match(r"ABI-PROBE .*set=(\w+) mutate=(\d) variant=(\S+)", line)
            if m:
                col = (m.group(3) + (" mutate" if m.group(2) == "1" else ""), m.group(1))
                continue
            m = re.match(r"RESULT (\d+) (\S+) (ok|faulted|hung|failed)(.*)", line)
            if m:
                n = int(m.group(1))
                names[(col[1], n)] = m.group(2)
                tab[col][n][m.group(3)] += 1
                zero_pac[col] += "pac_field_was_zero=yes" in m.group(4)
                mismatches += "EXPECT-MISMATCH" in m.group(4)
            if line.startswith("PAC-COLLISION-MISMATCH"):
                collisions += 1
    print("complete boots: %d of %d, EXPECT-MISMATCH lines: %d, PAC-COLLISION-MISMATCH lines: %d"
          % (boots, len(paths), mismatches, collisions))
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
    # an EXPECT-MISMATCH is a check whose verdict differs from what the reference build must get; a
    # PAC-COLLISION-MISMATCH is a reference check with no signature to authenticate, so it is
    # inconclusive: the run must be repeated with a fresh process, and until then this tally fails.
    return 1 if (mismatches or collisions) else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]) if len(sys.argv) > 1 else print(__doc__))
