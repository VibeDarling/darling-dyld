#!/bin/bash
# Guest-side check of the DARLING_DYLD_COLLECT_MISSING fixture. usage: collect-missing-check.sh <dir> <expected file>
# <dir> holds collect-missing-guest, collect-missing-flat, collect-missing-plugin.bundle and the library built from
# collect-missing-stub.c (see README-collect-missing.md). Runs every case, prints a transcript of return codes, the first
# interesting message line and the fixture's own list lines (referrer's last component, no slot, no pid), and diffs it with the
# expected file: exit 0 on an identical transcript, 1 on a difference. Names only.
D=$1; EXPECTED=$2
T=${TMPDIR:-/tmp}/collect-missing-check.$$
mkdir -p "$T"
ulimit -c 0
cases() {
	list() {
		[ -f "$1" ] || { echo "  (no list file)"; return; }
		grep -v '^#' "$1" | awk -F'\t' '$2 ~ /ollect/ { n = split($1, a, "/"); e = $3; if ( e ~ /^\// ) { m = split(e, b, "/"); e = b[m] } printf "  %s\t%s\t%s\t%s\t%s\t%s\t%s\n", a[n], $2, e, $4, $5, $6, $7 }' | sort
	}
	run() {   # label, list-or-empty, program, args...
		label=$1; lst=$2; shift 2
		rm -f "$T/list.txt"
		if [ -n "$lst" ]; then DARLING_DYLD_COLLECT_MISSING="$T/list.txt" "$@" > "$T/out.txt" 2>&1; else "$@" > "$T/out.txt" 2>&1; fi
		echo "$label rc=$?"
		grep -o -e 'Symbol not found: [^ ]*' -e 'collected missing symbol was called: [^ ]*' -e 'REACHED main [a-z]*' -e 'plugin [a-z ]*loaded' "$T/out.txt" | uniq | sed 's/^/  /'
		[ -n "$lst" ] && list "$T/list.txt"
	}
	run off-present "" "$D/collect-missing-guest" present
	run on-present 1 "$D/collect-missing-guest" present
	run on-a 1 "$D/collect-missing-guest" a
	run on-b 1 "$D/collect-missing-guest" b
	run on-c 1 "$D/collect-missing-guest" c
	run on-data 1 "$D/collect-missing-guest" data
	run on-plugin 1 "$D/collect-missing-guest" plugin
	run off-flat "" "$D/collect-missing-flat" present
	run on-flat 1 "$D/collect-missing-flat" present
}
cases > "$T/transcript.txt" 2> /dev/null
if diff "$EXPECTED" "$T/transcript.txt" > "$T/diff.txt"; then
	echo "PASS collect-missing guest transcript identical to $EXPECTED"
	exit 0
fi
echo "FAIL collect-missing guest transcript differs from $EXPECTED:"
cat "$T/diff.txt"
exit 1
