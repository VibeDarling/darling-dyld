#!/usr/bin/env bash
# Guest boots of the L5 objc test: each boot runs the configurations in $L5_CONFIGS (default "c3 c1 selftest"):
#   c3        arm64e with DYLD_SHARED_CACHE_SPLIT_DIR, so libobjc is served from the cache (the L5 proof)
#   c1        control: no cache variable, the pre-L5 dyld2 path; check 01 must report the image is not served
#   selftest  the harness's own children, no guest state involved
# One driver run forks one child per check, so a config needs one boot, not one per check.
#   DARLING_GUEST_BUILD=<dir> PROBE_DIR=<host dir from build_l5.py build> CACHE_DIR=<host dir with the split cache> \
#     run_l5.sh PREFIX FIRST LAST        # logs: <build>/logs/run-PREFIX<i>.out
# The variable is set inside the guest (on the test's own command), never on the launcher: the launcher
# passes its environment to launchd, which would then load the cache itself (RUN-GUEST.md of the private guest
# build). GUEST_ROOT (default /Volumes/SystemRoot) is where the guest sees the host's filesystem root.
# L5_POLICY=<host file> sets DYLD_SHARED_CACHE_SPLIT_POLICY on the c3 command (which cache images the dyld
# may serve over disk copies); without it c3 runs with the dyld's built-in allow-list. T10 reads the SUMMARY
# and OKMARK lines from the logs and ends each boot with run_guest.sh's `darling shutdown`.
set -u
[ $# -eq 3 ] || { echo "usage: run_l5.sh PREFIX FIRST LAST" >&2; exit 2; }
: "${DARLING_GUEST_BUILD:?}" "${PROBE_DIR:?}"
prefix=$1 first=$2 last=$3
here=$(cd "$(dirname "$0")" && pwd) || exit 2

# Absolute host path of an existing directory, or a loud exit.
absdir() { (cd "$1" 2>/dev/null && pwd) || { echo "not a directory: $1" >&2; exit 2; }; }
guest_root=${GUEST_ROOT:-/Volumes/SystemRoot}
# The guest command is one bash -c string, so every path goes in shell-quoted.
q() { printf '%q' "$1"; }

probe=$(absdir "$PROBE_DIR") || exit 2
cmd="E=$(q "$guest_root$probe/l5_probe")"
for c in ${L5_CONFIGS:-c3 c1 selftest}; do
  case $c in
    c1) cmd="$cmd; echo CONFIG c1; \"\$E\"" ;;
    c3) : "${CACHE_DIR:?c3 needs CACHE_DIR}"
        cache=$(absdir "$CACHE_DIR") || exit 2
        policy=""
        if [ -n "${L5_POLICY:-}" ]; then
          pdir=$(absdir "$(dirname "$L5_POLICY")") || exit 2
          [ -f "$pdir/$(basename "$L5_POLICY")" ] || { echo "no policy file: $L5_POLICY" >&2; exit 2; }
          policy=" DYLD_SHARED_CACHE_SPLIT_POLICY=$(q "$guest_root$pdir/$(basename "$L5_POLICY")")"
        fi
        cmd="$cmd; echo CONFIG c3; DYLD_SHARED_CACHE_SPLIT_DIR=$(q "$guest_root$cache")$policy \"\$E\"" ;;
    selftest) cmd="$cmd; echo CONFIG selftest; \"\$E\" selftest" ;;
    *) echo "unknown config $c" >&2; exit 2 ;;
  esac
done
for i in $(seq "$first" "$last"); do
  "$here/../abi/run_guest.sh" "$prefix$i" /bin/bash -c "$cmd" > "$probe/launch-$prefix$i.txt" 2>&1
done
echo ALLDONE
