#!/usr/bin/env bash
# Guest boots of the L4 C++ test: each boot runs the configurations in $L4_CONFIGS (default all):
#   c1  plain arm64 control, no cache variable            c2  arm64e, no cache variable
#   c3  arm64e with DYLD_SHARED_CACHE_SPLIT_DIR           selftest  the harness's own children, both builds
# The ABI-PROBE header line of each run names the arch and config, so the logs need no labels.
#   DARLING_GUEST_BUILD=<dir> PROBE_DIR=<host dir from build_l4.py build> CACHE_DIR=<host dir with the split cache> \
#     run_matrix.sh PREFIX FIRST LAST        # logs: <build>/logs/run-PREFIX<i>.out
# The variable is set inside the guest (on the test's own command), never on the launcher: the launcher
# passes its environment to launchd, which would then load the cache itself (RUN-GUEST.md of the private guest
# build). GUEST_ROOT (default /Volumes/SystemRoot) is where the guest sees the host's filesystem root.
# c3 maps the cache once per child, 28 children per run: use a local copy of the cache, and run a config
# per boot (L4_CONFIGS=c3) if the 300 s cap of run_guest.sh is not enough.
set -u
: "${DARLING_GUEST_BUILD:?}" "${PROBE_DIR:?}"
here=$(cd "$(dirname "$0")" && pwd)
g=${GUEST_ROOT:-/Volumes/SystemRoot}$(cd "$PROBE_DIR" && pwd)
cmd="E=$g/l4_probe_arm64e; C=$g/l4_probe_arm64"
for c in ${L4_CONFIGS:-c1 c2 c3 selftest}; do
  case $c in
    c1) cmd="$cmd; PROBE_CONFIG=c1 \$C" ;;
    c2) cmd="$cmd; PROBE_CONFIG=c2 \$E" ;;
    c3) : "${CACHE_DIR:?c3 needs CACHE_DIR}"
        cmd="$cmd; PROBE_CONFIG=c3 DYLD_SHARED_CACHE_SPLIT_DIR=${GUEST_ROOT:-/Volumes/SystemRoot}$(cd "$CACHE_DIR" && pwd) \$E" ;;
    selftest) cmd="$cmd; \$E selftest; \$C selftest" ;;
    *) echo "unknown config $c" >&2; exit 2 ;;
  esac
done
for i in $(seq "$2" "$3"); do
  "$here/../abi/run_guest.sh" "$1$i" /bin/bash -c "$cmd" > "${PROBE_DIR%/}/launch-$1$i.txt" 2>&1
done
echo ALLDONE
