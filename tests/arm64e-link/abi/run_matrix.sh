#!/usr/bin/env bash
# Guest boots of the ABI probe: each boot runs every built variant, the control and the self-test
# (plain and mutate). The ABI-PROBE header line of each run names the variant, so the logs need no
# labels from this script.
#   DARLING_GUEST_BUILD=<dir> PROBE_DIR=<host dir from build_abi.py build> \
#     run_matrix.sh PREFIX FIRST LAST        # logs: <build>/logs/run-PREFIX<i>.out
# GUEST_ROOT (default /Volumes/SystemRoot) is where the guest sees the host's filesystem root.
set -u
: "${DARLING_GUEST_BUILD:?}" "${PROBE_DIR:?}"
here=$(cd "$(dirname "$0")" && pwd)
g=${GUEST_ROOT:-/Volumes/SystemRoot}$(cd "$PROBE_DIR" && pwd)
# short variable names: `darling shell` expands ${name} itself, plain $name reaches the guest bash
cmd="E=$g/abi_probe_arm64e; N=$g/abi_probe_arm64e_noret; U=$g/abi_probe_arm64e_noret_unsigned"
cmd="$cmd; A=$g/abi_probe_arm64e_noret_unsigned_addend; X=$g/abi_probe_arm64e_nosign; C=$g/abi_probe_arm64"
cmd="$cmd; \$E; \$E mutate; \$N; \$U; \$A; \$A mutate; \$X; \$C; \$E selftest; \$E selftest mutate; \$C selftest"
for i in $(seq "$2" "$3"); do
  "$here/run_guest.sh" "$1$i" /bin/bash -c "$cmd" > "${PROBE_DIR%/}/launch-$1$i.txt" 2>&1
done
echo ALLDONE
