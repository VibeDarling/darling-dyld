#!/usr/bin/env bash
# One guest run in the private Darling build, under the shared heavy-step lock and a memory cap.
#   DARLING_GUEST_BUILD=<dir with run-once.sh and prefix/> run_guest.sh LABEL GUEST-COMMAND...
# The log is <build>/logs/run-LABEL.out (run-once.sh writes it). Never kills darling processes:
# run-once.sh ends with `darling shutdown`.
set -u
: "${DARLING_GUEST_BUILD:?set DARLING_GUEST_BUILD to the private guest build directory}"
lock=${DARLING_HEAVY_LOCK:-/tmp/agent-locks/darling-heavy-build.lock}
if [ -z "${ABI_LOCKED:-}" ]; then
  exec env ABI_LOCKED=1 flock -w 3600 "$lock" "$0" "$@"
fi
label=$1; shift
avail=$(awk '/MemAvailable/{print int($2/1024/1024)}' /proc/meminfo)
if [ "$avail" -lt 4 ]; then echo "MemAvailable ${avail}G below 4G, not running" >&2; exit 3; fi
systemd-run --user --scope --quiet -p MemoryMax=3G -p MemorySwapMax=0 timeout 300 \
  "$DARLING_GUEST_BUILD/run-once.sh" "$label" "$@"
echo "LAUNCH-RC=$?"
