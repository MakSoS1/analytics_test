#!/usr/bin/env bash
set -euo pipefail
if [[ $# -lt 8 ]]; then
  echo "usage: $0 FRAMEWORK IFACE SOURCE_IP PROTOCOL CAMPAIGN_ID EVIDENCE_ROOT -- DRIVER [ARGS...]" >&2
  exit 2
fi
FRAMEWORK="$1"; IFACE="$2"; SOURCE_IP="$3"; PROTOCOL="$4"; CAMPAIGN_ID="$5"; EVIDENCE_ROOT="$6"; shift 6
[[ "$1" == "--" ]] || { echo "missing -- before driver command" >&2; exit 2; }
shift
[[ $# -gt 0 ]] || { echo "driver command is required" >&2; exit 2; }

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
PYTHON_BIN="$(command -v python)"
mkdir -p "$EVIDENCE_ROOT/raw"
PCAP="$EVIDENCE_ROOT/raw/$CAMPAIGN_ID.pcap"

"$PYTHON_BIN" - "$SOURCE_IP" <<'PY'
import ipaddress,sys
ip=ipaddress.ip_address(sys.argv[1])
if not (ip.is_private or ip.is_loopback):
    raise SystemExit("SOURCE_IP must be private/loopback")
PY

ip link show "$IFACE" >/dev/null
rm -f "$PCAP"
STARTED_AT="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
sudo tcpdump -i "$IFACE" -s 0 -U -w "$PCAP" "host $SOURCE_IP" >"$EVIDENCE_ROOT/raw/$CAMPAIGN_ID.tcpdump.log" 2>&1 &
TCPDUMP_PID=$!
cleanup() {
  sudo kill -INT "$TCPDUMP_PID" 2>/dev/null || true
  wait "$TCPDUMP_PID" 2>/dev/null || true
}
trap cleanup EXIT
sleep 0.5

"$@"
sleep "${COVERLAB_CAPTURE_DRAIN_SECONDS:-2}"

cleanup
trap - EXIT
ENDED_AT="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
test -s "$PCAP"

PYTHONPATH="$ROOT/src" "$PYTHON_BIN" -m coverlab.register_framework_capture_v5   --root "$EVIDENCE_ROOT"   --framework "$FRAMEWORK"   --pcap "$PCAP"   --campaign-id "$CAMPAIGN_ID"   --protocol "$PROTOCOL"   --source-ip "$SOURCE_IP"   --started-at "$STARTED_AT"   --ended-at "$ENDED_AT"   --lifecycle "${COVERLAB_FRAMEWORK_LIFECYCLE:-registration,idle,poll,synthetic_task,synthetic_result,sleep,reconnect}"
