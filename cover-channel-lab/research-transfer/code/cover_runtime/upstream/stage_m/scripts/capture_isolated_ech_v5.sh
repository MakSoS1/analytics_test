#!/usr/bin/env bash
set -euo pipefail

if [[ $# -lt 11 ]]; then
  echo "usage: $0 NETNS CAPTURE_IF SOURCE_IP PROTOCOL CAMPAIGN_ID PAIR_ID ECH_MODE ECH_ENABLED EVIDENCE_ROOT -- DRIVER [ARGS...]" >&2
  exit 2
fi

NETNS="$1"
CAPTURE_IF="$2"
SOURCE_IP="$3"
PROTOCOL="$4"
CAMPAIGN_ID="$5"
PAIR_ID="$6"
ECH_MODE="$7"
ECH_ENABLED="$8"
EVIDENCE_ROOT="$9"
shift 9
[[ "$1" == "--" ]] || { echo "missing -- before driver command" >&2; exit 2; }
shift
[[ $# -gt 0 ]] || { echo "driver command is required" >&2; exit 2; }

[[ "${COVERLAB_ISOLATED_LAB:-0}" == "1" ]] || {
  echo "refusing ECH capture unless COVERLAB_ISOLATED_LAB=1" >&2
  exit 2
}

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
PYTHON_BIN="$(command -v python)"

"$PYTHON_BIN" - "$SOURCE_IP" <<'PY'
import ipaddress,sys
ip=ipaddress.ip_address(sys.argv[1])
if not (ip.is_private or ip.is_loopback):
    raise SystemExit("SOURCE_IP must be private/loopback")
PY

sudo ip netns list | awk '{print $1}' | grep -qx "$NETNS" || {
  echo "network namespace missing: $NETNS" >&2
  exit 1
}
if sudo ip netns exec "$NETNS" ip route show default | grep -q .; then
  echo "refusing ECH capture: namespace $NETNS has a default route" >&2
  exit 1
fi
ip link show "$CAPTURE_IF" >/dev/null

RAW_DIR="$EVIDENCE_ROOT/ech/raw"
mkdir -p "$RAW_DIR"
PCAP="$RAW_DIR/$CAMPAIGN_ID.pcap"
LOG="$RAW_DIR/$CAMPAIGN_ID.tcpdump.log"
rm -f "$PCAP" "$LOG"

STARTED_AT="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
sudo tcpdump -i "$CAPTURE_IF" -B 8192 -s 0 -U -w "$PCAP" "host $SOURCE_IP" >"$LOG" 2>&1 &
TCPDUMP_PID=$!
cleanup() {
  sudo kill -INT "$TCPDUMP_PID" 2>/dev/null || true
  wait "$TCPDUMP_PID" 2>/dev/null || true
}
trap cleanup EXIT
sleep 0.5

sudo ip netns exec "$NETNS" runuser -u "$USER" -- "$@"
sleep "${COVERLAB_CAPTURE_DRAIN_SECONDS:-2}"

cleanup
trap - EXIT
ENDED_AT="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
test -s "$PCAP"

LABEL_BINARY=0
[[ "$ECH_MODE" == "shared_frontend_suspicious" ]] && LABEL_BINARY=1

PYTHONPATH="$ROOT/src" "$PYTHON_BIN" -m coverlab.evidence_register_v4   --root "$EVIDENCE_ROOT" ech   --pcap "$PCAP"   --capture-id "$CAMPAIGN_ID"   --pair-id "$PAIR_ID"   --ech-mode "$ECH_MODE"   --ech-enabled "$ECH_ENABLED"   --label-binary "$LABEL_BINARY"   --source-ip "$SOURCE_IP"   --started-at "$STARTED_AT"   --ended-at "$ENDED_AT"   --protocol "$PROTOCOL"
