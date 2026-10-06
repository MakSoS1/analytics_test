#!/usr/bin/env bash
set -euo pipefail

if [[ $# -lt 9 ]]; then
  echo "usage: $0 FRAMEWORK NETNS CAPTURE_IF SOURCE_IP PROTOCOL CAMPAIGN_ID EVIDENCE_ROOT -- DRIVER [ARGS...]" >&2
  exit 2
fi

FRAMEWORK="$1"
NETNS="$2"
CAPTURE_IF="$3"
SOURCE_IP="$4"
PROTOCOL="$5"
CAMPAIGN_ID="$6"
EVIDENCE_ROOT="$7"
shift 7
[[ "$1" == "--" ]] || { echo "missing -- before driver command" >&2; exit 2; }
shift
[[ $# -gt 0 ]] || { echo "driver command is required" >&2; exit 2; }

[[ "${COVERLAB_ISOLATED_LAB:-0}" == "1" ]] || {
  echo "refusing framework capture unless COVERLAB_ISOLATED_LAB=1" >&2
  exit 2
}

: "${COVERLAB_FRAMEWORK_TOOL_VERSION:?set COVERLAB_FRAMEWORK_TOOL_VERSION to the concrete framework version/commit}"

case "$FRAMEWORK" in
  sliver|adaptix|mythic_httpx|mythic_websocket) ;;
  *) echo "unsupported framework: $FRAMEWORK" >&2; exit 2 ;;
esac

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
  echo "refusing framework capture: namespace $NETNS has a default route" >&2
  exit 1
fi
ip link show "$CAPTURE_IF" >/dev/null

RAW_DIR="$EVIDENCE_ROOT/framework/raw"
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

PYTHONPATH="$ROOT/src" "$PYTHON_BIN" -m coverlab.evidence_register_v4   --root "$EVIDENCE_ROOT" framework   --pcap "$PCAP"   --framework "$FRAMEWORK"   --campaign-id "$CAMPAIGN_ID"   --protocol "$PROTOCOL"   --lifecycle "${COVERLAB_FRAMEWORK_LIFECYCLE:-registration,idle,poll,synthetic_task,synthetic_result,sleep,reconnect}"   --tool-version "$COVERLAB_FRAMEWORK_TOOL_VERSION"   --adapter-version coverlab-v5   --source-ip "$SOURCE_IP"   --started-at "$STARTED_AT"   --ended-at "$ENDED_AT"
