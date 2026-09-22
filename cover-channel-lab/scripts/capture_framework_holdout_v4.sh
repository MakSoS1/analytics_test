#!/usr/bin/env bash
set -euo pipefail

if [[ $# -ne 5 ]]; then
  echo "usage: $0 FRAMEWORK ADAPTER_EXEC NETNS CAPTURE_IF OUTPUT_PCAP" >&2
  exit 2
fi

FRAMEWORK="$1"
ADAPTER="$2"
NETNS="$3"
CAPTURE_IF="$4"
OUT="$5"

case "$FRAMEWORK" in
  sliver|adaptix|mythic_httpx|mythic_websocket) ;;
  *) echo "unsupported framework: $FRAMEWORK" >&2; exit 2 ;;
esac

[[ -x "$ADAPTER" ]] || { echo "adapter is not executable: $ADAPTER" >&2; exit 1; }
sudo ip netns list | awk '{print $1}' | grep -qx "$NETNS" || { echo "network namespace missing: $NETNS" >&2; exit 1; }

# A real framework holdout must be isolated. Refuse to run if the namespace has
# a default route. The adapter may only exercise the safe synthetic lifecycle.
if sudo ip netns exec "$NETNS" ip route show default | grep -q .; then
  echo "refusing framework capture: namespace $NETNS has a default route" >&2
  exit 1
fi

mkdir -p "$(dirname "$OUT")"
rm -f "$OUT"
manifest="${OUT}.adapter.json"

sudo tcpdump -i "$CAPTURE_IF" -B 8192 -s 0 -U -w "$OUT" >/dev/null 2>&1 &
pid=$!
cleanup() {
  sudo kill -INT "$pid" 2>/dev/null || true
  wait "$pid" 2>/dev/null || true
}
trap cleanup EXIT
sleep .4

sudo ip netns exec "$NETNS" runuser -u "$USER" -- "$ADAPTER"   --framework "$FRAMEWORK"   --lifecycle registration,idle,poll,synthetic_task,synthetic_result,sleep,reconnect   --post-exploitation false   --output "$manifest"

sleep .5
cleanup
trap - EXIT

[[ -s "$OUT" ]] || { echo "framework capture is empty" >&2; exit 1; }
[[ -s "$manifest" ]] || { echo "adapter did not emit provenance JSON" >&2; exit 1; }
python - "$manifest" "$FRAMEWORK" <<'PY'
import json,sys
p,fw=sys.argv[1:]
r=json.load(open(p))
assert r.get("framework")==fw, r
assert r.get("isolated_lab") is True, r
assert r.get("post_exploitation") is False, r
allowed={"registration","idle","poll","synthetic_task","synthetic_result","sleep","reconnect"}
stages=set(r.get("lifecycle",[]))
assert stages and stages <= allowed, r
print(json.dumps(r,indent=2,sort_keys=True))
PY
