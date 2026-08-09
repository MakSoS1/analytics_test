#!/usr/bin/env bash
set -euo pipefail
if [[ $# -lt 5 ]]; then echo "usage: $0 STAGE SHARD SHARDS OUT_DIR CAPTURE_FILE" >&2; exit 2; fi
STAGE="$1" SHARD="$2" SHARDS="$3" OUT="$4" PCAP="$5"
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
PYTHON_BIN="$(command -v python)"
WSS_LOCK=/tmp/coverlab_wss_client.lock
rm -f /tmp/coverlab_server_trace.jsonl /tmp/coverlab_server_trace.jsonl.lock /tmp/coverlab_wss_trace.jsonl "$WSS_LOCK"
mkdir -p "$OUT" "$(dirname "$PCAP")"
rm -f "$PCAP"

# Capture on the host-side peer of the server namespace. Every synthetic client
# exchange to 10.20.0.20/10.20.0.21 crosses v-c2 exactly once; the bridge master
# can miss switched veth frames even when tcpdump reports zero kernel drops.
CAPTURE_IF="${COVERLAB_CAPTURE_IF:-v-c2}"
sudo ip link show "$CAPTURE_IF" >/dev/null
sudo tcpdump -i "$CAPTURE_IF" -s 0 -U -w "$PCAP" 'net 10.20.0.0/24' >"$OUT/tcpdump.log" 2>&1 &
TCPDUMP_PID=$!
cleanup_capture() { sudo kill -INT "$TCPDUMP_PID" 2>/dev/null || true; wait "$TCPDUMP_PID" 2>/dev/null || true; }
trap cleanup_capture EXIT
sleep .3

NAMESPACES=(cc-office cc-dev cc-devops cc-soc)
WORKER_PIDS=()
for idx in 0 1 2 3; do
  ns="${NAMESPACES[$idx]}"; pdir="$OUT/persona-$idx"; mkdir -p "$pdir"
  sudo ip netns exec "$ns" runuser -u "$USER" -- env \
    PYTHONPATH="$ROOT/src" GITHUB_SHA="${GITHUB_SHA:-local}" COVERLAB_GO_CLIENT=/tmp/coverlab-go-client COVERLAB_NODE_CLIENT="$ROOT/clients/node_client.mjs" \
    COVERLAB_WSS_CLIENT_LOCK="$WSS_LOCK" \
    NO_PROXY='.test,10.20.0.0/24,localhost,127.0.0.1' no_proxy='.test,10.20.0.0/24,localhost,127.0.0.1' \
    "$PYTHON_BIN" -m coverlab.orchestrate_v2 --stage "$STAGE" --shard "$SHARD" --shards "$SHARDS" \
      --persona-index "$idx" --out "$pdir" --capture-file "$(basename "$PCAP")" &
  WORKER_PIDS+=("$!")
done
worker_rc=0
for pid in "${WORKER_PIDS[@]}"; do
  if ! wait "$pid"; then worker_rc=1; fi
done
cleanup_capture
trap - EXIT
if [[ "$worker_rc" -ne 0 ]]; then
  echo "one or more persona workers failed for stage=$STAGE shard=$SHARD" >&2
  exit 1
fi

mkdir -p "$OUT/manifests"
: > "$OUT/manifests/campaigns.jsonl"; : > "$OUT/manifests/events.jsonl"
for idx in 0 1 2 3; do
  cat "$OUT/persona-$idx/campaigns.jsonl" >> "$OUT/manifests/campaigns.jsonl"
  cat "$OUT/persona-$idx/events.jsonl" >> "$OUT/manifests/events.jsonl"
done
cp "$OUT/manifests/campaigns.jsonl" "$OUT/campaigns.jsonl"
cp "$OUT/manifests/events.jsonl" "$OUT/events.jsonl"

# HTTP/H2 and WSS use separate local trace writers so high-volume WSS lifecycle
# cannot be blocked by the HTTP process' cross-process flock. Merge both streams
# into one ground-truth file before Silver/Gold processing.
: > "$OUT/manifests/decrypted_transactions.jsonl"
[[ -f /tmp/coverlab_server_trace.jsonl ]] && cat /tmp/coverlab_server_trace.jsonl >> "$OUT/manifests/decrypted_transactions.jsonl"
[[ -f /tmp/coverlab_wss_trace.jsonl ]] && cat /tmp/coverlab_wss_trace.jsonl >> "$OUT/manifests/decrypted_transactions.jsonl"

# Stage G is generated benign on the wire by orchestrate_v2. Normalize the
# canonical campaign metadata as a defensive idempotent step; this is no longer
# used to turn suspicious wire traffic into benign labels.
if [[ "$STAGE" == "lots" ]]; then
  python - "$OUT/manifests/campaigns.jsonl" <<'PY'
import json, sys
from pathlib import Path
p = Path(sys.argv[1])
out = []
for line in p.read_text().splitlines():
    if not line.strip():
        continue
    r = json.loads(line)
    r.update({
        "label_binary": 0,
        "label_family": "benign",
        "label_intent": "benign",
        "attack_mapping": [],
        "experiment_stage": "G_trusted_background",
        "dataset_role": "hard_negative",
        "source_family": "trusted_site_inspired",
        "target_task": "cover_channel_detection",
    })
    out.append(json.dumps(r, separators=(",", ":"), default=str))
p.write_text("\n".join(out) + ("\n" if out else ""))
PY
  cp "$OUT/manifests/campaigns.jsonl" "$OUT/campaigns.jsonl"
fi

PYTHONPATH="$ROOT/src" python -m coverlab.validate_dataset_contract --stage-dir "$OUT" --out "$OUT/manifests/dataset_contract.json"
python - <<PY
import json
from pathlib import Path
p=Path('$OUT/manifests/campaigns.jsonl'); e=Path('$OUT/manifests/events.jsonl')
print(json.dumps({'stage':'$STAGE','shard':$SHARD,'campaigns':sum(1 for _ in p.open()),'events':sum(1 for _ in e.open()),'pcap_bytes':Path('$PCAP').stat().st_size,'capture_if':'$CAPTURE_IF'}))
PY