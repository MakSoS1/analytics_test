#!/usr/bin/env bash
set -euo pipefail
if [[ $# -lt 5 ]]; then echo "usage: $0 STAGE SHARD SHARDS OUT_DIR CAPTURE_FILE" >&2; exit 2; fi
STAGE="$1" SHARD="$2" SHARDS="$3" OUT="$4" PCAP="$5"
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
PYTHON_BIN="$(command -v python)"
rm -f /tmp/coverlab_server_trace.jsonl /tmp/coverlab_server_trace.jsonl.lock /tmp/coverlab_wss_trace.jsonl
mkdir -p "$OUT" "$(dirname "$PCAP")"
rm -f "$PCAP"

sudo tcpdump -i ccbr0 -s 0 -U -w "$PCAP" 'net 10.20.0.0/24' >"$OUT/tcpdump.log" 2>&1 &
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
    NO_PROXY='.test,10.20.0.0/24,localhost,127.0.0.1' no_proxy='.test,10.20.0.0/24,localhost,127.0.0.1' \
    "$PYTHON_BIN" -m coverlab.orchestrate --stage "$STAGE" --shard "$SHARD" --shards "$SHARDS" \
      --persona-index "$idx" --out "$pdir" --capture-file "$(basename "$PCAP")" &
  WORKER_PIDS+=("$!")
done
for pid in "${WORKER_PIDS[@]}"; do wait "$pid"; done
cleanup_capture
trap - EXIT

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

# Stage G is retained only as a trusted-site-inspired hard-negative/background
# slice for Cover Channels. The runtime wrapper forces these sessions benign on
# the wire; normalize the experiment metadata so no LOTS sample becomes a
# positive Cover Channel label by accident.
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

python - <<PY
import json
from pathlib import Path
p=Path('$OUT/manifests/campaigns.jsonl'); e=Path('$OUT/manifests/events.jsonl')
print(json.dumps({'stage':'$STAGE','shard':$SHARD,'campaigns':sum(1 for _ in p.open()),'events':sum(1 for _ in e.open()),'pcap_bytes':Path('$PCAP').stat().st_size}))
PY
