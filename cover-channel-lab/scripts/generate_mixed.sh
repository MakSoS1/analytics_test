#!/usr/bin/env bash
set -euo pipefail
if [[ $# -ne 3 ]]; then echo "usage: $0 MIXED_INDEX OUT_DIR CAPTURE_FILE" >&2; exit 2; fi
IDX="$1" OUT="$2" PCAP="$3"
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
PYTHON_BIN="$(command -v python)"
DURATION=$(( 60 + (IDX % 3) * 30 ))
FLOWS=$(( 3000 + IDX * 400 )); (( FLOWS > 15000 )) && FLOWS=15000
rm -f /tmp/coverlab_server_trace.jsonl /tmp/coverlab_server_trace.jsonl.lock
mkdir -p "$OUT" "$(dirname "$PCAP")"
rm -f "$PCAP"
sudo tcpdump -i ccbr0 -s 0 -U -w "$PCAP" 'net 10.20.0.0/24' >"$OUT/tcpdump.log" 2>&1 &
TCPDUMP_PID=$!
cleanup_capture() { sudo kill -INT "$TCPDUMP_PID" 2>/dev/null || true; wait "$TCPDUMP_PID" 2>/dev/null || true; }
trap cleanup_capture EXIT
sleep .3
NAMESPACES=(cc-office cc-dev cc-devops cc-soc); PIDS=()
for pidx in 0 1 2 3; do
  ns="${NAMESPACES[$pidx]}"; pdir="$OUT/persona-$pidx"; mkdir -p "$pdir"
  sudo ip netns exec "$ns" runuser -u "$USER" -- env \
    PYTHONPATH="$ROOT/src" GITHUB_SHA="${GITHUB_SHA:-local}" COVERLAB_GO_CLIENT=/tmp/coverlab-go-client COVERLAB_NODE_CLIENT="$ROOT/clients/node_client.mjs" \
    NO_PROXY='.test,10.20.0.0/24,localhost,127.0.0.1' no_proxy='.test,10.20.0.0/24,localhost,127.0.0.1' \
    "$PYTHON_BIN" -m coverlab.orchestrate --stage mixed --mixed-index "$IDX" --duration-minutes "$DURATION" --flow-count "$FLOWS" \
      --persona-index "$pidx" --out "$pdir" --capture-file "$(basename "$PCAP")" &
  PIDS+=("$!")
done
for pid in "${PIDS[@]}"; do wait "$pid"; done
cleanup_capture; trap - EXIT
mkdir -p "$OUT/manifests"; : > "$OUT/manifests/campaigns.jsonl"; : > "$OUT/manifests/events.jsonl"
for pidx in 0 1 2 3; do
  cat "$OUT/persona-$pidx/campaigns.jsonl" >> "$OUT/manifests/campaigns.jsonl"
  cat "$OUT/persona-$pidx/events.jsonl" >> "$OUT/manifests/events.jsonl"
done
cp "$OUT/manifests/campaigns.jsonl" "$OUT/campaigns.jsonl"; cp "$OUT/manifests/events.jsonl" "$OUT/events.jsonl"
if [[ -f /tmp/coverlab_server_trace.jsonl ]]; then cp /tmp/coverlab_server_trace.jsonl "$OUT/manifests/decrypted_transactions.jsonl"; else : > "$OUT/manifests/decrypted_transactions.jsonl"; fi
echo "mixed capture $IDX complete: duration=${DURATION}m flows=$FLOWS pcap=$(stat -c%s "$PCAP")"
