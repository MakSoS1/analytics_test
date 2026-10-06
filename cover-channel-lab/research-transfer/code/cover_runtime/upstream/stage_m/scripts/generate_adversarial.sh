#!/usr/bin/env bash
set -euo pipefail
if [[ $# -ne 2 ]]; then echo "usage: $0 OUT_DIR CAPTURE_FILE" >&2; exit 2; fi
OUT="$1" PCAP="$2"
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
PYTHON_BIN="$(command -v python)"
WSS_LOCK=/tmp/coverlab_wss_client.lock
rm -f /tmp/coverlab_server_trace.jsonl /tmp/coverlab_server_trace.jsonl.lock /tmp/coverlab_wss_trace.jsonl "$WSS_LOCK"
mkdir -p "$OUT" "$(dirname "$PCAP")"
rm -f "$PCAP"

CAPTURE_IF="${COVERLAB_CAPTURE_IF:-v-c2}"
sudo ip link show "$CAPTURE_IF" >/dev/null
sudo tcpdump -i "$CAPTURE_IF" -s 0 -U -w "$PCAP" 'net 10.20.0.0/24' >"$OUT/tcpdump.log" 2>&1 &
TCPDUMP_PID=$!
cleanup_capture() { sudo kill -INT "$TCPDUMP_PID" 2>/dev/null || true; wait "$TCPDUMP_PID" 2>/dev/null || true; }
trap cleanup_capture EXIT
sleep .3

NAMESPACES=(cc-office cc-dev cc-devops cc-soc)
PIDS=()
for idx in 0 1 2 3; do
  ns="${NAMESPACES[$idx]}"; pdir="$OUT/persona-$idx"; mkdir -p "$pdir"
  sudo ip netns exec "$ns" runuser -u "$USER" -- env \
    PYTHONPATH="$ROOT/src" GITHUB_SHA="${GITHUB_SHA:-local}" COVERLAB_GO_CLIENT=/tmp/coverlab-go-client COVERLAB_NODE_CLIENT="$ROOT/clients/node_client.mjs" \
    COVERLAB_WSS_CLIENT_LOCK="$WSS_LOCK" \
    NO_PROXY='.test,10.20.0.0/24,localhost,127.0.0.1' no_proxy='.test,10.20.0.0/24,localhost,127.0.0.1' \
    "$PYTHON_BIN" -m coverlab.adversarial_gen --persona-index "$idx" --out "$pdir" --capture-file "$(basename "$PCAP")" &
  PIDS+=("$!")
done
worker_rc=0
for pid in "${PIDS[@]}"; do
  if ! wait "$pid"; then worker_rc=1; fi
done
cleanup_capture; trap - EXIT
if [[ "$worker_rc" -ne 0 ]]; then
  echo "one or more adversarial persona workers failed" >&2
  exit 1
fi

mkdir -p "$OUT/manifests"; : > "$OUT/manifests/campaigns.jsonl"; : > "$OUT/manifests/events.jsonl"
for idx in 0 1 2 3; do
  cat "$OUT/persona-$idx/campaigns.jsonl" >> "$OUT/manifests/campaigns.jsonl"
  cat "$OUT/persona-$idx/events.jsonl" >> "$OUT/manifests/events.jsonl"
done
cp "$OUT/manifests/campaigns.jsonl" "$OUT/campaigns.jsonl"
cp "$OUT/manifests/events.jsonl" "$OUT/events.jsonl"
: > "$OUT/manifests/decrypted_transactions.jsonl"
[[ -f /tmp/coverlab_server_trace.jsonl ]] && cat /tmp/coverlab_server_trace.jsonl >> "$OUT/manifests/decrypted_transactions.jsonl"
[[ -f /tmp/coverlab_wss_trace.jsonl ]] && cat /tmp/coverlab_wss_trace.jsonl >> "$OUT/manifests/decrypted_transactions.jsonl"
count="$(wc -l < "$OUT/manifests/campaigns.jsonl")"
if [[ "$count" -ne 500 ]]; then echo "expected 500 adversarial sessions, got $count" >&2; exit 1; fi
echo "adversarial campaigns=$count pcap=$(stat -c%s "$PCAP") capture_if=$CAPTURE_IF"