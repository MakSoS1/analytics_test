#!/usr/bin/env bash
set -euo pipefail
if [[ $# -lt 5 ]]; then
  echo "usage: $0 NETWORK_PROFILE SHARD SHARDS WORK_ROOT SHARD_NAME [LIMIT_PER_FAMILY]" >&2
  exit 2
fi
PROFILE="$1" SHARD="$2" SHARDS="$3" WORK="$4" NAME="$5" LIMIT_PER_FAMILY="${6:-0}"
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
STAGE_DIR="$WORK/stage" PARSER_DIR="$WORK/parsers" RELEASE_DIR="$WORK/release"
RAW_PCAP="$WORK/capture.raw.pcap" PCAP="$WORK/capture.pcap"
mkdir -p "$WORK" "$STAGE_DIR"
cleanup(){ bash "$ROOT/scripts/netem_v3.sh" clear v-c2 || true; "$ROOT/scripts/stop_services.sh" || true; }
trap cleanup EXIT

"$ROOT/scripts/stop_services.sh" || true
for dev in v-office v-dev v-c2 v-devops v-soc; do sudo ip link del "$dev" 2>/dev/null || true; done
"$ROOT/scripts/setup_netns.sh"
COVERLAB_ENABLE_STAGE_M=1 "$ROOT/scripts/start_services.sh"
bash "$ROOT/scripts/netem_v3.sh" apply "$PROFILE" v-c2

rm -f "$RAW_PCAP" "$PCAP" /tmp/coverlab_stage_m_dns_trace.jsonl /tmp/coverlab_stage_m_tunnel_trace.jsonl
sudo tcpdump -i v-c2 -B 8192 -s 0 -U -w "$RAW_PCAP" 'net 10.20.0.0/24' >"$WORK/tcpdump.log" 2>&1 &
TCPDUMP_PID=$!
stop_capture(){ sudo kill -INT "$TCPDUMP_PID" 2>/dev/null || true; wait "$TCPDUMP_PID" 2>/dev/null || true; }
trap 'stop_capture; cleanup' EXIT
sleep .3

NAMESPACES=(cc-office cc-dev cc-devops cc-soc)
PIDS=()
for idx in 0 1 2 3; do
  ns="${NAMESPACES[$idx]}"; pdir="$STAGE_DIR/persona-$idx"; mkdir -p "$pdir"
  sudo ip netns exec "$ns" runuser -u "$USER" -- env \
    PYTHONPATH="$ROOT/src" GITHUB_SHA="${GITHUB_SHA:-local}" \
    COVERLAB_GO_CLIENT=/tmp/coverlab-go-client COVERLAB_NODE_CLIENT="$ROOT/clients/node_client.mjs" \
    COVERLAB_STAGE_M_NODE_CLIENT="$ROOT/clients/stage_m_node_client.mjs" COVERLAB_STAGE_M_GO_TUNNEL=/tmp/coverlab-stage-m-go-tunnel \
    NO_PROXY='.test,10.20.0.0/24,localhost,127.0.0.1' no_proxy='.test,10.20.0.0/24,localhost,127.0.0.1' \
    python -m coverlab.stage_m_runtime --out "$pdir" --capture-file "$(basename "$PCAP")" \
      --network-profile "$PROFILE" --shard "$SHARD" --shards "$SHARDS" --persona-index "$idx" --limit-per-family "$LIMIT_PER_FAMILY" &
  PIDS+=("$!")
done
rc=0
for pid in "${PIDS[@]}"; do if ! wait "$pid"; then rc=1; fi; done
sleep 1
stop_capture
trap cleanup EXIT
if [[ "$rc" -ne 0 ]]; then echo "one or more Stage M persona workers failed" >&2; exit 1; fi

mkdir -p "$STAGE_DIR/manifests" "$STAGE_DIR/raw_runtime"
: > "$STAGE_DIR/manifests/campaigns.jsonl"; : > "$STAGE_DIR/manifests/events.jsonl"
for idx in 0 1 2 3; do
  cat "$STAGE_DIR/persona-$idx/campaigns.jsonl" >> "$STAGE_DIR/manifests/campaigns.jsonl"
  cat "$STAGE_DIR/persona-$idx/events.jsonl" >> "$STAGE_DIR/manifests/events.jsonl"
done
cp "$STAGE_DIR/manifests/campaigns.jsonl" "$STAGE_DIR/raw_runtime/campaigns.runtime.jsonl"
cp "$STAGE_DIR/manifests/events.jsonl" "$STAGE_DIR/raw_runtime/events.runtime.jsonl"
cp "$STAGE_DIR/manifests/campaigns.jsonl" "$STAGE_DIR/campaigns.jsonl"
cp "$STAGE_DIR/manifests/events.jsonl" "$STAGE_DIR/events.jsonl"

: > "$STAGE_DIR/manifests/decrypted_transactions.jsonl"
[[ -f /tmp/coverlab_server_trace.jsonl ]] && cat /tmp/coverlab_server_trace.jsonl >> "$STAGE_DIR/manifests/decrypted_transactions.jsonl"
[[ -f /tmp/coverlab_wss_trace.jsonl ]] && cat /tmp/coverlab_wss_trace.jsonl >> "$STAGE_DIR/manifests/decrypted_transactions.jsonl"
[[ -f /tmp/coverlab_stage_m_dns_trace.jsonl ]] && cp /tmp/coverlab_stage_m_dns_trace.jsonl "$STAGE_DIR/manifests/dns_trace.jsonl"
[[ -f /tmp/coverlab_stage_m_tunnel_trace.jsonl ]] && cp /tmp/coverlab_stage_m_tunnel_trace.jsonl "$STAGE_DIR/manifests/tunnel_trace.jsonl"

PYTHONPATH="$ROOT/src" python -m coverlab.stage_m_export --out "$STAGE_DIR/manifests/stage_m_catalog"
PYTHONPATH="$ROOT/src" python "$ROOT/scripts/retime_stage_m_pcap.py" \
  --input "$RAW_PCAP" --output "$PCAP" --campaigns "$STAGE_DIR/manifests/campaigns.jsonl" \
  --events "$STAGE_DIR/manifests/events.jsonl" --report "$STAGE_DIR/manifests/retime_report.json"
cp "$STAGE_DIR/manifests/campaigns.jsonl" "$STAGE_DIR/campaigns.jsonl"
cp "$STAGE_DIR/manifests/events.jsonl" "$STAGE_DIR/events.jsonl"
PYTHONPATH="$ROOT/src" python -m coverlab.stage_m_quality --stage-dir "$STAGE_DIR" --out "$STAGE_DIR/manifests/stage_m_quality.json"

PYTHONPATH="$ROOT/src" python -m coverlab.validate_dataset_contract_v3 --stage-dir "$STAGE_DIR" --out "$STAGE_DIR/manifests/dataset_contract.json"
"$ROOT/scripts/process_parsers.sh" "$PCAP" "$STAGE_DIR" "$PARSER_DIR"
"$ROOT/scripts/package_layers.sh" "$STAGE_DIR" "$PCAP" "$PARSER_DIR" "$RELEASE_DIR" "$NAME"

BRONZE="$RELEASE_DIR/bronze/$NAME" QUALITY="$RELEASE_DIR/quality/$NAME"
zstd -T0 -q -9 -f "$RAW_PCAP" -o "$BRONZE/captures/${NAME}.raw-runtime.pcap.zst"
cp -a "$STAGE_DIR/raw_runtime" "$BRONZE/manifests/"
cp -a "$STAGE_DIR/manifests/stage_m_catalog" "$QUALITY/"
cp "$STAGE_DIR/manifests/retime_report.json" "$QUALITY/"
cp "$STAGE_DIR/manifests/stage_m_quality.json" "$QUALITY/"
cat > "$QUALITY/stage_m_positive_only.json" <<JSON
{"positive_only":true,"network_profile":"$PROFILE","shard":$SHARD,"shards":$SHARDS,"runtime_capture_retained":true,"retimed_capture_used_for_parsers_and_features":true}
JSON

cleanup; trap - EXIT
echo "$RELEASE_DIR"
