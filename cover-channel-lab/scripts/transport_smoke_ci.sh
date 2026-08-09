#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
PY="$(command -v python)"
WORK="${RUNNER_TEMP:-/tmp}/coverlab-smoke-gate"
STAGE="$WORK/stage"
PARSER="$WORK/parsers"
RELEASE="$WORK/release"
PCAP="$WORK/smoke.pcap"
TCPDUMP_PID=""
FAILED=1

rm -rf "$WORK"
mkdir -p "$STAGE/manifests" "$PARSER" "$RELEASE"
rm -f /tmp/coverlab_server_trace.jsonl /tmp/coverlab_server_trace.jsonl.lock /tmp/coverlab_wss_trace.jsonl /tmp/coverlab_wss_client.lock

cleanup_capture() {
  if [[ -n "${TCPDUMP_PID:-}" ]]; then
    sudo kill -INT "$TCPDUMP_PID" 2>/dev/null || true
    wait "$TCPDUMP_PID" 2>/dev/null || true
    TCPDUMP_PID=""
  fi
}

dump_diagnostics() {
  local logdir="${RUNNER_TEMP:-/tmp}/coverlab-services"
  echo '===== COVERLAB SMOKE DIAGNOSTICS =====' >&2
  for name in http https wss h3 grpc mqtt connect; do
    if [[ -f "$logdir/$name.log" ]]; then
      echo "----- $name -----" >&2
      tail -n 160 "$logdir/$name.log" >&2 || true
    fi
  done
  sudo ip netns exec cc-c2 ss -s >&2 2>/dev/null || true
  sudo ip netns exec cc-c2 ss -lntup >&2 2>/dev/null || true
  sudo ip netns exec cc-c2 ss -lnup >&2 2>/dev/null || true
}

cleanup() {
  cleanup_capture
  if [[ "$FAILED" != 0 ]]; then dump_diagnostics; fi
  "$ROOT/scripts/stop_services.sh" || true
}
trap cleanup EXIT

"$ROOT/scripts/setup_netns.sh"
"$ROOT/scripts/start_services.sh"

# Capture the complete smoke path at the canonical server-side veth. Every
# synthetic exchange to 10.20.0.20/10.20.0.21 crosses this interface exactly
# once, unlike the bridge master which can miss switched frames.
CAPTURE_IF="${COVERLAB_CAPTURE_IF:-v-c2}"
sudo ip link show "$CAPTURE_IF" >/dev/null
sudo tcpdump -i "$CAPTURE_IF" -s 0 -U -w "$PCAP" 'net 10.20.0.0/24' >"$WORK/tcpdump.log" 2>&1 &
TCPDUMP_PID=$!
sleep .4

COMMON_ENV=(
  PYTHONPATH="$ROOT/src"
  GITHUB_SHA="${GITHUB_SHA:-local}"
  COVERLAB_GO_CLIENT=/tmp/coverlab-go-client
  COVERLAB_NODE_CLIENT="$ROOT/clients/node_client.mjs"
  COVERLAB_WSS_CLIENT_LOCK=/tmp/coverlab_wss_client.lock
  COVERLAB_CAPTURE_IF="$CAPTURE_IF"
  NO_PROXY='.test,10.20.0.0/24,localhost,127.0.0.1'
  no_proxy='.test,10.20.0.0/24,localhost,127.0.0.1'
)

# 1) Functional catalog smoke: every scenario ID, benign/suspicious semantics
# where applicable, every generic client stack, one 60-step Stage-C sequence,
# and Stage-G background-only contract checks.
sudo ip netns exec cc-dev runuser -u "$USER" -- env "${COMMON_ENV[@]}" \
  "$PY" "$ROOT/scripts/scenario_smoke.py" --out "$STAGE/manifests"

# 2) Exact regression for the scale-only failure seen in sequence-03: four
# persona processes execute real 60-transaction Stage-C campaigns concurrently.
# HTTP phases remain concurrent; the production asyncio WSS path owns the shared
# lifecycle lock for connect/send/recv/close. All four manifests are folded into
# this smoke's parser/Gold validation below.
SEQ_NAMESPACES=(cc-office cc-dev cc-devops cc-soc)
seq_pids=()
for idx in 0 1 2 3; do
  seq_out="$WORK/sequence-persona-$idx"
  mkdir -p "$seq_out"
  sudo ip netns exec "${SEQ_NAMESPACES[$idx]}" runuser -u "$USER" -- env "${COMMON_ENV[@]}" \
    "$PY" "$ROOT/scripts/sequence_concurrency_smoke.py" --persona-index "$idx" --out "$seq_out" &
  seq_pids+=("$!")
done
seq_rc=0
for pid in "${seq_pids[@]}"; do
  if ! wait "$pid"; then seq_rc=1; fi
done
if [[ "$seq_rc" -ne 0 ]]; then
  echo 'four-persona Stage-C concurrency regression failed' >&2
  exit 1
fi
for idx in 0 1 2 3; do
  cat "$WORK/sequence-persona-$idx/campaigns.jsonl" >> "$STAGE/manifests/campaigns.jsonl"
  cat "$WORK/sequence-persona-$idx/events.jsonl" >> "$STAGE/manifests/events.jsonl"
done

# 3) Bounded WSS server soak across every persona. This is intentionally
# sequential because production Python WSS lifetimes are serialized; the
# preceding Stage-C block is the true four-process concurrency regression.
for ns in cc-office cc-dev cc-devops cc-soc; do
  echo "WSS soak persona: $ns"
  sudo ip netns exec "$ns" runuser -u "$USER" -- env "${COMMON_ENV[@]}" \
    "$PY" "$ROOT/scripts/wss_stress_smoke.py" \
      --connections 40 --attempts 3 --open-timeout 8 --inter-delay 0.008
done

# 4) Recheck advanced QUIC transports after catalog + sequence + WSS churn.
for mode in request connect-udp webtransport; do
  extra=()
  if [[ "$mode" != request ]]; then extra=(--mode "$mode" --body "post-smoke-$mode"); fi
  sudo ip netns exec cc-dev runuser -u "$USER" -- env "${COMMON_ENV[@]}" \
    "$PY" -m coverlab.h3_fixture client --host cover-h3.test --port 8444 \
      "${extra[@]}"
done

# Final WSS acceptance check after the soak.
sudo ip netns exec cc-dev runuser -u "$USER" -- env "${COMMON_ENV[@]}" \
  "$PY" "$ROOT/scripts/wss_stress_smoke.py" --connections 20 --inter-delay 0.01

cleanup_capture

# Assemble the same ground-truth shape used by real shards.
: > "$STAGE/manifests/decrypted_transactions.jsonl"
[[ -f /tmp/coverlab_server_trace.jsonl ]] && cat /tmp/coverlab_server_trace.jsonl >> "$STAGE/manifests/decrypted_transactions.jsonl"
[[ -f /tmp/coverlab_wss_trace.jsonl ]] && cat /tmp/coverlab_wss_trace.jsonl >> "$STAGE/manifests/decrypted_transactions.jsonl"
cp "$STAGE/manifests/campaigns.jsonl" "$STAGE/campaigns.jsonl"
cp "$STAGE/manifests/events.jsonl" "$STAGE/events.jsonl"

# 5) Parser + feature smoke. Both parsers must succeed and package_layers must
# pass the same campaign mapping, leakage and Bronze/Silver/Gold quality gates
# used by full shards.
"$ROOT/scripts/process_parsers.sh" "$PCAP" "$STAGE" "$PARSER"
"$ROOT/scripts/package_layers.sh" "$STAGE" "$PCAP" "$PARSER" "$RELEASE" smoke-gate

HEALTH="$RELEASE/quality/smoke-gate/capture_health.json"
[[ -s "$HEALTH" ]]
jq -e '.passed == true and .suricata_exit_zero == true and .zeek_exit_zero == true and .mapping_coverage_ge_0_95 == true' "$HEALTH" >/dev/null

# 6) Exact future-02 regression. The previous bridge-master capture produced all
# 350 campaigns and 1,400 events but stopped before the final 18 DevOps sessions,
# yielding 0.948571 mapping despite zero tcpdump kernel drops. Re-run that exact
# shard through the server-veth capture point and require the unchanged >=0.95
# quality gate before a full corpus can start.
FUTURE_WORK="$WORK/future02-regression"
FUTURE_STAGE="$FUTURE_WORK/stage"
FUTURE_PARSER="$FUTURE_WORK/parsers"
FUTURE_RELEASE="$FUTURE_WORK/release"
FUTURE_PCAP="$FUTURE_WORK/future-02.pcap"
mkdir -p "$FUTURE_WORK"
COVERLAB_CAPTURE_IF="$CAPTURE_IF" "$ROOT/scripts/generate_stage.sh" future 2 4 "$FUTURE_STAGE" "$FUTURE_PCAP"
"$ROOT/scripts/process_parsers.sh" "$FUTURE_PCAP" "$FUTURE_STAGE" "$FUTURE_PARSER"
"$ROOT/scripts/package_layers.sh" "$FUTURE_STAGE" "$FUTURE_PCAP" "$FUTURE_PARSER" "$FUTURE_RELEASE" future-02-regression

FUTURE_HEALTH="$FUTURE_RELEASE/quality/future-02-regression/capture_health.json"
[[ -s "$FUTURE_HEALTH" ]]
jq -e '.campaign_count == 350 and .event_count == 1400 and .passed == true and .suricata_exit_zero == true and .zeek_exit_zero == true and .mapping_coverage_ge_0_95 == true' "$FUTURE_HEALTH" >/dev/null

echo 'future-02 exact mapping regression: PASS'
cat "$FUTURE_HEALTH"

FAILED=0
"$ROOT/scripts/stop_services.sh" || true
trap - EXIT

echo 'coverlab comprehensive smoke gate: PASS'
cat "$STAGE/manifests/smoke_summary.json"
cat "$HEALTH"