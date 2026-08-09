#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
PY="$(command -v python)"
WORK="${RUNNER_TEMP:-/tmp}/coverlab-smoke-gate"
STAGE="$WORK/stage"
PARSER="$WORK/parsers"
RELEASE="$WORK/release"
PCAP="$WORK/smoke.pcap"
MODEL_SMOKE="$WORK/model-smoke"
TCPDUMP_PID=""
CAPTURE_DRAIN_SECONDS="${COVERLAB_CAPTURE_DRAIN_SECONDS:-1.0}"
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

drain_capture() {
  if [[ -n "${TCPDUMP_PID:-}" ]]; then
    sleep "$CAPTURE_DRAIN_SECONDS"
    sudo kill -USR2 "$TCPDUMP_PID" 2>/dev/null || true
    sleep 0.20
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

CAPTURE_IF="${COVERLAB_CAPTURE_IF:-v-c2}"
sudo ip link show "$CAPTURE_IF" >/dev/null
sudo tcpdump -i "$CAPTURE_IF" -B 8192 -s 0 -U -w "$PCAP" 'net 10.20.0.0/24' >"$WORK/tcpdump.log" 2>&1 &
TCPDUMP_PID=$!
sleep .4

COMMON_ENV=(
  PYTHONPATH="$ROOT/src"
  GITHUB_SHA="${GITHUB_SHA:-local}"
  COVERLAB_GO_CLIENT=/tmp/coverlab-go-client
  COVERLAB_NODE_CLIENT="$ROOT/clients/node_client.mjs"
  COVERLAB_WSS_CLIENT_LOCK=/tmp/coverlab_wss_client.lock
  COVERLAB_CAPTURE_IF="$CAPTURE_IF"
  COVERLAB_CAPTURE_DRAIN_SECONDS="$CAPTURE_DRAIN_SECONDS"
  NO_PROXY='.test,10.20.0.0/24,localhost,127.0.0.1'
  no_proxy='.test,10.20.0.0/24,localhost,127.0.0.1'
)

# 1) Functional catalog smoke: every scenario ID, benign/suspicious semantics,
# every generic client stack, one Stage-C sequence, and Stage-G contract checks.
sudo ip netns exec cc-dev runuser -u "$USER" -- env "${COMMON_ENV[@]}" \
  "$PY" "$ROOT/scripts/scenario_smoke.py" --out "$STAGE/manifests"

# 2) Exact Stage-C four-persona concurrency regression.
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

# 3) Bounded WSS server soak across every persona, using the same asyncio stack
# as production generation rather than the previously flaky sync helper.
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

sudo ip netns exec cc-dev runuser -u "$USER" -- env "${COMMON_ENV[@]}" \
  "$PY" "$ROOT/scripts/wss_stress_smoke.py" --connections 20 --inter-delay 0.01

drain_capture
cleanup_capture

: > "$STAGE/manifests/decrypted_transactions.jsonl"
[[ -f /tmp/coverlab_server_trace.jsonl ]] && cat /tmp/coverlab_server_trace.jsonl >> "$STAGE/manifests/decrypted_transactions.jsonl"
[[ -f /tmp/coverlab_wss_trace.jsonl ]] && cat /tmp/coverlab_wss_trace.jsonl >> "$STAGE/manifests/decrypted_transactions.jsonl"
cp "$STAGE/manifests/campaigns.jsonl" "$STAGE/campaigns.jsonl"
cp "$STAGE/manifests/events.jsonl" "$STAGE/events.jsonl"

# 5) Parser + feature smoke.
"$ROOT/scripts/process_parsers.sh" "$PCAP" "$STAGE" "$PARSER"
"$ROOT/scripts/package_layers.sh" "$STAGE" "$PCAP" "$PARSER" "$RELEASE" smoke-gate

HEALTH="$RELEASE/quality/smoke-gate/capture_health.json"
[[ -s "$HEALTH" ]]
jq -e '.passed == true and .suricata_exit_zero == true and .zeek_exit_zero == true and .mapping_coverage_ge_0_95 == true' "$HEALTH" >/dev/null

# 6) Model-code regression on the compact smoke corpus. This isn't a quality
# benchmark; it proves field_features, temporal features, missingness handling,
# calibration/tuning separation and frozen scoring execute end-to-end before a
# long corpus run is allowed to start.
mkdir -p "$MODEL_SMOKE/models" "$MODEL_SMOKE/evaluation"
PYTHONPATH="$ROOT/src" "$PY" -m coverlab.train_baseline_v2 \
  --dataset-root "$RELEASE" --out "$MODEL_SMOKE/models" --seed 23
PYTHONPATH="$ROOT/src" "$PY" - "$MODEL_SMOKE/models/baseline_report.json" <<'PY'
import json, sys
from pathlib import Path
p=Path(sys.argv[1]); report=json.loads(p.read_text())
models=report.get('models', {})
ok=[name for name, r in models.items() if r.get('status') == 'ok']
assert len(ok) >= 2, (ok, models)
for name in ok:
    top=models[name].get('top_features', [])
    forbidden={'expected_events','seed','plaintext_sha256','suricata_alerts'}
    assert not forbidden.intersection({x.get('feature') for x in top}), (name, top)
print(json.dumps({'model_smoke':'pass','ok_models':ok}, sort_keys=True))
PY
PYTHONPATH="$ROOT/src" "$PY" -m coverlab.evaluate_mixed \
  --dataset-root "$RELEASE" --models "$MODEL_SMOKE/models" \
  --out "$MODEL_SMOKE/evaluation/scoring_codepath.json"
[[ -s "$MODEL_SMOKE/evaluation/scoring_codepath.json" ]]

# 7) Exact future-02 regression. Previous runs completed all 350 campaigns and
# 1,400 events while their PCAP ended before the final 18 campaigns. Keep the
# threshold unchanged and also enforce the new physical capture-tail guard.
FUTURE_WORK="$WORK/future02-regression"
FUTURE_STAGE="$FUTURE_WORK/stage"
FUTURE_PARSER="$FUTURE_WORK/parsers"
FUTURE_RELEASE="$FUTURE_WORK/release"
FUTURE_PCAP="$FUTURE_WORK/future-02.pcap"
mkdir -p "$FUTURE_WORK"
COVERLAB_CAPTURE_IF="$CAPTURE_IF" COVERLAB_CAPTURE_DRAIN_SECONDS="$CAPTURE_DRAIN_SECONDS" \
  "$ROOT/scripts/generate_stage.sh" future 2 4 "$FUTURE_STAGE" "$FUTURE_PCAP"
"$ROOT/scripts/process_parsers.sh" "$FUTURE_PCAP" "$FUTURE_STAGE" "$FUTURE_PARSER"
"$ROOT/scripts/package_layers.sh" "$FUTURE_STAGE" "$FUTURE_PCAP" "$FUTURE_PARSER" "$FUTURE_RELEASE" future-02-regression

FUTURE_HEALTH="$FUTURE_RELEASE/quality/future-02-regression/capture_health.json"
FUTURE_TAIL="$FUTURE_RELEASE/quality/future-02-regression/capture_tail_guard.json"
[[ -s "$FUTURE_HEALTH" && -s "$FUTURE_TAIL" ]]
jq -e '.campaign_count == 350 and .event_count == 1400 and .passed == true and .suricata_exit_zero == true and .zeek_exit_zero == true and .mapping_coverage_ge_0_95 == true' "$FUTURE_HEALTH" >/dev/null
jq -e '.passed == true' "$FUTURE_TAIL" >/dev/null

echo 'future-02 exact mapping + capture-tail regression: PASS'
cat "$FUTURE_HEALTH"
cat "$FUTURE_TAIL"

FAILED=0
"$ROOT/scripts/stop_services.sh" || true
trap - EXIT

echo 'coverlab comprehensive smoke gate: PASS'
cat "$STAGE/manifests/smoke_summary.json"
cat "$HEALTH"