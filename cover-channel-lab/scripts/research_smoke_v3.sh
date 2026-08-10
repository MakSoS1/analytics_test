#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
WORK="${RUNNER_TEMP:-/tmp}/coverlab-research-v3-smoke"
rm -rf "$WORK"; mkdir -p "$WORK"

# Real wire smoke for the new benign layer under actual kernel netem.
COVERLAB_BENIGN_SESSIONS=64 COVERLAB_NETEM_PROFILE=wan_20ms \
  "$ROOT/scripts/run_shard_ci.sh" benign 0 1 "$WORK/benign" K-benign-smoke
jq -e '.passed == true' "$WORK/benign/release/quality/K-benign-smoke/capture_health.json" >/dev/null
jq -e '.passed == true and .contract_revision == 3' "$WORK/benign/release/quality/K-benign-smoke/dataset_contract.json" >/dev/null

# Real, non-accelerated 5-second timing smoke. Full corpus owns 30s..60min profiles.
COVERLAB_LONG_REPETITIONS=1 COVERLAB_NETEM_PROFILE=clean \
  "$ROOT/scripts/run_shard_ci.sh" long 0 6 "$WORK/long" L-long-5s-smoke
jq -e '.passed == true' "$WORK/long/release/quality/L-long-5s-smoke/capture_health.json" >/dev/null
python - "$WORK/long/release/bronze/L-long-5s-smoke/manifests/campaigns.jsonl" <<'PY'
import json,sys
rows=[json.loads(x) for x in open(sys.argv[1]) if x.strip()]
assert rows and all(r.get('timing_acceleration')==1 for r in rows), rows
assert all(r.get('training_eligible') is False for r in rows), rows
assert all(float(r.get('real_interval_seconds',0))==5 for r in rows), rows
print({'long_timing_smoke':'pass','campaigns':len(rows)})
PY

# Deterministic model integration fixture: enough campaigns for four disjoint
# validation roles, sequence training and fusion without weakening the policy.
MODEL="$WORK/model-fixture"; OUT="$WORK/models"; EVAL="$WORK/evaluation"; READY="$WORK/readiness-dataset"
mkdir -p "$READY/bronze/K/manifests" "$READY/bronze/L/manifests" "$EVAL"
cp "$WORK/benign/release/bronze/K-benign-smoke/manifests/campaigns.jsonl" "$READY/bronze/K/manifests/"
cp "$WORK/long/release/bronze/L-long-5s-smoke/manifests/campaigns.jsonl" "$READY/bronze/L/manifests/"

PYTHONPATH="$ROOT/src" python "$ROOT/scripts/model_v3_smoke_fixture.py" --out "$MODEL"
PYTHONPATH="$ROOT/src" python -m coverlab.train_baseline_v3 --dataset-root "$MODEL" --out "$OUT" --seed 23
PYTHONPATH="$ROOT/src" python -m coverlab.sequence_fusion_v3 --dataset-root "$MODEL" --models "$OUT" --out "$OUT" --seed 23 --epochs 3
PYTHONPATH="$ROOT/src" python -m coverlab.unseen_eval_v3 --dataset-root "$MODEL" --out "$EVAL/unseen.json" --seed 23
PYTHONPATH="$ROOT/src" python -m coverlab.research_readiness_v3 --dataset-root "$READY" --out "$EVAL/research_readiness.json" --min-benign 64
PYTHONPATH="$ROOT/src" python -m coverlab.external_evidence_status_v3 --out-dir "$EVAL/external"
PYTHONPATH="$ROOT/src" python -m coverlab.model_acceptance_v3 \
  --baseline-report "$OUT/baseline_report.json" --advanced-report "$OUT/advanced_v3_report.json" \
  --unseen-report "$EVAL/unseen.json" --research-readiness-report "$EVAL/research_readiness.json" \
  --framework-report "$EVAL/external/framework_status.json" --ech-report "$EVAL/external/ech_status.json" \
  --environment-report "$EVAL/external/environment_status.json" --require-nine-point-evidence \
  --out "$EVAL/model_acceptance_v3.json"

for f in B1-content.joblib B2-session.joblib B3-opaque.joblib B2-sequence.pt fusion-router.joblib baseline_report.json advanced_v3_report.json; do
  [[ -s "$OUT/$f" ]] || { echo "missing advanced model artifact: $f" >&2; exit 1; }
done
jq -e '.sequence.status == "ok" and .fusion.status == "ok"' "$OUT/advanced_v3_report.json" >/dev/null
jq -e '.policy_revision == 3 and .model_artifacts_created == true and .model_candidate == false and .nine_point_evidence_ready == false' "$EVAL/model_acceptance_v3.json" >/dev/null
jq -e '.benign_corpus_ready == true and .long_timing_ready == false' "$EVAL/research_readiness.json" >/dev/null

echo 'coverlab research v3 smoke: PASS'
