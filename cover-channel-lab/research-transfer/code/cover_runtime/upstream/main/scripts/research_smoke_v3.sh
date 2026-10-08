#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
WORK="${RUNNER_TEMP:-/tmp}/coverlab-research-v3-smoke"
rm -rf "$WORK"; mkdir -p "$WORK"

# Stage K must include the complete event-count distribution in ACTUAL generated events,
# not merely metadata claiming a multi-event target.
COVERLAB_BENIGN_SESSIONS=100 COVERLAB_NETEM_PROFILE=wan_20ms \
  "$ROOT/scripts/run_shard_ci.sh" benign 0 1 "$WORK/benign" K-benign-smoke
jq -e '.passed == true' "$WORK/benign/release/quality/K-benign-smoke/capture_health.json" >/dev/null
jq -e '.passed == true and .contract_revision == 3' "$WORK/benign/release/quality/K-benign-smoke/dataset_contract.json" >/dev/null
python - "$WORK/benign/release/bronze/K-benign-smoke/manifests/campaigns.jsonl" <<'PY'
import json,sys
r=[json.loads(x) for x in open(sys.argv[1]) if x.strip()]; c=[int(x['event_count_target']) for x in r]
assert len(r)==100 and min(c)==1 and max(c)>=61
assert all(x.get('label_binary',0)==0 for x in r)
assert all(x.get('temporal_negative_pair') is True for x in r)
assert all(x.get('wire_family_matched') is True for x in r)
assert all(int(x.get('expected_events',-1))==int(x.get('event_count_target',-2)) for x in r)
print({'stage_k_multi_event':'pass','campaigns':len(r),'actual_events':sum(int(x['expected_events']) for x in r),'events_target':sum(c)})
PY

# Real, non-accelerated, multi-event 5-second timing smoke (~2.5 min wall clock).
COVERLAB_LONG_REPETITIONS=1 COVERLAB_NETEM_PROFILE=clean \
  "$ROOT/scripts/run_shard_ci.sh" long 0 6 "$WORK/long" L-long-5s-smoke
jq -e '.passed == true' "$WORK/long/release/quality/L-long-5s-smoke/capture_health.json" >/dev/null
python - "$WORK/long/release/bronze/L-long-5s-smoke/manifests/campaigns.jsonl" <<'PY'
import json,sys
rows=[json.loads(x) for x in open(sys.argv[1]) if x.strip()]
assert rows and all(r.get('timing_acceleration')==1 for r in rows)
assert all(r.get('training_eligible') is False for r in rows)
assert all(float(r.get('real_interval_seconds',0))==5 for r in rows)
assert all(int(r.get('event_count_target',0))>=30 for r in rows)
assert all(int(r.get('expected_events',0))==int(r.get('event_count_target',-1)) for r in rows)
assert all(len(r.get('timing_modes_exercised',[]))>=7 for r in rows)
print({'long_timing_smoke':'pass','campaigns':len(rows),'actual_events':sum(int(r['expected_events']) for r in rows)})
PY

MODEL="$WORK/model-fixture"; OUT="$WORK/models"; EVAL="$WORK/evaluation"; READY="$WORK/readiness-dataset"
mkdir -p "$READY/bronze/K/manifests" "$READY/bronze/L/manifests" "$EVAL"
cp "$WORK/benign/release/bronze/K-benign-smoke/manifests/campaigns.jsonl" "$READY/bronze/K/manifests/"
cp "$WORK/long/release/bronze/L-long-5s-smoke/manifests/campaigns.jsonl" "$READY/bronze/L/manifests/"

PYTHONPATH="$ROOT/src" python "$ROOT/scripts/model_v3_smoke_fixture.py" --out "$MODEL"
PYTHONPATH="$ROOT/src" python -m coverlab.train_baseline_v3 --dataset-root "$MODEL" --out "$OUT" --seed 23
PYTHONPATH="$ROOT/src" python -m coverlab.sequence_fusion_v3 --dataset-root "$MODEL" --models "$OUT" --out "$OUT" --seed 23 --epochs 3
PYTHONPATH="$ROOT/src" python -m coverlab.unseen_eval_v3 --dataset-root "$MODEL" --out "$EVAL/unseen.json" --seed 23
PYTHONPATH="$ROOT/src" python -m coverlab.research_readiness_v3 --dataset-root "$READY" --out "$EVAL/research_readiness.json" --min-benign 100
PYTHONPATH="$ROOT/src" python -m coverlab.external_evidence_status_v3 --out-dir "$EVAL/external"
PYTHONPATH="$ROOT/src" python -m coverlab.model_acceptance_v3 \
  --baseline-report "$OUT/baseline_report.json" --advanced-report "$OUT/advanced_v3_report.json" \
  --unseen-report "$EVAL/unseen.json" --research-readiness-report "$EVAL/research_readiness.json" \
  --framework-report "$EVAL/external/framework_status.json" --ech-report "$EVAL/external/ech_status.json" \
  --environment-report "$EVAL/external/environment_status.json" --long-timing-report "$EVAL/external/long_timing_status.json" \
  --require-nine-point-evidence --out "$EVAL/model_acceptance_v3.json"

for f in B1-content.joblib B2-session.joblib B3-opaque.joblib B2-sequence.pt B2-opaque-sequence.pt B2-visible-sequence.pt fusion-router.joblib baseline_report.json advanced_v3_report.json; do
  [[ -s "$OUT/$f" ]] || { echo "missing advanced model artifact: $f" >&2; exit 1; }
done
jq -e '.opaque_sequence.status == "ok" and .visible_sequence.status == "ok" and .fusion.status == "ok" and .opaque_plaintext_leakage_guard == true' "$OUT/advanced_v3_report.json" >/dev/null
jq -e '.policy_revision == 4 and .model_artifacts_created == true and .model_candidate == false and .nine_point_evidence_ready == false' "$EVAL/model_acceptance_v3.json" >/dev/null
jq -e '.benign_corpus_ready == true and .benign_multi_event_ready == true and .long_timing_ready == false' "$EVAL/research_readiness.json" >/dev/null

# P0 regression: opaque inference must survive physical deletion of every decrypted transaction/field table.
OPAQUE="$WORK/opaque-no-plaintext"; cp -a "$MODEL" "$OPAQUE"
python - "$OPAQUE" <<'PY'
import sys
from pathlib import Path
import pandas as pd
root=Path(sys.argv[1]); g=next(root.rglob('session_features.parquet')).parent
s=pd.read_parquet(g/'session_features.parquet'); ids=set(s.loc[s.visibility_mode.astype(str).str.contains('opaque'),'campaign_id'].astype(str))
assert ids
for name in ('session_features.parquet','campaign_splits.parquet','packet_sequence_features.parquet'):
    p=g/name; d=pd.read_parquet(p); d=d[d.campaign_id.astype(str).isin(ids)]; d.to_parquet(p,index=False)
for name in ('transaction_features.parquet','field_features.parquet'):
    p=g/name
    if p.exists(): p.unlink()
assert not any(root.rglob('transaction_features.parquet'))
assert any(root.rglob('packet_sequence_features.parquet'))
print({'opaque_campaigns':len(ids),'plaintext_tables_removed':True})
PY
PYTHONPATH="$ROOT/src" python -m coverlab.evaluate_advanced_v3 --dataset-root "$OPAQUE" --models "$OUT" --out "$EVAL/opaque_no_plaintext.json"
jq -e '."B2-opaque-sequence".rows > 0 and ."fusion-router".rows > 0 and .opaque_plaintext_leakage_guard == true' "$EVAL/opaque_no_plaintext.json" >/dev/null

echo 'coverlab research v4 audit smoke: PASS'
