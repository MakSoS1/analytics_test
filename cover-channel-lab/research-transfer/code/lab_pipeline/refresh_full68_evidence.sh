#!/usr/bin/env bash
# One pass over the current full68 capture snapshot, end to end, on WSL.
#
#   features -> protocol QC -> inventory -> frozen split -> route models
#            -> aggregate evidence -> per-family notebooks
#
# Every stage writes under the full68 release root and nothing here reads office
# traffic: the office acceptance is a separate phase with its own report. Re-run
# it whenever the campaigns have grown; each stage is a full recompute, so the
# artifacts always describe one consistent snapshot rather than a mixture.
set -uo pipefail

LAB=/opt/tunnel_lab
SCRIPTS="$LAB/scripts"
OUT="${FULL68_OUT:-$LAB/release/full68}"
EVID="$OUT/evidence"
MODELS="$OUT/models_lab"
export PYTHONPATH="${PYTHONPATH:-$SCRIPTS}"

mkdir -p "$EVID" "$MODELS" "$LAB/logs"
cd "$SCRIPTS" || exit 2

step() { printf '\n[%s] == %s ==\n' "$(date -u +%FT%TZ)" "$*"; }

step "fast-v1 features from the full68 captures"
python3 -m lab_pipeline.extract_fastv1_features \
  --metadata-dir "$OUT/captures/metadata" \
  --sources wsl_tunnel_lab_full68 \
  --out-csv "$EVID/lab.csv" || exit 3

step "protocol QC over the same captures"
python3 qc_protocol.py \
  --metadata-dir "$OUT/captures/metadata" --pcap-dir "$OUT/captures/pcaps" \
  --out-json "$EVID/qc.json" > "$LAB/logs/full68_qc.json" 2>&1 || exit 4
python3 -c "
import json
d = json.load(open('$EVID/qc.json'))
print('qc totals:', json.dumps(d['totals'], sort_keys=True))
"

step "inventory bound to the campaign contract"
python3 -m lab_pipeline.lab_inventory \
  --metadata-dir "$OUT/captures/metadata" \
  --scope docs/full_scope_catalogue.json \
  --campaign-contract docs/full68_campaign_contract.json \
  --qc "$EVID/qc.json" \
  --out-json "$EVID/inventory.json" || exit 5

step "frozen split, grouped by session and stratified by family"
python3 -m lab_pipeline.split_manifest \
  --csv "$EVID/lab.csv" --group-key session_id \
  --stratify-key label_family --out-json "$EVID/split.json" || exit 6

step "one lab-phase model per detection route"
ROUTE_ARGS=()
for route in tcp_tls_fast quic_udp special_transport; do
  if python3 -m lab_pipeline.train_route_lab \
      --lab-csv "$EVID/lab.csv" --route "$route" \
      --out-model "$MODELS/${route}.json" \
      --out-json "$MODELS/${route}_report.json"; then
    ROUTE_ARGS+=(--route-report "$MODELS/${route}_report.json")
  else
    printf 'route %s did not train on this snapshot\n' "$route" >&2
  fi
done

step "aggregate, data-free evidence for the notebooks"
python3 -m lab_pipeline.build_analysis_evidence \
  --inventory "$EVID/inventory.json" \
  --features-csv "$EVID/lab.csv" \
  --split-manifest "$EVID/split.json" \
  "${ROUTE_ARGS[@]}" \
  --out-json "$EVID/analysis_evidence.json" \
  --wsl-root "$LAB" || exit 7

step "regenerate the per-family notebooks"
python3 -m lab_pipeline.generate_analysis_notebooks \
  --out-dir "$OUT/notebooks" --wsl-root "$LAB" || exit 8

step "pack the portable route-release folder"
python3 -m lab_pipeline.pack_route_release \
  --models-dir "$MODELS" --out-dir "$OUT/release_bundle" \
  --evidence-json "$EVID/analysis_evidence.json" || exit 9

step "execute every notebook against this evidence"
bash lab_pipeline/run_full68_notebooks.sh \
  "$EVID/analysis_evidence.json" "$OUT/notebooks" "$OUT/notebooks_executed" || exit 10

step "done"
