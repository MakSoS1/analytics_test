#!/usr/bin/env bash
# Compare learners on ONE frozen snapshot, like for like.
#
# Same features, same split salt, same route, same threshold rule; only the
# estimator and the weighting change. The headline is the WORST family's flow
# recall at the lab FPR budget, because that is what the release gate is — a
# mean would let a strong family carry a failing one.
#
# Only the forest is exportable, so the boosted runs write a report and no
# model. This answers "is a different algorithm worth writing a new evaluator",
# which is a different question from "which model ships".
set -uo pipefail

LAB=/opt/tunnel_lab
SCRIPTS="$LAB/scripts"
OUT="${1:-$LAB/release/full68/learner_comparison}"
LAB_CSV="${2:-$LAB/release/full68/evidence/lab.csv}"
export PYTHONPATH="${PYTHONPATH:-$SCRIPTS}"

[ -f "$LAB_CSV" ] || { echo "no feature table: $LAB_CSV" >&2; exit 2; }
mkdir -p "$OUT"
cd "$SCRIPTS" || exit 2

for route in tcp_tls_fast quic_udp special_transport; do
  for candidate in "rf" "rf_balanced" "hist_gbdt" "lightgbm"; do
    case "$candidate" in
      rf)          learner=rf;        extra=() ;;
      rf_balanced) learner=rf;        extra=(--family-balance) ;;
      hist_gbdt)   learner=hist_gbdt; extra=(--family-balance) ;;
      lightgbm)    learner=lightgbm;  extra=(--family-balance) ;;
    esac
    python3 -m lab_pipeline.train_route_lab \
      --lab-csv "$LAB_CSV" --route "$route" --learner "$learner" "${extra[@]}" \
      --out-model "$OUT/${route}_${candidate}.model.json" \
      --out-json  "$OUT/${route}_${candidate}.json" >/dev/null 2>>"$OUT/errors.log" \
      || printf 'FAILED %s %s\n' "$route" "$candidate" >&2
  done
done

python3 - "$OUT" <<'PY'
import json
import sys
from pathlib import Path

out = Path(sys.argv[1])
rows = []
for path in sorted(out.glob("*.json")):
    if path.name == "errors.log":
        continue
    try:
        report = json.loads(path.read_text())
    except ValueError:
        continue
    if report.get("status") != "ok":
        continue
    rows.append({
        "route": report["route"],
        "candidate": path.stem.split("_", maxsplit=0)[0] and path.stem[len(report["route"]) + 1:],
        "learner": report.get("learner"),
        "family_balanced": report.get("family_balanced"),
        "worst_family_flow_recall": report.get("worst_family_flow_recall"),
        "families_below_0_95": len(report.get("families_below_0_95") or []),
        "lab_benign_fpr_test": report.get("lab_benign_fpr_test"),
        "exportable": report.get("exportable"),
    })
(out / "comparison.json").write_text(json.dumps(rows, indent=2) + "\n")
header = f"{'route':<18}{'candidate':<13}{'worst recall':>13}{'<0.95':>7}{'lab FPR':>10}{'export':>8}"
print(header)
print("-" * len(header))
for row in sorted(rows, key=lambda r: (r["route"], r["candidate"])):
    worst = row["worst_family_flow_recall"]
    fpr = row["lab_benign_fpr_test"]
    print(f"{row['route']:<18}{row['candidate']:<13}"
          f"{(f'{worst:.4f}' if worst is not None else '-'):>13}"
          f"{row['families_below_0_95']:>7}"
          f"{(f'{fpr:.5f}' if fpr is not None else '-'):>10}"
          f"{('yes' if row['exportable'] else 'no'):>8}")
PY
