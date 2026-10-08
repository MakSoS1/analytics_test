#!/usr/bin/env bash
# Execute every per-family full68 analysis notebook on WSL and summarise them.
#
# Executed notebooks are evidence: a family whose notebook fails to run, or
# whose verdict is not `ready`, must not be reported as covered. The summary
# this writes is the machine-readable form of that.
#
# Usage: run_full68_notebooks.sh [evidence.json] [notebook-dir] [out-dir]
set -uo pipefail

LAB=/opt/tunnel_lab
EVIDENCE=${1:-$LAB/release/full68/evidence/analysis_evidence.json}
NOTEBOOKS=${2:-$LAB/release/full68/notebooks}
OUT=${3:-$LAB/release/full68/notebooks_executed}

[ -f "$EVIDENCE" ] || { echo "no evidence file: $EVIDENCE" >&2; exit 2; }
[ -d "$NOTEBOOKS" ] || { echo "no notebook directory: $NOTEBOOKS" >&2; exit 2; }
# Stale outputs from a previous evidence snapshot would be summarised alongside
# the new ones, so the report would describe two different corpora at once.
rm -rf "$OUT"
mkdir -p "$OUT"

export PYTHONPATH="${PYTHONPATH:-$LAB/scripts}"
export FULL68_ANALYSIS_EVIDENCE_JSON="$EVIDENCE"
export MPLBACKEND=Agg

ok=0
failed=0
for nb in "$NOTEBOOKS"/*.ipynb; do
  name=$(basename "$nb")
  if timeout "${FULL68_NB_TIMEOUT:-600}" jupyter nbconvert --to notebook --execute \
      --ExecutePreprocessor.timeout="${FULL68_CELL_TIMEOUT:-300}" \
      --output-dir "$OUT" "$nb" >>"$LAB/logs/full68_notebooks.log" 2>&1; then
    ok=$((ok + 1))
  else
    failed=$((failed + 1))
    printf 'FAILED %s\n' "$name" >&2
  fi
done

printf 'executed ok=%s failed=%s -> %s\n' "$ok" "$failed" "$OUT"

# The verdict summary is read back out of the executed notebooks, not recomputed
# here, so the report and the artifact can never disagree.
PYTHONPATH="$PYTHONPATH" python3 - "$OUT" <<'PY'
import json
import re
import sys
from pathlib import Path

out_dir = Path(sys.argv[1])
states = {}
for path in sorted(out_dir.glob("*.ipynb")):
    family = path.stem
    verdict = "not_executed"
    notebook = json.loads(path.read_text())
    for cell in notebook["cells"]:
        for output in cell.get("outputs", []):
            if output.get("output_type") == "error":
                verdict = f"error:{output.get('ename')}"
                break
            text = "".join(output.get("data", {}).get("text/markdown", []))
            match = re.search(r"— \*\*([a-z_]+)\*\*", text)
            if match:
                verdict = match.group(1)
    states[family] = verdict

summary = {}
for family, verdict in states.items():
    summary.setdefault(verdict, []).append(family)
report = {
    "notebooks": len(states),
    "by_verdict": {key: len(value) for key, value in sorted(summary.items())},
    "families": states,
}
(out_dir / "summary.json").write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")
print(json.dumps({"notebooks": report["notebooks"], "by_verdict": report["by_verdict"]}, sort_keys=True))
PY
