#!/usr/bin/env bash
set -euo pipefail
if [[ $# -ne 2 ]]; then
  echo "usage: $0 EVIDENCE_ROOT OUT_ROOT" >&2
  exit 2
fi
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
EVIDENCE="$(realpath "$1")"
OUT="$(realpath -m "$2")"
MANIFEST="$EVIDENCE/framework_holdout.jsonl"
[[ -s "$MANIFEST" ]] || { echo "missing framework_holdout.jsonl" >&2; exit 1; }
mkdir -p "$OUT"

PYTHONPATH="$ROOT/src" python -m coverlab.external_campaign_adapter_v5 --kind framework --manifest "$MANIFEST" --evidence-root "$EVIDENCE" --out-root "$OUT"
while IFS= read -r cid; do
  [[ -n "$cid" ]] || continue
  STAGE="$OUT/$cid/stage"
  PARSERS="$OUT/$cid/parsers"
  SILVER="$OUT/$cid/silver"
  GOLD="$OUT/$cid/gold"
  QUALITY="$OUT/$cid/quality"
  PCAP="$(PYTHONPATH="$ROOT/src" python - "$MANIFEST" "$EVIDENCE" "$cid" <<'PY'
import json,sys
from pathlib import Path
m=Path(sys.argv[1]); root=Path(sys.argv[2]); cid=sys.argv[3]
for line in m.read_text().splitlines():
    if not line.strip(): continue
    r=json.loads(line)
    if str(r.get("campaign_id"))==cid:
        print(root/r["pcap_file"]);break
else:
    raise SystemExit(1)
PY
)"
  "$ROOT/scripts/process_parsers.sh" "$PCAP" "$STAGE" "$PARSERS"
  PYTHONPATH="$ROOT/src" python -m coverlab.pipeline_v3 --stage-dir "$STAGE" --pcap "$PCAP" --silver "$SILVER" --gold "$GOLD" --quality "$QUALITY"
done < <(python - "$MANIFEST" <<'PY'
import json,sys
for line in open(sys.argv[1]):
    if line.strip(): print(json.loads(line)["campaign_id"])
PY
)

echo "$OUT"
