#!/usr/bin/env bash
set -euo pipefail
if [[ $# -ne 2 ]]; then
  echo "usage: $0 EVIDENCE_ROOT OUT_ROOT" >&2
  exit 2
fi
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
EVIDENCE="$(realpath "$1")"
OUT="$(realpath -m "$2")"
MANIFEST="$EVIDENCE/ech_holdout.jsonl"
[[ -s "$MANIFEST" ]] || { echo "missing ech_holdout.jsonl" >&2; exit 1; }
mkdir -p "$OUT"

PYTHONPATH="$ROOT/src" python - "$MANIFEST" "$EVIDENCE" "$OUT" <<'PY'
import json,sys
from pathlib import Path
manifest=Path(sys.argv[1]); evidence=Path(sys.argv[2]); out=Path(sys.argv[3])
rows=[json.loads(x) for x in manifest.read_text().splitlines() if x.strip()]
for row in rows:
    cid=str(row["campaign_id"])
    stage=out/cid/"stage"
    (stage/"manifests").mkdir(parents=True,exist_ok=True)
    campaign=dict(row)
    campaign.setdefault("scenario_id","EXTERNAL_ECH")
    campaign.setdefault("expected_events",0)
    campaign.setdefault("attack_mapping",[])
    (stage/"manifests"/"campaigns.jsonl").write_text(json.dumps(campaign,separators=(",",":"),sort_keys=True)+"\n")
    (stage/"manifests"/"events.jsonl").write_text("")
    (stage/"manifests"/"decrypted_transactions.jsonl").write_text("")
    (stage/"campaigns.jsonl").write_text(json.dumps(campaign,separators=(",",":"),sort_keys=True)+"\n")
    (stage/"events.jsonl").write_text("")
    p=evidence/row["pcap_file"]
    if not p.is_file():
        raise SystemExit(f"missing pcap for {cid}: {p}")
PY

while IFS= read -r cid; do
  [[ -n "$cid" ]] || continue
  STAGE="$OUT/$cid/stage"
  PARSERS="$OUT/$cid/parsers"
  SILVER="$OUT/$cid/silver"
  GOLD="$OUT/$cid/gold"
  QUALITY="$OUT/$cid/quality"
  PCAP="$(python - "$MANIFEST" "$EVIDENCE" "$cid" <<'PY'
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
