#!/usr/bin/env bash
set -euo pipefail
if [[ $# -ne 6 ]]; then
  echo "usage: $0 MODE SHARD SHARDS NETEM_PROFILE WORK_ROOT SHARD_NAME" >&2
  exit 2
fi
MODE="$1"; SHARD="$2"; SHARDS="$3"; PROFILE="$4"; WORK="$5"; NAME="$6"
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
STAGE_DIR="$WORK/stage"; PARSER_DIR="$WORK/parsers"; RELEASE_DIR="$WORK/release"; PCAP="$WORK/capture.pcap"
mkdir -p "$WORK"
cleanup(){
  bash "$ROOT/scripts/netem_v3.sh" clear v-c2 || true
  "$ROOT/scripts/stop_services.sh" || true
}
trap cleanup EXIT

"$ROOT/scripts/stop_services.sh" || true
for dev in v-office v-dev v-c2 v-dns v-devops v-soc; do sudo ip link del "$dev" 2>/dev/null || true; done
"$ROOT/scripts/setup_netns.sh"
"$ROOT/scripts/start_services.sh"
bash "$ROOT/scripts/netem_v3.sh" apply "$PROFILE" v-c2

export COVERLAB_CAPTURE_IF="${COVERLAB_CAPTURE_IF:-ccbr0}"
export COVERLAB_STAGE_M_MODE="$MODE"
export COVERLAB_NETEM_PROFILE="$PROFILE"
export COVERLAB_STAGE_M_TIME_SCALE="${COVERLAB_STAGE_M_TIME_SCALE:-0.001}"
export COVERLAB_STAGE_M_MAX_SLEEP_SECONDS="${COVERLAB_STAGE_M_MAX_SLEEP_SECONDS-0.05}"

"$ROOT/scripts/generate_stage.sh" stage_m "$SHARD" "$SHARDS" "$STAGE_DIR" "$PCAP"
"$ROOT/scripts/process_parsers.sh" "$PCAP" "$STAGE_DIR" "$PARSER_DIR"
"$ROOT/scripts/package_layers.sh" "$STAGE_DIR" "$PCAP" "$PARSER_DIR" "$RELEASE_DIR" "$NAME"

PYTHONPATH="$ROOT/src" python -m coverlab.stage_m validate --manifest "$STAGE_DIR/manifests/campaigns.jsonl" > "$RELEASE_DIR/stage_m_positive_contract.json"
python - "$STAGE_DIR/manifests/campaigns.jsonl" "$RELEASE_DIR/stage_m_inventory.json" <<'PY'
import json, sys
from collections import Counter
from pathlib import Path
src=Path(sys.argv[1]); dst=Path(sys.argv[2])
rows=[json.loads(x) for x in src.read_text().splitlines() if x.strip()]
obj={
  "positive_only": True,
  "campaigns": len(rows),
  "families": dict(sorted(Counter(r["scenario_id"] for r in rows).items())),
  "implementations": dict(sorted(Counter(r["implementation_id"] for r in rows).items())),
  "clients": dict(sorted(Counter(r["client_impl"] for r in rows).items())),
  "servers": dict(sorted(Counter(r["server_impl"] for r in rows).items())),
  "netem": dict(sorted(Counter(r["netem_profile"] for r in rows).items())),
  "timing_fidelity": dict(sorted(Counter(r["timing_fidelity"] for r in rows).items())),
}
dst.write_text(json.dumps(obj,indent=2,sort_keys=True)+"\n")
print(json.dumps(obj,sort_keys=True))
PY

cleanup; trap - EXIT
echo "$RELEASE_DIR"
