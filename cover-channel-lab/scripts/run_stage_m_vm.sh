#!/usr/bin/env bash
set -euo pipefail

if [[ $# -lt 7 || $# -gt 8 ]]; then
  echo "usage: $0 MODE SHARD SHARDS NETEM_PROFILE INVENTORY WORK_ROOT SHARD_NAME [SSH_KEY]" >&2
  exit 2
fi

MODE="$1"; SHARD="$2"; SHARDS="$3"; PROFILE="$4"; INVENTORY="$5"; WORK="$6"; NAME="$7"; SSH_KEY="${8:-}"
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
PLAN="$WORK/plan.jsonl"
MAX_SLEEP="${COVERLAB_STAGE_M_MAX_SLEEP_SECONDS-0.05}"
if [[ "$MAX_SLEEP" == "-1" ]]; then MAX_SLEEP=""; fi
REMOTE="$WORK/vm-run"
STAGE="$WORK/stage"
PARSERS="$WORK/parsers"
RELEASE="$WORK/release"
MASTER="$REMOTE/capture.pcapng"
PCAP="$WORK/capture.normalized.pcap"

mkdir -p "$WORK" "$STAGE/manifests"
command -v editcap >/dev/null || { echo "editcap is required on the controller" >&2; exit 1; }
command -v ssh >/dev/null || { echo "ssh is required on the controller" >&2; exit 1; }
command -v scp >/dev/null || { echo "scp is required on the controller" >&2; exit 1; }

PLAN_ARGS=(--inventory "$INVENTORY" --out "$PLAN" --mode "$MODE" --shard "$SHARD" --shards "$SHARDS")
[[ -n "${COVERLAB_VM_FAMILIES:-}" ]] && PLAN_ARGS+=(--families "$COVERLAB_VM_FAMILIES")
[[ -n "${COVERLAB_VM_FORCE_INTERVAL_SECONDS:-}" ]] && PLAN_ARGS+=(--force-interval "$COVERLAB_VM_FORCE_INTERVAL_SECONDS")
[[ -n "${COVERLAB_VM_EVENT_COUNT:-}" ]] && PLAN_ARGS+=(--event-count "$COVERLAB_VM_EVENT_COUNT")
[[ -n "${COVERLAB_VM_PLAN_OFFSET:-}" ]] && PLAN_ARGS+=(--offset "$COVERLAB_VM_PLAN_OFFSET")
[[ -n "${COVERLAB_VM_PLAN_LIMIT:-}" ]] && PLAN_ARGS+=(--limit "$COVERLAB_VM_PLAN_LIMIT")
[[ -n "${COVERLAB_VM_FORCE_SPLIT_ROLE:-}" ]] && PLAN_ARGS+=(--force-split-role "$COVERLAB_VM_FORCE_SPLIT_ROLE")
PYTHONPATH="$ROOT/src" python -m coverlab.vm_plan "${PLAN_ARGS[@]}"

CTRL=(python -m coverlab.vm_remote_controller
  --inventory "$INVENTORY"
  --plan "$PLAN"
  --out "$REMOTE"
  --netem-profile "$PROFILE"
  --bootstrap-services
  --capture-wire
  --event-cap "${COVERLAB_STAGE_M_EVENT_COUNT_CAP:-0}"
  --time-scale "${COVERLAB_STAGE_M_TIME_SCALE:-0.001}"
  --max-sleep "$MAX_SLEEP"
)
if [[ -n "$SSH_KEY" ]]; then CTRL+=(--ssh-key "$SSH_KEY"); fi
PYTHONPATH="$ROOT/src" "${CTRL[@]}"

test -s "$MASTER"
cp "$REMOTE/merged/campaigns.jsonl" "$STAGE/manifests/campaigns.jsonl"
cp "$REMOTE/merged/events.jsonl" "$STAGE/manifests/events.jsonl"
cp "$REMOTE/merged/decrypted_transactions.jsonl" "$STAGE/manifests/decrypted_transactions.jsonl"
cp "$STAGE/manifests/campaigns.jsonl" "$STAGE/campaigns.jsonl"
cp "$STAGE/manifests/events.jsonl" "$STAGE/events.jsonl"

# pcapng is the archival source of truth. The existing parser/feature pipeline
# receives a deterministic classic-PCAP derivative for backwards compatibility.
editcap -F pcap "$MASTER" "$PCAP"
test -s "$PCAP"

"$ROOT/scripts/process_parsers.sh" "$PCAP" "$STAGE" "$PARSERS"
"$ROOT/scripts/package_layers.sh" "$STAGE" "$PCAP" "$PARSERS" "$RELEASE" "$NAME"

BRONZE="$RELEASE/bronze/$NAME"
zstd -T0 -q -9 -f "$MASTER" -o "$BRONZE/captures/${NAME}.pcapng.zst"
sha256sum "$MASTER" "$PCAP" > "$RELEASE/quality/$NAME/wire_checksums.sha256"
PYTHONPATH="$ROOT/src" python -m coverlab.stage_m validate   --manifest "$STAGE/manifests/campaigns.jsonl" > "$RELEASE/quality/$NAME/stage_m_positive_contract.json"
PYTHONPATH="$ROOT/src" python -m coverlab.diversity_audit   --manifest "$STAGE/manifests/campaigns.jsonl" --out "$RELEASE/quality/$NAME/diversity_audit.json"

python - "$INVENTORY" "$PLAN" "$MASTER" "$PCAP" "$BRONZE/reproducibility.json" <<'PY'
import hashlib, json, sys
from pathlib import Path
inv, plan, master, pcap, repro = map(Path, sys.argv[1:])
obj=json.loads(repro.read_text())
def digest(p):
    h=hashlib.sha256()
    with p.open("rb") as f:
        for chunk in iter(lambda:f.read(1024*1024), b""): h.update(chunk)
    return h.hexdigest()
obj.update({
  "capture_environment":"vm_wire",
  "wire_master_format":"pcapng",
  "wire_master_sha256":digest(master),
  "normalized_pcap_sha256":digest(pcap),
  "inventory_sha256":digest(inv),
  "plan_sha256":digest(plan),
})
repro.write_text(json.dumps(obj,indent=2,sort_keys=True)+"\n")
PY

echo "$RELEASE"
