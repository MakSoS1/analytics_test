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

# Bind every campaign to the exact captured bytes and capture time range before
# parser/Gold packaging. These provenance fields are metadata, not model inputs.
PYTHONPATH="$ROOT/src" python - "$MASTER" "$PCAP" "$STAGE/manifests/campaigns.jsonl" <<'PY'
import hashlib, json, sys
from datetime import datetime, timezone
from pathlib import Path
from scapy.all import PcapReader

master, pcap, manifest = map(Path, sys.argv[1:])
def digest(p):
    h=hashlib.sha256()
    with p.open("rb") as f:
        for chunk in iter(lambda:f.read(1024*1024), b""):
            h.update(chunk)
    return h.hexdigest()

first=last=None
with PcapReader(str(pcap)) as rd:
    for pkt in rd:
        ts=float(pkt.time)
        if first is None: first=ts
        last=ts
if first is None or last is None:
    raise SystemExit("empty VM wire capture")
def iso(ts):
    return datetime.fromtimestamp(ts, timezone.utc).isoformat(timespec="milliseconds").replace("+00:00","Z")
meta={
    "pcap_sha256":digest(pcap),
    "pcapng_sha256":digest(master),
    "capture_start_utc":iso(first),
    "capture_end_utc":iso(last),
    "capture_duration_s":round(max(0.0,last-first),6),
}
rows=[]
for line in manifest.read_text().splitlines():
    if not line.strip(): continue
    r=json.loads(line); r.update(meta); rows.append(r)
manifest.write_text("\n".join(json.dumps(r,separators=(",",":"),default=str) for r in rows)+"\n")
print(json.dumps(meta,sort_keys=True))
PY
cp "$STAGE/manifests/campaigns.jsonl" "$STAGE/campaigns.jsonl"

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

SURICATA_VERSION="$(suricata -V 2>&1 | head -1 | tr -d '\r')"
ZEEK_VERSION="$(docker run --rm zeek/zeek:8.2.1 zeek --version 2>&1 | head -1 | tr -d '\r')"
python - "$BRONZE/reproducibility.json" "$SURICATA_VERSION" "$ZEEK_VERSION" <<'PY'
import json,sys
from pathlib import Path
p=Path(sys.argv[1]); obj=json.loads(p.read_text())
obj["parser_versions"]={"suricata":sys.argv[2],"zeek":sys.argv[3]}
p.write_text(json.dumps(obj,indent=2,sort_keys=True)+"\n")
PY

echo "$RELEASE"
