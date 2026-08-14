#!/usr/bin/env bash
set -euo pipefail

if [[ $# -ne 5 ]]; then
  echo "usage: $0 STAGE SHARD COUNT SEED ROOT" >&2
  exit 2
fi

STAGE="$1"
SHARD="$2"
COUNT="$3"
SEED="$4"
OUT_ROOT="$(realpath -m "$5")"
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
PYTHON_BIN="${ADMINLAB_PYTHON:-python3}"
OUTPUT_UID="${ADMINLAB_OUTPUT_UID:-${SUDO_UID:-0}}"
OUTPUT_GID="${ADMINLAB_OUTPUT_GID:-${SUDO_GID:-0}}"
STATE_DIR="$OUT_ROOT/state/$SHARD"
RUN_DIR="$OUT_ROOT/work/$SHARD"
RELEASE="$OUT_ROOT/release"
BRONZE="$RELEASE/bronze/$SHARD"
QUALITY="$RELEASE/quality/$SHARD"
RAW_PCAP="$RUN_DIR/$SHARD.pcap"
COMPRESSED_PCAP="$BRONZE/captures/$SHARD.pcap.zst"
TCPDUMP_PGID=""

if [[ ! -x "$PYTHON_BIN" ]]; then
  echo "configured ADMINLAB_PYTHON is not executable: $PYTHON_BIN" >&2
  exit 2
fi
if [[ ! "$OUTPUT_UID" =~ ^[0-9]+$ || ! "$OUTPUT_GID" =~ ^[0-9]+$ ]]; then
  echo "ADMINLAB_OUTPUT_UID/GID must be numeric" >&2
  exit 2
fi

mkdir -p "$RUN_DIR" "$BRONZE/captures" "$BRONZE/manifests" "$QUALITY"

stop_capture() {
  if [[ "$TCPDUMP_PGID" =~ ^[0-9]+$ ]] && kill -0 -- "-$TCPDUMP_PGID" 2>/dev/null; then
    kill -INT -- "-$TCPDUMP_PGID" 2>/dev/null || true
    for _ in 1 2 3 4 5 6 7 8 9 10; do
      kill -0 -- "-$TCPDUMP_PGID" 2>/dev/null || break
      sleep 0.2
    done
    if kill -0 -- "-$TCPDUMP_PGID" 2>/dev/null; then
      kill -TERM -- "-$TCPDUMP_PGID" 2>/dev/null || true
    fi
    wait "$TCPDUMP_PGID" 2>/dev/null || true
  fi
}

cleanup() {
  set +e
  stop_capture
  sudo -E bash "$ROOT/scripts/start_services.sh" stop "$STATE_DIR/services"
  sudo -E bash "$ROOT/scripts/setup_topology.sh" down "$ROOT/configs/topology.yaml"
}
trap cleanup EXIT INT TERM

sudo -E bash "$ROOT/scripts/setup_topology.sh" up "$ROOT/configs/topology.yaml"
sudo -E bash "$ROOT/scripts/start_services.sh" start "$STATE_DIR/services"

# Full bridge capture is the Bronze rollback source. It starts before any
# scenario traffic and is retained losslessly as zstd-compressed PCAP.
setsid tcpdump -i br-adminlab -U -s 0 -n -w "$RAW_PCAP" >"$RUN_DIR/tcpdump.log" 2>&1 &
TCPDUMP_PGID=$!
sleep 1
kill -0 -- "-$TCPDUMP_PGID"

PYTHONPATH="$ROOT/src" "$PYTHON_BIN" "$ROOT/scripts/run_scenarios.py" \
  --stage "$STAGE" \
  --count "$COUNT" \
  --seed "$SEED" \
  --protocols ssh,smb \
  --state-dir "$STATE_DIR/services" \
  --out "$RUN_DIR/scenarios"

stop_capture
TCPDUMP_PGID=""

if [[ ! -s "$RAW_PCAP" ]]; then
  echo "capture missing or empty: $RAW_PCAP" >&2
  exit 1
fi
if ! tcpdump -nn -r "$RAW_PCAP" -c 1 >/dev/null 2>&1; then
  echo "capture cannot be read by tcpdump" >&2
  exit 1
fi

zstd -T0 -q -9 -f "$RAW_PCAP" -o "$COMPRESSED_PCAP"
zstd -q -t "$COMPRESSED_PCAP"

PYTHONPATH="$ROOT/src" "$PYTHON_BIN" "$ROOT/scripts/package_bronze.py" \
  --topology "$ROOT/configs/topology.yaml" \
  --executed "$RUN_DIR/scenarios/sessions-executed.jsonl" \
  --planned "$RUN_DIR/scenarios/sessions-planned.jsonl" \
  --bronze "$BRONZE" \
  --stage "$STAGE" \
  --shard "$SHARD" \
  --seed "$SEED"

(
  cd "$BRONZE"
  find captures manifests -type f -print0 | sort -z | xargs -0 sha256sum
  sha256sum reproducibility.json
) > "$BRONZE/checksums.sha256"

PCAP_BYTES="$(stat -c%s "$COMPRESSED_PCAP")"
RAW_BYTES="$(stat -c%s "$RAW_PCAP")"
SESSION_COUNT="$(wc -l < "$BRONZE/manifests/sessions.jsonl")"
cat > "$QUALITY/capture_health.json" <<JSON
{
  "ok": true,
  "shard": "$SHARD",
  "stage": "$STAGE",
  "sessions": $SESSION_COUNT,
  "raw_pcap_bytes": $RAW_BYTES,
  "compressed_pcap_bytes": $PCAP_BYTES,
  "capture_format": "pcap.zst",
  "full_capture_retained": true,
  "output_owner_uid": $OUTPUT_UID,
  "output_owner_gid": $OUTPUT_GID
}
JSON

PYTHONPATH="$ROOT/src" "$PYTHON_BIN" - "$BRONZE" "$QUALITY/bronze_contract.json" <<'PY'
import json, sys
from pathlib import Path
from adminlab.quality import validate_bronze_tree
report = validate_bronze_tree(Path(sys.argv[1]), verify_checksums=True)
Path(sys.argv[2]).write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
if not report["ok"]:
    raise SystemExit(json.dumps(report, sort_keys=True))
print(json.dumps(report, sort_keys=True))
PY

# The uncompressed working copy is disposable only after the complete compressed
# PCAP passed decompression and checksum validation. Bronze keeps the full bytes.
rm -f "$RAW_PCAP"
trap - EXIT INT TERM
cleanup

# Privileged work ends here. Hand the complete tree back to the invoking runner
# so Silver/Gold/HF stages can operate without root and cannot mutate networking.
if [[ "$OUTPUT_UID" != "0" || "$OUTPUT_GID" != "0" ]]; then
  chown -R "$OUTPUT_UID:$OUTPUT_GID" "$OUT_ROOT"
fi

echo "bronze_ready=$BRONZE sessions=$SESSION_COUNT pcap_zst_bytes=$PCAP_BYTES output_owner=$OUTPUT_UID:$OUTPUT_GID"
