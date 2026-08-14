#!/usr/bin/env bash
set -euo pipefail

if [[ $# -ne 2 ]]; then
  echo "usage: $0 RELEASE_ROOT SHARD" >&2
  exit 2
fi

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
PYTHON_BIN="${ADMINLAB_PYTHON:-python3}"
RELEASE="$(realpath -m "$1")"
SHARD="$2"
BRONZE="$RELEASE/bronze/$SHARD"
SILVER="$RELEASE/silver/$SHARD"
QUALITY="$RELEASE/quality/$SHARD"
WORK="${RUNNER_TEMP:-/tmp}/adminlab-silver-$SHARD"
PCAP_ZST="$BRONZE/captures/$SHARD.pcap.zst"
PCAP="$WORK/$SHARD.pcap"
SURI_RAW="$WORK/suricata"
ZEEK_RAW="$WORK/zeek"
ZEEK_IMAGE="zeek/zeek:8.2.1"

if [[ ! -x "$PYTHON_BIN" ]]; then
  echo "configured ADMINLAB_PYTHON is not executable: $PYTHON_BIN" >&2
  exit 2
fi
if [[ ! -w "$RELEASE" ]]; then
  echo "release tree is not writable by Silver stage: $RELEASE" >&2
  stat -c 'owner=%u:%g mode=%a path=%n' "$RELEASE" >&2 || true
  exit 1
fi

rm -rf "$WORK"
mkdir -p "$WORK" "$SURI_RAW" "$ZEEK_RAW" "$SILVER/suricata" "$SILVER/zeek" "$QUALITY"

if [[ ! -s "$PCAP_ZST" ]]; then
  echo "Bronze PCAP missing: $PCAP_ZST" >&2
  exit 1
fi

zstd -q -d -f "$PCAP_ZST" -o "$PCAP"
tcpdump -nn -r "$PCAP" -c 1 >/dev/null 2>&1

suricata -r "$PCAP" -c /etc/suricata/suricata.yaml -l "$SURI_RAW" --runmode=single
if [[ ! -s "$SURI_RAW/eve.json" ]]; then
  echo "Suricata did not produce non-empty eve.json" >&2
  exit 1
fi

# Pinned Zeek Docker image keeps parser behavior reproducible across runners.
docker image inspect "$ZEEK_IMAGE" >/dev/null 2>&1 || docker pull "$ZEEK_IMAGE"
docker run --rm \
  -v "$WORK:/work" \
  -w /work/zeek \
  "$ZEEK_IMAGE" \
  zeek -C -r "/work/$SHARD.pcap" LogAscii::use_json=T

if [[ ! -s "$ZEEK_RAW/conn.log" ]]; then
  echo "Zeek did not produce non-empty conn.log" >&2
  exit 1
fi

zstd -T0 -q -9 -f "$SURI_RAW/eve.json" -o "$SILVER/suricata/eve.json.zst"
for log in "$ZEEK_RAW"/*.log; do
  [[ -s "$log" ]] || continue
  zstd -T0 -q -9 -f "$log" -o "$SILVER/zeek/$(basename "$log").zst"
done

SURICATA_VERSION="$(suricata --build-info 2>/dev/null | sed -n 's/^This is Suricata version //p' | head -n1)"
if [[ -z "$SURICATA_VERSION" ]]; then
  SURICATA_VERSION="$(suricata -V 2>&1 | head -n1)"
fi
ZEEK_VERSION="$(docker run --rm "$ZEEK_IMAGE" zeek --version 2>&1 | head -n1)"
cat > "$SILVER/parser_versions.json" <<JSON
{
  "suricata": "${SURICATA_VERSION//\"/}",
  "zeek": "${ZEEK_VERSION//\"/}",
  "zeek_image": "$ZEEK_IMAGE"
}
JSON

EVE_LINES="$(wc -l < "$SURI_RAW/eve.json")"
FLOW_EVENTS="$(jq -c 'select(.event_type == "flow")' "$SURI_RAW/eve.json" | wc -l)"
SSH_EVENTS="$(jq -c 'select(.event_type == "ssh" or .app_proto == "ssh")' "$SURI_RAW/eve.json" | wc -l)"
SMB_EVENTS="$(jq -c 'select(.event_type == "smb" or .app_proto == "smb")' "$SURI_RAW/eve.json" | wc -l)"
ZEEK_CONN_LINES="$(wc -l < "$ZEEK_RAW/conn.log")"
ZEEK_SSH_LINES=0
[[ -s "$ZEEK_RAW/ssh.log" ]] && ZEEK_SSH_LINES="$(wc -l < "$ZEEK_RAW/ssh.log")"
ZEEK_SMB_LINES=0
for f in "$ZEEK_RAW"/smb*.log; do
  [[ -s "$f" ]] || continue
  ZEEK_SMB_LINES=$((ZEEK_SMB_LINES + $(wc -l < "$f")))
done

cat > "$QUALITY/parser_health.json" <<JSON
{
  "ok": true,
  "shard": "$SHARD",
  "suricata_eve_lines": $EVE_LINES,
  "suricata_flow_events": $FLOW_EVENTS,
  "suricata_ssh_events": $SSH_EVENTS,
  "suricata_smb_events": $SMB_EVENTS,
  "zeek_conn_lines": $ZEEK_CONN_LINES,
  "zeek_ssh_lines": $ZEEK_SSH_LINES,
  "zeek_smb_lines": $ZEEK_SMB_LINES
}
JSON

if [[ "$EVE_LINES" -le 0 || "$FLOW_EVENTS" -le 0 || "$ZEEK_CONN_LINES" -le 0 ]]; then
  echo "parser quality gate failed" >&2
  cat "$QUALITY/parser_health.json" >&2
  exit 1
fi

PYTHONPATH="$ROOT/src" "$PYTHON_BIN" - "$SILVER" "$QUALITY/silver_contract.json" <<'PY'
import json, sys
from pathlib import Path
from adminlab.quality import validate_silver_tree
report = validate_silver_tree(Path(sys.argv[1]))
Path(sys.argv[2]).write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
if not report["ok"]:
    raise SystemExit(json.dumps(report, sort_keys=True))
print(json.dumps(report, sort_keys=True))
PY

rm -rf "$WORK"
echo "silver_ready=$SILVER eve_lines=$EVE_LINES zeek_conn_lines=$ZEEK_CONN_LINES"
