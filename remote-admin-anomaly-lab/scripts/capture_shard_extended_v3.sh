#!/usr/bin/env bash
set -euo pipefail

if [[ $# -ne 5 ]]; then
  echo "usage: $0 STAGE SHARD COUNT SEED ROOT" >&2
  exit 2
fi
STAGE="$1"; SHARD="$2"; COUNT="$3"; SEED="$4"; OUT_ROOT="$(realpath -m "$5")"
ROOT="$(cd "$(dirname "$0")/.." && pwd)"; PYTHON_BIN="${ADMINLAB_PYTHON:-python3}"; OUTPUT_UID="${ADMINLAB_OUTPUT_UID:-${SUDO_UID:-0}}"; OUTPUT_GID="${ADMINLAB_OUTPUT_GID:-${SUDO_GID:-0}}"
STATE_DIR="$OUT_ROOT/state/$SHARD"; RUN_DIR="$OUT_ROOT/work/$SHARD"; RELEASE="$OUT_ROOT/release"; BRONZE="$RELEASE/bronze/$SHARD"; QUALITY="$RELEASE/quality/$SHARD"; RAW_PCAP="$RUN_DIR/$SHARD.pcap"; COMPRESSED_PCAP="$BRONZE/captures/$SHARD.pcap.zst"; TCPDUMP_PGID=""
[[ -x "$PYTHON_BIN" ]]; [[ "$OUTPUT_UID" =~ ^[0-9]+$ ]]; [[ "$OUTPUT_GID" =~ ^[0-9]+$ ]]; mkdir -p "$RUN_DIR" "$BRONZE/captures" "$BRONZE/manifests" "$QUALITY"

stop_capture(){
  if [[ "$TCPDUMP_PGID" =~ ^[0-9]+$ ]] && kill -0 -- "-$TCPDUMP_PGID" 2>/dev/null; then
    kill -INT -- "-$TCPDUMP_PGID" 2>/dev/null || true
    for _ in $(seq 1 20); do kill -0 -- "-$TCPDUMP_PGID" 2>/dev/null || break; sleep .2; done
    kill -TERM -- "-$TCPDUMP_PGID" 2>/dev/null || true; wait "$TCPDUMP_PGID" 2>/dev/null || true
  fi
}
cleanup(){
  set +e; stop_capture; "$PYTHON_BIN" "$ROOT/scripts/start_extended_services.py" stop "$STATE_DIR/extended"; bash "$ROOT/scripts/start_services.sh" stop "$STATE_DIR/core"; bash "$ROOT/scripts/setup_topology.sh" down "$ROOT/configs/topology.yaml"
}
trap cleanup EXIT INT TERM

bash "$ROOT/scripts/setup_topology.sh" up "$ROOT/configs/topology.yaml"
bash "$ROOT/scripts/start_services.sh" start "$STATE_DIR/core"
"$PYTHON_BIN" "$ROOT/scripts/start_extended_services.py" start "$STATE_DIR/extended"
"$PYTHON_BIN" "$ROOT/scripts/start_extended_services.py" verify "$STATE_DIR/extended"

setsid tcpdump -i br-adminlab -U -s 0 -n -w "$RAW_PCAP" >"$RUN_DIR/tcpdump.log" 2>&1 & TCPDUMP_PGID=$!; sleep 1; kill -0 -- "-$TCPDUMP_PGID"
EXTRA_ARGS=(); [[ "$STAGE" == "H" ]] && EXTRA_ARGS+=(--include-partial-winrm)
PYTHONPATH="$ROOT/src" "$PYTHON_BIN" "$ROOT/scripts/run_scenarios_extended_v2.py" --stage "$STAGE" --count "$COUNT" --seed "$SEED" --core-state "$STATE_DIR/core" --out "$RUN_DIR/scenarios" "${EXTRA_ARGS[@]}"
stop_capture; TCPDUMP_PGID=""

[[ -s "$RAW_PCAP" ]]; tcpdump -nn -r "$RAW_PCAP" -c 1 >/dev/null 2>&1; zstd -T0 -q -9 -f "$RAW_PCAP" -o "$COMPRESSED_PCAP"; zstd -q -t "$COMPRESSED_PCAP"
PYTHONPATH="$ROOT/src" "$PYTHON_BIN" "$ROOT/scripts/package_bronze.py" --topology "$ROOT/configs/topology.yaml" --executed "$RUN_DIR/scenarios/sessions-executed.jsonl" --planned "$RUN_DIR/scenarios/sessions-planned.jsonl" --bronze "$BRONZE" --stage "$STAGE" --shard "$SHARD" --seed "$SEED"
(cd "$BRONZE"; find captures manifests -type f -print0 | sort -z | xargs -0 sha256sum; sha256sum reproducibility.json) > "$BRONZE/checksums.sha256"
PCAP_BYTES="$(stat -c%s "$COMPRESSED_PCAP")"; RAW_BYTES="$(stat -c%s "$RAW_PCAP")"; SESSION_COUNT="$(wc -l < "$BRONZE/manifests/sessions.jsonl")"; SUMMARY="$RUN_DIR/scenarios/summary.json"
"$PYTHON_BIN" - "$SUMMARY" "$QUALITY/capture_health.json" "$SHARD" "$STAGE" "$SESSION_COUNT" "$RAW_BYTES" "$PCAP_BYTES" "$OUTPUT_UID" "$OUTPUT_GID" <<'PY'
import json,sys
summary=json.load(open(sys.argv[1],encoding='utf-8'))
p={'ok':summary.get('status_counts',{}).get('failed',0)==0,'shard':sys.argv[3],'stage':sys.argv[4],'sessions':int(sys.argv[5]),'raw_pcap_bytes':int(sys.argv[6]),'compressed_pcap_bytes':int(sys.argv[7]),'capture_format':'pcap.zst','full_capture_retained':True,'output_owner_uid':int(sys.argv[8]),'output_owner_gid':int(sys.argv[9]),'protocol_counts':summary.get('protocol_counts',{}),'label_counts':summary.get('label_counts',{}),'protocol_balance_max_minus_min':summary.get('protocol_balance_max_minus_min'),'dcerpc_train_included':False,'partial_winrm_included':summary.get('partial_winrm_included',False)}
open(sys.argv[2],'w',encoding='utf-8').write(json.dumps(p,indent=2,sort_keys=True)+'\n')
if not p['ok']: raise SystemExit('scenario failures present')
PY
PYTHONPATH="$ROOT/src" "$PYTHON_BIN" - "$BRONZE" "$QUALITY/bronze_contract.json" <<'PY'
import json,sys
from pathlib import Path
from adminlab.quality import validate_bronze_tree
r=validate_bronze_tree(Path(sys.argv[1]),verify_checksums=True);Path(sys.argv[2]).write_text(json.dumps(r,indent=2,sort_keys=True)+'\n',encoding='utf-8')
if not r['ok']:raise SystemExit(json.dumps(r,sort_keys=True))
PY
rm -f "$RAW_PCAP"; trap - EXIT INT TERM; cleanup
if [[ "$OUTPUT_UID" != "0" || "$OUTPUT_GID" != "0" ]]; then chown -R "$OUTPUT_UID:$OUTPUT_GID" "$OUT_ROOT"; fi
echo "extended_v3_bronze_ready=$BRONZE sessions=$SESSION_COUNT pcap_zst_bytes=$PCAP_BYTES"
