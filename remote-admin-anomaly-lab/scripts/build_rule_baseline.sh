#!/usr/bin/env bash
set -euo pipefail

if [[ $# -ne 2 ]]; then
  echo "usage: $0 RELEASE_ROOT SHARD" >&2
  exit 2
fi
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
RELEASE="$(realpath -m "$1")"
SHARD="$2"
PCAP_RAW="$RELEASE/bronze/$SHARD/captures/$SHARD.pcap"
PCAP_ZST="$RELEASE/bronze/$SHARD/captures/$SHARD.pcap.zst"
OUT="$RELEASE/silver/$SHARD/suricata-rules"
QUALITY="$RELEASE/quality/$SHARD"
WORK="${RUNNER_TEMP:-/tmp}/adminlab-rules-$SHARD"
RULES="$ROOT/rules/remote-admin.rules"
rm -rf "$WORK"
mkdir -p "$WORK" "$WORK/out" "$OUT" "$QUALITY"

if [[ -s "$PCAP_RAW" ]]; then
  PCAP="$PCAP_RAW"
  CAPTURE_FORMAT="pcap"
elif [[ -s "$PCAP_ZST" ]]; then
  # Backward compatibility for older V1/V2 release trees only.
  zstd -q -d -f "$PCAP_ZST" -o "$WORK/$SHARD.pcap"
  PCAP="$WORK/$SHARD.pcap"
  CAPTURE_FORMAT="legacy-pcap.zst"
else
  echo "Bronze PCAP missing: expected $PCAP_RAW (or legacy $PCAP_ZST)" >&2
  exit 1
fi

COMMON_OVERRIDES=(
  --set "vars.address-groups.HOME_NET=[10.77.0.0/24]"
  --set "default-log-dir=$WORK/out"
  --set "unix-command.enabled=no"
)

# Config/rules validation and replay share a private writable runtime directory,
# avoiding command-socket collisions with the preceding Silver parser invocation.
suricata -T -c /etc/suricata/suricata.yaml -S "$RULES" -l "$WORK/out" "${COMMON_OVERRIDES[@]}"
rm -f "$WORK/out/eve.json" "$WORK/out/suricata.log" "$WORK/out/stats.log" "$WORK/out/fast.log"
suricata -r "$PCAP" -c /etc/suricata/suricata.yaml -S "$RULES" \
  -l "$WORK/out" "${COMMON_OVERRIDES[@]}" --runmode=single
[[ -s "$WORK/out/eve.json" ]]
zstd -T0 -q -9 -f "$WORK/out/eve.json" -o "$OUT/eve.json.zst"
ALERTS="$(jq -c 'select(.event_type=="alert")' "$WORK/out/eve.json" | wc -l)"
SIDS="$(jq -r 'select(.event_type=="alert") | .alert.signature_id' "$WORK/out/eve.json" | sort -u | paste -sd, -)"
cat > "$QUALITY/rule_health.json" <<JSON
{
  "ok": true,
  "rules_file": "rules/remote-admin.rules",
  "alert_count": $ALERTS,
  "unique_sids": "${SIDS}",
  "ground_truth_source": false,
  "purpose": "M0 deterministic comparison baseline",
  "bronze_capture_format": "$CAPTURE_FORMAT",
  "private_runtime": true,
  "unix_command_enabled": false
}
JSON
rm -rf "$WORK"
echo "rule_baseline_ready capture_format=$CAPTURE_FORMAT alerts=$ALERTS sids=${SIDS:-none}"
