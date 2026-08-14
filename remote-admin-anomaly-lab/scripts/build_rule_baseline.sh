#!/usr/bin/env bash
set -euo pipefail

if [[ $# -ne 2 ]]; then
  echo "usage: $0 RELEASE_ROOT SHARD" >&2
  exit 2
fi
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
RELEASE="$(realpath -m "$1")"
SHARD="$2"
PCAP_ZST="$RELEASE/bronze/$SHARD/captures/$SHARD.pcap.zst"
OUT="$RELEASE/silver/$SHARD/suricata-rules"
QUALITY="$RELEASE/quality/$SHARD"
WORK="${RUNNER_TEMP:-/tmp}/adminlab-rules-$SHARD"
RULES="$ROOT/rules/remote-admin.rules"
rm -rf "$WORK"
mkdir -p "$WORK" "$OUT" "$QUALITY"

[[ -s "$PCAP_ZST" ]]
suricata -T -c /etc/suricata/suricata.yaml -S "$RULES" --set vars.address-groups.HOME_NET='[10.77.0.0/24]'
zstd -q -d -f "$PCAP_ZST" -o "$WORK/$SHARD.pcap"
suricata -r "$WORK/$SHARD.pcap" -c /etc/suricata/suricata.yaml -S "$RULES" \
  --set vars.address-groups.HOME_NET='[10.77.0.0/24]' -l "$WORK/out" --runmode=single
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
  "purpose": "M0 deterministic comparison baseline"
}
JSON
rm -rf "$WORK"
echo "rule_baseline_ready alerts=$ALERTS sids=${SIDS:-none}"
