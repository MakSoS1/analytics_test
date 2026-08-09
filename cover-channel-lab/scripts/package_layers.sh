#!/usr/bin/env bash
set -euo pipefail
if [[ $# -ne 5 ]]; then echo "usage: $0 STAGE_DIR PCAP PARSER_DIR RELEASE_DIR SHARD_NAME" >&2; exit 2; fi
STAGE="$(realpath "$1")" PCAP="$(realpath "$2")" PARSER="$(realpath "$3")" RELEASE="$(realpath -m "$4")" NAME="$5"
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
BRONZE="$RELEASE/bronze/$NAME" SILVER="$RELEASE/silver/$NAME" GOLD="$RELEASE/gold/$NAME" QUALITY="$RELEASE/quality/$NAME"
mkdir -p "$BRONZE/captures" "$BRONZE/manifests" "$SILVER" "$GOLD" "$QUALITY"

# Validate semantic ground truth and physical capture completeness before a
# shard is allowed into Bronze. Mapping >=.95 alone can hide a short truncated
# tail when the corpus is large, so the PCAP must also reach the latest campaign.
PYTHONPATH="$ROOT/src" python -m coverlab.validate_dataset_contract \
  --stage-dir "$STAGE" --out "$QUALITY/dataset_contract.json"
PYTHONPATH="$ROOT/src" python -m coverlab.capture_tail_guard \
  --stage-dir "$STAGE" --pcap "$PCAP" --out "$QUALITY/capture_tail_guard.json"

cp "$STAGE/manifests/campaigns.jsonl" "$BRONZE/manifests/"
cp "$STAGE/manifests/events.jsonl" "$BRONZE/manifests/"
cp "$STAGE/manifests/decrypted_transactions.jsonl" "$BRONZE/manifests/"
cp -a "$PARSER/suricata" "$SILVER/suricata-raw"
cp -a "$PARSER/zeek" "$SILVER/zeek-raw"
zstd -T0 -q -9 -f "$PCAP" -o "$BRONZE/captures/${NAME}.pcap.zst"
PYTHONPATH="$ROOT/src" python -m coverlab.pipeline_v2 --stage-dir "$STAGE" --pcap "$PCAP" --silver "$SILVER/normalized" --gold "$GOLD" --quality "$QUALITY"
# Copy source code revision metadata sufficient to reproduce a shard.
cat > "$BRONZE/reproducibility.json" <<JSON
{"github_sha":"${GITHUB_SHA:-local}","runner_os":"${RUNNER_OS:-local}","runner_arch":"${RUNNER_ARCH:-unknown}","shard":"$NAME","dataset_contract_revision":2,"capture_tail_guard_revision":1}
JSON
