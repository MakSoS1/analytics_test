#!/usr/bin/env bash
set -euo pipefail
if [[ $# -ne 5 ]]; then echo "usage: $0 STAGE_DIR PCAP PARSER_DIR RELEASE_DIR SHARD_NAME" >&2; exit 2; fi
STAGE="$(realpath "$1")" PCAP="$(realpath "$2")" PARSER="$(realpath "$3")" RELEASE="$(realpath -m "$4")" NAME="$5"
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
BRONZE="$RELEASE/bronze/$NAME" SILVER="$RELEASE/silver/$NAME" GOLD="$RELEASE/gold/$NAME" QUALITY="$RELEASE/quality/$NAME"
mkdir -p "$BRONZE/captures" "$BRONZE/manifests" "$SILVER" "$GOLD" "$QUALITY"
cp "$STAGE/manifests/campaigns.jsonl" "$BRONZE/manifests/"
cp "$STAGE/manifests/events.jsonl" "$BRONZE/manifests/"
cp "$STAGE/manifests/decrypted_transactions.jsonl" "$BRONZE/manifests/"
cp -a "$PARSER/suricata" "$SILVER/suricata-raw"
cp -a "$PARSER/zeek" "$SILVER/zeek-raw"
zstd -T0 -q -9 -f "$PCAP" -o "$BRONZE/captures/${NAME}.pcap.zst"
PYTHONPATH="$ROOT/src" python -m coverlab.pipeline --stage-dir "$STAGE" --pcap "$PCAP" --silver "$SILVER/normalized" --gold "$GOLD" --quality "$QUALITY"
# Copy source code revision metadata sufficient to reproduce a shard.
cat > "$BRONZE/reproducibility.json" <<JSON
{"github_sha":"${GITHUB_SHA:-local}","runner_os":"${RUNNER_OS:-local}","runner_arch":"${RUNNER_ARCH:-unknown}","shard":"$NAME"}
JSON
