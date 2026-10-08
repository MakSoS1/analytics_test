#!/usr/bin/env bash
set -euo pipefail
if [[ $# -ne 3 ]]; then echo "usage: $0 MIXED_INDEX WORK_ROOT SHARD_NAME" >&2; exit 2; fi
IDX="$1" WORK="$2" NAME="$3"
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
STAGE_DIR="$WORK/stage"; PARSER_DIR="$WORK/parsers"; RELEASE_DIR="$WORK/release"; PCAP="$WORK/capture.pcap"
mkdir -p "$WORK"
cleanup(){ "$ROOT/scripts/stop_services.sh" || true; }
trap cleanup EXIT
"$ROOT/scripts/stop_services.sh" || true
for dev in v-office v-dev v-c2 v-devops v-soc; do sudo ip link del "$dev" 2>/dev/null || true; done
"$ROOT/scripts/setup_netns.sh"
"$ROOT/scripts/start_services.sh"
"$ROOT/scripts/generate_mixed.sh" "$IDX" "$STAGE_DIR" "$PCAP"
"$ROOT/scripts/process_parsers.sh" "$PCAP" "$STAGE_DIR" "$PARSER_DIR"
"$ROOT/scripts/package_layers.sh" "$STAGE_DIR" "$PCAP" "$PARSER_DIR" "$RELEASE_DIR" "$NAME"
cleanup; trap - EXIT
echo "$RELEASE_DIR"
