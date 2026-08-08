#!/usr/bin/env bash
set -euo pipefail
if [[ $# -ne 2 ]]; then echo "usage: $0 WORK_ROOT SHARD_NAME" >&2; exit 2; fi
WORK="$1" NAME="$2"
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
STAGE_DIR="$WORK/stage"; PARSER_DIR="$WORK/parsers"; RELEASE_DIR="$WORK/release"; PCAP="$WORK/capture.pcap"
mkdir -p "$WORK"
cleanup(){ "$ROOT/scripts/stop_services.sh" || true; }
trap cleanup EXIT
"$ROOT/scripts/setup_netns.sh"
"$ROOT/scripts/start_services.sh"
"$ROOT/scripts/generate_adversarial.sh" "$STAGE_DIR" "$PCAP"
"$ROOT/scripts/process_parsers.sh" "$PCAP" "$STAGE_DIR" "$PARSER_DIR"
"$ROOT/scripts/package_layers.sh" "$STAGE_DIR" "$PCAP" "$PARSER_DIR" "$RELEASE_DIR" "$NAME"
cleanup; trap - EXIT
echo "$RELEASE_DIR"
