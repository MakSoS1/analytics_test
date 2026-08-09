#!/usr/bin/env bash
set -euo pipefail
if [[ $# -ne 5 ]]; then echo "usage: $0 STAGE SHARD SHARDS WORK_ROOT SHARD_NAME" >&2; exit 2; fi
STAGE="$1" SHARD="$2" SHARDS="$3" WORK="$4" NAME="$5"
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
STAGE_DIR="$WORK/stage"; PARSER_DIR="$WORK/parsers"; RELEASE_DIR="$WORK/release"; PCAP="$WORK/capture.pcap"
mkdir -p "$WORK"
cleanup(){ "$ROOT/scripts/stop_services.sh" || true; }
trap cleanup EXIT

# Stage A is the fan-out gate for the entire corpus. Before generating its 600
# parser-validation sessions, reproduce the transport failure modes that broke
# the previous full run. If WSS lifecycle, MQTT routing, H3 CONNECT-UDP,
# WebTransport, gRPC, or trusted-background labeling is bad, the workflow stops
# here and no expensive Stage B/C/D/F/G/H matrix is started.
if [[ "$STAGE" == "parser" ]]; then
  "$ROOT/scripts/transport_smoke_ci.sh"
fi

"$ROOT/scripts/setup_netns.sh"
"$ROOT/scripts/start_services.sh"
"$ROOT/scripts/generate_stage.sh" "$STAGE" "$SHARD" "$SHARDS" "$STAGE_DIR" "$PCAP"
"$ROOT/scripts/process_parsers.sh" "$PCAP" "$STAGE_DIR" "$PARSER_DIR"
"$ROOT/scripts/package_layers.sh" "$STAGE_DIR" "$PCAP" "$PARSER_DIR" "$RELEASE_DIR" "$NAME"
cleanup; trap - EXIT
echo "$RELEASE_DIR"
