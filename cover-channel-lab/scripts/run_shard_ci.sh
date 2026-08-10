#!/usr/bin/env bash
set -euo pipefail
if [[ $# -ne 5 ]]; then echo "usage: $0 STAGE SHARD SHARDS WORK_ROOT SHARD_NAME" >&2; exit 2; fi
STAGE="$1" SHARD="$2" SHARDS="$3" WORK="$4" NAME="$5"
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
STAGE_DIR="$WORK/stage"; PARSER_DIR="$WORK/parsers"; RELEASE_DIR="$WORK/release"; PCAP="$WORK/capture.pcap"
mkdir -p "$WORK"
cleanup(){ bash "$ROOT/scripts/netem_v3.sh" clear v-c2 || true; "$ROOT/scripts/stop_services.sh" || true; }
trap cleanup EXIT

# A shard may run after another comprehensive smoke in the same hosted runner.
# Tear down the prior lab first so orphan namespaces/veths cannot collide with
# the deterministic topology names used below.
"$ROOT/scripts/stop_services.sh" || true
for dev in v-office v-dev v-c2 v-devops v-soc; do sudo ip link del "$dev" 2>/dev/null || true; done
"$ROOT/scripts/setup_netns.sh"
"$ROOT/scripts/start_services.sh"
PROFILE="${COVERLAB_NETEM_PROFILE:-clean}"
bash "$ROOT/scripts/netem_v3.sh" apply "$PROFILE" v-c2
"$ROOT/scripts/generate_stage.sh" "$STAGE" "$SHARD" "$SHARDS" "$STAGE_DIR" "$PCAP"
"$ROOT/scripts/process_parsers.sh" "$PCAP" "$STAGE_DIR" "$PARSER_DIR"
"$ROOT/scripts/package_layers.sh" "$STAGE_DIR" "$PCAP" "$PARSER_DIR" "$RELEASE_DIR" "$NAME"
cleanup; trap - EXIT
echo "$RELEASE_DIR"
