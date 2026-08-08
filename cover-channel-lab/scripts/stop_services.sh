#!/usr/bin/env bash
set -euo pipefail
LOGDIR="${RUNNER_TEMP:-/tmp}/coverlab-services"
for p in "$LOGDIR"/*.pid; do
  [[ -f "$p" ]] || continue
  kill "$(cat "$p")" 2>/dev/null || true
done
sudo ip netns del cc-office 2>/dev/null || true
sudo ip netns del cc-dev 2>/dev/null || true
sudo ip netns del cc-c2 2>/dev/null || true
sudo ip netns del cc-devops 2>/dev/null || true
sudo ip netns del cc-soc 2>/dev/null || true
sudo ip link del ccbr0 2>/dev/null || true
