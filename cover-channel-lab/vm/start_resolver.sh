#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
IFACE="${COVERLAB_VM_IFACE:-ens19}"
PYTHON_BIN="${COVERLAB_PYTHON:-python3}"
STATE_DIR="${COVERLAB_VM_STATE:-/tmp/coverlab-vm-resolver}"
mkdir -p "$STATE_DIR"
sudo ip addr replace 10.20.0.23/24 dev "$IFACE"
if [[ -f "$STATE_DIR/resolver.pid" ]]; then
  sudo kill "$(cat "$STATE_DIR/resolver.pid")" 2>/dev/null || true
fi
sudo env PYTHONPATH="$ROOT/src" "$PYTHON_BIN" -m coverlab.stage_m_dns_server   --bind 10.20.0.23 --port 53 --upstream 10.20.0.20   >"$STATE_DIR/resolver.log" 2>&1 &
echo $! > "$STATE_DIR/resolver.pid"
sleep 1
echo "coverlab VM recursive resolver ready"
