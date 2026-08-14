#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
bash "$ROOT/scripts/install_extended_runner.sh"

# The package may auto-start xrdp in the host namespace and share /run pid files
# with our isolated endpoint. Stop only the package service; the lab later starts
# its own xrdp process inside ra-rdp01.
sudo systemctl stop xrdp xrdp-sesman 2>/dev/null || true
sudo pkill -x xrdp 2>/dev/null || true
sudo pkill -x xrdp-sesman 2>/dev/null || true
sudo rm -f /run/xrdp/xrdp.pid /run/xrdp/xrdp-sesman.pid 2>/dev/null || true
sudo mkdir -p /run/xrdp

echo "extended_runner_v2_ready host_xrdp_stopped=true"
