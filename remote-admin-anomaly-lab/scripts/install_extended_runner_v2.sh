#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
bash "$ROOT/scripts/install_extended_runner.sh"

# V3 authoritative Bronze is sliced and verified with the Wireshark CLI. Keep
# these tools in the shared extended-runner fixture so smoke/full release use the
# exact same runtime rather than installing ad hoc packages in workflows.
if ! command -v tshark >/dev/null 2>&1 || ! command -v editcap >/dev/null 2>&1 || ! command -v mergecap >/dev/null 2>&1; then
  echo 'wireshark-common wireshark-common/install-setuid boolean false' | sudo debconf-set-selections
  sudo DEBIAN_FRONTEND=noninteractive apt-get update -qq
  sudo DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends tshark wireshark-common
fi
for tool in tshark editcap mergecap capinfos; do
  command -v "$tool" >/dev/null 2>&1 || { echo "missing V3 PCAP tool: $tool" >&2; exit 1; }
done

# The package may auto-start xrdp in the host namespace and share /run pid files
# with our isolated endpoint. Stop only the package service; the lab later starts
# its own xrdp process inside ra-rdp01.
sudo systemctl stop xrdp xrdp-sesman 2>/dev/null || true
sudo pkill -x xrdp 2>/dev/null || true
sudo pkill -x xrdp-sesman 2>/dev/null || true
sudo rm -f /run/xrdp/xrdp.pid /run/xrdp/xrdp-sesman.pid 2>/dev/null || true
sudo mkdir -p /run/xrdp

echo "extended_runner_v2_ready host_xrdp_stopped=true wireshark_cli=true"
