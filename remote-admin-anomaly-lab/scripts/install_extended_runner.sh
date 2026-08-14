#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
bash "$ROOT/scripts/install_runner.sh"

export DEBIAN_FRONTEND=noninteractive
candidates=(xrdp tigervnc-standalone-server freerdp3-x11)
for pkg in "${candidates[@]}"; do
  if apt-cache show "$pkg" >/dev/null 2>&1; then
    sudo apt-get install -y --no-install-recommends "$pkg" >/dev/null
  fi
done

# Some Ubuntu images expose the FreeRDP client under a versioned name.
rdp_client=""
for cmd in xfreerdp3 xfreerdp sdl-freerdp; do
  if command -v "$cmd" >/dev/null 2>&1; then
    rdp_client="$(command -v "$cmd")"
    break
  fi
done
vnc_server=""
for cmd in Xtigervnc Xvnc; do
  if command -v "$cmd" >/dev/null 2>&1; then
    vnc_server="$(command -v "$cmd")"
    break
  fi
done

command -v xrdp >/dev/null
[[ -n "$rdp_client" ]]
[[ -n "$vnc_server" ]]
command -v curl >/dev/null

echo "extended_wire_ready xrdp=$(command -v xrdp) freerdp=$rdp_client vnc=$vnc_server"
