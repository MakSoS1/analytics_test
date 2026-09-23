#!/usr/bin/env bash
set -euo pipefail

if [[ $# -lt 1 || $# -gt 2 ]]; then
  echo "usage: $0 {mythic|adaptix|sliver|all} [INSTALL_ROOT]" >&2
  exit 2
fi
[[ "${COVERLAB_ISOLATED_LAB:-0}" == "1" ]] || {
  echo "refusing to bootstrap C2 frameworks unless COVERLAB_ISOLATED_LAB=1" >&2
  exit 2
}

MODE="$1"
INSTALL_ROOT="${2:-/opt/coverlab/tools}"
mkdir -p "$INSTALL_ROOT"

need() {
  command -v "$1" >/dev/null 2>&1 || {
    echo "missing required command: $1" >&2
    exit 1
  }
}

clone_or_update() {
  local url="$1" dir="$2"
  if [[ -d "$dir/.git" ]]; then
    git -C "$dir" fetch --depth 1 origin
    git -C "$dir" reset --hard FETCH_HEAD
  else
    git clone --depth 1 "$url" "$dir"
  fi
}

bootstrap_mythic() {
  need git
  need docker
  local dir="$INSTALL_ROOT/Mythic"
  clone_or_update https://github.com/its-a-feature/Mythic.git "$dir"
  (
    cd "$dir"
    sudo make
    sudo ./mythic-cli install github https://github.com/MythicC2Profiles/httpx
    sudo ./mythic-cli install github https://github.com/MythicC2Profiles/websocket
    sudo ./mythic-cli install github https://github.com/MythicAgents/Apollo
    sudo ./mythic-cli install github https://github.com/MythicAgents/Athena
    sudo ./mythic-cli start
    sudo ./mythic-cli status || true
  )
  echo "Mythic core + HTTPX/WebSocket profiles + Apollo/Athena installed under $dir"
  echo "Only use check-in/poll/sleep/synthetic task-result lifecycle for CoverLab evidence."
}

bootstrap_adaptix() {
  need git
  need docker
  local dir="$INSTALL_ROOT/AdaptixC2"
  clone_or_update https://github.com/Adaptix-Framework/AdaptixC2.git "$dir"
  (
    cd "$dir"
    docker compose --profile build-server-ext run --rm server-ext-builder
    docker compose --profile runtime up -d adaptix-server-runtime
    docker compose --profile runtime ps
  )
  echo "AdaptixC2 server + official extenders installed under $dir"
  echo "Configure only a private RFC1918 HTTP/S listener for CoverLab evidence."
}

bootstrap_sliver() {
  need curl
  need sudo
  # Official Sliver installer. The resulting installation is intentionally
  # left without payload generation; use a pre-approved isolated lab beacon.
  curl -fsSL https://sliver.sh/install | sudo bash
  if command -v sliver >/dev/null 2>&1; then
    sliver --help >/dev/null 2>&1 || true
  fi
  if command -v sliver-server >/dev/null 2>&1; then
    sliver-server version 2>/dev/null || true
  fi
  echo "Sliver installed from the official installer."
  echo "Start the server only inside the isolated lab and use HTTP(S) beacon traffic for holdout capture."
}

case "$MODE" in
  mythic) bootstrap_mythic ;;
  adaptix) bootstrap_adaptix ;;
  sliver) bootstrap_sliver ;;
  all)
    bootstrap_mythic
    bootstrap_adaptix
    bootstrap_sliver
    ;;
  *)
    echo "unknown mode: $MODE" >&2
    exit 2
    ;;
esac


VERSION_FILE="$INSTALL_ROOT/coverlab-tool-versions.env"
mythic_version=""
adaptix_version=""
sliver_version=""
[[ -d "$INSTALL_ROOT/Mythic/.git" ]] && mythic_version="$(git -C "$INSTALL_ROOT/Mythic" rev-parse HEAD)"
[[ -d "$INSTALL_ROOT/AdaptixC2/.git" ]] && adaptix_version="$(git -C "$INSTALL_ROOT/AdaptixC2" rev-parse HEAD)"
if command -v sliver-server >/dev/null 2>&1; then
  sliver_version="$(sliver-server version 2>/dev/null | head -n1 || true)"
elif command -v sliver >/dev/null 2>&1; then
  sliver_version="$(sliver --version 2>/dev/null | head -n1 || true)"
fi
{
  printf 'COVERLAB_MYTHIC_TOOL_VERSION=%q\n' "$mythic_version"
  printf 'COVERLAB_ADAPTIX_TOOL_VERSION=%q\n' "$adaptix_version"
  printf 'COVERLAB_SLIVER_TOOL_VERSION=%q\n' "$sliver_version"
} > "$VERSION_FILE"
echo "Tool provenance written to $VERSION_FILE"
cat "$VERSION_FILE"
