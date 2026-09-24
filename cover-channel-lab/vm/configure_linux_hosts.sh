#!/usr/bin/env bash
set -euo pipefail
SERVER_MAIN="${1:-10.20.0.20}"
SERVER_WSS="${2:-10.20.0.21}"
SERVER_FRONT="${3:-10.20.0.22}"
RESOLVER="${4:-10.20.0.23}"

block_start="# BEGIN COVERLAB STAGE M"
block_end="# END COVERLAB STAGE M"
tmp="$(mktemp)"
sudo awk -v a="$block_start" -v b="$block_end" '
  $0==a {skip=1; next}
  $0==b {skip=0; next}
  !skip {print}
' /etc/hosts > "$tmp"
cat >> "$tmp" <<EOF
$block_start
$SERVER_MAIN cover-api.test cover-h2.test cover-h3.test doh-relay.test doq-resolver.test mqtt-broker.test synthetic-api.test echo.test
$SERVER_WSS cover-ws.test
$SERVER_FRONT edge-front.test edge-ws.test cdn-front.test workers-front.test graph-front.test telegram-front.test resolver-front.test plain-front.test
$RESOLVER stage-m-resolver.test
$block_end
EOF
sudo cp "$tmp" /etc/hosts
rm -f "$tmp"
getent hosts cover-api.test >/dev/null
getent hosts edge-front.test >/dev/null
echo "coverlab Linux client hosts configured"
