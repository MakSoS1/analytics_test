#!/usr/bin/env bash
set -euo pipefail
if [[ $# -ne 3 ]]; then
  echo "usage: $0 PROFILE CLIENT_IF SERVER_IF" >&2
  exit 2
fi
PROFILE="$1"; CLIENT_IF="$2"; SERVER_IF="$3"

case "$PROFILE" in
  lan)
    CLIENT_ARGS=(delay 1ms 0.2ms distribution normal)
    SERVER_ARGS=(delay 1ms 0.2ms distribution normal)
    ;;
  wan_low)
    CLIENT_ARGS=(delay 10ms 2ms distribution normal loss 0.01% rate 200mbit)
    SERVER_ARGS=(delay 10ms 3ms distribution normal loss 0.01% rate 200mbit)
    ;;
  wan)
    CLIENT_ARGS=(delay 35ms 8ms distribution normal loss 0.05% rate 80mbit)
    SERVER_ARGS=(delay 35ms 7ms distribution normal loss 0.05% rate 80mbit)
    ;;
  bad_wifi)
    CLIENT_ARGS=(delay 60ms 25ms distribution normal loss 0.6% reorder 0.1% 25% rate 20mbit)
    SERVER_ARGS=(delay 60ms 20ms distribution normal loss 0.2% rate 20mbit)
    ;;
  asymmetric)
    CLIENT_ARGS=(delay 15ms 5ms distribution normal loss 0.05% rate 100mbit)
    SERVER_ARGS=(delay 70ms 18ms distribution normal loss 0.25% rate 20mbit)
    ;;
  clear)
    sudo tc qdisc del dev "$CLIENT_IF" root 2>/dev/null || true
    sudo tc qdisc del dev "$SERVER_IF" root 2>/dev/null || true
    exit 0
    ;;
  *)
    echo "unknown VM netem profile: $PROFILE" >&2
    exit 2
    ;;
esac
sudo tc qdisc replace dev "$CLIENT_IF" root netem "${CLIENT_ARGS[@]}"
sudo tc qdisc replace dev "$SERVER_IF" root netem "${SERVER_ARGS[@]}"
tc qdisc show dev "$CLIENT_IF"
tc qdisc show dev "$SERVER_IF"
