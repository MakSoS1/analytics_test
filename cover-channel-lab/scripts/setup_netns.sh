#!/usr/bin/env bash
set -euo pipefail

BR=ccbr0
SUBNET=10.20.0.0/24

delete_ns() { sudo ip netns del "$1" 2>/dev/null || true; }
for ns in cc-office cc-dev cc-c2 cc-devops cc-soc; do delete_ns "$ns"; done
sudo ip link del "$BR" 2>/dev/null || true
sudo ip link add "$BR" type bridge
sudo ip addr add 10.20.0.2/24 dev "$BR"
sudo ip link set "$BR" up

create_ns() {
  local ns="$1" ipaddr="$2" hostif="v-${1#cc-}"
  sudo ip netns add "$ns"
  sudo ip link add "$hostif" type veth peer name eth0 netns "$ns"
  sudo ip link set "$hostif" master "$BR"
  sudo ip link set "$hostif" up
  sudo ip netns exec "$ns" ip link set lo up
  sudo ip netns exec "$ns" ip addr add "$ipaddr/24" dev eth0
  sudo ip netns exec "$ns" ip link set eth0 up
  # Deliberately no default route: simulated clients cannot reach the Internet.
}
create_ns cc-office 10.20.0.10
create_ns cc-dev 10.20.0.11
create_ns cc-c2 10.20.0.20
create_ns cc-devops 10.20.0.30
create_ns cc-soc 10.20.0.31

HOSTS=(cover-api.test cover-h2.test cover-h3.test cover-ws.test cover-static.test benign-api.test benign-chat.test benign-market.test benign-update.test lots-chatops.test lots-tunnel.test lots-bucket.test mqtt-broker.test dyndns-relay.test benign-devtunnel.test doh-relay.test synthetic-api.test echo.test)
for h in "${HOSTS[@]}"; do
  if ! grep -qE "(^|[[:space:]])${h//./\\.}([[:space:]]|$)" /etc/hosts; then
    echo "10.20.0.20 $h" | sudo tee -a /etc/hosts >/dev/null
  fi
done

for ns in cc-office cc-dev cc-devops cc-soc; do
  if sudo ip netns exec "$ns" ip route | grep -q '^default'; then
    echo "unexpected default route in $ns" >&2; exit 1
  fi
done
sudo ip -br addr show "$BR"
