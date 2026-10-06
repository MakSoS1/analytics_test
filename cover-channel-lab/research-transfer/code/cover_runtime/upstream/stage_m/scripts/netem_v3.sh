#!/usr/bin/env bash
set -euo pipefail
# Safe lab-only network randomization on the isolated coverlab veth.
# Only profiles implemented as actual kernel/network changes are accepted here.
# NAT/proxy/TLS-inspection/partial-capture are separate evidence layers and are
# deliberately not faked by a delay-only netem profile.
ACTION="${1:-}"; PROFILE="${2:-clean}"; IFACE="${3:-${COVERLAB_NETEM_IF:-v-c2}}"
restore_mtu() {
  sudo ip link set dev "$IFACE" mtu 1500 2>/dev/null || true
  if [[ "$IFACE" == "v-c2" ]]; then sudo ip netns exec cc-c2 ip link set dev eth0 mtu 1500 2>/dev/null || true; fi
}
if [[ "$ACTION" == "clear" ]]; then
  IFACE="${2:-${COVERLAB_NETEM_IF:-v-c2}}"
  sudo tc qdisc del dev "$IFACE" root 2>/dev/null || true
  restore_mtu
  exit 0
fi
[[ "$ACTION" == "apply" ]] || { echo "usage: $0 apply PROFILE [IFACE] | clear [IFACE]" >&2; exit 2; }
sudo ip link show "$IFACE" >/dev/null
sudo tc qdisc del dev "$IFACE" root 2>/dev/null || true
restore_mtu
case "$PROFILE" in
  clean) exit 0 ;;
  wan_20ms) sudo tc qdisc add dev "$IFACE" root netem delay 20ms 3ms distribution normal ;;
  wan_80ms) sudo tc qdisc add dev "$IFACE" root netem delay 80ms 15ms distribution normal ;;
  lossy_wifi) sudo tc qdisc add dev "$IFACE" root netem delay 35ms 12ms loss 0.7% reorder 0.2% 50% ;;
  constrained)
    sudo ip link set dev "$IFACE" mtu 1280
    if [[ "$IFACE" == "v-c2" ]]; then sudo ip netns exec cc-c2 ip link set dev eth0 mtu 1280; fi
    sudo tc qdisc add dev "$IFACE" root handle 1: netem delay 60ms 10ms
    sudo tc qdisc add dev "$IFACE" parent 1:1 handle 10: tbf rate 5mbit burst 64kb latency 400ms
    ;;
  nat_proxy|inspected|partial_capture)
    echo "$PROFILE requires a dedicated wire-real evidence adapter; refusing semantic-only emulation" >&2
    exit 4
    ;;
  *) echo "unknown netem profile: $PROFILE" >&2; exit 2 ;;
esac
