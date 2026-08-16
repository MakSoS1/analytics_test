#!/usr/bin/env bash
set -euo pipefail

MODE="${1:-}"
TOPOLOGY="${2:-}"

if [[ -z "$MODE" || -z "$TOPOLOGY" ]]; then
  echo "usage: $0 {up|verify|down} configs/topology.yaml" >&2
  exit 2
fi
if [[ ! -f "$TOPOLOGY" ]]; then echo "topology file not found: $TOPOLOGY" >&2; exit 2; fi
if [[ "${EUID}" -ne 0 ]]; then echo "topology operations require root" >&2; exit 2; fi

readarray -t LAB_META < <(python3 - "$TOPOLOGY" <<'PY'
import sys, yaml
from ipaddress import ip_network, ip_interface
with open(sys.argv[1], encoding="utf-8") as f: d=yaml.safe_load(f)
lab=d["lab"]
if lab.get("external_routing") is not False: raise SystemExit("external_routing must be false")
net=ip_network(lab["cidr"],strict=True); bridge=ip_interface(lab["bridge_ip"])
if bridge.ip not in net: raise SystemExit("bridge_ip outside lab cidr")
print(lab["bridge"]); print(lab["cidr"]); print(lab["bridge_ip"])
PY
)
BRIDGE="${LAB_META[0]}"; LAB_CIDR="${LAB_META[1]}"; BRIDGE_IP="${LAB_META[2]}"

list_hosts() {
  python3 - "$TOPOLOGY" <<'PY'
import sys,yaml
with open(sys.argv[1],encoding="utf-8") as f: d=yaml.safe_load(f)
for i,h in enumerate(d["hosts"]): print(f"{i}\t{h['id']}\t{h['namespace']}\t{h['ip']}")
PY
}

down_topology() {
  declare -A removed=()
  while IFS=$'\t' read -r idx host_id ns ip_cidr; do
    [[ -n "$ns" ]] || continue
    [[ -n "${removed[$ns]:-}" ]] && continue
    removed[$ns]=1
    if ip netns list | awk '{print $1}' | grep -Fxq "$ns"; then ip netns delete "$ns"; fi
  done < <(list_hosts)
  if ip link show "$BRIDGE" >/dev/null 2>&1; then ip link delete "$BRIDGE" type bridge; fi
}

up_topology() {
  down_topology
  ip link add "$BRIDGE" type bridge
  ip addr add "$BRIDGE_IP" dev "$BRIDGE"
  ip link set "$BRIDGE" up

  while IFS=$'\t' read -r idx host_id ns ip_cidr; do
    # Multiple logical service endpoints may intentionally share one validated
    # server namespace. Additional host rows then become additional L3 addresses
    # on the same kernel/service stack instead of fake independent servers.
    if ip netns list | awk '{print $1}' | grep -Fxq "$ns"; then
      ip netns exec "$ns" ip addr add "$ip_cidr" dev eth0
      continue
    fi
    host_if="rah${idx}"; ns_if="ran${idx}"
    ip netns add "$ns"
    ip link add "$host_if" type veth peer name "$ns_if"
    ip link set "$host_if" master "$BRIDGE"; ip link set "$host_if" up
    ip link set "$ns_if" netns "$ns"
    ip netns exec "$ns" ip link set lo up
    ip netns exec "$ns" ip link set "$ns_if" name eth0
    ip netns exec "$ns" ip addr add "$ip_cidr" dev eth0
    ip netns exec "$ns" ip link set eth0 up
  done < <(list_hosts)
}

verify_topology() {
  ip link show "$BRIDGE" >/dev/null
  python3 - "$LAB_CIDR" "$BRIDGE_IP" <<'PY'
import sys
from ipaddress import ip_network,ip_interface
network=ip_network(sys.argv[1],strict=True); bridge=ip_interface(sys.argv[2]); assert bridge.ip in network
PY
  count=0; declare -A namespaces=()
  while IFS=$'\t' read -r idx host_id ns ip_cidr; do
    count=$((count+1)); namespaces[$ns]=1
    if ! ip netns list | awk '{print $1}' | grep -Fxq "$ns"; then echo "missing namespace: $ns" >&2; exit 1; fi
    expected_ip="${ip_cidr%/*}"
    if ! ip netns exec "$ns" ip -o -4 addr show dev eth0 | grep -Fq "$expected_ip/"; then echo "missing expected address $ip_cidr in namespace $ns" >&2; exit 1; fi
    default_route="$(ip netns exec "$ns" ip route show default || true)"
    if [[ -n "$default_route" ]]; then echo "unexpected default route in $ns: $default_route" >&2; exit 1; fi
  done < <(list_hosts)
  if [[ "$count" -lt 2 ]]; then echo "topology must contain at least two endpoints" >&2; exit 1; fi
  echo "topology verified: bridge=$BRIDGE endpoints=$count namespaces=${#namespaces[@]} cidr=$LAB_CIDR external_routing=false"
}

case "$MODE" in
  up) up_topology; verify_topology ;;
  verify) verify_topology ;;
  down) down_topology ;;
  *) echo "unknown mode: $MODE" >&2; exit 2 ;;
esac
