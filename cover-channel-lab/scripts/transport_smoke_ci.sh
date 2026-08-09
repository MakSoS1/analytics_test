#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
PY="$(command -v python)"
cleanup(){ "$ROOT/scripts/stop_services.sh" || true; }
trap cleanup EXIT

"$ROOT/scripts/setup_netns.sh"
"$ROOT/scripts/start_services.sh"

# Exercise the exact failure mode seen in the previous full run: sustained
# short-lived WSS connections from all four personas, not just one readiness
# handshake.
pids=()
for ns in cc-office cc-dev cc-devops cc-soc; do
  sudo ip netns exec "$ns" runuser -u "$USER" -- env \
    NO_PROXY='.test,10.20.0.0/24,localhost,127.0.0.1' \
    no_proxy='.test,10.20.0.0/24,localhost,127.0.0.1' \
    "$PY" "$ROOT/scripts/wss_stress_smoke.py" --connections 400 &
  pids+=("$!")
done
for pid in "${pids[@]}"; do wait "$pid"; done

# Assert the historical LOTS-inspired slice is truly benign on the wire and in
# labels even if a caller accidentally requests a suspicious variant.
rm -f /tmp/g-smoke.jsonl /tmp/g-smoke-events.jsonl
code='from types import SimpleNamespace; from coverlab.run_campaign import run; import json; a=SimpleNamespace(scenario="CC_LOTS_05",variant="suspicious",seed=23,campaign_id="g-smoke",run_id="smoke",persona="Victim-2-Dev",source_ip="10.20.0.11",events=1,client_impl="python_httpx",state="/tmp/coverlab_server_state.json",manifest="/tmp/g-smoke.jsonl",events_out="/tmp/g-smoke-events.jsonl",capture_file="smoke.pcap"); r=run(a); assert r["label_binary"]==0 and r["label_intent"]=="benign" and not r["attack_mapping"], r; assert r.get("dataset_role")=="hard_negative", r; print(json.dumps({"label_binary":r["label_binary"],"dataset_role":r.get("dataset_role"),"status":"pass"}))'
sudo ip netns exec cc-dev runuser -u "$USER" -- env PYTHONPATH="$ROOT/src" \
  NO_PROXY='.test,10.20.0.0/24,localhost,127.0.0.1' \
  no_proxy='.test,10.20.0.0/24,localhost,127.0.0.1' \
  "$PY" -c "$code"

# Recheck advanced QUIC transports after WSS stress so readiness is not merely a
# startup property.
for mode in connect-udp webtransport; do
  sudo ip netns exec cc-dev runuser -u "$USER" -- env PYTHONPATH="$ROOT/src" \
    NO_PROXY='.test,10.20.0.0/24,localhost,127.0.0.1' \
    no_proxy='.test,10.20.0.0/24,localhost,127.0.0.1' \
    "$PY" -m coverlab.h3_fixture client --host cover-h3.test --port 8444 \
      --mode "$mode" --body "post-stress-$mode"
done

# One final WSS handshake proves the listener is still accepting new sessions.
sudo ip netns exec cc-dev runuser -u "$USER" -- env \
  NO_PROXY='.test,10.20.0.0/24,localhost,127.0.0.1' \
  no_proxy='.test,10.20.0.0/24,localhost,127.0.0.1' \
  "$PY" "$ROOT/scripts/wss_stress_smoke.py" --connections 20

cleanup
trap - EXIT
echo 'transport smoke: PASS'
