#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
PYTHON_BIN="$(command -v python)"
CERTDIR="${RUNNER_TEMP:-/tmp}/coverlab-certs"
LOGDIR="${RUNNER_TEMP:-/tmp}/coverlab-services"
mkdir -p "$CERTDIR" "$LOGDIR"
rm -f /tmp/coverlab_server_state.json /tmp/coverlab_server_state.json.lock /tmp/coverlab_server_trace.jsonl /tmp/coverlab_server_trace.jsonl.lock /tmp/coverlab_wss_trace.jsonl
go build -o /tmp/coverlab-go-client "$ROOT/clients/go_client.go"
chmod 755 /tmp/coverlab-go-client

cat > "$CERTDIR/openssl.cnf" <<'CNF'
[req]
distinguished_name=dn
prompt=no
x509_extensions=v3
[dn]
CN=coverlab.test
[v3]
subjectAltName=@alt
basicConstraints=critical,CA:FALSE
keyUsage=digitalSignature,keyEncipherment
extendedKeyUsage=serverAuth
[alt]
DNS.1=cover-api.test
DNS.2=cover-h2.test
DNS.3=cover-h3.test
DNS.4=cover-ws.test
DNS.5=cover-static.test
DNS.6=lots-chatops.test
DNS.7=lots-tunnel.test
DNS.8=lots-bucket.test
DNS.9=mqtt-broker.test
DNS.10=dyndns-relay.test
DNS.11=doh-relay.test
DNS.12=benign-api.test
DNS.13=benign-chat.test
DNS.14=benign-market.test
DNS.15=benign-update.test
DNS.16=benign-devtunnel.test
DNS.17=synthetic-api.test
DNS.18=echo.test
CNF
openssl req -x509 -newkey rsa:2048 -nodes -days 2 -keyout "$CERTDIR/server.key" -out "$CERTDIR/server.crt" -config "$CERTDIR/openssl.cnf" >/dev/null 2>&1
chmod 600 "$CERTDIR/server.key"; chmod 644 "$CERTDIR/server.crt"

cat > "$CERTDIR/mosquitto.conf" <<EOF
listener 9443 10.20.0.20
protocol websockets
allow_anonymous true
persistence false
certfile $CERTDIR/server.crt
keyfile $CERTDIR/server.key
EOF

run_in_c2() {
  sudo ip netns exec cc-c2 runuser -u "$USER" -- env PYTHONPATH="$ROOT/src" NO_PROXY='.test,10.20.0.0/24,localhost,127.0.0.1' no_proxy='.test,10.20.0.0/24,localhost,127.0.0.1' "$@"
}
run_in_c2 "$PYTHON_BIN" -m hypercorn coverlab.server:app --bind 10.20.0.20:8080 --workers 1 >"$LOGDIR/http.log" 2>&1 & echo $! > "$LOGDIR/http.pid"
run_in_c2 "$PYTHON_BIN" -m hypercorn coverlab.server:app --bind 10.20.0.20:8443 --certfile "$CERTDIR/server.crt" --keyfile "$CERTDIR/server.key" --workers 1 >"$LOGDIR/https.log" 2>&1 & echo $! > "$LOGDIR/https.pid"
# Keep WSS local and synthetic, but give it a dedicated listener so WebSocket
# upgrades don't depend on Hypercorn's shared HTTPS listener on hosted runners.
run_in_c2 "$PYTHON_BIN" -m coverlab.wss_server --host 10.20.0.21 --port 8443 --cert "$CERTDIR/server.crt" --key "$CERTDIR/server.key" >"$LOGDIR/wss.log" 2>&1 & echo $! > "$LOGDIR/wss.pid"
run_in_c2 "$PYTHON_BIN" -m coverlab.grpc_server --bind 10.20.0.20:50051 >"$LOGDIR/grpc.log" 2>&1 & echo $! > "$LOGDIR/grpc.pid"
run_in_c2 "$PYTHON_BIN" -m coverlab.h3_fixture server --host 10.20.0.20 --port 8444 --cert "$CERTDIR/server.crt" --key "$CERTDIR/server.key" >"$LOGDIR/h3.log" 2>&1 & echo $! > "$LOGDIR/h3.pid"
run_in_c2 "$PYTHON_BIN" -m coverlab.connect_server --host 10.20.0.20 --port 8082 >"$LOGDIR/connect.log" 2>&1 & echo $! > "$LOGDIR/connect.pid"
run_in_c2 mosquitto -c "$CERTDIR/mosquitto.conf" -v >"$LOGDIR/mqtt.log" 2>&1 & echo $! > "$LOGDIR/mqtt.pid"

CORE_READY=false
for _ in $(seq 1 80); do
  if sudo ip netns exec cc-dev curl --noproxy '*' -fsS http://cover-api.test:8080/healthz >/dev/null 2>&1; then
    CORE_READY=true
    break
  fi
  sleep .25
done
if [[ "$CORE_READY" != true ]]; then
  echo "core HTTP service did not become ready" >&2
  cat "$LOGDIR/http.log" "$LOGDIR/https.log" >&2 || true
  exit 1
fi

# WSS is part of the core dataset path, so validate an actual RFC6455 handshake
# and request/reply here instead of discovering a broken listener minutes later.
wss_probe='import json,ssl; from websockets.sync.client import connect; x=ssl.create_default_context(); x.check_hostname=False; x.verify_mode=ssl.CERT_NONE; w=connect("wss://cover-ws.test:8443/ws",ssl=x,open_timeout=5,proxy=None,compression=None); w.send(json.dumps({"action":"recv","container":"HEALTH","target":"LAB","sender":"fixture","message":"STATUS"})); r=w.recv(); w.close(); raise SystemExit(0 if r else 1)'
WSS_READY=false
for _ in $(seq 1 40); do
  if timeout 8s sudo ip netns exec cc-dev runuser -u "$USER" -- env PYTHONPATH="$ROOT/src" NO_PROXY='.test,10.20.0.0/24,localhost,127.0.0.1' no_proxy='.test,10.20.0.0/24,localhost,127.0.0.1' "$PYTHON_BIN" -c "$wss_probe" >/dev/null 2>&1; then
    WSS_READY=true
    break
  fi
  sleep .25
done
if [[ "$WSS_READY" != true ]]; then
  echo "core WSS service did not become ready" >&2
  cat "$LOGDIR/wss.log" >&2 || true
  exit 1
fi

echo "coverlab core HTTP/HTTPS/H2/WSS services ready"

required_probe() {
  local name="$1" logfile="$2"; shift 2
  local ok=false
  for _ in $(seq 1 12); do
    if timeout 15s "$@" >/dev/null 2>&1; then
      ok=true
      break
    fi
    sleep .25
  done
  if [[ "$ok" == true ]]; then
    echo "required service probe: $name=ready"
    return 0
  fi
  echo "required service probe failed: $name" >&2
  [[ -f "$logfile" ]] && tail -n 120 "$logfile" >&2 || true
  return 1
}

grpc_probe='import grpc; c=grpc.insecure_channel("cover-h2.test:50051"); grpc.channel_ready_future(c).result(timeout=4); c.close()'
mqtt_probe='import ssl,time,paho.mqtt.client as mqtt; c=mqtt.Client(mqtt.CallbackAPIVersion.VERSION2,client_id="health-probe",protocol=mqtt.MQTTv5,transport="websockets"); x=ssl.create_default_context(); x.check_hostname=False; x.verify_mode=ssl.CERT_NONE; c.tls_set_context(x); c.ws_set_options(path="/mqtt"); c.connect("mqtt-broker.test",9443,keepalive=5); c.loop_start(); time.sleep(1.0); ok=c.is_connected(); c.disconnect(); c.loop_stop(); raise SystemExit(0 if ok else 1)'

COMMON_ENV=(env PYTHONPATH="$ROOT/src" NO_PROXY='.test,10.20.0.0/24,localhost,127.0.0.1' no_proxy='.test,10.20.0.0/24,localhost,127.0.0.1')
required_probe h3-request "$LOGDIR/h3.log" sudo ip netns exec cc-dev runuser -u "$USER" -- "${COMMON_ENV[@]}" "$PYTHON_BIN" -m coverlab.h3_fixture client --host cover-h3.test --port 8444 --path /healthz
required_probe h3-connect-udp "$LOGDIR/h3.log" sudo ip netns exec cc-dev runuser -u "$USER" -- "${COMMON_ENV[@]}" "$PYTHON_BIN" -m coverlab.h3_fixture client --host cover-h3.test --port 8444 --mode connect-udp --body health-datagram
required_probe h3-webtransport "$LOGDIR/h3.log" sudo ip netns exec cc-dev runuser -u "$USER" -- "${COMMON_ENV[@]}" "$PYTHON_BIN" -m coverlab.h3_fixture client --host cover-h3.test --port 8444 --mode webtransport --body health-webtransport
required_probe grpc "$LOGDIR/grpc.log" sudo ip netns exec cc-dev runuser -u "$USER" -- "${COMMON_ENV[@]}" "$PYTHON_BIN" -c "$grpc_probe"
required_probe mqtt-wss "$LOGDIR/mqtt.log" sudo ip netns exec cc-dev runuser -u "$USER" -- "${COMMON_ENV[@]}" "$PYTHON_BIN" -c "$mqtt_probe"

echo "coverlab H3/CONNECT-UDP/WebTransport/gRPC/MQTT fixtures ready"

# Socket-level diagnostics make a later protocol-shard failure actionable.
sudo ip netns exec cc-c2 ss -lntup 2>/dev/null | grep -E ':(8080|8443|50051|8082|9443)\b' || true
sudo ip netns exec cc-c2 ss -lnup 2>/dev/null | grep -E ':8444\b' || true
