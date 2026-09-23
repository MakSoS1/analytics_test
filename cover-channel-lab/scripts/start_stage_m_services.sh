#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
PYTHON_BIN="$(command -v python)"
CERTDIR="${1:-${RUNNER_TEMP:-/tmp}/coverlab-certs}"
LOGDIR="${RUNNER_TEMP:-/tmp}/coverlab-services"
mkdir -p "$LOGDIR"

go build -o /tmp/coverlab-stage-m-go-server "$ROOT/clients/stage_m_go_server.go"
go build -o /tmp/coverlab-stage-m-go-tcp "$ROOT/clients/stage_m_go_tcp_client.go"
chmod 755 /tmp/coverlab-stage-m-go-server /tmp/coverlab-stage-m-go-tcp

COMMON_NO_PROXY='.test,10.20.0.0/24,localhost,127.0.0.1'
run_c2_user() {
  local name="$1"; shift
  sudo ip netns exec cc-c2 runuser -u "$USER" -- env     PYTHONPATH="$ROOT/src"     NO_PROXY="$COMMON_NO_PROXY" no_proxy="$COMMON_NO_PROXY"     COVERLAB_STAGE_M_GO_TCP=/tmp/coverlab-stage-m-go-tcp     "$@" >"$LOGDIR/$name.log" 2>&1 &
  echo $! > "$LOGDIR/$name.pid"
}
run_ns_root() {
  local ns="$1" name="$2"; shift 2
  sudo ip netns exec "$ns" env PYTHONPATH="$ROOT/src" NO_PROXY="$COMMON_NO_PROXY" no_proxy="$COMMON_NO_PROXY"     "$@" >"$LOGDIR/$name.log" 2>&1 &
  echo $! > "$LOGDIR/$name.pid"
}

run_c2_user stage-m-asgi-tls "$PYTHON_BIN" -m hypercorn coverlab.stage_m_asgi:app --bind 10.20.0.20:9443 --certfile "$CERTDIR/server.crt" --keyfile "$CERTDIR/server.key" --workers 1
run_c2_user stage-m-asgi-http "$PYTHON_BIN" -m hypercorn coverlab.stage_m_asgi:app --bind 10.20.0.20:9082 --workers 1
run_c2_user stage-m-go /tmp/coverlab-stage-m-go-server --host 10.20.0.20 --http-port 9080 --https-port 9444 --cert "$CERTDIR/server.crt" --key "$CERTDIR/server.key"
run_c2_user stage-m-node node "$ROOT/clients/stage_m_node_server.mjs" --host 10.20.0.20 --http-port 9081 --https-port 9445 --cert "$CERTDIR/server.crt" --key "$CERTDIR/server.key"
run_c2_user stage-m-wss "$PYTHON_BIN" -m coverlab.stage_m_ws_server --host 10.20.0.21 --port 9550 --cert "$CERTDIR/server.crt" --key "$CERTDIR/server.key"
run_c2_user stage-m-duplex "$PYTHON_BIN" -m coverlab.duplex_server --host 10.20.0.20 --port 9090

run_ns_root cc-c2 stage-m-dns-direct "$PYTHON_BIN" -m coverlab.dns_fixture --host 10.20.0.22 --port 53 --mode authoritative
run_ns_root cc-dns stage-m-dns-upstream "$PYTHON_BIN" -m coverlab.dns_fixture --host 10.20.0.40 --port 53 --mode authoritative
run_ns_root cc-c2 stage-m-dns-resolver "$PYTHON_BIN" -m coverlab.dns_fixture --host 10.20.0.23 --port 53 --mode resolver --upstream 10.20.0.40 --upstream-port 53
run_ns_root cc-c2 stage-m-plain443 "$PYTHON_BIN" -m coverlab.plain_http_server --host 10.20.0.24 --ports 80,443

probe() {
  local name="$1"; shift
  local ok=false
  for _ in $(seq 1 40); do
    if timeout 10s "$@" >/dev/null 2>&1; then ok=true; break; fi
    sleep .25
  done
  if [[ "$ok" != true ]]; then
    echo "Stage M readiness probe failed: $name" >&2
    for log in "$LOGDIR"/stage-m-*.log; do [[ -f "$log" ]] && { echo "===== $log =====" >&2; tail -n 80 "$log" >&2 || true; }; done
    exit 1
  fi
  echo "Stage M readiness probe: $name=ready"
}

NS_DEV=(sudo ip netns exec cc-dev runuser -u "$USER" -- env PYTHONPATH="$ROOT/src" NO_PROXY="$COMMON_NO_PROXY" no_proxy="$COMMON_NO_PROXY")
probe asgi "${NS_DEV[@]}" curl --noproxy '*' -ksS https://stage-m-asgi.test:9443/healthz
probe go "${NS_DEV[@]}" curl --noproxy '*' -ksS https://stage-m-go.test:9444/healthz
probe node "${NS_DEV[@]}" curl --noproxy '*' -ksS https://stage-m-node.test:9445/healthz
probe plain443 "${NS_DEV[@]}" curl --noproxy '*' -sS http://plain-http.test:443/healthz
probe dns-direct "${NS_DEV[@]}" dig @10.20.0.22 -p 53 a.stage-m.test A +time=1 +tries=1 +short
probe dns-resolver "${NS_DEV[@]}" dig @10.20.0.23 -p 53 x.stage-m.test TXT +time=1 +tries=1 +short

wss_probe='import json,ssl;from websockets.sync.client import connect;x=ssl.create_default_context();x.check_hostname=False;x.verify_mode=ssl.CERT_NONE;w=connect("wss://stage-m-ws.test:9550/ws",ssl=x,proxy=None,compression=None,open_timeout=5);w.send(json.dumps({"response_bytes":32}));r=w.recv();w.close();raise SystemExit(0 if len(r)==32 else 1)'
probe wss "${NS_DEV[@]}" "$PYTHON_BIN" -c "$wss_probe"

duplex_probe='import socket,struct;s=socket.create_connection(("stage-m-tcp.test",9090),timeout=4);s.sendall(b"STAGEM1 fixed 32\n");assert s.recv(3)==b"OK\n";s.sendall(struct.pack("!H",4)+b"PING");h=s.recv(2);n=struct.unpack("!H",h)[0];d=b""
while len(d)<n:
 d+=s.recv(n-len(d))
s.close();raise SystemExit(0 if len(d)==32 else 1)'
probe duplex "${NS_DEV[@]}" "$PYTHON_BIN" -c "$duplex_probe"

echo "coverlab Stage M positive-only fixtures ready"
