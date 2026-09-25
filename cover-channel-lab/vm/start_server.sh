#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
IFACE="${COVERLAB_VM_IFACE:-ens19}"
PYTHON_BIN="${COVERLAB_PYTHON:-python3}"
STATE_DIR="${COVERLAB_VM_STATE:-/tmp/coverlab-vm-server}"
mkdir -p "$STATE_DIR/certs" "$STATE_DIR/logs" "$STATE_DIR/pids"

# The server VM intentionally owns separate service/front addresses so WSS and
# nginx-front traffic have distinct real L2/L3 destinations on the wire.
for addr in 10.20.0.20/24 10.20.0.21/24 10.20.0.22/24; do
  sudo ip addr replace "$addr" dev "$IFACE"
done

cat > "$STATE_DIR/certs/openssl.cnf" <<'CNF'
[req]
distinguished_name=dn
prompt=no
x509_extensions=v3
[dn]
CN=coverlab-vm.test
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
DNS.5=edge-front.test
DNS.6=edge-ws.test
DNS.7=cdn-front.test
DNS.8=workers-front.test
DNS.9=graph-front.test
DNS.10=telegram-front.test
DNS.11=resolver-front.test
DNS.12=plain-front.test
DNS.13=doh-relay.test
DNS.14=doq-resolver.test
DNS.15=mqtt-broker.test
DNS.16=synthetic-api.test
DNS.17=echo.test
CNF
openssl req -x509 -newkey rsa:2048 -nodes -days 30   -keyout "$STATE_DIR/certs/server.key" -out "$STATE_DIR/certs/server.crt"   -config "$STATE_DIR/certs/openssl.cnf" >/dev/null 2>&1

cat > "$STATE_DIR/mosquitto.conf" <<EOF
listener 9443 10.20.0.20
protocol websockets
allow_anonymous true
persistence false
certfile $STATE_DIR/certs/server.crt
keyfile $STATE_DIR/certs/server.key
EOF

cat > "$STATE_DIR/nginx.conf" <<EOF
pid $STATE_DIR/pids/nginx.pid;
error_log $STATE_DIR/logs/nginx-error.log notice;
events { worker_connections 2048; }
http {
  access_log $STATE_DIR/logs/nginx-access.log;
  server {
    listen 10.20.0.22:8443 ssl;
    server_name edge-front.test edge-ws.test cdn-front.test workers-front.test graph-front.test telegram-front.test resolver-front.test;
    ssl_certificate $STATE_DIR/certs/server.crt;
    ssl_certificate_key $STATE_DIR/certs/server.key;
    ssl_protocols TLSv1.2 TLSv1.3;
    location /ws {
      proxy_pass https://10.20.0.21:8443;
      proxy_ssl_verify off;
      proxy_http_version 1.1;
      proxy_set_header Upgrade \$http_upgrade;
      proxy_set_header Connection "upgrade";
      proxy_set_header Host \$host;
    }
    location / {
      proxy_pass http://10.20.0.20:8080;
      proxy_http_version 1.1;
      proxy_set_header Host \$host;
      proxy_set_header X-Forwarded-For \$remote_addr;
    }
  }
  server {
    listen 10.20.0.22:443;
    server_name plain-front.test;
    location / {
      proxy_pass http://10.20.0.20:8080;
      proxy_set_header Host \$host;
    }
  }
}
EOF

stop_pid() {
  local name="$1"
  if [[ -f "$STATE_DIR/pids/$name.pid" ]]; then
    kill "$(cat "$STATE_DIR/pids/$name.pid")" 2>/dev/null || true
    rm -f "$STATE_DIR/pids/$name.pid"
  fi
}
for n in http https wss h3 doq grpc mqtt dns raw_sink nginx; do stop_pid "$n"; done

export PYTHONPATH="$ROOT/src"
"$PYTHON_BIN" -m hypercorn coverlab.server:app --bind 10.20.0.20:8080 --workers 2   >"$STATE_DIR/logs/http.log" 2>&1 & echo $! > "$STATE_DIR/pids/http.pid"
"$PYTHON_BIN" -m hypercorn coverlab.server:app --bind 10.20.0.20:8443   --certfile "$STATE_DIR/certs/server.crt" --keyfile "$STATE_DIR/certs/server.key" --workers 2   >"$STATE_DIR/logs/https.log" 2>&1 & echo $! > "$STATE_DIR/pids/https.pid"
"$PYTHON_BIN" -m coverlab.wss_server --host 10.20.0.21 --port 8443   --cert "$STATE_DIR/certs/server.crt" --key "$STATE_DIR/certs/server.key"   >"$STATE_DIR/logs/wss.log" 2>&1 & echo $! > "$STATE_DIR/pids/wss.pid"
"$PYTHON_BIN" -m coverlab.h3_fixture server --host 10.20.0.20 --port 8444   --cert "$STATE_DIR/certs/server.crt" --key "$STATE_DIR/certs/server.key"   >"$STATE_DIR/logs/h3.log" 2>&1 & echo $! > "$STATE_DIR/pids/h3.pid"
"$PYTHON_BIN" -m coverlab.doq_fixture server --host 10.20.0.20 --port 8853   --cert "$STATE_DIR/certs/server.crt" --key "$STATE_DIR/certs/server.key"   >"$STATE_DIR/logs/doq.log" 2>&1 & echo $! > "$STATE_DIR/pids/doq.pid"
"$PYTHON_BIN" -m coverlab.grpc_server --bind 10.20.0.20:50051   >"$STATE_DIR/logs/grpc.log" 2>&1 & echo $! > "$STATE_DIR/pids/grpc.pid"
mosquitto -c "$STATE_DIR/mosquitto.conf" -v   >"$STATE_DIR/logs/mqtt.log" 2>&1 & echo $! > "$STATE_DIR/pids/mqtt.pid"
sudo env PYTHONPATH="$ROOT/src" "$PYTHON_BIN" -m coverlab.stage_m_dns_server --bind 10.20.0.20 --port 53   >"$STATE_DIR/logs/dns.log" 2>&1 & echo $! > "$STATE_DIR/pids/dns.pid"
"$PYTHON_BIN" -m coverlab.stage_m_raw_sink --bind 10.20.0.20 --port 9091 >"$STATE_DIR/logs/raw-sink.log" 2>&1 & echo $! > "$STATE_DIR/pids/raw_sink.pid"
sudo nginx -c "$STATE_DIR/nginx.conf" -g 'daemon off;'   >"$STATE_DIR/logs/nginx.log" 2>&1 & echo $! > "$STATE_DIR/pids/nginx.pid"

sleep 2
curl --noproxy '*' -fsS http://10.20.0.20:8080/healthz >/dev/null
curl --noproxy '*' -kfsS --resolve edge-front.test:8443:10.20.0.22 https://edge-front.test:8443/healthz >/dev/null
"$PYTHON_BIN" - <<'PY'
import socket
s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM); s.settimeout(3)
s.sendto(b"probe",("10.20.0.20",9091)); d,_=s.recvfrom(64)
if d != b"probe": raise SystemExit("raw UDP sink echo mismatch")
PY
echo "coverlab VM server services ready"
