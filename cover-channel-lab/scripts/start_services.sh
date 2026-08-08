#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
PYTHON_BIN="$(command -v python)"
CERTDIR="${RUNNER_TEMP:-/tmp}/coverlab-certs"
LOGDIR="${RUNNER_TEMP:-/tmp}/coverlab-services"
mkdir -p "$CERTDIR" "$LOGDIR"
rm -f /tmp/coverlab_server_state.json /tmp/coverlab_server_state.json.lock
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
DNS.3=cover-ws.test
DNS.4=cover-static.test
DNS.5=lots-chatops.test
DNS.6=lots-tunnel.test
DNS.7=lots-bucket.test
DNS.8=mqtt-broker.test
DNS.9=dyndns-relay.test
DNS.10=doh-relay.test
DNS.11=benign-api.test
DNS.12=benign-chat.test
DNS.13=benign-market.test
DNS.14=benign-update.test
DNS.15=benign-devtunnel.test
DNS.16=synthetic-api.test
DNS.17=echo.test
CNF
openssl req -x509 -newkey rsa:2048 -nodes -days 2 -keyout "$CERTDIR/server.key" -out "$CERTDIR/server.crt" -config "$CERTDIR/openssl.cnf" >/dev/null 2>&1

run_in_c2() {
  sudo ip netns exec cc-c2 runuser -u "$USER" -- env PYTHONPATH="$ROOT/src" NO_PROXY='.test,10.20.0.0/24,localhost,127.0.0.1' no_proxy='.test,10.20.0.0/24,localhost,127.0.0.1' "$@"
}
run_in_c2 "$PYTHON_BIN" -m hypercorn coverlab.server:app --bind 10.20.0.20:8080 --workers 1 >"$LOGDIR/http.log" 2>&1 &
echo $! > "$LOGDIR/http.pid"
run_in_c2 "$PYTHON_BIN" -m hypercorn coverlab.server:app --bind 10.20.0.20:8443 --certfile "$CERTDIR/server.crt" --keyfile "$CERTDIR/server.key" --workers 1 >"$LOGDIR/https.log" 2>&1 &
echo $! > "$LOGDIR/https.pid"

for _ in $(seq 1 60); do
  if sudo ip netns exec cc-dev curl --noproxy '*' -fsS http://cover-api.test:8080/healthz >/dev/null 2>&1; then
    echo "coverlab services ready"; exit 0
  fi
  sleep .2
done
cat "$LOGDIR/http.log" "$LOGDIR/https.log" >&2 || true
exit 1
