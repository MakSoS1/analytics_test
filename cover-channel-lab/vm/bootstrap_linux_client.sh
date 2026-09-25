#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
STATE_DIR="${COVERLAB_VM_CLIENT_STATE:-/tmp/coverlab-vm-client}"
VENV="$STATE_DIR/venv"
mkdir -p "$STATE_DIR" /tmp/coverlab-java-client

for cmd in python3 go node javac java cargo curl sudo; do
  command -v "$cmd" >/dev/null || { echo "missing Linux VM client dependency: $cmd" >&2; exit 1; }
done
sudo -n true

if [[ ! -x "$VENV/bin/python" ]]; then
  python3 -m venv "$VENV"
fi
"$VENV/bin/python" -m pip install --upgrade pip
"$VENV/bin/python" -m pip install -r "$ROOT/requirements.txt"

go build -o /tmp/coverlab-go-client "$ROOT/clients/go_client.go"
javac -d /tmp/coverlab-java-client "$ROOT/clients/CoverlabJavaClient.java"
(
  cd "$ROOT/clients/rust_client"
  cargo build --release
)
cp "$ROOT/clients/rust_client/target/release/coverlab-rust-client" /tmp/coverlab-rust-client
chmod 755 /tmp/coverlab-go-client /tmp/coverlab-rust-client

chrome=""
for c in google-chrome google-chrome-stable chromium chromium-browser; do
  if command -v "$c" >/dev/null 2>&1; then chrome="$(command -v "$c")"; break; fi
done
[[ -n "$chrome" ]] || { echo "Chrome/Chromium is required on the main Linux VM client" >&2; exit 1; }

# Validate that the same interpreter used by the normal agent also works via
# passwordless sudo for the bounded raw-header family.
sudo -n env PYTHONPATH="$ROOT/src" "$VENV/bin/python" - <<'PY'
import scapy.all
import coverlab.stage_m_raw
print("raw-header runtime ok")
PY

cat > "$STATE_DIR/runtime.env" <<EOF
COVERLAB_VM_PYTHON=$VENV/bin/python
COVERLAB_GO_CLIENT=/tmp/coverlab-go-client
COVERLAB_JAVA_CLIENT_DIR=/tmp/coverlab-java-client
COVERLAB_RUST_CLIENT=/tmp/coverlab-rust-client
COVERLAB_NODE_CLIENT=$ROOT/clients/node_client.mjs
COVERLAB_CHROME=$chrome
EOF
chmod 644 "$STATE_DIR/runtime.env"
echo "coverlab Linux VM client runtime ready"
