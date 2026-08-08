#!/usr/bin/env bash
set -euo pipefail
if [[ $# -ne 3 ]]; then echo "usage: $0 PCAP STAGE_DIR PARSER_DIR" >&2; exit 2; fi
PCAP="$(realpath "$1")" STAGE_DIR="$(realpath "$2")" OUT="$(realpath -m "$3")"
mkdir -p "$OUT/suricata" "$OUT/zeek"

# Suricata from the Ubuntu package keeps its production config root-readable on
# the hosted runner. Run only the offline parser as root, then immediately hand
# the resulting files back to the unprivileged runner user.
suricata --build-info > "$OUT/suricata/version.txt" 2>&1 || suricata -V > "$OUT/suricata/version.txt" 2>&1
set +e
sudo suricata -r "$PCAP" -c /etc/suricata/suricata.yaml -l "$OUT/suricata" --runmode=single > "$OUT/suricata/run.log" 2>&1
SURI_RC=$?
set -e
echo "$SURI_RC" | sudo tee "$OUT/suricata/exit_code.txt" >/dev/null
sudo chown -R "$(id -u):$(id -g)" "$OUT/suricata"

# Zeek 8.2.1 is pinned for parser reproducibility. The official image installs
# binaries under /opt/zeek/bin; do not depend on the image shell PATH.
set +e
docker run --rm -v "$PCAP:/data/input.pcap:ro" -v "$OUT/zeek:/out" -w /out zeek/zeek:8.2.1 \
  sh -lc '/opt/zeek/bin/zeek --version > version.txt 2>&1; /opt/zeek/bin/zeek -C -r /data/input.pcap LogAscii::use_json=T > run.stdout 2>run.stderr'
ZEEK_RC=$?
set -e
echo "$ZEEK_RC" > "$OUT/zeek/exit_code.txt"
sudo chmod -R a+rX "$OUT/zeek" 2>/dev/null || true

mkdir -p "$STAGE_DIR/parser"
cp -a "$OUT/suricata" "$STAGE_DIR/parser/"
cp -a "$OUT/zeek" "$STAGE_DIR/parser/"

# A parser failure must fail the shard. The dataset plan explicitly requires
# parser-observable PCAPs rather than silently accepting capture-only output.
FAIL=0
if [[ "$SURI_RC" -ne 0 ]]; then
  echo "Suricata offline parser failed with rc=$SURI_RC" >&2
  FAIL=1
fi
if [[ "$ZEEK_RC" -ne 0 ]]; then
  echo "Zeek offline parser failed with rc=$ZEEK_RC" >&2
  FAIL=1
fi
if [[ ! -s "$OUT/suricata/eve.json" ]]; then
  echo "Suricata did not produce a non-empty eve.json" >&2
  FAIL=1
fi
if [[ ! -s "$OUT/zeek/conn.log" ]]; then
  echo "Zeek did not produce a non-empty conn.log" >&2
  FAIL=1
fi
if [[ "$FAIL" -ne 0 ]]; then
  echo "--- Suricata parser log ---" >&2
  tail -100 "$OUT/suricata/run.log" >&2 || true
  echo "--- Zeek parser stderr ---" >&2
  tail -100 "$OUT/zeek/run.stderr" >&2 || true
  exit 1
fi

printf 'suricata_rc=%s zeek_rc=%s eve_bytes=%s conn_bytes=%s\n' \
  "$SURI_RC" "$ZEEK_RC" "$(stat -c%s "$OUT/suricata/eve.json")" "$(stat -c%s "$OUT/zeek/conn.log")"
