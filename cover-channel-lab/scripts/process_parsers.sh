#!/usr/bin/env bash
set -euo pipefail
if [[ $# -ne 3 ]]; then echo "usage: $0 PCAP STAGE_DIR PARSER_DIR" >&2; exit 2; fi
PCAP="$(realpath "$1")" STAGE_DIR="$(realpath "$2")" OUT="$(realpath -m "$3")"
mkdir -p "$OUT/suricata" "$OUT/zeek"

suricata --build-info > "$OUT/suricata/version.txt" 2>&1 || suricata -V > "$OUT/suricata/version.txt" 2>&1
set +e
suricata -r "$PCAP" -c /etc/suricata/suricata.yaml -l "$OUT/suricata" --runmode=single > "$OUT/suricata/run.log" 2>&1
SURI_RC=$?
set -e
echo "$SURI_RC" > "$OUT/suricata/exit_code.txt"

# Zeek 8.2.1 is pinned to retain parser reproducibility and JA4+ support from this release line.
docker run --rm -v "$PCAP:/data/input.pcap:ro" -v "$OUT/zeek:/out" -w /out zeek/zeek:8.2.1 \
  sh -lc 'zeek --version > version.txt 2>&1; zeek -C -r /data/input.pcap LogAscii::use_json=T > run.stdout 2>run.stderr' || true
sudo chmod -R a+rX "$OUT/zeek" 2>/dev/null || true

mkdir -p "$STAGE_DIR/parser"
cp -a "$OUT/suricata" "$STAGE_DIR/parser/"
cp -a "$OUT/zeek" "$STAGE_DIR/parser/"
