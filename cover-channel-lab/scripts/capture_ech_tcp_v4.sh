#!/usr/bin/env bash
set -euo pipefail

if [[ $# -lt 3 || $# -gt 5 ]]; then
  echo "usage: $0 URL ECH_CONFIG OUTPUT_PCAP [DOH_URL] [INTERFACE]" >&2
  echo "ECH_CONFIG: false|grease|true|hard|ecl:<base64>|pn:<name>" >&2
  exit 2
fi

URL="$1"
ECH_CONFIG="$2"
OUT="$3"
DOH_URL="${4:-}"
IFACE="${5:-any}"

for cmd in curl tcpdump python sha256sum; do
  command -v "$cmd" >/dev/null || { echo "missing dependency: $cmd" >&2; exit 1; }
done
curl --help all 2>/dev/null | grep -q -- '--ech' || {
  echo "this curl build has no --ech support" >&2
  exit 1
}

case "$ECH_CONFIG" in
  false|grease|true|hard|ecl:*|pn:*) ;;
  *) echo "invalid ECH config: $ECH_CONFIG" >&2; exit 2 ;;
esac

mkdir -p "$(dirname "$OUT")"
rm -f "$OUT"
log="${OUT}.curl.log"

sudo tcpdump -i "$IFACE" -B 8192 -s 0 -U -w "$OUT" 'tcp port 443' >/dev/null 2>&1 &
pid=$!
cleanup() {
  sudo kill -INT "$pid" 2>/dev/null || true
  wait "$pid" 2>/dev/null || true
}
trap cleanup EXIT
sleep .4

args=(--fail-with-body --silent --show-error --tlsv1.3 --http2 --ech "$ECH_CONFIG" --output /dev/null)
if [[ -n "$DOH_URL" ]]; then
  args+=(--doh-url "$DOH_URL")
fi
set +e
curl "${args[@]}" "$URL" >"$log" 2>&1
rc=$?
set -e
sleep .5
cleanup
trap - EXIT

[[ -s "$OUT" ]] || { echo "ECH capture is empty" >&2; exit 1; }
sha="$(sha256sum "$OUT" | awk '{print $1}')"
python - "$URL" "$ECH_CONFIG" "$DOH_URL" "$IFACE" "$OUT" "$sha" "$rc" <<'PY'
import json,sys
url,ech,doh,iface,out,sha,rc=sys.argv[1:]
print(json.dumps({
  "url":url,
  "ech_config":ech,
  "doh_url":doh or None,
  "interface":iface,
  "pcap":out,
  "pcap_sha256":sha,
  "curl_rc":int(rc),
  "wire_real":True,
  "transport":"tcp",
  "http_version_target":"h2",
},indent=2,sort_keys=True))
PY
exit "$rc"
