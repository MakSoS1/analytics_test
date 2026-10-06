#!/usr/bin/env bash
set -euo pipefail

if [[ $# -lt 3 || $# -gt 4 ]]; then
  echo "usage: $0 BACKGROUND_PCAP COVER_PCAP OUTPUT_PCAP [OFFSET_SECONDS]" >&2
  exit 2
fi

BACKGROUND="$1"
COVER="$2"
OUTPUT="$3"
OFFSET="${4:-60}"

for cmd in tshark editcap mergecap sha256sum capinfos python; do
  command -v "$cmd" >/dev/null || { echo "missing dependency: $cmd" >&2; exit 1; }
done
[[ -s "$BACKGROUND" ]] || { echo "background PCAP missing/empty" >&2; exit 1; }
[[ -s "$COVER" ]] || { echo "cover PCAP missing/empty" >&2; exit 1; }

bg_first="$(tshark -r "$BACKGROUND" -c 1 -T fields -e frame.time_epoch 2>/dev/null | head -n1)"
cc_first="$(tshark -r "$COVER" -c 1 -T fields -e frame.time_epoch 2>/dev/null | head -n1)"
[[ -n "$bg_first" && -n "$cc_first" ]] || { echo "cannot read packet timestamps" >&2; exit 1; }

delta="$(python - "$bg_first" "$cc_first" "$OFFSET" <<'PY'
import sys
bg,cc,offset=map(float,sys.argv[1:])
print(f"{bg + offset - cc:.9f}")
PY
)"

tmp="$(mktemp --suffix=.pcap)"
trap 'rm -f "$tmp"' EXIT
editcap -t "$delta" "$COVER" "$tmp"
mergecap -w "$OUTPUT" "$BACKGROUND" "$tmp"

bg_packets="$(capinfos -c "$BACKGROUND" | awk -F: '/Number of packets/{gsub(/ /,"",$2); print $2; exit}')"
cc_packets="$(capinfos -c "$COVER" | awk -F: '/Number of packets/{gsub(/ /,"",$2); print $2; exit}')"
out_packets="$(capinfos -c "$OUTPUT" | awk -F: '/Number of packets/{gsub(/ /,"",$2); print $2; exit}')"
sha="$(sha256sum "$OUTPUT" | awk '{print $1}')"

python - "$BACKGROUND" "$COVER" "$OUTPUT" "$OFFSET" "$delta" "$bg_packets" "$cc_packets" "$out_packets" "$sha" <<'PY'
import json,sys
bg,cc,out,offset,delta,bgp,ccp,outp,sha=sys.argv[1:]
bgp=int(bgp or 0); ccp=int(ccp or 0); outp=int(outp or 0)
print(json.dumps({
  "background_pcap":bg,
  "cover_pcap":cc,
  "output_pcap":out,
  "offset_seconds":float(offset),
  "applied_timestamp_shift_seconds":float(delta),
  "background_packets":bgp,
  "cover_packets":ccp,
  "output_packets":outp,
  "cover_packet_fraction":ccp/max(1,bgp+ccp),
  "output_sha256":sha,
  "composition":"offline_timestamp_preserving_merge",
},indent=2,sort_keys=True))
PY
