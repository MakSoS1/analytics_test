#!/usr/bin/env bash
set -euo pipefail

if [[ $# -lt 3 || $# -gt 4 ]]; then
  echo "usage: $0 URL ECH_CONFIG {h2|h3|https} [DOH_URL]" >&2
  echo "ECH_CONFIG: false|grease|true|hard|ecl:<base64>|pn:<name>" >&2
  exit 2
fi

URL="$1"
ECH_CONFIG="$2"
PROTOCOL="$3"
DOH_URL="${4:-}"

[[ "${COVERLAB_ISOLATED_LAB:-0}" == "1" ]] || {
  echo "refusing ECH request unless COVERLAB_ISOLATED_LAB=1" >&2
  exit 2
}

case "$ECH_CONFIG" in
  false|grease|true|hard|ecl:*|pn:*) ;;
  *) echo "invalid ECH config: $ECH_CONFIG" >&2; exit 2 ;;
esac
case "$PROTOCOL" in
  h2|h3|https) ;;
  *) echo "protocol must be h2, h3 or https" >&2; exit 2 ;;
esac

command -v curl >/dev/null
command -v python >/dev/null
curl --help all 2>/dev/null | grep -q -- '--ech' || {
  echo "this curl build has no --ech support" >&2
  exit 1
}
if [[ "$PROTOCOL" == "h3" ]]; then
  curl --help all 2>/dev/null | grep -q -- '--http3-only' || {
    echo "this curl build has no HTTP/3 support" >&2
    exit 1
  }
fi

# The wrapper executes this script inside a netns with no default route. This
# additional check ensures the requested URL itself resolves only to lab/local
# addresses.
python - "$URL" <<'PY'
import ipaddress
import socket
import sys
from urllib.parse import urlparse

u=urlparse(sys.argv[1])
if u.scheme != "https" or not u.hostname:
    raise SystemExit("URL must be an https URL with a hostname")
infos=socket.getaddrinfo(u.hostname, u.port or 443, type=socket.SOCK_STREAM)
ips={ipaddress.ip_address(item[4][0]) for item in infos}
if not ips:
    raise SystemExit("target did not resolve")
bad=[str(ip) for ip in ips if not (ip.is_private or ip.is_loopback)]
if bad:
    raise SystemExit("ECH target resolved outside isolated/private lab: "+",".join(bad))
print("ECH lab target:", ",".join(sorted(map(str,ips))))
PY

args=(--fail-with-body --silent --show-error --tlsv1.3 --ech "$ECH_CONFIG" --output /dev/null)
case "$PROTOCOL" in
  h2) args+=(--http2) ;;
  h3) args+=(--http3-only) ;;
  https) ;;
esac
if [[ -n "$DOH_URL" ]]; then
  args+=(--doh-url "$DOH_URL")
fi

curl "${args[@]}" "$URL"
