#!/usr/bin/env python3
"""The key dictionary as one table: every hashed key the tables carry -> its address or name.

Runs ON THE SENSOR, where the per-interval dictionaries are written while the
pcaps are read (`names/*.keys.json`). Moving it off the sensor is the owner's
decision (2026-09-30): Cosmolake is an internal tool only he can open, and
without it the tables are only numbers.

One CSV row per key, in the form the tables use it:

  kind          address | sni
  key           host_key / server_key (addresses) or service_key (server names)
  packet_key    the first-layer key of an address, as the packet rows carry it
  value         IP address or server name (SNI)
  is_private    1 for RFC 1918 / loopback / link-local / ULA addresses
  first_file    first capture interval (file stamp) the key was seen in
  last_file     last one
  files         in how many interval dictionaries it appears

An address key is `hmac(session salt, packet key)`, exactly what
extract_office_sessions.py writes; a server-name key is the sidecar's own key,
used as is. Two addresses behind one key would be a bug and stop the export.

  export_key_map.py --names-dir /var/tmp/office-month/names \\
      --session-salt /var/tmp/office-month/session_salt --out key_map.csv
"""
from __future__ import annotations

import argparse
import csv
import hashlib
import hmac
import ipaddress
import json
import re
import sys
from pathlib import Path

_INTERNAL = [ipaddress.ip_network(n) for n in (
    "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "127.0.0.0/8", "169.254.0.0/16",
    "::1/128", "fc00::/7", "fe80::/10")]
STAMP = re.compile(r"(\d{8}T\d{6}Z)")


def private(ip: str) -> int:
    try:
        a = ipaddress.ip_address(ip)
    except ValueError:
        return 0
    return int(any(a.version == n.version and a in n for n in _INTERNAL))


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--names-dir", type=Path, required=True)
    ap.add_argument("--session-salt", type=Path, required=True)
    ap.add_argument("--out", type=Path, required=True)
    a = ap.parse_args()
    salt = a.session_salt.read_bytes().strip()

    addr: dict[str, list] = {}      # packet key -> [ip, first, last, files]
    sni: dict[str, list] = {}       # service key -> [name, first, last, files]
    conflicts = 0
    files = sorted(a.names_dir.glob("*.keys.json"))
    for path in files:
        m = STAMP.search(path.name)
        stamp = m.group(1) if m else path.name
        data = json.loads(path.read_text())
        for table, src in ((addr, data.get("addresses") or {}), (sni, data.get("sni") or {})):
            for k, v in src.items():
                e = table.get(k)
                if e is None:
                    table[k] = [v, stamp, stamp, 1]
                    continue
                if e[0] != v:
                    conflicts += 1
                e[2] = stamp
                e[3] += 1
    if conflicts:
        print(json.dumps({"error": "один ключ у разных значений", "conflicts": conflicts}), file=sys.stderr)
        return 1

    tmp = a.out.with_suffix(".tmp")
    with tmp.open("w", newline="") as fh:
        w = csv.writer(fh)
        w.writerow(["kind", "key", "packet_key", "value", "is_private", "first_file", "last_file", "files"])
        for pk, (ip, f0, f1, n) in addr.items():
            key = hmac.new(salt, pk.encode(), hashlib.sha256).hexdigest()[:16]
            w.writerow(["address", key, pk, ip, private(ip), f0, f1, n])
        for sk, (name, f0, f1, n) in sni.items():
            w.writerow(["sni", sk, "", name, 0, f0, f1, n])
    tmp.replace(a.out)
    a.out.chmod(0o600)
    print(json.dumps({"interval_files": len(files), "addresses": len(addr), "server_names": len(sni),
                      "private_addresses": sum(private(v[0]) for v in addr.values()),
                      "first_file": files[0].name if files else None, "last_file": files[-1].name if files else None}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
