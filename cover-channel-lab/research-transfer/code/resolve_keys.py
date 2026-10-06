#!/usr/bin/env python3
"""Turn the hashed keys in a finding back into addresses. Runs ON THE SENSOR.

Everything that leaves the sensor is hashed, which is the point -- and the cost
is that a row saying "this host moved 300 MB to that peer" names nobody. The
dictionary built while the pcaps were read is the only way back, and once those
pcaps are deleted there is no second chance to build it.

So it is built during capture, kept here, and queried here. Keys go in, a few
addresses come out; the dictionary itself never travels.

Two layers of hashing have to be undone, and they use different salts:

    address --blake2s(sensor salt)--> packet key --hmac(session salt)--> host_key

The packet rows carry the middle value, the session table carries the last one.
Both salts are needed, so the session salt has to be here too -- which is why
`office_autopilot.sh` copies it over at 0600 rather than moving the addresses
the other way.

    ./resolve_keys.py --names-dir /var/tmp/office-month/names \\
        --session-salt ~/.office_iter_salt --keys a1b2c3d4e5f60718 ...
"""
from __future__ import annotations

import argparse
import hashlib
import hmac
import json
import sys
from pathlib import Path


def load_dictionary(names_dir: Path) -> tuple[dict, dict]:
    """Fold every minute's dictionary into one. Later minutes do not overwrite:
    a key always came from the same address, so a disagreement is a bug worth
    seeing rather than a value worth picking."""
    addresses: dict[str, str] = {}
    sni: dict[str, str] = {}
    conflicts: list[dict] = []
    for path in sorted(names_dir.glob("*.keys.json")):
        data = json.loads(path.read_text())
        for key, value in (data.get("addresses") or {}).items():
            if key in addresses and addresses[key] != value:
                conflicts.append({"key": key, "was": addresses[key], "now": value})
            addresses.setdefault(key, value)
        for key, value in (data.get("sni") or {}).items():
            sni.setdefault(key, value)
    if conflicts:
        print(json.dumps({"warning": "один ключ у разных адресов",
                          "conflicts": conflicts[:5]}, ensure_ascii=False),
              file=sys.stderr)
    return addresses, sni


def session_key(session_salt: bytes, packet_key_hex: str) -> str:
    """`extract_office_sessions._hkey` applied to a packet key, as the session
    table writes it."""
    return hmac.new(session_salt, packet_key_hex.encode(),
                    hashlib.sha256).hexdigest()[:16]


def build_reverse(addresses: dict, session_salt: bytes | None) -> dict:
    out = {key: addr for key, addr in addresses.items()}
    if session_salt:
        for key, addr in addresses.items():
            out[session_key(session_salt, key)] = addr
    return out


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--names-dir", type=Path, required=True)
    ap.add_argument("--session-salt", type=Path,
                    help="соль, которой считались host_key/server_key")
    ap.add_argument("--keys", nargs="*", default=[],
                    help="host_key / server_key / service_key; иначе читаю stdin")
    ap.add_argument("--stats", action="store_true", help="только размер словаря")
    args = ap.parse_args()

    addresses, sni = load_dictionary(args.names_dir)
    salt = args.session_salt.read_bytes().strip() if args.session_salt else None
    reverse = build_reverse(addresses, salt)

    if args.stats:
        print(json.dumps({"minute_files": len(list(args.names_dir.glob("*.keys.json"))),
                          "addresses": len(addresses), "server_names": len(sni),
                          "resolvable_keys": len(reverse),
                          "session_salt": bool(salt)}, ensure_ascii=False))
        return 0

    keys = args.keys or [line.strip() for line in sys.stdin if line.strip()]
    found = 0
    for key in keys:
        value = reverse.get(key) or sni.get(key)
        if value:
            found += 1
        print(json.dumps({"key": key, "value": value or None,
                          "kind": ("адрес" if key in reverse
                                   else "имя сервера" if key in sni else None)},
                         ensure_ascii=False))
    print(json.dumps({"asked": len(keys), "resolved": found}, ensure_ascii=False),
          file=sys.stderr)
    return 0 if found else 1


if __name__ == "__main__":
    raise SystemExit(main())
