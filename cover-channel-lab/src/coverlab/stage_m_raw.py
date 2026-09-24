from __future__ import annotations

"""Bounded raw-packet Stage M fixture for header-level storage channels.

This helper requires CAP_NET_RAW/root and is intentionally restricted to the
isolated CoverLab server at 10.20.0.20. It cannot select arbitrary targets,
ports, commands, or forwarding behavior.
"""

import argparse
import json
import math
import random
import time
from datetime import datetime, timezone

from scapy.all import ICMP, IP, Raw, TCP, UDP, send

DST = "10.20.0.20"
UDP_SINK = 9091
TCP_SINK = 8080
MODES = ("ipv4_id_udp", "udp_source_port", "icmp_id_seq", "tcp_initial_seq", "tcp_timestamp")


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")


def sleep_between(interval: float, jitter: float, scale: float, cap: str, r: random.Random, i: int, n: int) -> None:
    if i + 1 >= n:
        return
    requested = max(0.0, interval * (1.0 + r.uniform(-jitter, jitter)))
    actual = requested * scale
    if cap:
        actual = min(actual, float(cap))
    if actual > 0:
        time.sleep(actual)


def packet(mode: str, source: str, i: int, r: random.Random):
    symbol16 = r.randrange(0, 65536)
    symbol32 = r.randrange(0, 2**32)
    payload = (f"STAGE_M_RAW_{i:04d}").encode()
    if mode == "ipv4_id_udp":
        pkt = IP(src=source, dst=DST, id=symbol16) / UDP(
            sport=40000 + (i % 20000), dport=UDP_SINK
        ) / Raw(payload)
        carrier_value = symbol16
    elif mode == "udp_source_port":
        sport = 32768 + (symbol16 % 28232)
        pkt = IP(src=source, dst=DST, id=r.randrange(0, 65536)) / UDP(
            sport=sport, dport=UDP_SINK
        ) / Raw(payload)
        carrier_value = sport
    elif mode == "icmp_id_seq":
        ident = symbol16
        seq = i & 0xFFFF
        pkt = IP(src=source, dst=DST, id=r.randrange(0, 65536)) / ICMP(
            type=8, id=ident, seq=seq
        ) / Raw(payload)
        carrier_value = (ident << 16) | seq
    elif mode == "tcp_initial_seq":
        sport = 40000 + (i % 20000)
        pkt = IP(src=source, dst=DST, id=r.randrange(0, 65536)) / TCP(
            sport=sport, dport=TCP_SINK, flags="S", seq=symbol32,
            options=[("MSS", 1460), ("SAckOK", b""), ("WScale", 7)],
        )
        carrier_value = symbol32
    elif mode == "tcp_timestamp":
        sport = 40000 + (i % 20000)
        tsval = symbol32
        pkt = IP(src=source, dst=DST, id=r.randrange(0, 65536)) / TCP(
            sport=sport, dport=TCP_SINK, flags="S", seq=r.randrange(0, 2**32),
            options=[("MSS", 1460), ("SAckOK", b""), ("Timestamp", (tsval, 0)), ("WScale", 7)],
        )
        carrier_value = tsval
    else:
        raise ValueError(mode)
    return pkt, carrier_value


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--mode", choices=MODES, required=True)
    ap.add_argument("--source-ip", required=True)
    ap.add_argument("--events", type=int, required=True)
    ap.add_argument("--seed", type=int, required=True)
    ap.add_argument("--interval", type=float, required=True)
    ap.add_argument("--jitter", type=float, required=True)
    ap.add_argument("--time-scale", type=float, required=True)
    ap.add_argument("--max-sleep", default="0.05")
    a = ap.parse_args()
    if not a.source_ip.startswith("10.20.0."):
        raise SystemExit("raw Stage M source must be inside 10.20.0.0/24")
    if not 1 <= a.events <= 120:
        raise SystemExit("events must be 1..120")
    if not 0 <= a.jitter <= 0.5 or not 0 <= a.time_scale <= 1:
        raise SystemExit("invalid timing bounds")
    if a.max_sleep and float(a.max_sleep) < 0:
        raise SystemExit("max sleep must be empty or non-negative")

    r = random.Random(a.seed)
    for i in range(a.events):
        pkt, value = packet(a.mode, a.source_ip, i, r)
        started = now_iso()
        send(pkt, verbose=False)
        row = {
            "event_id": f"e{i:03d}",
            "event_type": "stage_m_raw_header",
            "sent_at": started,
            "completed_at": now_iso(),
            "raw_mode": a.mode,
            "carrier_value": int(value),
            "encoded_length": len(bytes(pkt)),
            "destination_ip": DST,
        }
        print(json.dumps(row, separators=(",", ":")), flush=True)
        sleep_between(a.interval, a.jitter, a.time_scale, a.max_sleep, r, i, a.events)


if __name__ == "__main__":
    main()
