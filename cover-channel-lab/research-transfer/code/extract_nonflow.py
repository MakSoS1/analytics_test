#!/usr/bin/env python3
"""Everything that is not a TCP or UDP session, so the accounting closes at 100%.

The session tables cover 99.70% of captured packets.  The remainder is real
traffic that the flow model simply has no shape for: ARP, ICMP, ICMPv6, and any
other IP protocol or Ethertype on the wire.  Measured on one minute of the
office mirror: ARP 2648, ICMP 487, L2 control 1, other 18.

ICMP is the reason this is not a formality.  ICMP tunnelling hides payload in
echo requests, and an echo whose data field is neither the usual 56 bytes nor
low-entropy padding is exactly what covert-channel work looks for -- so the
payload shape is measured here, not just the packet count.

Grouping is by (src, dst, protocol, discriminator) with an idle timeout, so a
long ping stays one row instead of becoming thousands.  The discriminator is the
ICMP echo identifier where there is one, which keeps two concurrent pings
between the same pair apart.

Addresses are salted-hashed exactly as in the session tables, so a row here can
be joined to a session row by host_key without either carrying an address.
"""
from __future__ import annotations

import argparse
import csv
import hashlib
import hmac
import ipaddress
import json
import math
import os
import struct
import time
from collections import Counter
from pathlib import Path

IDLE = 300.0
PAY_PKTS, PAY_BYTES = 16, 128

_PCAP_MAGICS = {
    0xA1B2C3D4: ("<", 1_000_000), 0xD4C3B2A1: (">", 1_000_000),
    0xA1B23C4D: ("<", 1_000_000_000), 0x4D3CB2A1: (">", 1_000_000_000),
}
IP_PROTO_NAMES = {
    1: "icmp", 2: "igmp", 41: "ipv6_encap", 47: "gre", 50: "esp", 51: "ah",
    58: "icmpv6", 88: "eigrp", 89: "ospf", 103: "pim", 112: "vrrp", 132: "sctp",
}
ETH_NAMES = {0x0806: "arp", 0x8035: "rarp", 0x88cc: "lldp", 0x88a8: "qinq",
             0x8892: "profinet", 0x8847: "mpls", 0x86dd: "ipv6", 0x0800: "ipv4"}


def _entropy(buf: bytes) -> float:
    if not buf:
        return 0.0
    c = Counter(buf)
    n = len(buf)
    return -sum((v / n) * math.log2(v / n) for v in c.values())


def _pct(vals, q):
    if not vals:
        return 0.0
    s = sorted(vals)
    if len(s) == 1:
        return float(s[0])
    pos = (len(s) - 1) * q / 100.0
    lo = int(math.floor(pos)); hi = min(lo + 1, len(s) - 1)
    return float(s[lo] * (1 - (pos - lo)) + s[hi] * (pos - lo))


class Agg:
    __slots__ = ("packets", "bytes", "first", "last", "prev", "iats", "paylen",
                 "pay", "pay_n", "types", "fwd", "rev", "a")

    def __init__(self, a):
        self.packets = self.bytes = 0
        self.first = self.last = self.prev = None
        self.iats: list[float] = []
        self.paylen: list[int] = []
        self.pay = bytearray()
        self.pay_n = 0
        self.types: Counter = Counter()
        self.fwd = self.rev = 0
        self.a = a


def iter_frames(path: Path):
    with path.open("rb") as fh:
        head = fh.read(24)
        if len(head) < 24:
            return
        magic = struct.unpack("<I", head[:4])[0]
        if magic not in _PCAP_MAGICS:
            magic = struct.unpack(">I", head[:4])[0]
        if magic not in _PCAP_MAGICS:
            raise ValueError(f"{path}: not a pcap")
        endian, tick = _PCAP_MAGICS[magic]
        if struct.unpack(endian + "I", head[20:24])[0] != 1:
            raise ValueError(f"{path}: only Ethernet is handled")
        rec = struct.Struct(endian + "IIII").unpack_from
        read = fh.read
        buf, pos = b"", 0
        while True:
            if len(buf) - pos < 16:
                buf, pos = buf[pos:] + read(8 << 20), 0
                if len(buf) < 16:
                    return
            ts_s, ts_f, caplen, origlen = rec(buf, pos)
            pos += 16
            if len(buf) - pos < caplen:
                buf, pos = buf[pos:] + read(max(8 << 20, caplen)), 0
                if len(buf) < caplen:
                    return
            frame = buf[pos:pos + caplen]
            pos += caplen
            yield ts_s + ts_f / tick, frame, origlen


def classify(frame: bytes):
    """(proto_name, src, dst, discriminator, type_code, payload) or None for TCP/UDP."""
    u16 = struct.Struct("!H").unpack_from
    if len(frame) < 14:
        return ("runt", "", "", 0, "", b"")
    off = 12
    eth = u16(frame, off)[0]
    off += 2
    while eth in (0x8100, 0x88A8) and len(frame) >= off + 4:
        eth = u16(frame, off + 2)[0]
        off += 4
    if eth == 0x0806:
        if len(frame) >= off + 28:
            spa = ".".join(str(x) for x in frame[off + 14:off + 18])
            tpa = ".".join(str(x) for x in frame[off + 24:off + 28])
            op = u16(frame, off + 6)[0]
            return ("arp", spa, tpa, 0, f"op{op}", b"")
        return ("arp", "", "", 0, "", b"")
    if eth == 0x0800:
        if len(frame) < off + 20:
            return ("ipv4_runt", "", "", 0, "", b"")
        ihl = (frame[off] & 0x0F) * 4
        pnum = frame[off + 9]
        src = ".".join(str(x) for x in frame[off + 12:off + 16])
        dst = ".".join(str(x) for x in frame[off + 16:off + 20])
        l4 = off + ihl
        iplen = u16(frame, off + 2)[0]
        end = min(off + iplen, len(frame))
        if pnum in (6, 17):
            # Noninitial fragments have no TCP/UDP header. The session parser
            # cannot assign them to a 4-tuple, so account for them explicitly.
            if u16(frame, off + 6)[0] & 0x1FFF:
                name = "ipv4_tcp_fragment" if pnum == 6 else "ipv4_udp_fragment"
                return (name, src, dst, u16(frame, off + 4)[0], "", frame[l4:end])
            return None
        name = IP_PROTO_NAMES.get(pnum, f"ip_proto_{pnum}")
        if pnum == 1 and len(frame) >= l4 + 8:
            t, c = frame[l4], frame[l4 + 1]
            ident = u16(frame, l4 + 4)[0] if t in (0, 8) else 0
            return (name, src, dst, ident, f"{t}/{c}", frame[l4 + 8:end])
        return (name, src, dst, 0, "", frame[l4:end])
    if eth == 0x86DD:
        if len(frame) < off + 40:
            return ("ipv6_runt", "", "", 0, "", b"")
        pnum = frame[off + 6]
        if pnum in (6, 17):
            return None
        src = str(ipaddress.ip_address(frame[off + 8:off + 24]))
        dst = str(ipaddress.ip_address(frame[off + 24:off + 40]))
        l4 = off + 40
        end = min(l4 + u16(frame, off + 4)[0], len(frame))
        name = IP_PROTO_NAMES.get(pnum, f"ip_proto_{pnum}")
        if pnum == 58 and len(frame) >= l4 + 8:
            t, c = frame[l4], frame[l4 + 1]
            ident = u16(frame, l4 + 4)[0] if t in (128, 129) else 0
            return (name, src, dst, ident, f"{t}/{c}", frame[l4 + 8:end])
        return (name, src, dst, 0, "", frame[l4:end])
    return (ETH_NAMES.get(eth, f"eth_0x{eth:04x}"), "", "", 0, "", b"")


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--pcap-dir", required=True)
    ap.add_argument("--glob", default="chunk-*.pcap")
    ap.add_argument("--out-csv", required=True)
    ap.add_argument("--stats-json", default="")
    ap.add_argument("--salt-file", default="~/.office_iter_salt")
    args = ap.parse_args()

    salt = Path(os.path.expanduser(args.salt_file)).read_bytes()
    hk = lambda v: hmac.new(salt, v.encode(), hashlib.sha256).hexdigest()[:16] if v else ""

    live: dict[tuple, Agg] = {}
    done: list[tuple] = []
    counts = Counter()
    total = tcpudp = 0
    t0 = time.time()

    def close(key, agg):
        done.append((key, agg))

    for pcap in sorted(Path(args.pcap_dir).glob(args.glob)):
        for ts, frame, origlen in iter_frames(pcap):
            total += 1
            c = classify(frame)
            if c is None:
                tcpudp += 1
                continue
            name, src, dst, ident, typecode, payload = c
            counts[name] += 1
            a, b = (src, dst)
            key = (name, a, b, ident) if a <= b else (name, b, a, ident)
            forward = (a <= b)
            agg = live.get(key)
            if agg is not None and agg.last is not None and ts - agg.last > IDLE:
                close(key, agg)
                del live[key]
                agg = None
            if agg is None:
                agg = live[key] = Agg(a)
                agg.first = ts
            agg.packets += 1
            agg.bytes += origlen
            if agg.prev is not None:
                agg.iats.append(max(ts - agg.prev, 0.0))
            agg.prev = agg.last = ts
            agg.types[typecode] += 1
            if forward:
                agg.fwd += 1
            else:
                agg.rev += 1
            if payload:
                agg.paylen.append(len(payload))
                if agg.pay_n < PAY_PKTS:
                    agg.pay += payload[:PAY_BYTES]
                    agg.pay_n += 1

    for key, agg in live.items():
        close(key, agg)

    cols = ["l3_proto", "src_key", "dst_key", "discriminator", "packets", "bytes",
            "first_ts", "duration", "pkt_rate", "fwd_packets", "rev_packets",
            "fwd_rev_ratio", "distinct_type_codes", "top_type_code",
            "iat_mean", "iat_p50", "iat_cv", "iat_regularity",
            "pay_len_mean", "pay_len_max", "pay_len_unique", "pay_entropy",
            "pay_printable_share", "time_bucket", "out_of_scope_vpn",
            "y_presumed", "label_source", "label_family"]
    out = Path(args.out_csv)
    out.parent.mkdir(parents=True, exist_ok=True)
    printable = set(range(32, 127))
    with out.open("w", newline="", encoding="utf-8") as fh:
        w = csv.DictWriter(fh, fieldnames=cols)
        w.writeheader()
        for (name, a, b, ident), agg in done:
            dur = (agg.last - agg.first) if agg.last and agg.first else 0.0
            iats = agg.iats
            mean_iat = sum(iats) / len(iats) if iats else 0.0
            std = (sum((x - mean_iat) ** 2 for x in iats) / len(iats)) ** 0.5 if iats else 0.0
            q = Counter(round(x, 3) for x in iats)
            pay = bytes(agg.pay)
            w.writerow({
                "l3_proto": name, "src_key": hk(a), "dst_key": hk(b),
                "discriminator": ident, "packets": agg.packets, "bytes": agg.bytes,
                "first_ts": round(agg.first, 6) if agg.first else 0.0,
                "duration": round(dur, 6),
                "pkt_rate": round(agg.packets / dur, 6) if dur > 0 else 0.0,
                "fwd_packets": agg.fwd, "rev_packets": agg.rev,
                "fwd_rev_ratio": round(agg.fwd / agg.rev, 6) if agg.rev else float(agg.fwd),
                "distinct_type_codes": len(agg.types),
                "top_type_code": agg.types.most_common(1)[0][0] if agg.types else "",
                "iat_mean": round(mean_iat, 6), "iat_p50": round(_pct(iats, 50), 6),
                "iat_cv": round(std / mean_iat, 6) if mean_iat > 0 else 0.0,
                "iat_regularity": round(q.most_common(1)[0][1] / len(iats), 6) if iats else 0.0,
                "pay_len_mean": round(sum(agg.paylen) / len(agg.paylen), 3) if agg.paylen else 0.0,
                "pay_len_max": max(agg.paylen) if agg.paylen else 0,
                "pay_len_unique": len(set(agg.paylen)),
                "pay_entropy": round(_entropy(pay), 6),
                "pay_printable_share": round(sum(1 for x in pay if x in printable) / len(pay), 6) if pay else 0.0,
                "time_bucket": time.strftime("%Y-%m-%dT%H", time.gmtime(agg.first or 0)),
                "out_of_scope_vpn": 1,
                "y_presumed": 0, "label_source": "office_unlabeled",
                "label_family": "office_benign",
            })

    report = {
        "status": "ok",
        "frames_total": total,
        "frames_tcp_udp_handled_by_sessions": tcpudp,
        "frames_here": total - tcpudp,
        "coverage_check": round((tcpudp + sum(counts.values())) / max(total, 1), 6),
        "rows": len(done),
        "by_protocol": dict(counts.most_common()),
        "seconds": round(time.time() - t0, 1),
        "note": "every captured frame is either a TCP/UDP session packet or one row here",
    }
    print(json.dumps(report, indent=2))
    if args.stats_json:
        Path(args.stats_json).write_text(json.dumps(report, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
