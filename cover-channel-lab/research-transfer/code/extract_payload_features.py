#!/usr/bin/env python3
"""Second pass: SNI and payload statistics, joined to sessions by exact index.

The session pass reads tcpdump text, which carries no payload.  This pass reads
the same capture files as binary and attaches what only the bytes can answer:
the TLS server name that LoTS keys its windows on, and the payload shape that
covert-channel work asks for.

It does NOT re-derive session identity.  The session pass writes a private index
of (4-tuple, time span, segment_uid, client endpoint); here every packet is
matched against that index by tuple and timestamp.  Re-running the instance logic over a slightly
different packet stream would have been a second source of truth, and the two
would drift exactly where it is hardest to notice.

Payload is read, never stored: only aggregate numbers leave this file, and the
SNI leaves as a salted hash unless the name map is explicitly requested.
"""
from __future__ import annotations

import argparse
import bisect
import csv
import hashlib
import hmac
import json
import math
import os
import struct
import sys
import time
from collections import Counter
from pathlib import Path

# Одна ячейка держит всю последовательность пакетов сессии, поэтому
# стандартный лимит поля в 128 КиБ пробивается на первой же длинной сессии.
csv.field_size_limit(1 << 24)

PAY_PKTS = 8           # packets per direction that contribute payload stats
PAY_BYTES = 256        # bytes taken from each of them
_B64 = set(b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=-_")
_PRINT = set(range(32, 127))

_PCAP_MAGICS = {
    0xA1B2C3D4: ("<", 1_000_000), 0xD4C3B2A1: (">", 1_000_000),
    0xA1B23C4D: ("<", 1_000_000_000), 0x4D3CB2A1: (">", 1_000_000_000),
}

PAY_NAMES = [
    "bytes_up_ip", "bytes_down_ip",
    "cc_pay_entropy_up", "cc_pay_entropy_down", "cc_pay_printable_up",
    "cc_pay_printable_down", "cc_pay_null_share_up", "cc_pay_b64_share_up",
    "cc_pay_bytes_sampled_up", "cc_pay_bytes_sampled_down",
    "cc_dns_qname_len_mean", "cc_dns_qname_len_max", "cc_dns_label_entropy",
    "cc_dns_query_count", "cc_tls_has_sni", "cc_tls_sni_len",
]


def _entropy_bytes(buf: bytes) -> float:
    if not buf:
        return 0.0
    counts = Counter(buf)
    n = len(buf)
    return -sum((c / n) * math.log2(c / n) for c in counts.values())


def iter_packets(path: Path):
    """(ts, src, sport, dst, dport, proto, payload) with payload as raw bytes."""
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
        u16 = struct.Struct("!H").unpack_from
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
            if len(frame) < 14:
                continue
            off = 12
            eth = u16(frame, off)[0]
            off += 2
            while eth in (0x8100, 0x88A8) and len(frame) >= off + 4:
                eth = u16(frame, off + 2)[0]
                off += 4
            if eth == 0x0800:
                if len(frame) < off + 20:
                    continue
                ihl = (frame[off] & 0x0F) * 4
                if ihl < 20 or u16(frame, off + 6)[0] & 0x1FFF:
                    continue
                pnum = frame[off + 9]
                src = ".".join(str(x) for x in frame[off + 12:off + 16])
                dst = ".".join(str(x) for x in frame[off + 16:off + 20])
                l4 = off + ihl
                iplen = u16(frame, off + 2)[0]
                ipend = off + iplen
            elif eth == 0x86DD:
                if len(frame) < off + 40:
                    continue
                pnum = frame[off + 6]
                import ipaddress as _ip
                src = str(_ip.ip_address(frame[off + 8:off + 24]))
                dst = str(_ip.ip_address(frame[off + 24:off + 40]))
                l4 = off + 40
                ipend = l4 + u16(frame, off + 4)[0]
            else:
                continue
            ipend = min(ipend, len(frame))
            if pnum == 6:
                if len(frame) < l4 + 20:
                    continue
                sport, dport = u16(frame, l4)[0], u16(frame, l4 + 2)[0]
                doff = (frame[l4 + 12] >> 4) * 4
                payload = frame[l4 + doff:ipend] if l4 + doff <= ipend else b""
                proto = "tcp"
            elif pnum == 17:
                if len(frame) < l4 + 8:
                    continue
                sport, dport = u16(frame, l4)[0], u16(frame, l4 + 2)[0]
                payload = frame[l4 + 8:ipend] if l4 + 8 <= ipend else b""
                proto = "udp"
            else:
                continue
            yield ts_s + ts_f / tick, src, sport, dst, dport, proto, payload, ipend - off


def parse_sni(payload: bytes) -> str:
    """Server name from a TLS ClientHello that fits in this record."""
    try:
        if len(payload) < 45 or payload[0] != 0x16 or payload[1] != 0x03:
            return ""
        if payload[5] != 0x01:                      # handshake type ClientHello
            return ""
        p = 43                                      # past version + random
        sid = payload[p]; p += 1 + sid
        cs = struct.unpack("!H", payload[p:p + 2])[0]; p += 2 + cs
        comp = payload[p]; p += 1 + comp
        if p + 2 > len(payload):
            return ""
        ext_total = struct.unpack("!H", payload[p:p + 2])[0]; p += 2
        end = min(p + ext_total, len(payload))
        while p + 4 <= end:
            etype, elen = struct.unpack("!HH", payload[p:p + 4]); p += 4
            if etype == 0x0000 and p + 5 <= len(payload):
                nlen = struct.unpack("!H", payload[p + 3:p + 5])[0]
                name = payload[p + 5:p + 5 + nlen]
                return name.decode("ascii", "ignore")
            p += elen
    except Exception:
        return ""
    return ""


def dns_qname(payload: bytes) -> str:
    try:
        if len(payload) < 13:
            return ""
        p, labels = 12, []
        while p < len(payload):
            ln = payload[p]
            if ln == 0 or ln > 63:
                break
            labels.append(payload[p + 1:p + 1 + ln].decode("ascii", "ignore"))
            p += 1 + ln
        return ".".join(labels)
    except Exception:
        return ""


class Acc:
    __slots__ = ("up", "down", "up_n", "down_n", "sni", "dns_names", "dns_q",
                 "client", "ip_up", "ip_down")

    def __init__(self):
        self.up, self.down = bytearray(), bytearray()
        self.up_n = self.down_n = 0
        self.sni = ""
        self.dns_names: list[str] = []
        self.dns_q = 0
        self.client = None
        # The LoTS contract counts IP bytes, header-inclusive, to match
        # Suricata's flow.bytes_to*.  The session pass counts L2 frames, so the
        # figure the contract wants is accumulated here from the IP header.
        self.ip_up = 0
        self.ip_down = 0


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--pcap-dir", required=True)
    ap.add_argument("--glob", default="chunk-*.pcap")
    ap.add_argument("--session-index", required=True)
    ap.add_argument("--out-csv", required=True)
    ap.add_argument("--sni-map", default="", help="service_key -> SNI; keep local")
    ap.add_argument("--salt-file", default="~/.office_iter_salt")
    args = ap.parse_args()

    salt = Path(os.path.expanduser(args.salt_file)).read_bytes()
    # tuple -> sorted list of (t_start, t_end, uid); matching is by time span, so
    # a reused tuple lands in the right instance without re-deriving anything.
    index: dict[tuple, list] = {}
    with open(args.session_index) as fh:
        for r in csv.DictReader(fh):
            # Protocol is deliberately NOT part of the join key.  The session
            # pass labels protocols the way tcpdump's text does, which calls DNS
            # "other" because its output has no "UDP" token, while this pass
            # reads the IP header and says "udp".  Keying on it silently lost
            # every DNS session -- exactly the traffic covert-channel work needs.
            key = (r["ip_a"], int(r["port_a"]), r["ip_b"], int(r["port_b"]))
            index.setdefault(key, []).append((
                float(r["t_start"]), float(r["t_end"]), r["segment_uid"],
                (r["client_ip"], int(r["client_port"])),
            ))
    for v in index.values():
        v.sort()
    starts = {k: [x[0] for x in v] for k, v in index.items()}

    acc: dict[str, Acc] = {}
    matched = unmatched = 0
    pcaps = sorted(Path(args.pcap_dir).glob(args.glob))
    t0 = time.time()
    for pcap in pcaps:
        for ts, src, sport, dst, dport, proto, payload, ip_bytes in iter_packets(pcap):
            a, b = (src, sport), (dst, dport)
            key = (a[0], a[1], b[0], b[1]) if a <= b else (b[0], b[1], a[0], a[1])
            spans = index.get(key)
            if not spans:
                unmatched += 1
                continue
            i = bisect.bisect_right(starts[key], ts) - 1
            if i < 0 or ts > spans[i][1]:
                unmatched += 1
                continue
            matched += 1
            uid = spans[i][2]
            ac = acc.get(uid)
            if ac is None:
                ac = acc[uid] = Acc()
                # The session pass decided which endpoint is the client; a
                # continuation segment can begin with a server packet, so
                # guessing from the first packet seen here would flip up/down.
                ac.client = spans[i][3]
            is_up = (src, sport) == ac.client
            if is_up:
                ac.ip_up += ip_bytes
            else:
                ac.ip_down += ip_bytes
            if not payload:
                continue
            if is_up and ac.up_n < PAY_PKTS:
                ac.up += payload[:PAY_BYTES]; ac.up_n += 1
            elif not is_up and ac.down_n < PAY_PKTS:
                ac.down += payload[:PAY_BYTES]; ac.down_n += 1
            if not ac.sni and proto == "tcp" and is_up:
                s = parse_sni(payload)
                if s:
                    ac.sni = s
            if proto == "udp" and (dport == 53 or sport == 53) and is_up:
                ac.dns_q += 1
                if len(ac.dns_names) < 32:
                    q = dns_qname(payload)
                    if q:
                        ac.dns_names.append(q)

    sni_map: dict[str, str] = {}
    cols = ["segment_uid", "service_key"] + PAY_NAMES
    with open(args.out_csv, "w", newline="", encoding="utf-8") as fh:
        w = csv.DictWriter(fh, fieldnames=cols)
        w.writeheader()
        for uid, ac in acc.items():
            up, down = bytes(ac.up), bytes(ac.down)
            lens = [len(x) for x in ac.dns_names]
            labels = [l for name in ac.dns_names for l in name.split(".") if l]
            skey = hmac.new(salt, (ac.sni or "").encode(), hashlib.sha256).hexdigest()[:16] if ac.sni else ""
            if ac.sni and args.sni_map:
                sni_map[skey] = ac.sni
            w.writerow({
                "segment_uid": uid,
                "service_key": skey,
                "bytes_up_ip": ac.ip_up,
                "bytes_down_ip": ac.ip_down,
                "cc_pay_entropy_up": round(_entropy_bytes(up), 6),
                "cc_pay_entropy_down": round(_entropy_bytes(down), 6),
                "cc_pay_printable_up": round(sum(1 for c in up if c in _PRINT) / len(up), 6) if up else 0.0,
                "cc_pay_printable_down": round(sum(1 for c in down if c in _PRINT) / len(down), 6) if down else 0.0,
                "cc_pay_null_share_up": round(up.count(0) / len(up), 6) if up else 0.0,
                "cc_pay_b64_share_up": round(sum(1 for c in up if c in _B64) / len(up), 6) if up else 0.0,
                "cc_pay_bytes_sampled_up": len(up),
                "cc_pay_bytes_sampled_down": len(down),
                "cc_dns_qname_len_mean": round(sum(lens) / len(lens), 3) if lens else 0.0,
                "cc_dns_qname_len_max": max(lens) if lens else 0,
                "cc_dns_label_entropy": round(_entropy_bytes("".join(labels).encode()), 6),
                "cc_dns_query_count": ac.dns_q,
                "cc_tls_has_sni": int(bool(ac.sni)),
                "cc_tls_sni_len": len(ac.sni),
            })
    if args.sni_map:
        Path(args.sni_map).write_text(json.dumps(sni_map, indent=1))
        Path(args.sni_map).chmod(0o600)
    print(json.dumps({
        "status": "ok", "pcap_files": len(pcaps), "sessions_with_payload": len(acc),
        "packets_matched": matched, "packets_unmatched": unmatched,
        "match_rate": round(matched / max(matched + unmatched, 1), 4),
        "sni_found": sum(1 for a in acc.values() if a.sni),
        "seconds": round(time.time() - t0, 1),
    }))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
