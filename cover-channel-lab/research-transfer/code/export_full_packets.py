#!/usr/bin/env python3
"""Read a full-snaplen pcap and write one packed row per packet.

The office mirror is faster than the path that can carry the pcap, so the
pcap cannot be kept. It is read on the sensor immediately after `-s 0`
tcpdump closes the minute file. A frame with caplen < origlen is a hard
error: that would be a truncated packet, and behavioural features must see
the on-wire length and the real payload length.

These rows REPLACE the pcap as the input to session assembly, which is what
makes a month possible: the text `tcpdump` path parses slower than the mirror
fills, and it needs the pcap to still be there. So a row has to carry everything
session assembly reads -- which an earlier version did not, because it hashed
the two endpoints together into one key. That key identifies a conversation and
nothing else: it cannot say which host the traffic belongs to, and it cannot say
which side is the private one. Both endpoints are therefore hashed separately,
and the two facts about them that are not recoverable from a hash -- whether the
address is private, and whether it is IPv6 -- travel in `meta`.

Each row is 35 bytes, little-endian:

    double ts
    8-byte keyed hash of the source address      (address only, not the port)
    8-byte keyed hash of the destination address
    uint16 origlen, sport, dport, payload_len
    uint8 ip_proto, tcp_flags, meta

`meta` bit 0: source address is private.  bit 1: destination is private.
bit 2: the packet is IPv6.  The canonical flow key is the sorted pair of
endpoint keys with their ports, so direction needs no byte of its own.
"""
from __future__ import annotations

import argparse
import hashlib
import ipaddress
import struct
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from payload_sidecar import SidecarWriter  # noqa: E402

# RFC 1918, loopback, link-local and unique-local, tested on the raw address
# bytes. A hash cannot be asked this later, so it is answered here.
def _is_private(addr: bytes) -> int:
    if len(addr) == 4:
        if addr[0] == 10 or addr[0] == 127:
            return 1
        if addr[0] == 192 and addr[1] == 168:
            return 1
        if addr[0] == 169 and addr[1] == 254:
            return 1
        if addr[0] == 172 and 16 <= addr[1] <= 31:
            return 1
        return 0
    if len(addr) == 16:
        if addr == b"\x00" * 15 + b"\x01":          # ::1
            return 1
        if addr[0] & 0xFE == 0xFC:                   # fc00::/7 unique local
            return 1
        if addr[0] == 0xFE and (addr[1] & 0xC0) == 0x80:   # fe80::/10
            return 1
    return 0

_PCAP_MAGICS = {
    0xA1B2C3D4: ("<", 1_000_000),
    0xD4C3B2A1: (">", 1_000_000),
    0xA1B23C4D: ("<", 1_000_000_000),
    0x4D3CB2A1: (">", 1_000_000_000),
}
_REC = struct.Struct("<d8s8sHHHHBBB")


def _addr_text(addr: bytes) -> str:
    if len(addr) == 4:
        return ".".join(str(b) for b in addr)
    return str(ipaddress.ip_address(addr))


def export_pcap(path: Path, out, salt: bytes, sidecar=None,
                addresses: dict | None = None) -> dict:
    """Write packet rows, and -- when a `SidecarWriter` is given -- the payload
    facts from the same frames. The payload pass used to be a second read of the
    pcap; there is no second read once the pcap is gone."""
    frames = packets = truncated = 0
    # Every frame that does not become a row is counted by reason. Without the
    # pcap there is no second pass to classify them later, and an uncounted
    # frame is indistinguishable from a lost one.
    skipped = {"runt": 0, "non_ip": 0, "ip_fragment": 0, "short_header": 0,
               "other_l4": 0, "bad_tcp_header": 0}
    cache: dict[bytes, tuple[bytes, int]] = {}
    flows: set[tuple] = set()
    pack = _REC.pack
    key_salt = salt[:32].ljust(32, b"\0")
    batch: list[bytes] = []
    write = out.write
    with path.open("rb") as fh:
        head = fh.read(24)
        if len(head) < 24:
            raise ValueError(f"{path}: truncated pcap header")
        magic = struct.unpack("<I", head[:4])[0]
        if magic not in _PCAP_MAGICS:
            magic = struct.unpack(">I", head[:4])[0]
        if magic not in _PCAP_MAGICS:
            raise ValueError(f"{path}: not a pcap")
        endian, tick = _PCAP_MAGICS[magic]
        if struct.unpack(endian + "I", head[20:24])[0] != 1:
            raise ValueError(f"{path}: only Ethernet is handled")
        rec = struct.Struct(endian + "IIII")
        u16 = struct.Struct("!H")
        read = fh.read
        buf = b""
        pos = 0

        def take(n: int) -> bytes:
            nonlocal buf, pos
            if len(buf) - pos < n:
                buf = buf[pos:] + read(max(8 << 20, n))
                pos = 0
            if len(buf) - pos < n:
                return b""
            chunk = buf[pos:pos + n]
            pos += n
            return chunk

        while True:
            hdr = take(16)
            if not hdr:
                break
            ts_s, ts_f, caplen, origlen = rec.unpack(hdr)
            frame = take(caplen)
            if len(frame) < caplen:
                raise ValueError(f"{path}: truncated frame {frames}")
            frames += 1
            if caplen < origlen:
                truncated += 1
                continue
            if len(frame) < 14:
                skipped["runt"] += 1
                continue
            eth = u16.unpack_from(frame, 12)[0]
            off = 14
            while eth in (0x8100, 0x88A8) and len(frame) >= off + 4:
                eth = u16.unpack_from(frame, off + 2)[0]
                off += 4
            if eth == 0x0800 and len(frame) >= off + 20:
                ihl = (frame[off] & 0x0F) * 4
                if ihl < 20:
                    skipped["short_header"] += 1
                    continue
                if u16.unpack_from(frame, off + 6)[0] & 0x1FFF:
                    # A non-initial fragment has no transport header, so it is
                    # not a packet of any flow this file can name.
                    skipped["ip_fragment"] += 1
                    continue
                proto_n = frame[off + 9]
                src = frame[off + 12:off + 16]
                dst = frame[off + 16:off + 20]
                l4 = off + ihl
                ipend = min(off + u16.unpack_from(frame, off + 2)[0], len(frame))
            elif eth == 0x86DD and len(frame) >= off + 40:
                proto_n = frame[off + 6]
                src = frame[off + 8:off + 24]
                dst = frame[off + 24:off + 40]
                l4 = off + 40
                ipend = min(l4 + u16.unpack_from(frame, off + 4)[0], len(frame))
            elif eth in (0x0800, 0x86DD):
                skipped["short_header"] += 1
                continue
            else:
                skipped["non_ip"] += 1
                continue
            if proto_n == 6 and len(frame) >= l4 + 20:
                sport = u16.unpack_from(frame, l4)[0]
                dport = u16.unpack_from(frame, l4 + 2)[0]
                doff = (frame[l4 + 12] >> 4) * 4
                if doff < 20 or l4 + doff > ipend:
                    # A data offset under five words is not a TCP header, and
                    # one past the end of the IP packet has nothing behind it.
                    # tshark refuses to dissect either (measured: 4 frames in a
                    # 10-second office capture); taking the payload length from
                    # such a header gives a number that is simply made up. The
                    # frame is counted here, not dropped silently.
                    skipped["bad_tcp_header"] += 1
                    continue
                pay_at = l4 + doff
                payload_len = max(0, ipend - pay_at)
                flags = frame[l4 + 13]
            elif proto_n == 17 and len(frame) >= l4 + 8:
                sport = u16.unpack_from(frame, l4)[0]
                dport = u16.unpack_from(frame, l4 + 2)[0]
                pay_at = l4 + 8
                payload_len = max(0, ipend - pay_at)
                flags = 0
            else:
                skipped["other_l4"] += 1
                continue
            # One entry per address, holding both the hash and the answer to
            # "is it private" -- this runs once per packet at mirror rate.
            ent = cache.get(src)
            if ent is None:
                ent = cache[src] = (
                    hashlib.blake2s(src, key=key_salt, digest_size=8).digest(),
                    _is_private(src))
                if addresses is not None:
                    addresses[ent[0].hex()] = _addr_text(src)
            src_key, src_priv = ent
            ent = cache.get(dst)
            if ent is None:
                ent = cache[dst] = (
                    hashlib.blake2s(dst, key=key_salt, digest_size=8).digest(),
                    _is_private(dst))
                if addresses is not None:
                    addresses[ent[0].hex()] = _addr_text(dst)
            dst_key, dst_priv = ent
            meta = src_priv | (dst_priv << 1) | ((eth == 0x86DD) << 2)
            a, b = (src_key, sport), (dst_key, dport)
            flows.add((a, b, proto_n) if a <= b else (b, a, proto_n))
            ts = ts_s + ts_f / tick
            batch.append(pack(
                ts, src_key, dst_key, origlen, sport, dport,
                payload_len, proto_n, flags, meta,
            ))
            if sidecar is not None:
                sidecar.add(ts, src_key, sport, dst_key, dport, proto_n,
                            max(0, ipend - off),
                            frame[pay_at:ipend] if payload_len else b"",
                            flags,
                            int.from_bytes(frame[l4 + 4:l4 + 8], "big") if proto_n == 6 else None)
            if len(batch) >= 4096:
                write(b"".join(batch))
                batch.clear()
            packets += 1
        if batch:
            write(b"".join(batch))
    if truncated:
        raise ValueError(f"{path}: {truncated} frames were shorter than on the wire")
    accounted = packets + sum(skipped.values()) + truncated
    if accounted != frames:
        raise ValueError(
            f"{path}: {frames} frames read but {accounted} accounted for")
    return {"frames": frames, "packets": packets, "truncated": truncated,
            "flows": len(flows), "addresses": len(cache), "nonflow": skipped}


def export_with_payload(pcap: Path, rows_out, payload_out, salt: bytes,
                        names: dict | None = None,
                        addresses: dict | None = None) -> dict:
    """One read of the pcap producing both of the files that replace it.

    `addresses` and `names` collect the reverse of the hashing -- key to
    address, key to server name. They are the only way a finding in the tables
    can ever be turned back into "which machine, talking to what", and once the
    pcap is deleted there is no second chance to build them. They stay on the
    sensor: what leaves is still only hashes.
    """
    sidecar = SidecarWriter(salt, names)
    stats = export_pcap(pcap, rows_out, salt, sidecar=sidecar, addresses=addresses)
    stats.update(sidecar.write(payload_out))
    return stats


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--pcap", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--payload-out", type=Path,
                        help="payload sidecar for the same frames; without it "
                             "SNI and payload shape are lost with the pcap")
    parser.add_argument("--salt-file", type=Path, required=True)
    parser.add_argument("--names-out", type=Path,
                        help="service_key -> SNI, cleartext; keep it on this host")
    args = parser.parse_args()
    salt = args.salt_file.read_bytes().strip()
    if not salt:
        raise SystemExit("empty salt")
    args.out.parent.mkdir(parents=True, exist_ok=True)
    if args.payload_out is None:
        with args.out.open("wb") as fh:
            stats = export_pcap(args.pcap, fh, salt)
    else:
        args.payload_out.parent.mkdir(parents=True, exist_ok=True)
        names = {} if args.names_out else None
        with args.out.open("wb") as rows, args.payload_out.open("wb") as pay:
            stats = export_with_payload(args.pcap, rows, pay, salt, names)
        if args.names_out:
            import json
            args.names_out.write_text(json.dumps(names, indent=1))
            args.names_out.chmod(0o600)
    print(stats)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
