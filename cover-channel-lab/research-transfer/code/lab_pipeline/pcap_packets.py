#!/usr/bin/env python3
"""Read a capture file directly, with no tcpdump and no third-party package.

`extract_lab_features.read_pcap_packets` shells out to tcpdump. That is right
on the lab stand, and impossible anywhere the capture tools are not installed —
the analysis host that runs the demo notebook has neither tcpdump nor tshark
nor scapy, and installing them there is not something a notebook should do.

So this parses pcap and pcapng itself and returns the SAME dicts the tcpdump
path returns, field for field, which is what lets the demo feed
`flow_observation.ObservationTable` the identical input the corpus was built
from. `tests/test_pcap_packets.py` pins the two against each other on real lab
captures; if they ever diverge, the demo is measuring something else and the
test says so.
"""
from __future__ import annotations

import struct
import sys
from pathlib import Path
from typing import Any, Iterator

_PKG_ROOT = Path(__file__).resolve().parent.parent
if str(_PKG_ROOT) not in sys.path:
    sys.path.insert(0, str(_PKG_ROOT))
from lab_pipeline.extract_lab_features import split_coalesced_frames  # noqa: E402
from lab_pipeline.online_schema import in_scope  # noqa: E402


class CaptureFormatError(RuntimeError):
    """The file is not a capture this reader understands."""


LINKTYPE_ETHERNET = 1
LINKTYPE_RAW = 101
LINKTYPE_LINUX_SLL = 113
LINKTYPE_LINUX_SLL2 = 276
_SUPPORTED_LINKTYPES = frozenset({
    LINKTYPE_ETHERNET, LINKTYPE_RAW, LINKTYPE_LINUX_SLL, LINKTYPE_LINUX_SLL2,
})

_PCAP_MAGICS = {
    0xA1B2C3D4: ("<", 1_000_000),      # microseconds, little endian
    0xD4C3B2A1: (">", 1_000_000),
    0xA1B23C4D: ("<", 1_000_000_000),  # nanoseconds
    0x4D3CB2A1: (">", 1_000_000_000),
}
_PCAPNG_MAGIC = 0x0A0D0D0A


def read_pcap_packets(path: Path) -> list[dict[str, Any]]:
    """Every in-scope TCP/UDP packet of a capture, as the tcpdump path returns it."""
    return split_coalesced_frames(list(_iter_packets(Path(path))))


def _iter_packets(path: Path) -> Iterator[dict[str, Any]]:
    data = path.read_bytes()
    if len(data) < 4:
        raise CaptureFormatError(f"{path.name}: file is too short to be a capture")
    head = struct.unpack("<I", data[:4])[0]
    if head == _PCAPNG_MAGIC or struct.unpack(">I", data[:4])[0] == _PCAPNG_MAGIC:
        frames = _pcapng_frames(data, path.name)
    else:
        frames = _pcap_frames(data, path.name)
    for ts, linktype, frame, orig_len in frames:
        parsed = _parse_frame(linktype, frame, orig_len)
        if parsed is not None:
            parsed["ts"] = ts
            yield parsed


def _pcap_frames(data: bytes, name: str) -> Iterator[tuple[float, int, bytes, int]]:
    magic = struct.unpack("<I", data[:4])[0]
    if magic not in _PCAP_MAGICS:
        magic = struct.unpack(">I", data[:4])[0]
    if magic not in _PCAP_MAGICS:
        raise CaptureFormatError(f"{name}: not a pcap or pcapng file")
    endian, ticks = _PCAP_MAGICS[magic]
    if len(data) < 24:
        raise CaptureFormatError(f"{name}: truncated pcap header")
    linktype = struct.unpack(endian + "I", data[20:24])[0]
    _check_linktype(linktype, name)
    offset = 24
    record = struct.Struct(endian + "IIII")
    while offset + 16 <= len(data):
        sec, frac, caplen, orig_len = record.unpack_from(data, offset)
        offset += 16
        # A capture cut off mid-record is normal — tcpdump was killed — and the
        # frames before it are still real, so stop rather than raise.
        if offset + caplen > len(data):
            return
        yield sec + frac / ticks, linktype, data[offset:offset + caplen], orig_len
        offset += caplen


def _pcapng_frames(data: bytes, name: str) -> Iterator[tuple[float, int, bytes, int]]:
    endian = "<"
    if struct.unpack(">I", data[:4])[0] == _PCAPNG_MAGIC:
        endian = ">"
    interfaces: list[tuple[int, int]] = []          # (linktype, ticks per second)
    offset = 0
    while offset + 12 <= len(data):
        block_type, block_len = struct.unpack_from(endian + "II", data, offset)
        if block_len < 12 or offset + block_len > len(data):
            return
        body = data[offset + 8:offset + block_len - 4]
        if block_type == _PCAPNG_MAGIC:                       # section header
            if struct.unpack_from(endian + "I", body, 0)[0] != 0x1A2B3C4D:
                endian = ">" if endian == "<" else "<"
            interfaces = []
        elif block_type == 0x00000001:                        # interface description
            linktype = struct.unpack_from(endian + "H", body, 0)[0]
            _check_linktype(linktype, name)
            interfaces.append((linktype, _if_ticks(body[8:], endian)))
        elif block_type == 0x00000006 and interfaces:         # enhanced packet
            iface, high, low, caplen, orig_len = struct.unpack_from(endian + "IIIII", body, 0)
            linktype, ticks = interfaces[min(iface, len(interfaces) - 1)]
            stamp = ((high << 32) | low) / ticks
            yield stamp, linktype, body[20:20 + caplen], orig_len
        offset += block_len
    return


def _if_ticks(options: bytes, endian: str) -> float:
    """if_tsresol (option 9): ticks per second, 10^n or 2^n. Default microseconds."""
    offset = 0
    while offset + 4 <= len(options):
        code, length = struct.unpack_from(endian + "HH", options, offset)
        value = options[offset + 4:offset + 4 + length]
        if code == 0:
            break
        if code == 9 and length >= 1:
            raw = value[0]
            return float(2 ** (raw & 0x7F)) if raw & 0x80 else float(10 ** raw)
        offset += 4 + ((length + 3) // 4) * 4
    return 1_000_000.0


def _check_linktype(linktype: int, name: str) -> None:
    if linktype not in _SUPPORTED_LINKTYPES:
        raise CaptureFormatError(
            f"{name}: link type {linktype} is not supported; the lab captures are "
            "Ethernet, and guessing a layout would silently shift every offset")


def _parse_frame(linktype: int, frame: bytes, orig_len: int) -> dict[str, Any] | None:
    if linktype == LINKTYPE_ETHERNET:
        payload, ethertype = _strip_ethernet(frame)
    elif linktype == LINKTYPE_LINUX_SLL:
        if len(frame) < 16:
            return None
        payload, ethertype = frame[16:], struct.unpack_from(">H", frame, 14)[0]
    elif linktype == LINKTYPE_LINUX_SLL2:
        if len(frame) < 20:
            return None
        payload, ethertype = frame[20:], struct.unpack_from(">H", frame, 0)[0]
    else:                                                     # raw IP
        if not frame:
            return None
        ethertype = 0x0800 if (frame[0] >> 4) == 4 else 0x86DD
        payload = frame
    if payload is None:
        return None
    if ethertype == 0x0800:
        network = _parse_ipv4(payload)
    elif ethertype == 0x86DD:
        network = _parse_ipv6(payload)
    else:
        return None
    if network is None:
        return None
    src, dst, proto_num, transport = network
    declared = 0
    if proto_num == 6:
        ports = _parse_tcp(transport)
    elif proto_num == 17:
        parsed = _parse_udp(transport)
        ports = parsed[:4] if parsed else None
        declared = parsed[4] if parsed else 0
    else:
        return None
    if ports is None:
        return None
    sport, dport, proto, flags = ports
    if not in_scope(sport, dport):
        return None
    # The frame length as it was on the wire, which is what `tcpdump -e` prints
    # and therefore what the corpus counted.
    return {"src": src, "dst": dst, "sport": sport, "dport": dport,
            "length": max(int(orig_len), declared, 1), "proto": proto, "flags": flags}


def _strip_ethernet(frame: bytes) -> tuple[bytes | None, int]:
    if len(frame) < 14:
        return None, 0
    ethertype = struct.unpack_from(">H", frame, 12)[0]
    offset = 14
    while ethertype in (0x8100, 0x88A8, 0x9100):              # VLAN tags
        if len(frame) < offset + 4:
            return None, 0
        ethertype = struct.unpack_from(">H", frame, offset + 2)[0]
        offset += 4
    return frame[offset:], ethertype


def _parse_ipv4(packet: bytes) -> tuple[str, str, int, bytes] | None:
    if len(packet) < 20:
        return None
    ihl = (packet[0] & 0x0F) * 4
    if ihl < 20 or len(packet) < ihl:
        return None
    # A non-first fragment carries no ports; it is not a flow packet.
    if struct.unpack_from(">H", packet, 6)[0] & 0x1FFF:
        return None
    proto = packet[9]
    src = ".".join(str(b) for b in packet[12:16])
    dst = ".".join(str(b) for b in packet[16:20])
    return src, dst, proto, packet[ihl:]


_IPV6_SKIPPABLE = frozenset({0, 43, 60})                       # hop-by-hop, routing, dest opts


def _parse_ipv6(packet: bytes) -> tuple[str, str, int, bytes] | None:
    if len(packet) < 40:
        return None
    nxt = packet[6]
    src, dst = _ipv6_text(packet[8:24]), _ipv6_text(packet[24:40])
    rest = packet[40:]
    while nxt in _IPV6_SKIPPABLE:
        if len(rest) < 8:
            return None
        length = (rest[1] + 1) * 8
        nxt, rest = rest[0], rest[length:]
    return src, dst, nxt, rest


def _ipv6_text(raw: bytes) -> str:
    import ipaddress
    return str(ipaddress.IPv6Address(raw))


def _parse_tcp(segment: bytes) -> tuple[int, int, str, str] | None:
    if len(segment) < 20:
        return None
    sport, dport = struct.unpack_from(">HH", segment, 0)
    bits = segment[13]
    # Spelled the way tcpdump spells it, because the caller reads the string:
    # a SYN with ACK is "S." and the extractor distinguishes the two.
    flags = ""
    if bits & 0x02:
        flags += "S"
    if bits & 0x01:
        flags += "F"
    if bits & 0x04:
        flags += "R"
    if bits & 0x08:
        flags += "P"
    if bits & 0x20:
        flags += "U"
    if bits & 0x10:
        flags += "."
    return sport, dport, "tcp", flags or "."


# tcpdump names a datagram by its dissector, and the text path reads that name:
# on these ports it prints `isakmp` and `UDP-encap`, never `UDP`, so the corpus
# recorded proto "other" for them — which also sends them down a different
# route. Measured against tcpdump over 150 lab captures; these are the only two.
_TCPDUMP_DISSECTED_UDP_PORTS = frozenset({500, 4500})


def _parse_udp(datagram: bytes) -> tuple[int, int, str, str, int] | None:
    if len(datagram) < 8:
        return None
    sport, dport, declared = struct.unpack_from(">HHH", datagram, 0)
    proto = "other" if (sport in _TCPDUMP_DISSECTED_UDP_PORTS
                        or dport in _TCPDUMP_DISSECTED_UDP_PORTS) else "udp"
    # The length tcpdump reports is the one the UDP header declares, which on a
    # fragmented datagram is larger than the frame that carries it. Matching the
    # frame instead would quietly shift every length feature on those packets.
    return sport, dport, proto, "", declared + 34
