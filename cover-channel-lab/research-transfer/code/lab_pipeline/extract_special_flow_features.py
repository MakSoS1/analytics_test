#!/usr/bin/env python3
"""WSL-only flow-tier extraction for DNS and ICMP special transports.

The fast-v1 feature contract deliberately excludes DNS and has no ICMP flow
key.  Reusing it would turn a protocol boundary into silently missing positive
rows.  This extractor reads only packet headers from WSL PCAPs and emits the
same counter-only ``FLOW_TIER_FEATURES`` that EVE can export, but into a
separate special-transport corpus.  It never writes packet payloads, addresses,
ports, or PCAP paths to the CSV.
"""
from __future__ import annotations

import argparse
import csv
import ipaddress
import json
import struct
import sys
from pathlib import Path
from typing import Any, Iterator

_PKG_ROOT = Path(__file__).resolve().parent.parent
if str(_PKG_ROOT) not in sys.path:
    sys.path.insert(0, str(_PKG_ROOT))

from lab_pipeline.extract_flow_features import iter_raw_metadata  # noqa: E402
from lab_pipeline.flow_tier import FLOW_TIER_FEATURES, flow_features  # noqa: E402


DEFAULT_WSL_ROOT = Path("/opt/tunnel_lab")
DEFAULT_SOURCES = "wsl_tunnel_lab_full68"
SUPPORTED_FAMILIES = frozenset({"dns_tunnel", "icmp_tunnel"})
META_COLUMNS = [
    "session_id", "campaign_id", "label_family", "workload", "netem_profile", "y",
    "route", "transport_class",
]


def _under_root(path: Path, root: Path, purpose: str) -> Path:
    result = path.resolve()
    try:
        result.relative_to(root.resolve())
    except ValueError as exc:
        raise ValueError(f"{purpose} must be under the declared WSL root") from exc
    return result


def _pcap_layout(header: bytes) -> tuple[str, float]:
    magic = header[:4]
    layouts = {
        b"\xd4\xc3\xb2\xa1": ("<", 1e-6),
        b"\xa1\xb2\xc3\xd4": (">", 1e-6),
        b"\x4d\x3c\xb2\xa1": ("<", 1e-9),
        b"\xa1\xb2\x3c\x4d": (">", 1e-9),
    }
    if magic not in layouts:
        raise ValueError("unsupported pcap magic")
    return layouts[magic]


def _decode_ethernet(frame: bytes, ts: float, wire_len: int) -> dict[str, Any] | None:
    if len(frame) < 14:
        return None
    offset = 14
    ethertype = int.from_bytes(frame[12:14], "big")
    while ethertype in {0x8100, 0x88A8, 0x9100}:
        if len(frame) < offset + 4:
            return None
        ethertype = int.from_bytes(frame[offset + 2:offset + 4], "big")
        offset += 4
    if ethertype != 0x0800 or len(frame) < offset + 20:
        return None
    ver_ihl = frame[offset]
    if ver_ihl >> 4 != 4:
        return None
    ihl = (ver_ihl & 0x0F) * 4
    if ihl < 20 or len(frame) < offset + ihl:
        return None
    proto_n = frame[offset + 9]
    proto = {1: "icmp", 17: "udp"}.get(proto_n)
    if proto is None:
        return None
    src = str(ipaddress.IPv4Address(frame[offset + 12:offset + 16]))
    dst = str(ipaddress.IPv4Address(frame[offset + 16:offset + 20]))
    sport = dport = 0
    if proto == "udp":
        if len(frame) < offset + ihl + 8:
            return None
        sport = int.from_bytes(frame[offset + ihl:offset + ihl + 2], "big")
        dport = int.from_bytes(frame[offset + ihl + 2:offset + ihl + 4], "big")
    return {
        "ts": ts, "length": max(1, wire_len), "proto": proto,
        "src": src, "dst": dst, "sport": sport, "dport": dport,
    }


def iter_special_packets(pcap: Path) -> Iterator[dict[str, Any]]:
    """Yield DNS/ICMP-capable L2 records without retaining packet content."""
    with pcap.open("rb") as fh:
        global_header = fh.read(24)
        if len(global_header) != 24:
            return
        endian, fraction = _pcap_layout(global_header)
        rec_hdr = struct.Struct(endian + "IIII")
        while True:
            header = fh.read(rec_hdr.size)
            if not header:
                return
            if len(header) != rec_hdr.size:
                raise ValueError("truncated pcap record header")
            sec, subsec, included, original = rec_hdr.unpack(header)
            if included > 16 * 1024 * 1024:
                raise ValueError("unreasonable pcap record length")
            frame = fh.read(included)
            if len(frame) != included:
                raise ValueError("truncated pcap record")
            packet = _decode_ethernet(frame, float(sec) + float(subsec) * fraction, original)
            if packet is not None:
                yield packet


def _flow_key(packet: dict[str, Any]) -> tuple[tuple[str, int], tuple[str, int], str]:
    left = (str(packet["src"]), int(packet["sport"]))
    right = (str(packet["dst"]), int(packet["dport"]))
    return (*((left, right) if left <= right else (right, left)), str(packet["proto"]))


def _belongs_to_family(packet: dict[str, Any], family: str) -> bool:
    if family == "dns_tunnel":
        return packet["proto"] == "udp" and 53 in {int(packet["sport"]), int(packet["dport"])}
    return family == "icmp_tunnel" and packet["proto"] == "icmp"


def rows_for_session(meta: dict[str, Any], pcap: Path) -> list[dict[str, Any]]:
    family = str(meta.get("label_family") or "")
    if family not in SUPPORTED_FAMILIES:
        return []
    flows: dict[tuple[tuple[str, int], tuple[str, int], str], dict[str, Any]] = {}
    for packet in iter_special_packets(pcap):
        if not _belongs_to_family(packet, family):
            continue
        key = _flow_key(packet)
        flow = flows.get(key)
        if flow is None:
            flow = flows[key] = {
                "initiator": (packet["src"], packet["sport"]),
                "up_pkts": 0, "down_pkts": 0, "up_bytes": 0, "down_bytes": 0,
                "t0": packet["ts"], "t1": packet["ts"], "proto": packet["proto"],
            }
        upward = (packet["src"], packet["sport"]) == flow["initiator"]
        if upward:
            flow["up_pkts"] += 1
            flow["up_bytes"] += int(packet["length"])
        else:
            flow["down_pkts"] += 1
            flow["down_bytes"] += int(packet["length"])
        flow["t0"] = min(float(flow["t0"]), float(packet["ts"]))
        flow["t1"] = max(float(flow["t1"]), float(packet["ts"]))

    y = 1 if str(meta.get("label_binary") or "") == "tunnel" else 0
    out: list[dict[str, Any]] = []
    for flow in flows.values():
        row = flow_features(
            flow["up_pkts"], flow["down_pkts"], flow["up_bytes"], flow["down_bytes"],
            float(flow["t1"]) - float(flow["t0"]), str(flow["proto"]),
        )
        row.update({
            "session_id": str(meta.get("session_id") or pcap.stem),
            "campaign_id": str(meta.get("campaign_id") or ""),
            "label_family": family,
            "workload": str(meta.get("workload") or ""),
            "netem_profile": str(meta.get("netem_profile") or ""),
            "y": y,
            "route": "special_transport",
            "transport_class": str(flow["proto"]),
        })
        out.append(row)
    return out


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--metadata-dir", type=Path, required=True)
    parser.add_argument("--out-csv", type=Path, required=True)
    parser.add_argument("--wsl-root", type=Path, default=DEFAULT_WSL_ROOT)
    parser.add_argument("--source-filter", default=DEFAULT_SOURCES)
    args = parser.parse_args()
    root = args.wsl_root.resolve()
    metadata_dir = _under_root(args.metadata_dir, root, "metadata directory")
    out_csv = _under_root(args.out_csv, root, "feature CSV")

    rows: list[dict[str, Any]] = []
    invalid = 0
    for meta, pcap in iter_raw_metadata(metadata_dir, args.source_filter):
        try:
            rows.extend(rows_for_session(meta, pcap))
        except (OSError, ValueError):
            invalid += 1
    out_csv.parent.mkdir(parents=True, exist_ok=True)
    with out_csv.open("w", newline="", encoding="utf-8") as fh:
        writer = csv.DictWriter(fh, fieldnames=FLOW_TIER_FEATURES + META_COLUMNS)
        writer.writeheader()
        writer.writerows(rows)
    print(json.dumps({
        "rows": len(rows), "positive_rows": sum(row["y"] == 1 for row in rows),
        "negative_rows": sum(row["y"] == 0 for row in rows), "invalid_pcaps": invalid,
        "families": sorted({row["label_family"] for row in rows}), "csv": str(out_csv),
    }, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
