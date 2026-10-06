#!/usr/bin/env python3
"""Verify every record and minute boundary before treating a capture as complete."""
from __future__ import annotations

import argparse
from datetime import datetime, timedelta, timezone
import json
import mmap
from pathlib import Path
import re
import struct


MAGICS = {
    b"\xd4\xc3\xb2\xa1": ("<", 1_000_000),
    b"\xa1\xb2\xc3\xd4": (">", 1_000_000),
    b"\x4d\x3c\xb2\xa1": ("<", 1_000_000_000),
    b"\xa1\xb2\x3c\x4d": (">", 1_000_000_000),
}
NAME = re.compile(r"chunk-(\d{8}T\d{6}Z)\.pcap$")


def audit_file(path: Path) -> dict:
    path = Path(path)
    with path.open("rb") as fh:
        if path.stat().st_size < 24:
            raise ValueError(f"{path}: truncated global pcap header")
        with mmap.mmap(fh.fileno(), 0, access=mmap.ACCESS_READ) as data:
            fmt = MAGICS.get(data[:4])
            if fmt is None:
                raise ValueError(f"{path}: unsupported pcap magic")
            endian, ticks = fmt
            major, minor, _, _, snaplen, linktype = struct.unpack_from(
                endian + "HHIIII", data, 4
            )
            if (major, minor) != (2, 4) or linktype != 1 or snaplen < 1:
                raise ValueError(f"{path}: unsupported pcap header")
            record = struct.Struct(endian + "IIII")
            pos, count, first, last, regressions, truncated_frames = 24, 0, None, None, 0, 0
            while pos < len(data):
                if len(data) - pos < 16:
                    raise ValueError(f"{path}: truncated record header at {pos}")
                seconds, subsec, caplen, origlen = record.unpack_from(data, pos)
                pos += 16
                if subsec >= ticks or caplen > snaplen or caplen > origlen:
                    raise ValueError(f"{path}: invalid record at {pos - 16}")
                if len(data) - pos < caplen:
                    raise ValueError(f"{path}: truncated record body at {pos}")
                ts = seconds + subsec / ticks
                if first is None:
                    first = ts
                if last is not None and ts < last:
                    regressions += 1
                last = ts
                count += 1
                truncated_frames += caplen < origlen
                pos += caplen
    return {
        "name": path.name,
        "bytes": path.stat().st_size,
        "frames": count,
        "first_ts": first,
        "last_ts": last,
        "timestamp_regressions": regressions,
        "frames_with_short_caplen": truncated_frames,
    }


def audit_series(paths: list[Path]) -> dict:
    paths = sorted(map(Path, paths))
    if not paths:
        raise ValueError("no pcap files")
    names = [p.name for p in paths]
    if len(names) != len(set(names)):
        raise ValueError("duplicate minute filename")
    stamps = []
    for path in paths:
        match = NAME.fullmatch(path.name)
        if not match:
            raise ValueError(f"unexpected minute filename: {path.name}")
        stamps.append(datetime.strptime(match.group(1), "%Y%m%dT%H%M%SZ").replace(tzinfo=timezone.utc))
    missing = []
    for prev, nxt in zip(stamps, stamps[1:]):
        if nxt <= prev or (nxt - prev).total_seconds() % 60:
            raise ValueError(f"non-minute rotation: {prev} -> {nxt}")
        t = prev + timedelta(minutes=1)
        while t < nxt:
            missing.append(t.strftime("%Y%m%dT%H%M%SZ"))
            t += timedelta(minutes=1)
    details = [audit_file(path) for path in paths]
    return {
        "files": len(details),
        "frames_total": sum(item["frames"] for item in details),
        "bytes_total": sum(item["bytes"] for item in details),
        "missing_minutes": missing,
        "timestamp_regressions": sum(item["timestamp_regressions"] for item in details),
        "frames_with_short_caplen": sum(item["frames_with_short_caplen"] for item in details),
        "details": details,
    }


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--pcap-dir", type=Path, required=True)
    ap.add_argument("--out-json", type=Path, required=True)
    args = ap.parse_args()
    result = audit_series(list(args.pcap_dir.glob("chunk-*.pcap")))
    args.out_json.parent.mkdir(parents=True, exist_ok=True)
    args.out_json.write_text(json.dumps(result, indent=2) + "\n")
    print(json.dumps({k: v for k, v in result.items() if k != "details"}))
    return 0 if not result["missing_minutes"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
