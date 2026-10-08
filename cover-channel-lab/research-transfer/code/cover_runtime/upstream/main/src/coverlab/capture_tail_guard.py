from __future__ import annotations

import argparse
import json
import struct
from datetime import datetime, timezone
from pathlib import Path


def _parse_iso(value: str) -> float:
    text = str(value or "").strip()
    if not text:
        return 0.0
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"
    dt = datetime.fromisoformat(text)
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.timestamp()


def last_pcap_timestamp(path: Path) -> tuple[float, int]:
    with path.open("rb") as fh:
        header = fh.read(24)
        if len(header) != 24:
            raise RuntimeError("PCAP global header is truncated")
        magic = header[:4]
        formats = {
            b"\xd4\xc3\xb2\xa1": ("<", 1_000_000.0),
            b"\xa1\xb2\xc3\xd4": (">", 1_000_000.0),
            b"\x4d\x3c\xb2\xa1": ("<", 1_000_000_000.0),
            b"\xa1\xb2\x3c\x4d": (">", 1_000_000_000.0),
        }
        if magic not in formats:
            raise RuntimeError(f"unsupported capture magic {magic.hex()}; expected classic PCAP")
        endian, divisor = formats[magic]
        packet_header = struct.Struct(endian + "IIII")
        last_ts = 0.0
        count = 0
        while True:
            raw = fh.read(packet_header.size)
            if not raw:
                break
            if len(raw) != packet_header.size:
                raise RuntimeError("truncated PCAP packet header")
            sec, frac, incl_len, _orig_len = packet_header.unpack(raw)
            if incl_len > 64 * 1024 * 1024:
                raise RuntimeError(f"unreasonable PCAP incl_len={incl_len}")
            fh.seek(incl_len, 1)
            last_ts = sec + frac / divisor
            count += 1
        return last_ts, count


def _campaign_rows(stage_dir: Path) -> list[dict]:
    for candidate in (
        stage_dir / "manifests" / "campaigns.jsonl",
        stage_dir / "campaigns.jsonl",
    ):
        if candidate.exists():
            return [json.loads(line) for line in candidate.read_text(errors="replace").splitlines() if line.strip()]
    raise RuntimeError("campaigns.jsonl not found")


def check(stage_dir: Path, pcap: Path, tolerance_seconds: float = 0.05) -> dict:
    rows = _campaign_rows(stage_dir)
    successful = [r for r in rows if str(r.get("status", "success")) == "success"]
    latest_start = max((_parse_iso(r.get("started_at", "")) for r in successful), default=0.0)
    latest_end = max((_parse_iso(r.get("ended_at", "")) for r in successful), default=0.0)
    last_ts, packet_count = last_pcap_timestamp(pcap)
    lag_from_latest_start = latest_start - last_ts
    passed = bool(successful) and packet_count > 0 and last_ts + tolerance_seconds >= latest_start
    return {
        "passed": passed,
        "packet_count": packet_count,
        "last_pcap_timestamp": last_ts,
        "latest_campaign_started_at": latest_start,
        "latest_campaign_ended_at": latest_end,
        "lag_from_latest_campaign_start_seconds": round(lag_from_latest_start, 6),
        "end_minus_last_packet_seconds": round(latest_end - last_ts, 6),
        "tolerance_seconds": tolerance_seconds,
        "successful_campaigns": len(successful),
        "guard_revision": 1,
    }


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--stage-dir", required=True)
    ap.add_argument("--pcap", required=True)
    ap.add_argument("--out", required=True)
    ap.add_argument("--tolerance-seconds", type=float, default=0.05)
    args = ap.parse_args()
    report = check(Path(args.stage_dir), Path(args.pcap), args.tolerance_seconds)
    out = Path(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")
    print(json.dumps(report, sort_keys=True))
    if not report["passed"]:
        raise SystemExit("PCAP tail completeness guard failed")


if __name__ == "__main__":
    main()
