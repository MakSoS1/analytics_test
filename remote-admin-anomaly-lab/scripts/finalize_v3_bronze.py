#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hashlib
import json
import shutil
import subprocess
import sys
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from adminlab.manifest import SessionRecord
from adminlab.pcap_slicing import (
    build_campaign_pcaps,
    build_pcap_index,
    slice_session_pcaps,
    split_raw_chunks,
    verify_sample_pcaps,
    write_pcap_index,
)


def read_sessions(path: Path) -> list[SessionRecord]:
    return [SessionRecord.from_dict(json.loads(line)) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def write_checksums(bronze: Path) -> None:
    target = bronze / "checksums.sha256"
    lines = [f"{sha256(path)}  {path.relative_to(bronze).as_posix()}" for path in sorted(p for p in bronze.rglob("*") if p.is_file() and p != target)]
    target.write_text("\n".join(lines) + "\n", encoding="utf-8")


def verify_checksums(bronze: Path) -> None:
    for line in (bronze / "checksums.sha256").read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        expected, relative = line.split("  ", 1)
        path = bronze / relative
        if not path.is_file() or sha256(path) != expected:
            raise ValueError(f"checksum mismatch: {relative}")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--release", type=Path, required=True)
    parser.add_argument("--shard", required=True)
    parser.add_argument("--sample-size", type=int, default=20)
    parser.add_argument("--raw-chunk-packets", type=int, default=50000)
    parser.add_argument("--min-session-coverage", type=float, default=0.99)
    args = parser.parse_args()

    bronze = args.release / "bronze" / args.shard
    quality = args.release / "quality" / args.shard
    merged_raw = bronze / "captures" / f"{args.shard}.pcap"
    sessions_path = bronze / "manifests" / "sessions.jsonl"
    if not merged_raw.is_file() or not sessions_path.is_file():
        raise SystemExit("temporary raw merged Bronze and session manifest are required")
    if list((bronze / "captures").glob("*.pcap.zst")):
        raise SystemExit("corrected V3 must not create a compressed merged PCAP")

    sessions = read_sessions(sessions_path)
    successful = [row for row in sessions if row.status == "success"]
    if not successful:
        raise SystemExit("no successful sessions available for V3 Bronze slicing")

    quality.mkdir(parents=True, exist_ok=True)
    merged_source = {
        "relative_path_before_removal": f"captures/{args.shard}.pcap",
        "raw_bytes": int(merged_raw.stat().st_size),
        "raw_sha256": sha256(merged_raw),
        "compression": "none",
        "authoritative_after_finalization": False,
        "purpose": "ephemeral parser/slicing source only",
    }
    merged_source["raw_packet_count"] = int(
        subprocess.check_output(["tshark", "-r", str(merged_raw), "-T", "fields", "-e", "frame.number"], text=True, stderr=subprocess.DEVNULL).count("\n")
    )

    session_evidence = slice_session_pcaps(merged_raw, successful, bronze)
    campaign_evidence = build_campaign_pcaps(session_evidence, successful, bronze)
    raw_evidence = split_raw_chunks(merged_raw, bronze, packets_per_chunk=args.raw_chunk_packets)

    evidence = raw_evidence + session_evidence + campaign_evidence
    index = build_pcap_index(evidence, successful)
    write_pcap_index(index, bronze / "manifests")
    verified_sample = verify_sample_pcaps(bronze, index, sample_size=args.sample_size, seed=2026081403)

    session_coverage = len(session_evidence) / len(successful)
    successful_campaigns = len({row.campaign_id for row in successful})
    campaign_ids = {item.campaign_id for item in campaign_evidence}
    campaign_coverage = len(campaign_ids) / max(1, successful_campaigns)
    if session_coverage < args.min_session_coverage:
        raise SystemExit(f"V3 session PCAP coverage below threshold: {session_coverage:.6f}")
    if campaign_coverage < 0.99:
        raise SystemExit(f"V3 campaign PCAP coverage below threshold: {campaign_coverage:.6f}")
    if sum(item.packet_count for item in raw_evidence) != int(merged_source["raw_packet_count"]):
        raise SystemExit("raw chunk packet total differs from merged source")
    if any(str(path).endswith(".pcap.zst") for path in bronze.rglob("*.pcap.zst")):
        raise SystemExit("compressed PCAP remains in corrected V3 Bronze")

    captures = bronze / "captures"
    if captures.exists():
        shutil.rmtree(captures)
    if any(bronze.glob("captures/*.pcap*")):
        raise SystemExit("persisted merged capture remains after V3 finalization")

    (bronze / "manifests" / "ephemeral_merged_source.json").write_text(json.dumps(merged_source, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    write_checksums(bronze)
    verify_checksums(bronze)

    kinds = Counter(index["kind"].astype(str))
    label_protocol = index[index["kind"] == "session"].groupby(["label_name", "protocol"]).size().to_dict()
    report = {
        "schema_version": 4,
        "status": "PASS",
        "shard": args.shard,
        "successful_sessions": len(successful),
        "session_pcaps": len(session_evidence),
        "session_pcap_coverage": session_coverage,
        "campaigns": successful_campaigns,
        "campaign_pcaps": len(campaign_evidence),
        "campaign_pcap_coverage": campaign_coverage,
        "raw_chunks": len(raw_evidence),
        "raw_chunk_packet_total": int(sum(item.packet_count for item in raw_evidence)),
        "source_merged_packet_total": int(merged_source["raw_packet_count"]),
        "pcap_index_rows": int(len(index)),
        "kind_counts": dict(kinds),
        "session_label_protocol_counts": {f"{label}/{protocol}": int(value) for (label, protocol), value in sorted(label_protocol.items())},
        "reparsed_session_sample": verified_sample,
        "merged_pcap_persisted": False,
        "pcap_compression": "none",
        "compressed_pcaps_present": False,
        "full_raw_traffic_preserved_in_chunks": True,
        "checksums_verified": True,
        "inspection_layout": {
            "session": "sessions/<label>/<protocol>/<session_id>.pcap",
            "campaign": "campaigns/<label>/<campaign_id>.pcap",
            "raw": "raw_chunks/chunk-XXXX.pcap",
            "index_csv": "manifests/pcap_index.csv",
        },
    }
    (quality / "v3_bronze_quality.json").write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps(report, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
