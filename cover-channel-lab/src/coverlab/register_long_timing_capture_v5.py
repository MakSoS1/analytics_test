from __future__ import annotations

import argparse
import hashlib
import json
import shutil
from pathlib import Path


REQUIRED_EVENTS = {1200: 5, 3600: 4}


def sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def main() -> None:
    ap = argparse.ArgumentParser(description="Register real-time 20/60 minute timing evidence.")
    ap.add_argument("--root", required=True)
    ap.add_argument("--pcap", required=True)
    ap.add_argument("--campaign-id", required=True)
    ap.add_argument("--interval-seconds", required=True, type=int, choices=sorted(REQUIRED_EVENTS))
    ap.add_argument("--event-count", required=True, type=int)
    ap.add_argument("--label-binary", required=True, type=int, choices=[0, 1])
    args = ap.parse_args()

    minimum = REQUIRED_EVENTS[args.interval_seconds]
    if args.event_count < minimum:
        raise SystemExit(f"{args.interval_seconds}s requires at least {minimum} events")

    pcap = Path(args.pcap).resolve()
    if not pcap.is_file() or pcap.stat().st_size == 0:
        raise SystemExit("non-empty PCAP is required")

    root = Path(args.root).resolve()
    pcaps = root / "pcaps"
    pcaps.mkdir(parents=True, exist_ok=True)
    dst = pcaps / f"{args.campaign_id}.pcap"
    shutil.copy2(pcap, dst)

    row = {
        "campaign_id": args.campaign_id,
        "real_interval_seconds": args.interval_seconds,
        "event_count": args.event_count,
        "event_count_target": args.event_count,
        "timing_acceleration": 1,
        "label_binary": args.label_binary,
        "wire_real": True,
        "isolated_lab": True,
        "training_eligible": False,
        "dataset_role": "external_long_timing_challenge",
        "pcap_file": str(dst.relative_to(root)),
        "pcap_sha256": sha256(dst),
        "long_timing_evidence_revision": 5,
    }
    manifest = root / "long_timing_evidence.jsonl"
    existing = []
    if manifest.exists():
        existing = [json.loads(x) for x in manifest.read_text().splitlines() if x.strip()]
    if any(str(x.get("campaign_id")) == args.campaign_id for x in existing):
        raise SystemExit(f"duplicate campaign_id: {args.campaign_id}")
    with manifest.open("a") as f:
        f.write(json.dumps(row, separators=(",", ":"), sort_keys=True) + "\n")
    print(json.dumps(row, sort_keys=True))


if __name__ == "__main__":
    main()
