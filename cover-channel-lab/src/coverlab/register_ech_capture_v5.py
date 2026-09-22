from __future__ import annotations

import argparse
import hashlib
import ipaddress
import json
import shutil
from datetime import datetime, timezone
from pathlib import Path

from .research_contract_v3 import ECH_MODES


def sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def _iso(value: str) -> str:
    dt = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def main() -> None:
    ap = argparse.ArgumentParser(description="Register wire-real ECH evidence from an isolated lab endpoint.")
    ap.add_argument("--root", required=True)
    ap.add_argument("--pcap", required=True)
    ap.add_argument("--campaign-id", required=True)
    ap.add_argument("--pair-id", required=True)
    ap.add_argument("--ech-mode", required=True, choices=ECH_MODES)
    ap.add_argument("--ech-enabled", required=True, choices=["true", "false"])
    ap.add_argument("--source-ip", required=True)
    ap.add_argument("--started-at", required=True)
    ap.add_argument("--ended-at", required=True)
    ap.add_argument("--protocol", required=True, choices=["h2", "h3", "https"])
    args = ap.parse_args()

    source_ip = ipaddress.ip_address(args.source_ip)
    if not (source_ip.is_private or source_ip.is_loopback):
        raise SystemExit("ECH evidence source_ip must be private/loopback")

    pcap = Path(args.pcap).resolve()
    if not pcap.is_file() or pcap.stat().st_size == 0:
        raise SystemExit("non-empty PCAP is required")

    root = Path(args.root).resolve()
    pcaps = root / "pcaps"
    pcaps.mkdir(parents=True, exist_ok=True)
    dst = pcaps / f"{args.campaign_id}.pcap"
    shutil.copy2(pcap, dst)

    suspicious = args.ech_mode == "shared_frontend_suspicious"
    row = {
        "campaign_id": args.campaign_id,
        "pair_id": args.pair_id,
        "ech_mode": args.ech_mode,
        "ech_enabled": args.ech_enabled == "true",
        "protocol": args.protocol,
        "source_ip": str(source_ip),
        "started_at": _iso(args.started_at),
        "ended_at": _iso(args.ended_at),
        "pcap_file": str(dst.relative_to(root)),
        "pcap_sha256": sha256(dst),
        "wire_real": True,
        "isolated_lab": True,
        "label_binary": 1 if suspicious else 0,
        "label_family": "ech_shared_frontend_behavior" if suspicious else "benign",
        "label_intent": "c2" if suspicious else "benign",
        "experiment_stage": "M_ech_holdout",
        "dataset_role": "external_ech_holdout",
        "training_eligible": False,
        "ech_evidence_revision": 5,
    }
    manifest = root / "ech_holdout.jsonl"
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
