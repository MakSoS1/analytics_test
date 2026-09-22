from __future__ import annotations

import argparse
import hashlib
import ipaddress
import json
import shutil
from datetime import datetime, timezone
from pathlib import Path

from .research_contract_v3 import FRAMEWORKS, framework_record

SAFE_LIFECYCLE = ("registration", "idle", "poll", "synthetic_task", "synthetic_result", "sleep", "reconnect")


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
    ap = argparse.ArgumentParser(description="Register an isolated, non-post-exploitation framework PCAP as challenge-only evidence.")
    ap.add_argument("--root", required=True)
    ap.add_argument("--framework", required=True, choices=FRAMEWORKS)
    ap.add_argument("--pcap", required=True)
    ap.add_argument("--campaign-id", required=True)
    ap.add_argument("--protocol", required=True)
    ap.add_argument("--source-ip", required=True)
    ap.add_argument("--started-at", required=True)
    ap.add_argument("--ended-at", required=True)
    ap.add_argument("--lifecycle", default="registration,idle,poll,synthetic_task,synthetic_result,sleep,reconnect")
    args = ap.parse_args()

    source_ip = ipaddress.ip_address(args.source_ip)
    if not (source_ip.is_private or source_ip.is_loopback):
        raise SystemExit("framework holdout source_ip must be private/loopback; public targets are rejected")

    lifecycle = [x.strip() for x in args.lifecycle.split(",") if x.strip()]
    if not lifecycle or any(x not in SAFE_LIFECYCLE for x in lifecycle):
        raise SystemExit(f"lifecycle must be a subset of {SAFE_LIFECYCLE}")

    pcap = Path(args.pcap).resolve()
    if not pcap.is_file() or pcap.stat().st_size == 0:
        raise SystemExit("non-empty PCAP is required")

    root = Path(args.root).resolve()
    pcaps = root / "pcaps"
    pcaps.mkdir(parents=True, exist_ok=True)
    dst = pcaps / f"{args.campaign_id}.pcap"
    shutil.copy2(pcap, dst)

    row = framework_record(
        args.framework,
        args.campaign_id,
        protocol=args.protocol,
        pcap_sha256=sha256(dst),
        lifecycle=lifecycle,
        isolated=True,
    )
    row.update(
        {
            "pcap_file": str(dst.relative_to(root)),
            "source_ip": str(source_ip),
            "started_at": _iso(args.started_at),
            "ended_at": _iso(args.ended_at),
            "label_binary": 1,
            "label_family": "framework_c2_holdout",
            "label_intent": "c2",
            "wire_real": True,
            "safe_lifecycle_only": True,
            "framework_evidence_revision": 5,
        }
    )
    manifest = root / "framework_holdout.jsonl"
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
