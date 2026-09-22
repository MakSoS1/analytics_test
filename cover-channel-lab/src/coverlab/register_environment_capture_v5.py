from __future__ import annotations

import argparse
import hashlib
import json
import shutil
from pathlib import Path

from .research_contract_v3 import CLIENT_STACKS, NETWORK_EVIDENCE_TYPES, SERVER_STACKS


def sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def main() -> None:
    ap = argparse.ArgumentParser(description="Register wire-real environment diversity evidence.")
    ap.add_argument("--root", required=True)
    ap.add_argument("--pcap", required=True)
    ap.add_argument("--evidence-id", required=True)
    ap.add_argument("--session-count", required=True, type=int)
    ap.add_argument("--client-stack", choices=CLIENT_STACKS)
    ap.add_argument("--server-stack", choices=SERVER_STACKS)
    ap.add_argument("--network-evidence", choices=NETWORK_EVIDENCE_TYPES)
    args = ap.parse_args()

    if args.session_count <= 0:
        raise SystemExit("session-count must be positive")
    if not any((args.client_stack, args.server_stack, args.network_evidence)):
        raise SystemExit("at least one of client-stack/server-stack/network-evidence is required")

    pcap = Path(args.pcap).resolve()
    if not pcap.is_file() or pcap.stat().st_size == 0:
        raise SystemExit("non-empty PCAP is required")

    root = Path(args.root).resolve()
    pcaps = root / "pcaps"
    pcaps.mkdir(parents=True, exist_ok=True)
    dst = pcaps / f"{args.evidence_id}.pcap"
    shutil.copy2(pcap, dst)

    row = {
        "evidence_id": args.evidence_id,
        "session_count": args.session_count,
        "client_stack": args.client_stack or "",
        "server_stack": args.server_stack or "",
        "network_evidence": args.network_evidence or "",
        "wire_real": True,
        "isolated_lab": True,
        "training_eligible": False,
        "dataset_role": "environment_external_holdout",
        "pcap_file": str(dst.relative_to(root)),
        "pcap_sha256": sha256(dst),
        "environment_evidence_revision": 5,
    }
    manifest = root / "environment_evidence.jsonl"
    existing = []
    if manifest.exists():
        existing = [json.loads(x) for x in manifest.read_text().splitlines() if x.strip()]
    if any(str(x.get("evidence_id")) == args.evidence_id for x in existing):
        raise SystemExit(f"duplicate evidence_id: {args.evidence_id}")
    with manifest.open("a") as f:
        f.write(json.dumps(row, separators=(",", ":"), sort_keys=True) + "\n")
    print(json.dumps(row, sort_keys=True))


if __name__ == "__main__":
    main()
