from __future__ import annotations

import argparse
import json
import subprocess
import tempfile
from pathlib import Path

from .evidence_register_v4 import register_long_timing


def main() -> None:
    ap = argparse.ArgumentParser(description="Import canonical self-hosted Stage L release into external long-timing evidence.")
    ap.add_argument("--release-root", required=True)
    ap.add_argument("--shard-name", required=True)
    ap.add_argument("--evidence-root", required=True)
    a = ap.parse_args()

    release = Path(a.release_root)
    bronze = release / "bronze" / a.shard_name
    manifest = bronze / "manifests" / "campaigns.jsonl"
    compressed = bronze / "captures" / f"{a.shard_name}.pcap.zst"
    if not manifest.is_file() or not compressed.is_file():
        raise SystemExit("canonical long-timing release is missing manifest or pcap.zst")
    rows = [json.loads(x) for x in manifest.read_text().splitlines() if x.strip()]
    if not rows:
        raise SystemExit("canonical long-timing manifest is empty")

    with tempfile.TemporaryDirectory(prefix="coverlab-long-import-") as td:
        pcap = Path(td) / f"{a.shard_name}.pcap"
        subprocess.run(["zstd", "-q", "-d", "-f", str(compressed), "-o", str(pcap)], check=True)
        imported = []
        for row in rows:
            rec = register_long_timing(
                Path(a.evidence_root),
                pcap,
                campaign_id=str(row["campaign_id"]),
                interval_seconds=int(row["real_interval_seconds"]),
                event_count=int(row.get("event_count_target", row.get("expected_events", 0))),
                label_binary=int(row["label_binary"]),
                protocol=str(row["protocol"]),
                source_ip=str(row["source_ip"]),
                started_at=str(row["started_at"]),
                ended_at=str(row["ended_at"]),
            )
            imported.append(rec["campaign_id"])
    print(json.dumps({"shard": a.shard_name, "imported": imported}, sort_keys=True))


if __name__ == "__main__":
    main()
