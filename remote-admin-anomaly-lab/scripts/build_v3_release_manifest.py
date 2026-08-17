#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--release", type=Path, required=True)
    parser.add_argument("--shard", required=True)
    parser.add_argument("--decision", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()

    release = args.release.resolve()
    decision = json.loads(args.decision.read_text(encoding="utf-8"))
    if decision.get("dataset_release_status") != "READY":
        raise SystemExit("cannot manifest technically incomplete V3 release")

    bronze = release / "bronze" / args.shard
    silver = release / "silver" / args.shard
    gold = release / "gold" / args.shard
    quality = release / "quality" / args.shard
    required = [
        bronze / "manifests" / "sessions.parquet",
        bronze / "manifests" / "pcap_index.parquet",
        bronze / "manifests" / "pcap_index.csv",
        bronze / "checksums.sha256",
        bronze / "manifests" / "ephemeral_merged_source.json",
        silver / "suricata" / "eve.json.zst",
        gold / "production_flow_features.parquet",
        gold / "production_flow_labels.parquet",
        gold / "production_model_matrix.parquet",
        gold / "session_features.parquet",
        gold / "campaign_features.parquet",
        gold / "models" / "flow-primary.joblib",
        gold / "models" / "flow-primary.metrics.json",
        gold / "models" / "M1-lightgbm.joblib",
        gold / "models" / "M1-lightgbm.metrics.json",
        gold / "models" / "shortcut-audit.json",
        quality / "production_flow_gold.json",
        quality / "v3_bronze_quality.json",
        quality / "V3_RESEARCH_DECISION.json",
        quality / "external" / "lanl" / "reference_quality.json",
        quality / "external" / "windows" / "windows_v3_fidelity.json",
    ]
    missing = [str(path.relative_to(release)) for path in required if not path.is_file() or path.stat().st_size <= 0]
    if missing:
        raise SystemExit("required V3 release files missing/empty: " + ", ".join(missing))

    if (bronze / "captures").exists() and any((bronze / "captures").rglob("*.pcap*")):
        raise SystemExit("V3 final Bronze must not retain giant merged captures")
    compressed_pcaps = list(bronze.rglob("*.pcap.zst"))
    if compressed_pcaps:
        raise SystemExit(f"corrected V3 final Bronze contains compressed PCAPs: {len(compressed_pcaps)}")
    session_pcaps = list((bronze / "sessions").rglob("*.pcap"))
    campaign_pcaps = list((bronze / "campaigns").rglob("*.pcap"))
    raw_chunks = list((bronze / "raw_chunks").glob("*.pcap"))
    if len(session_pcaps) < 990:
        raise SystemExit(f"V3 final Bronze has too few session PCAPs: {len(session_pcaps)}")
    if not campaign_pcaps:
        raise SystemExit("V3 final Bronze missing campaign PCAPs")
    if not raw_chunks:
        raise SystemExit("V3 final Bronze missing complete raw chunks")

    bronze_quality = json.loads((quality / "v3_bronze_quality.json").read_text(encoding="utf-8"))
    if not bronze_quality.get("checksums_verified") or not bronze_quality.get("full_raw_traffic_preserved_in_chunks"):
        raise SystemExit("V3 Bronze quality evidence incomplete")
    if bronze_quality.get("merged_pcap_persisted"):
        raise SystemExit("V3 Bronze quality says merged PCAP persisted")
    if bronze_quality.get("pcap_compression") != "none" or bronze_quality.get("compressed_pcaps_present") is not False:
        raise SystemExit("V3 Bronze quality does not prove raw uncompressed PCAP storage")

    out_resolved = args.out.resolve()
    files: list[dict] = []
    layer_bytes: dict[str, int] = {}
    for path in sorted(item for item in release.rglob("*") if item.is_file()):
        if path.resolve() == out_resolved:
            continue
        rel = path.relative_to(release).as_posix()
        size = int(path.stat().st_size)
        top = rel.split("/", 1)[0]
        layer_bytes[top] = layer_bytes.get(top, 0) + size
        files.append({"path": rel, "bytes": size, "sha256": sha256(path)})

    payload = {
        "schema_version": 5,
        "dataset": "remote-admin-anomaly-v3",
        "primary_unit": "suricata_eve_flow",
        "deployment_model": "gold/%s/models/M1-lightgbm.joblib" % args.shard,
        "pcap_storage": "raw_uncompressed",
        "shard": args.shard,
        "git_sha": os.environ.get("GITHUB_SHA", ""),
        "github_run_id": os.environ.get("GITHUB_RUN_ID", ""),
        "github_run_attempt": os.environ.get("GITHUB_RUN_ATTEMPT", ""),
        "dataset_release_status": decision.get("dataset_release_status"),
        "research_status": decision.get("research_status"),
        "scale_decision": decision.get("scale_decision"),
        "bronze_layout": {
            "session_pcaps": len(session_pcaps),
            "campaign_pcaps": len(campaign_pcaps),
            "raw_chunks": len(raw_chunks),
            "merged_pcap_persisted": False,
            "compression": "none",
        },
        "file_count": len(files),
        "total_bytes": sum(item["bytes"] for item in files),
        "layer_bytes": dict(sorted(layer_bytes.items())),
        "files": files,
    }
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps({
        "dataset_release_status": payload["dataset_release_status"],
        "research_status": payload["research_status"],
        "scale_decision": payload["scale_decision"],
        "primary_unit": payload["primary_unit"],
        "deployment_model": payload["deployment_model"],
        "pcap_storage": payload["pcap_storage"],
        "bronze_layout": payload["bronze_layout"],
        "file_count": payload["file_count"],
        "total_bytes": payload["total_bytes"],
        "layer_bytes": payload["layer_bytes"],
    }, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
