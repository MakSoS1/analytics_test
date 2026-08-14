from __future__ import annotations

import hashlib
import json
from pathlib import Path


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _parse_checksums(path: Path) -> dict[str, str]:
    result: dict[str, str] = {}
    for line in path.read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        parts = line.split(maxsplit=1)
        if len(parts) != 2:
            continue
        digest, rel = parts
        result[rel.lstrip("* ")] = digest
    return result


def validate_bronze_tree(shard_dir: Path | str, *, verify_checksums: bool = True) -> dict:
    shard = Path(shard_dir)
    errors: list[str] = []
    captures = sorted((shard / "captures").glob("*.pcap.zst")) if (shard / "captures").is_dir() else []
    if len(captures) != 1:
        errors.append(f"expected exactly one compressed capture, found {len(captures)}")
        pcap_bytes = 0
    else:
        pcap_bytes = captures[0].stat().st_size
        if pcap_bytes <= 0:
            errors.append("capture is empty")

    required = [
        shard / "manifests/sessions.jsonl",
        shard / "reproducibility.json",
        shard / "checksums.sha256",
    ]
    for path in required:
        if not path.is_file() or path.stat().st_size <= 0:
            errors.append(f"missing or empty required Bronze file: {path.relative_to(shard)}")

    checksum_checked = 0
    if verify_checksums and (shard / "checksums.sha256").is_file():
        expected = _parse_checksums(shard / "checksums.sha256")
        if not expected:
            errors.append("checksums.sha256 contains no entries")
        for rel, digest in expected.items():
            target = shard / rel
            if not target.is_file():
                errors.append(f"checksum target missing: {rel}")
                continue
            checksum_checked += 1
            if _sha256(target) != digest:
                errors.append(f"checksum mismatch: {rel}")

    return {
        "ok": not errors,
        "errors": errors,
        "pcap_bytes": pcap_bytes,
        "checksum_entries_verified": checksum_checked,
        "shard": shard.name,
    }


def validate_silver_tree(shard_dir: Path | str) -> dict:
    shard = Path(shard_dir)
    errors: list[str] = []
    eve = shard / "suricata/eve.json.zst"
    conn = shard / "zeek/conn.log.zst"
    versions = shard / "parser_versions.json"

    eve_bytes = eve.stat().st_size if eve.is_file() else 0
    conn_bytes = conn.stat().st_size if conn.is_file() else 0
    if eve_bytes <= 0:
        errors.append("missing or empty Suricata eve.json.zst")
    if conn_bytes <= 0:
        errors.append("missing or empty Zeek conn.log.zst")
    if not versions.is_file() or versions.stat().st_size <= 0:
        errors.append("missing or empty parser_versions.json")
    else:
        try:
            payload = json.loads(versions.read_text(encoding="utf-8"))
            if not payload.get("suricata"):
                errors.append("Suricata version missing")
            if not payload.get("zeek"):
                errors.append("Zeek version missing")
        except (json.JSONDecodeError, OSError):
            errors.append("invalid parser_versions.json")

    return {
        "ok": not errors,
        "errors": errors,
        "eve_bytes": eve_bytes,
        "conn_bytes": conn_bytes,
        "shard": shard.name,
    }


def validate_gold_tree(shard_dir: Path | str) -> dict:
    shard = Path(shard_dir)
    names = [
        "flow_features.parquet",
        "window_features.parquet",
        "graph_features.parquet",
        "splits.parquet",
        "labels.parquet",
        "model_matrix.parquet",
        "feature_contract.json",
    ]
    errors: list[str] = []
    total_bytes = 0
    for name in names:
        path = shard / name
        if not path.is_file() or path.stat().st_size <= 0:
            errors.append(f"missing or empty Gold file: {name}")
        else:
            total_bytes += path.stat().st_size

    contract = shard / "feature_contract.json"
    if contract.is_file() and contract.stat().st_size > 0:
        try:
            payload = json.loads(contract.read_text(encoding="utf-8"))
            if not payload.get("feature_contract_sha256"):
                errors.append("feature_contract_sha256 missing from feature_contract.json")
            if not payload.get("feature_contract_version"):
                errors.append("feature_contract_version missing from feature_contract.json")
        except (json.JSONDecodeError, OSError):
            errors.append("invalid feature_contract.json")

    return {
        "ok": not errors,
        "errors": errors,
        "required_files": len(names),
        "gold_bytes": total_bytes,
        "shard": shard.name,
    }
