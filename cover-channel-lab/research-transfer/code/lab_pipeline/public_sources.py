"""Portable contract for public traffic-source provenance and admissibility."""
from __future__ import annotations

import hashlib
import json
import re
from pathlib import Path

from lab_pipeline.full_scope import load_full_scope, required_families, validate_scope


PUBLIC_SOURCE_REGISTRY_PATH = Path(__file__).resolve().parent.parent / "docs" / "public_source_registry.json"
PUBLIC_SOURCE_REGISTRY_FORMAT = "full68-public-source-registry-v1"
SOURCE_STATUSES = frozenset({"research_only", "queued", "accepted", "rejected"})
IMPORTABLE_FORMATS = frozenset({"pcap", "pcapng", "archive"})
KNOWN_FORMATS = IMPORTABLE_FORMATS | frozenset({"feature_csv", "measurement_zip", "unknown_pcap_layout"})
_ROW_FIELDS = frozenset({
    "source_id",
    "status",
    "source_url",
    "download_url",
    "terms_url",
    "families",
    "expected_format",
    "expected_checksum",
    "purpose",
    "import_allowed",
    "rejection_reason",
})
_SOURCE_ID = re.compile(r"^[a-z][a-z0-9_]{2,63}$")


def load_public_source_registry(path: Path = PUBLIC_SOURCE_REGISTRY_PATH, scope: dict | None = None) -> dict:
    """Load a registry containing source metadata only, never traffic bytes."""
    registry = json.loads(path.read_text())
    validate_public_source_registry(registry, scope)
    return registry


def validate_public_source_registry(registry: dict, scope: dict | None = None) -> None:
    """Reject a source that lacks the provenance required for WSL-only staging."""
    checked_scope = load_full_scope() if scope is None else scope
    validate_scope(checked_scope)
    if not isinstance(registry, dict) or registry.get("format") != PUBLIC_SOURCE_REGISTRY_FORMAT:
        raise ValueError("unexpected public source registry format")
    rows = registry.get("sources")
    if not isinstance(rows, list):
        raise ValueError("public source registry sources must be a list")
    source_ids: list[str] = []
    canonical = set(required_families(checked_scope))
    for row in rows:
        if not isinstance(row, dict) or set(row) != _ROW_FIELDS:
            raise ValueError("every public source row must contain the complete contract")
        source_id = row["source_id"]
        if not isinstance(source_id, str) or not _SOURCE_ID.fullmatch(source_id):
            raise ValueError("public source_id must be a stable snake_case identifier")
        source_ids.append(source_id)
        if row["status"] not in SOURCE_STATUSES:
            raise ValueError(f"{source_id}: invalid source status")
        for field in ("source_url", "terms_url"):
            if not isinstance(row[field], str) or not row[field].startswith("https://"):
                raise ValueError(f"{source_id}: {field} must be an HTTPS URL")
        if not isinstance(row["download_url"], str) or (row["download_url"] and not row["download_url"].startswith("https://")):
            raise ValueError(f"{source_id}: download_url must be empty or HTTPS")
        families = row["families"]
        if not isinstance(families, list) or not families or not all(isinstance(family, str) for family in families):
            raise ValueError(f"{source_id}: families must be a non-empty list")
        if not set(families) <= canonical:
            raise ValueError(f"{source_id}: sources may use only canonical full68 labels")
        if row["expected_format"] not in KNOWN_FORMATS:
            raise ValueError(f"{source_id}: unknown expected format")
        _validate_checksum(source_id, row["expected_checksum"])
        if not isinstance(row["purpose"], str) or not row["purpose"]:
            raise ValueError(f"{source_id}: purpose must be non-empty")
        if not isinstance(row["import_allowed"], bool):
            raise ValueError(f"{source_id}: import_allowed must be boolean")
        if not isinstance(row["rejection_reason"], str):
            raise ValueError(f"{source_id}: rejection_reason must be a string")
        if row["import_allowed"]:
            if row["status"] not in {"queued", "accepted"}:
                raise ValueError(f"{source_id}: import_allowed requires queued or accepted status")
            if not row["terms_url"]:
                raise ValueError(f"{source_id}: import_allowed requires terms_url")
            if not row["download_url"] or row["expected_format"] not in IMPORTABLE_FORMATS:
                raise ValueError(f"{source_id}: import_allowed requires an importable direct download")
            if row["expected_checksum"] is None:
                raise ValueError(f"{source_id}: import_allowed requires expected_checksum")
        elif row["status"] == "rejected" and not row["rejection_reason"]:
            raise ValueError(f"{source_id}: rejected sources require a rejection_reason")
    if len(source_ids) != len(set(source_ids)):
        raise ValueError("public source IDs must be unique")


def find_public_source(source_id: str, registry: dict | None = None) -> dict:
    """Return one validated source record without changing its admissibility."""
    checked_registry = load_public_source_registry() if registry is None else registry
    validate_public_source_registry(checked_registry)
    for row in checked_registry["sources"]:
        if row["source_id"] == source_id:
            return row
    raise ValueError(f"unknown public source {source_id!r}")


def _validate_checksum(source_id: str, checksum: object) -> None:
    if checksum is None:
        return
    if not isinstance(checksum, dict) or set(checksum) != {"algorithm", "value"}:
        raise ValueError(f"{source_id}: invalid expected_checksum")
    algorithm = checksum["algorithm"]
    if algorithm not in {"md5", "sha256"}:
        raise ValueError(f"{source_id}: unsupported expected_checksum algorithm")
    value = checksum["value"]
    expected_length = hashlib.new(algorithm).digest_size * 2
    if not isinstance(value, str) or not re.fullmatch(r"[0-9a-f]{%d}" % expected_length, value):
        raise ValueError(f"{source_id}: invalid expected_checksum value")
