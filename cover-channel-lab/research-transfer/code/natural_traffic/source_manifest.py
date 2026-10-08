"""Fail-closed, immutable source manifests for defensive MITRE research.

The manifest attests file identity and declared evidence. It does not prove
that a third party's semantic claim is true or authorize executing that claim.
"""

from __future__ import annotations

from hashlib import sha256
import json
from pathlib import Path
import re


VERSION = "defender-source-manifest-v1"
LABEL_STATES = frozenset({
    "verified_positive", "matched_control", "hard_negative",
    "unlabeled_office", "unverified_external",
})
EVIDENCE_TIERS = frozenset({"fixture_only", "operator_attested", "independently_verified"})
SOURCE_FORMATS = frozenset({".pcap", ".parquet", ".csv", ".tsv", ".jsonl"})
_SHA = re.compile(r"[a-f0-9]{64}\Z")
_MITRE = re.compile(r"T[0-9]{4}(?:\.[0-9]{3})?\Z")
_REQUIRED = (
    "source_id", "relative_path", "sha256", "label_state", "technique_ids",
    "pair_id", "parent_campaign_id", "runtime_profile_id", "capture_group_id",
    "capture_day_id", "measurement_vantage", "extractor_version", "evidence_tier",
)


def _digest(path: Path) -> str:
    hash_state = sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1 << 20), b""):
            hash_state.update(block)
    return hash_state.hexdigest()


def _reject_duplicate_keys(pairs):
    obj = {}
    for key, value in pairs:
        if key in obj:
            raise ValueError(f"duplicate JSON key {key!r}")
        obj[key] = value
    return obj


def _path_under_root(relative: str, root: Path) -> Path:
    if not isinstance(relative, str) or not relative.strip():
        raise ValueError("relative source path required")
    logical = Path(relative)
    if logical.is_absolute() or ".." in logical.parts:
        raise ValueError("path outside source root")
    resolved = (root / logical).resolve()
    if not resolved.is_relative_to(root):
        raise ValueError("path outside source root")
    if not resolved.is_file():
        raise ValueError(f"source path does not exist: {relative!r}")
    return resolved


def _require_digest(value: object, field: str) -> str:
    if not isinstance(value, str) or not _SHA.fullmatch(value):
        raise ValueError(f"invalid SHA256 for {field}")
    return value


def _require_name(value: object, field: str) -> str:
    if not isinstance(value, str) or not value.strip() or len(value) > 256:
        raise ValueError(f"missing or invalid {field}")
    return value


def load_source_manifest(path: Path, *, allowed_root: Path) -> dict:
    """Parse and authenticate source declarations within an explicit root."""
    root = Path(allowed_root).resolve(strict=True)
    p = Path(path)
    original_hash = _digest(p)
    raw = json.loads(p.read_text(encoding="utf-8"), object_pairs_hook=_reject_duplicate_keys)
    if not isinstance(raw, dict) or raw.get("version") != VERSION:
        raise ValueError(f"unsupported source manifest version; expected {VERSION}")
    entries = raw.get("sources")
    if not isinstance(entries, list) or not entries:
        raise ValueError("manifest sources must be a nonempty array")
    seen_ids = set()
    seen_pairs: dict[str, list[dict]] = {}
    canonical = []
    for source in entries:
        if not isinstance(source, dict):
            raise ValueError("manifest source must be an object")
        for key in _REQUIRED:
            if key not in source:
                raise ValueError(f"missing source field {key}")
        entry = dict(source)
        for field in _REQUIRED:
            if field not in {"sha256", "technique_ids", "relative_path", "label_state", "evidence_tier", "pair_id"}:
                _require_name(entry[field], field)
        source_id = entry["source_id"]
        if source_id in seen_ids:
            raise ValueError(f"duplicate source_id {source_id}")
        seen_ids.add(source_id)
        if entry["label_state"] not in LABEL_STATES:
            raise ValueError("unrecognized label_state")
        if entry["evidence_tier"] not in EVIDENCE_TIERS:
            raise ValueError("unrecognized evidence_tier")
        techniques = entry["technique_ids"]
        if (not isinstance(techniques, list) or
                any(not isinstance(t, str) or not _MITRE.fullmatch(t) for t in techniques) or
                len(techniques) != len(set(techniques))):
            raise ValueError("invalid MITRE technique_ids")
        labeled_pair = entry["label_state"] in {"verified_positive", "matched_control"}
        if labeled_pair != bool(techniques):
            raise ValueError("technique IDs require a verified positive/control pair")
        if labeled_pair:
            _require_name(entry["pair_id"], "pair_id")
            seen_pairs.setdefault(entry["pair_id"], []).append(entry)
        elif entry["pair_id"] not in (None, ""):
            raise ValueError("pair_id reserved for verified positive/control")
        _require_digest(entry["sha256"], "source")
        entry["path"] = _path_under_root(entry["relative_path"], root)
        if entry["path"].suffix.lower() not in SOURCE_FORMATS:
            raise ValueError("unsupported source format; use measured feature tables or classic PCAP")
        for kind in ("membership", "receipt"):
            ref, digest = f"{kind}_relative_path", f"{kind}_sha256"
            have_ref, have_digest = bool(entry.get(ref)), bool(entry.get(digest))
            if have_ref != have_digest:
                raise ValueError(f"{kind} requires both pinned relative path and SHA256")
            if have_ref:
                _require_digest(entry[digest], kind)
                entry[f"{kind}_path"] = _path_under_root(entry[ref], root)
            elif entry["label_state"] == "verified_positive" or (kind == "receipt" and entry["label_state"] == "hard_negative"):
                raise ValueError(f"{entry['label_state']} requires {kind} evidence")
        canonical.append(entry)
    for pair_id, members in seen_pairs.items():
        if len(members) != 2 or {m["label_state"] for m in members} != {"verified_positive", "matched_control"}:
            raise ValueError(f"pair {pair_id} requires one positive and one matched control")
        first, second = members
        for key in ("technique_ids", "parent_campaign_id", "runtime_profile_id", "capture_day_id",
                    "measurement_vantage", "extractor_version"):
            if first[key] != second[key]:
                raise ValueError(f"pair {pair_id} has incompatible {key}")
    result = {
        "version": VERSION,
        "manifest_path": p.resolve(),
        "manifest_sha256": original_hash,
        "allowed_root": root,
        "sources": canonical,
    }
    verify_sources(result)
    return result


def verify_sources(manifest: dict) -> None:
    """Recheck original bytes, evidence and path identity before/after use."""
    if _digest(Path(manifest["manifest_path"])) != manifest["manifest_sha256"]:
        raise ValueError("manifest SHA256 mismatch")
    root = Path(manifest["allowed_root"])
    for entry in manifest["sources"]:
        for kind in ("source", "membership", "receipt"):
            path_key = "path" if kind == "source" else f"{kind}_path"
            digest_key = "sha256" if kind == "source" else f"{kind}_sha256"
            if path_key not in entry:
                continue
            pinned_path = Path(entry[path_key])
            current = _path_under_root(entry["relative_path"] if kind == "source" else entry[f"{kind}_relative_path"], root)
            if current != pinned_path or _digest(current) != entry[digest_key]:
                raise ValueError(f"{kind} SHA256 or path identity mismatch for {entry['source_id']}")
