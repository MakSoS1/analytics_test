from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
from pathlib import Path
import re
from typing import Any

from .pcap_quality import audit_pcap


_COMMIT = re.compile(r"^[0-9a-f]{40}$")
_TECHNIQUE = re.compile(r"(?<![A-Z0-9])T\d{4}(?:\.\d{3})?(?!\d)", re.IGNORECASE)


@dataclass(frozen=True)
class ExternalReferenceSource:
    version: str
    source_id: str
    tool_repository: str
    tool_commit: str
    pcap_repository: str
    pcap_commit: str
    replay_semantics: str
    observed_pcap_count: int
    observed_techniques: tuple[str, ...]
    observed_scope: str
    license_status: str
    training_eligible: bool
    naturalness_calibration_eligible: bool
    ood_eval_eligible: bool


def load_source_descriptor(path: Path) -> ExternalReferenceSource:
    body = json.loads(Path(path).read_text())
    source = ExternalReferenceSource(
        version=str(body["version"]), source_id=str(body["source_id"]),
        tool_repository=str(body["tool_repository"]),
        tool_commit=str(body["tool_commit"]).lower(),
        pcap_repository=str(body["pcap_repository"]),
        pcap_commit=str(body["pcap_commit"]).lower(),
        replay_semantics=str(body["replay_semantics"]),
        observed_pcap_count=int(body.get("observed_pcap_count", 0)),
        observed_techniques=tuple(str(x).upper() for x in body.get("observed_techniques", [])),
        observed_scope=str(body.get("observed_scope", "")),
        license_status=str(body.get("license_status", "unverified")),
        training_eligible=bool(body.get("training_eligible", False)),
        naturalness_calibration_eligible=bool(body.get("naturalness_calibration_eligible", False)),
        ood_eval_eligible=bool(body.get("ood_eval_eligible", True)),
    )
    if not _COMMIT.fullmatch(source.tool_commit) or not _COMMIT.fullmatch(source.pcap_commit):
        raise ValueError("external references must be pinned to immutable 40-hex commits")
    if source.replay_semantics != "stateless_record_replay":
        raise ValueError("Attack Replay reference must remain explicitly stateless")
    if source.training_eligible or source.naturalness_calibration_eligible:
        raise ValueError("external replay sources cannot enter training or naturalness calibration")
    return source


def extract_mitre_technique(path: Path) -> str | None:
    match = _TECHNIQUE.search(str(path))
    return match.group(0).upper() if match else None


def _sha256(path: Path) -> str:
    h = hashlib.sha256()
    with Path(path).open("rb") as fh:
        for block in iter(lambda: fh.read(1 << 20), b""):
            h.update(block)
    return h.hexdigest()


def build_reference_manifest(
    root: Path, source: ExternalReferenceSource, *,
    max_timestamp_regression_us: float = 50,
) -> dict[str, Any]:
    base = Path(root)
    if not base.is_dir():
        raise FileNotFoundError(base)
    candidates = sorted(
        p for p in base.rglob("*")
        if p.is_file() and p.suffix.lower() in {".pcap", ".pcapng", ".cap"}
    )
    entries = []
    for path in candidates:
        quality = audit_pcap(path, max_timestamp_regression_us=max_timestamp_regression_us)
        entries.append({
            "relative_path": path.relative_to(base).as_posix(),
            "sha256": _sha256(path), "bytes": int(path.stat().st_size),
            "technique_id": extract_mitre_technique(path.relative_to(base)),
            "source_fidelity": "external_recorded_pcap",
            "replay_semantics": source.replay_semantics,
            "training_eligible": False,
            "naturalness_calibration_eligible": False,
            "ood_eval_eligible": bool(source.ood_eval_eligible and quality.accepted),
            "quality": quality.as_dict(),
        })
    accepted = sum(bool(row["quality"]["accepted"]) for row in entries)
    techniques = sorted({row["technique_id"] for row in entries if row["technique_id"]})
    return {
        "version": "natural-external-reference-v1",
        "source": {
            "source_id": source.source_id,
            "tool_repository": source.tool_repository, "tool_commit": source.tool_commit,
            "pcap_repository": source.pcap_repository, "pcap_commit": source.pcap_commit,
            "replay_semantics": source.replay_semantics,
            "license_status": source.license_status,
            "observed_scope": source.observed_scope,
        },
        "policy": {
            "training_eligible": False,
            "naturalness_calibration_eligible": False,
            "purpose": "read_only_ood_and_extractor_regression",
            "post_capture_rewrite_for_naturalness": False,
        },
        "summary": {
            "pcaps": len(entries), "accepted_quality": accepted,
            "rejected_quality": len(entries)-accepted, "techniques": techniques,
            "descriptor_observed_pcap_count": source.observed_pcap_count,
            "descriptor_observed_techniques": list(source.observed_techniques),
        },
        "entries": entries,
    }
