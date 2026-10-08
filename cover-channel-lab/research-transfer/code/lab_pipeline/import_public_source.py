"""Stage a verified public traffic source directly inside a WSL quarantine root.

Staging never makes a source eligible for training: separate WSL-local parsing,
protocol QC, provenance review, and split policy are required afterwards.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import shutil
from pathlib import Path

from lab_pipeline.public_sources import find_public_source, validate_public_source_registry


DEFAULT_WSL_ROOT = Path("/opt/tunnel_lab")


def stage_public_source(
    registry: dict,
    source_id: str,
    source_file: Path,
    *,
    wsl_root: Path = DEFAULT_WSL_ROOT,
) -> dict:
    """Copy one already-direct-downloaded WSL file into a verified quarantine.

    The source file and destination must both live below the supplied WSL root.
    No macOS path can be accepted, and the provenance manifest intentionally
    contains hashes and source metadata rather than a packet/file path.
    """
    validate_public_source_registry(registry)
    record = find_public_source(source_id, registry)
    if not record["import_allowed"]:
        raise ValueError(f"{source_id}: source is not approved for staging")
    root = wsl_root.resolve()
    source = source_file.resolve()
    _require_within_wsl(source, root)
    if not source.is_file():
        raise ValueError(f"{source_id}: source file does not exist")
    _verify_expected_checksum(source, record["expected_checksum"])

    destination_dir = root / "quarantine" / "public" / source_id
    destination_dir.mkdir(parents=True, exist_ok=True)
    destination = destination_dir / source.name
    if destination.exists():
        raise FileExistsError(f"{source_id}: quarantine destination already exists")
    shutil.copyfile(source, destination)
    source_sha256 = _digest(destination, "sha256")
    provenance = {
        "format": "full68-public-source-provenance-v1",
        "source_id": source_id,
        "families": record["families"],
        "source_kind": "public_source",
        "source_sha256": source_sha256,
        "expected_checksum_algorithm": record["expected_checksum"]["algorithm"],
        "expected_checksum_verified": True,
        "training_admission": "disabled",
    }
    manifest = destination_dir / "provenance.json"
    manifest.write_text(json.dumps(provenance, indent=2, sort_keys=True) + "\n")
    return {"staged_file": destination, "provenance_manifest": manifest}


def _require_within_wsl(path: Path, root: Path) -> None:
    try:
        path.relative_to(root)
    except ValueError as exc:
        raise ValueError("public source staging accepts WSL-local paths only") from exc


def _verify_expected_checksum(path: Path, expected: dict | None) -> None:
    if expected is None:
        raise ValueError("public source lacks an expected checksum")
    observed = _digest(path, expected["algorithm"])
    if observed != expected["value"]:
        raise ValueError("public source checksum mismatch")


def _digest(path: Path, algorithm: str) -> str:
    hasher = hashlib.new(algorithm)
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            hasher.update(block)
    return hasher.hexdigest()


def _parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--registry", type=Path, required=True)
    parser.add_argument("--source-id", required=True)
    parser.add_argument("--source-file", type=Path, required=True)
    parser.add_argument("--wsl-root", type=Path, default=DEFAULT_WSL_ROOT)
    return parser.parse_args()


if __name__ == "__main__":
    args = _parse_args()
    registry = json.loads(args.registry.read_text())
    result = stage_public_source(registry, args.source_id, args.source_file, wsl_root=args.wsl_root)
    print(json.dumps({key: str(value) for key, value in result.items()}))
