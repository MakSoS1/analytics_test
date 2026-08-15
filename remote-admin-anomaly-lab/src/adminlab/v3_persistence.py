from __future__ import annotations

from typing import Any


def _normalize(path: str) -> str:
    return str(path).strip().strip("/")


def expected_remote_paths(
    manifest: dict[str, Any],
    upload_status: dict[str, Any],
    *,
    shard: str,
    remote_prefix: str,
) -> list[dict[str, Any]]:
    """Map authoritative release-manifest files to their expected HF objects.

    Most files are persisted byte-for-byte under ``remote_prefix``. Lossless
    transport transformations are declared by the uploader relative to the
    layer/shard root; the expected remote checksum/size describes the stored
    representation while the release manifest remains authoritative locally.
    """
    shard = _normalize(shard)
    prefix = _normalize(remote_prefix)
    if not shard or not prefix:
        raise ValueError("shard and remote_prefix must be non-empty")

    transforms: dict[str, dict[str, Any]] = {}
    for item in upload_status.get("transport_transforms", []) or []:
        original = _normalize(item.get("original_path", ""))
        stored = _normalize(item.get("stored_path", ""))
        if not original or not stored:
            raise ValueError("transport transform requires original_path and stored_path")
        transforms[original] = dict(item)

    rows: list[dict[str, Any]] = []
    seen_remote: set[str] = set()
    marker = f"/{shard}/"
    for file_row in manifest.get("files", []) or []:
        local = _normalize(file_row.get("path", ""))
        if not local:
            raise ValueError("release manifest contains empty file path")
        if marker not in f"/{local}":
            continue
        layer, remainder = local.split(f"/{shard}/", 1)
        layer = _normalize(layer)
        remainder = _normalize(remainder)
        if not layer or not remainder:
            raise ValueError(f"invalid shard file path: {local}")

        transform = transforms.get(remainder) if layer == "quality" else None
        if transform is not None:
            remote_remainder = _normalize(transform["stored_path"])
            remote_sha = str(transform.get("stored_sha256", ""))
            remote_bytes = int(transform.get("stored_bytes", 0))
            transport = str(transform.get("transform", "lossless_transform"))
        else:
            remote_remainder = remainder
            remote_sha = str(file_row.get("sha256", ""))
            remote_bytes = int(file_row.get("bytes", 0))
            transport = "identity"

        if len(remote_sha) != 64:
            raise ValueError(f"invalid expected sha256 for {local}")
        if remote_bytes < 0:
            raise ValueError(f"invalid expected byte count for {local}")

        remote = f"{prefix}/{layer}/{shard}/{remote_remainder}"
        if remote in seen_remote:
            raise ValueError(f"duplicate expected remote path: {remote}")
        seen_remote.add(remote)
        rows.append(
            {
                "local_path": local,
                "local_sha256": str(file_row.get("sha256", "")),
                "local_bytes": int(file_row.get("bytes", 0)),
                "remote_path": remote,
                "remote_sha256": remote_sha,
                "remote_bytes": remote_bytes,
                "transport": transport,
            }
        )

    if not rows:
        raise ValueError(f"release manifest contains no files for shard {shard}")
    return rows


def build_verified_release_status(
    decision: dict[str, Any],
    hf_verification: dict[str, Any],
    *,
    github_final_run_id: int,
    github_final_artifact_id: int,
    github_artifact_verified: bool,
) -> dict[str, Any]:
    """Create the only status object authorized to unlock destructive cleanup."""
    failures: list[str] = []
    if decision.get("dataset_release_status") != "READY":
        failures.append("dataset_release_status")
    if hf_verification.get("status") != "PASS" or hf_verification.get("full_remote_download_verified") is not True:
        failures.append("hf_verification")
    remote_prefix = _normalize(hf_verification.get("remote_prefix", ""))
    if not remote_prefix.startswith("v3/final/"):
        failures.append("hf_final_path")
    try:
        run_id = int(github_final_run_id)
        artifact_id = int(github_final_artifact_id)
    except (TypeError, ValueError):
        run_id = artifact_id = 0
    if run_id <= 0:
        failures.append("github_final_run_id")
    if artifact_id <= 0:
        failures.append("github_final_artifact_id")
    if github_artifact_verified is not True:
        failures.append("github_artifact_verified")
    if failures:
        raise RuntimeError("V3 verified release status failed: " + ",".join(failures))

    return {
        "schema_version": 3,
        "dataset_release_status": "READY",
        "technical_status": "READY",
        "research_status": str(decision.get("research_status", "UNKNOWN")),
        "scale_decision": str(decision.get("scale_decision", "STOP_AT_1K")),
        "hf_verified": True,
        "hf_final_path": remote_prefix,
        "hf_verified_files": int(hf_verification.get("verified_files", 0)),
        "hf_verified_bytes": int(hf_verification.get("verified_bytes", 0)),
        "github_artifact_verified": True,
        "github_final_run_id": run_id,
        "github_final_artifact_id": artifact_id,
        "cleanup_policy": "B_after_verified_v3_only",
    }
