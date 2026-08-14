from __future__ import annotations

from typing import Any


def validate_cleanup_preconditions(status: dict[str, Any]) -> dict[str, Any]:
    """Validate irreversible V1/V2 cleanup preconditions.

    Cleanup is storage-only and is permitted after a technically complete V3
    release is independently verified on both persistence backends. Research
    PASS is intentionally not required: a scientifically negative V3 release can
    still replace superseded V1/V2 storage if it is complete/reproducible.
    """
    failures: list[str] = []
    if status.get("dataset_release_status") != "READY":
        failures.append("dataset_release_status")
    if status.get("technical_status") != "READY":
        failures.append("technical_status")
    if status.get("hf_verified") is not True:
        failures.append("hf_verified")
    if status.get("github_artifact_verified") is not True:
        failures.append("github_artifact_verified")

    hf_path = str(status.get("hf_final_path", "")).strip("/")
    if not hf_path.startswith("v3/final/") or hf_path.count("/") < 2:
        failures.append("hf_final_path")
    artifact_id = status.get("github_final_artifact_id")
    try:
        artifact_id_int = int(artifact_id)
    except (TypeError, ValueError):
        artifact_id_int = 0
    if artifact_id_int <= 0:
        failures.append("github_final_artifact_id")

    if failures:
        raise RuntimeError("V3 cleanup preconditions failed: " + ",".join(failures))
    return {
        "allowed": True,
        "retained_hf_prefix": hf_path,
        "retained_github_artifact_id": artifact_id_int,
        "policy": "delete superseded Remote Admin V1/V2 storage only; preserve verified V3 final and unrelated repository workflows/artifacts",
    }
