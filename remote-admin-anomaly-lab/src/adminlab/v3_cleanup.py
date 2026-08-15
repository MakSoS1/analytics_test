from __future__ import annotations

from typing import Any, Iterable


REMOTE_ADMIN_BRANCHES = {
    "remote-admin-anomaly-lab-v1",
    "remote-admin-anomaly-lab-v2",
    "remote-admin-anomaly-lab-v3",
}
ROOT_HF_METADATA = {"README.md", ".gitattributes"}


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


def select_github_run_ids_for_cleanup(
    runs: Iterable[dict[str, Any]],
    *,
    final_run_id: int,
    current_run_id: int,
) -> list[int]:
    """Return only superseded Remote Admin Action run ids, never unrelated CI."""
    preserve = {int(final_run_id), int(current_run_id)}
    selected: set[int] = set()
    for run in runs:
        try:
            run_id = int(run.get("id", 0))
        except (TypeError, ValueError):
            continue
        if run_id <= 0 or run_id in preserve:
            continue
        branch = str(run.get("head_branch", ""))
        workflow_path = str(run.get("path", "")).lower()
        if branch not in REMOTE_ADMIN_BRANCHES:
            continue
        if "remote-admin" not in workflow_path:
            continue
        selected.add(run_id)
    return sorted(selected)


def select_hf_paths_for_cleanup(files: Iterable[str], *, retained_prefix: str) -> list[str]:
    """Delete all superseded dataset payloads while retaining one V3 final tree.

    The remote-admin HF repository is dedicated to this dataset lineage. Root
    README/.gitattributes remain; every payload object outside the verified final
    V3 prefix is superseded by user-authorized cleanup policy B.
    """
    prefix = str(retained_prefix).strip("/")
    if not prefix.startswith("v3/final/"):
        raise ValueError("retained_prefix must be a V3 final path")
    selected: list[str] = []
    for raw in files:
        path = str(raw).strip("/")
        if not path or path in ROOT_HF_METADATA:
            continue
        if path == prefix or path.startswith(prefix + "/"):
            continue
        selected.append(path)
    return sorted(set(selected))
