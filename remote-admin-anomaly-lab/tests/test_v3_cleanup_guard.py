import pytest

from adminlab.v3_cleanup import (
    select_github_run_ids_for_cleanup,
    select_hf_paths_for_cleanup,
    validate_cleanup_preconditions,
)


def _status():
    return {
        "dataset_release_status": "READY",
        "technical_status": "READY",
        "hf_verified": True,
        "github_artifact_verified": True,
        "hf_final_path": "v3/final/run-123",
        "github_final_artifact_id": 999,
    }


def test_cleanup_refuses_unverified_hf():
    value = _status(); value["hf_verified"] = False
    with pytest.raises(RuntimeError):
        validate_cleanup_preconditions(value)


def test_cleanup_refuses_unverified_github_artifact():
    value = _status(); value["github_artifact_verified"] = False
    with pytest.raises(RuntimeError):
        validate_cleanup_preconditions(value)


def test_cleanup_refuses_non_v3_final_path():
    value = _status(); value["hf_final_path"] = "v2/quarantine/run-1"
    with pytest.raises(RuntimeError):
        validate_cleanup_preconditions(value)


def test_cleanup_accepts_only_fully_verified_v3_release():
    result = validate_cleanup_preconditions(_status())
    assert result["allowed"] is True
    assert result["retained_hf_prefix"] == "v3/final/run-123"
    assert result["retained_github_artifact_id"] == 999


def test_cleanup_selects_only_remote_admin_old_runs_and_preserves_final_and_current():
    runs = [
        {"id": 1, "head_branch": "remote-admin-anomaly-lab-v1", "path": ".github/workflows/remote-admin-v4-final.yml"},
        {"id": 2, "head_branch": "remote-admin-anomaly-lab-v2", "path": ".github/workflows/remote-admin-v2-smoke.yml"},
        {"id": 3, "head_branch": "remote-admin-anomaly-lab-v3", "path": ".github/workflows/remote-admin-v3-smoke.yml"},
        {"id": 123, "head_branch": "remote-admin-anomaly-lab-v3", "path": ".github/workflows/remote-admin-v3-release.yml"},
        {"id": 124, "head_branch": "remote-admin-anomaly-lab-v3", "path": ".github/workflows/remote-admin-v3-cleanup.yml"},
        {"id": 9, "head_branch": "main", "path": ".github/workflows/mbi-hourly-monitor.yml"},
    ]
    assert select_github_run_ids_for_cleanup(runs, final_run_id=123, current_run_id=124) == [1, 2, 3]


def test_cleanup_hf_selection_preserves_only_root_metadata_and_final_v3_prefix():
    files = [
        ".gitattributes",
        "README.md",
        "releases/31818445960/bronze/a.pcap.zst",
        "v2/quarantine/run-5/gold/x.parquet",
        "v3/candidates/run-10/gold/y.parquet",
        "v3/final/run-123/bronze/V3-1k/sessions/benign/ssh/a.pcap.zst",
        "v3/final/run-123/quality/V3-1k/V3_RESEARCH_DECISION.json",
    ]
    assert select_hf_paths_for_cleanup(files, retained_prefix="v3/final/run-123") == [
        "releases/31818445960/bronze/a.pcap.zst",
        "v2/quarantine/run-5/gold/x.parquet",
        "v3/candidates/run-10/gold/y.parquet",
    ]
