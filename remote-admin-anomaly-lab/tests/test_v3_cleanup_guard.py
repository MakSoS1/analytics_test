import pytest

from adminlab.v3_cleanup import validate_cleanup_preconditions


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
