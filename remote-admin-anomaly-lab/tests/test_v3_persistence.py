import pytest

from adminlab.v3_persistence import build_verified_release_status, expected_remote_paths


def test_expected_remote_paths_apply_lossless_transport_mapping():
    manifest = {
        "files": [
            {"path": "bronze/V3-1k/sessions/benign/ssh/s1.pcap.zst", "sha256": "a" * 64, "bytes": 10},
            {"path": "quality/V3-1k/external/windows/capture.txt", "sha256": "b" * 64, "bytes": 20},
            {"path": "gold/V3-1k/session_features.parquet", "sha256": "c" * 64, "bytes": 30},
        ]
    }
    upload = {
        "transport_transforms": [{
            "original_path": "external/windows/capture.txt",
            "stored_path": "external/windows/capture.txt.gz",
            "stored_sha256": "d" * 64,
            "stored_bytes": 12,
        }]
    }
    rows = expected_remote_paths(manifest, upload, shard="V3-1k", remote_prefix="v3/final/run-123")
    by_local = {row["local_path"]: row for row in rows}
    transformed = by_local["quality/V3-1k/external/windows/capture.txt"]
    assert transformed["remote_path"] == "v3/final/run-123/quality/V3-1k/external/windows/capture.txt.gz"
    assert transformed["remote_sha256"] == "d" * 64
    normal = by_local["bronze/V3-1k/sessions/benign/ssh/s1.pcap.zst"]
    assert normal["remote_path"] == "v3/final/run-123/bronze/V3-1k/sessions/benign/ssh/s1.pcap.zst"
    assert normal["remote_sha256"] == "a" * 64


def test_verified_release_status_requires_ready_decision_hf_and_github_artifact():
    decision={"dataset_release_status":"READY","research_status":"FAIL","scale_decision":"STOP_AT_1K"}
    hf={"status":"PASS","full_remote_download_verified":True,"remote_prefix":"v3/final/run-123","verified_files":500}
    value=build_verified_release_status(decision,hf,github_final_run_id=123,github_final_artifact_id=999,github_artifact_verified=True)
    assert value["technical_status"] == "READY"
    assert value["hf_verified"] is True
    assert value["github_artifact_verified"] is True
    assert value["research_status"] == "FAIL"
    assert value["hf_final_path"] == "v3/final/run-123"


def test_verified_release_status_fails_closed_when_hf_not_verified():
    decision={"dataset_release_status":"READY","research_status":"PASS","scale_decision":"ALLOW_4K"}
    with pytest.raises(RuntimeError):
        build_verified_release_status(
            decision,
            {"status":"FAIL","full_remote_download_verified":False,"remote_prefix":"v3/final/run-1"},
            github_final_run_id=1,
            github_final_artifact_id=2,
            github_artifact_verified=True,
        )
