from adminlab.v3_persistence import expected_remote_paths


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
