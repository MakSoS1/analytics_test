from __future__ import annotations

import hashlib
from pathlib import Path

import pytest

from adminlab.v3_remote_verify import verify_downloaded_remote_tree


def _sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def test_verify_downloaded_remote_tree_checks_every_expected_object(tmp_path: Path):
    remote = tmp_path / "v3" / "final" / "run-1"
    (remote / "bronze" / "V3-1k").mkdir(parents=True)
    (remote / "gold" / "V3-1k").mkdir(parents=True)
    first=b"pcap-bytes"; second=b"gold-bytes"
    (remote / "bronze" / "V3-1k" / "a.pcap.zst").write_bytes(first)
    (remote / "gold" / "V3-1k" / "features.parquet").write_bytes(second)
    expected=[
        {"remote_path":"v3/final/run-1/bronze/V3-1k/a.pcap.zst","remote_sha256":_sha(first),"remote_bytes":len(first)},
        {"remote_path":"v3/final/run-1/gold/V3-1k/features.parquet","remote_sha256":_sha(second),"remote_bytes":len(second)},
    ]
    report=verify_downloaded_remote_tree(tmp_path, expected)
    assert report["ok"] is True
    assert report["verified_files"] == 2
    assert report["verified_bytes"] == len(first)+len(second)


def test_verify_downloaded_remote_tree_fails_on_missing_or_checksum_mismatch(tmp_path: Path):
    target=tmp_path / "v3/final/run-1/quality/V3-1k/status.json"
    target.parent.mkdir(parents=True)
    target.write_bytes(b"wrong")
    expected=[{"remote_path":"v3/final/run-1/quality/V3-1k/status.json","remote_sha256":_sha(b"right"),"remote_bytes":5}]
    with pytest.raises(RuntimeError, match="remote verification failed"):
        verify_downloaded_remote_tree(tmp_path, expected)
