import importlib.util
from pathlib import Path

import pytest


def _module():
    root = Path(__file__).resolve().parents[1]
    spec = importlib.util.spec_from_file_location("verify_v3_hf_test", root / "scripts/verify_v3_hf.py")
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_snapshot_retry_reuses_local_dir_and_limits_concurrency(tmp_path):
    module = _module()
    calls = []

    def fake_snapshot(**kwargs):
        calls.append(kwargs)
        if len(calls) < 3:
            raise ConnectionError("429 Too Many Requests from xet-read-token")
        return str(tmp_path)

    delays = []
    result = module.download_snapshot_with_retries(
        snapshot_fn=fake_snapshot,
        repo_id="owner/repo",
        token="secret",
        prefix="v3/final/run-1",
        local_dir=tmp_path,
        attempts=3,
        sleep_fn=delays.append,
    )

    assert result == str(tmp_path)
    assert len(calls) == 3
    assert all(call["local_dir"] == tmp_path for call in calls)
    assert all(call["force_download"] is False for call in calls)
    assert all(call["max_workers"] == 2 for call in calls)
    assert delays == [10, 30]


def test_snapshot_retry_does_not_hide_non_rate_limit_failures(tmp_path):
    module = _module()

    def fake_snapshot(**kwargs):
        raise RuntimeError("repository not found")

    with pytest.raises(RuntimeError, match="repository not found"):
        module.download_snapshot_with_retries(
            snapshot_fn=fake_snapshot,
            repo_id="owner/repo",
            token="secret",
            prefix="v3/final/run-1",
            local_dir=tmp_path,
            attempts=3,
            sleep_fn=lambda _: None,
        )
