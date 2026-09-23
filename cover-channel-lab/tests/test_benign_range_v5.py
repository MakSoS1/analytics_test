from __future__ import annotations

from types import SimpleNamespace

from coverlab import orchestrate_v3 as ov3


def _collect(monkeypatch, tmp_path, start: int, end: int) -> list[str]:
    seen: list[str] = []

    def fake_invoke(
        scenario_id,
        suspicious,
        seed,
        campaign_id,
        run_id,
        persona,
        source_ip,
        event_count,
        manifest,
        events_out,
        capture_file,
        config,
    ):
        seen.append(str(campaign_id))

    monkeypatch.setattr(ov3._base, "invoke", fake_invoke)
    monkeypatch.setenv("COVERLAB_BENIGN_RANGE_START", str(start))
    monkeypatch.setenv("COVERLAB_BENIGN_RANGE_END", str(end))
    monkeypatch.setenv("COVERLAB_NETEM_PROFILE", "wan_80ms")
    args = SimpleNamespace(
        sessions=100,
        shards=10,
        shard=7,
        seed=23,
        capture_file="capture.pcap",
    )
    ov3.benign_stage(args, tmp_path / "campaigns.jsonl", tmp_path / "events.jsonl")
    return seen


def test_problematic_shard_can_be_split_without_changing_campaign_ids(monkeypatch, tmp_path):
    left = _collect(monkeypatch, tmp_path, 0, 50)
    right = _collect(monkeypatch, tmp_path, 50, 100)
    combined = left + right
    expected = [f"k-{i:07d}" for i in range(100) if i % 10 == 7]

    assert left == [f"k-{i:07d}" for i in range(50) if i % 10 == 7]
    assert right == [f"k-{i:07d}" for i in range(50, 100) if i % 10 == 7]
    assert combined == expected
    assert len(combined) == len(set(combined))


def test_invalid_benign_range_is_rejected(monkeypatch, tmp_path):
    monkeypatch.setenv("COVERLAB_BENIGN_RANGE_START", "80")
    monkeypatch.setenv("COVERLAB_BENIGN_RANGE_END", "20")
    args = SimpleNamespace(sessions=100, shards=10, shard=7, seed=23, capture_file="capture.pcap")

    try:
        ov3.benign_stage(args, tmp_path / "campaigns.jsonl", tmp_path / "events.jsonl")
    except ValueError as exc:
        assert "invalid benign range" in str(exc)
    else:
        raise AssertionError("invalid benign range was accepted")
