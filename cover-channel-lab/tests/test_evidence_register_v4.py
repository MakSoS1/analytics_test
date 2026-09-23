from pathlib import Path

import pytest

from coverlab.evidence_register_v4 import (
    register_ech,
    register_environment,
    register_framework,
    register_long_timing,
    register_office,
)
from coverlab.framework_holdout_v3 import validate_source
from coverlab.framework_metrics_v4 import build as build_framework_metrics
from coverlab.ech_v3 import validate_ech_import
from coverlab.environment_evidence_v3 import validate as validate_environment
from coverlab.long_timing_evidence_v4 import validate as validate_long_timing


def _pcap(tmp_path: Path, name: str) -> Path:
    p = tmp_path / name
    p.write_bytes(b"pcap-fixture-" + b"x" * 64)
    return p


def test_framework_registration_is_challenge_only(tmp_path):
    root = tmp_path / "external"
    register_framework(
        root,
        _pcap(tmp_path, "sliver.pcap"),
        framework="sliver",
        campaign_id="j-sliver-safe-1",
        protocol="https",
        lifecycle=["registration", "idle", "poll", "synthetic_task", "synthetic_result", "sleep", "reconnect"],
        tool_version="test",
        adapter_version="test",
        source_ip="10.77.0.21",
        started_at="2026-09-22T10:00:00Z",
        ended_at="2026-09-22T10:01:00Z",
        model_score=0.99,
        decision_threshold=0.5,
    )
    rows, errors = validate_source(root / "framework")
    assert errors == []
    assert rows[0]["training_eligible"] is False
    assert rows[0]["post_exploitation"] is False
    assert rows[0]["wire_real"] is True
    metrics = build_framework_metrics(root / "framework")
    assert metrics["sliver"]["status"] == "ok"
    assert metrics["sliver"]["recall"] == 1.0


def test_ech_registration_enforces_benign_ech_semantics(tmp_path):
    root = tmp_path / "external"
    register_ech(root, _pcap(tmp_path, "ech.pcap"), capture_id="e1", ech_mode="accepted_h3", pair_id="p1", label_binary=0, protocol="h3", source_ip="10.77.0.31", started_at="2026-09-22T10:00:00Z", ended_at="2026-09-22T10:00:10Z", ech_enabled=True, model_score=.01, decision_threshold=.5)
    report = validate_ech_import(root / "ech")
    assert report["records"] == 1
    with pytest.raises(ValueError):
        register_ech(root, _pcap(tmp_path, "bad.pcap"), capture_id="e2", ech_mode="accepted_h3", pair_id="p2", label_binary=1, protocol="h3", source_ip="10.77.0.31", started_at="2026-09-22T10:00:00Z", ended_at="2026-09-22T10:00:10Z", ech_enabled=True, model_score=.9, decision_threshold=.5)


def test_environment_registration_is_wire_real_and_holdout(tmp_path):
    root = tmp_path / "external"
    register_environment(root, _pcap(tmp_path, "env.pcap"), capture_id="env-1", session_count=10, client_stack="chromium", network_evidence="nat")
    report = validate_environment(root / "environment")
    assert report["records"] == 1
    assert report["training_eligible"] is False


def test_long_timing_registration_uses_real_intervals(tmp_path):
    root = tmp_path / "external"
    register_long_timing(
        root,
        _pcap(tmp_path, "long1.pcap"),
        campaign_id="l-1200-benign",
        interval_seconds=1200,
        event_count=5,
        label_binary=0,
        protocol="https",
        source_ip="10.77.0.41",
        started_at="2026-09-22T10:00:00Z",
        ended_at="2026-09-22T11:40:00Z",
    )
    register_long_timing(
        root,
        _pcap(tmp_path, "long2.pcap"),
        campaign_id="l-1200-positive",
        interval_seconds=1200,
        event_count=5,
        label_binary=1,
        protocol="https",
        source_ip="10.77.0.42",
        started_at="2026-09-22T12:00:00Z",
        ended_at="2026-09-22T13:40:00Z",
    )
    report = validate_long_timing(root / "long-timing")
    assert report["records"] == 2
    assert report["coverage"]["1200"]["ready"] is True


def test_office_requires_privacy_scrub(tmp_path):
    root = tmp_path / "external"
    with pytest.raises(ValueError):
        register_office(root, _pcap(tmp_path, "office.pcap"), capture_id="office-1", duration_seconds=3600, session_count=100, privacy_scrubbed=False)
    rec = register_office(root, _pcap(tmp_path, "office-ok.pcap"), capture_id="office-2", duration_seconds=3600, session_count=100, privacy_scrubbed=True)
    assert rec["training_eligible"] is False
    assert rec["privacy_scrubbed"] is True


def test_framework_registration_rejects_public_source_ip(tmp_path):
    root = tmp_path / "external"
    with pytest.raises(ValueError):
        register_framework(
            root,
            _pcap(tmp_path, "public.pcap"),
            framework="sliver",
            campaign_id="j-public-rejected",
            protocol="https",
            lifecycle=["registration", "idle", "poll"],
            tool_version="test",
            adapter_version="test",
            source_ip="8.8.8.8",
            started_at="2026-09-22T10:00:00Z",
            ended_at="2026-09-22T10:01:00Z",
        )
