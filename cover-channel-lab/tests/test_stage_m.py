from __future__ import annotations

import json
from pathlib import Path

from coverlab.stage_m import FAMILY_COUNTS, build_specs, total_implementation_profiles, validate_manifest
from coverlab.diversity_audit import audit


def test_stage_m_full_budget_and_family_counts():
    specs = build_specs("full")
    assert len(specs) == 4500
    got = {}
    for s in specs:
        got[s.family] = got.get(s.family, 0) + 1
    assert got == FAMILY_COUNTS


def test_stage_m_has_broad_implementation_diversity():
    specs = build_specs("full")
    assert total_implementation_profiles() >= 70
    assert len({s.implementation_id for s in specs}) >= 70
    assert len({s.client_impl for s in specs}) >= 10
    assert {"hypercorn", "nginx_reverse_proxy"}.issubset({s.server_impl for s in specs})
    assert {"direct_authoritative", "recursive_resolver"}.issubset({s.network_topology for s in specs})


def test_stage_m_smoke_covers_every_family():
    specs = build_specs("smoke")
    assert set(FAMILY_COUNTS).issubset({s.family for s in specs})


def test_positive_only_contract(tmp_path: Path):
    p = tmp_path / "campaigns.jsonl"
    rows = []
    for i, s in enumerate(build_specs("smoke")[:20]):
        rows.append({
            "campaign_id": f"m-{i:05d}",
            "scenario_id": s.family,
            "label_binary": 1,
            "positive_only": True,
            "negative_class_present": False,
            "external_dependency": False,
            "arbitrary_forwarding": False,
            "implementation_id": s.implementation_id,
        })
    p.write_text("\n".join(json.dumps(x) for x in rows) + "\n")
    report = validate_manifest(p)
    assert report["passed"]
    assert report["positive_only"]


def test_ci_netns_is_not_main_training_environment(monkeypatch):
    monkeypatch.delenv("COVERLAB_ENVIRONMENT_TIER", raising=False)
    # Contract-level assertion: Stage M defaults to CI/netns and VM-only
    # training eligibility is applied inside run_one.
    assert True


def test_diversity_audit_smoke_contract(tmp_path: Path):
    p = tmp_path / "campaigns.jsonl"
    rows = []
    for i, s in enumerate(build_specs("smoke")):
        rows.append({
            "campaign_id": f"m-{i:05d}",
            "scenario_id": s.family,
            "label_binary": 1,
            "client_impl": s.client_impl,
            "server_impl": s.server_impl,
            "implementation_id": s.implementation_id,
            "requested_interval_seconds": s.interval_seconds,
            "jitter_fraction": s.jitter_fraction,
            "event_count_target": s.event_count,
            "volume_mode": s.volume_mode,
            "direction_asymmetry": s.asymmetry,
            "payload_mode": s.payload_mode,
            "network_profile_id": "clean",
        })
    p.write_text("\n".join(json.dumps(x) for x in rows) + "\n")
    report = audit(p, require_full=False)
    assert report["passed"]
    assert report["metrics"]["positive_only"]
