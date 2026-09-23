from __future__ import annotations

import json
from pathlib import Path

from coverlab.stage_m import FAMILY_COUNTS, build_specs, total_implementation_profiles, validate_manifest


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
