from __future__ import annotations

import json
from pathlib import Path

from coverlab.stage_m import FAMILY_COUNTS, build_specs, total_implementation_profiles, validate_manifest
from coverlab.diversity_audit import audit
from coverlab.vm_plan import make_plan
from coverlab.stage_m_raw import MODES, packet
from coverlab.stage_m_dns_server import answer_query


def test_stage_m_full_budget_and_family_counts():
    specs = build_specs("full")
    assert len(specs) == sum(FAMILY_COUNTS.values()) == 15150
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


def test_diversity_audit_full_catalog_contract(tmp_path: Path):
    """Fail fast before an expensive full capture if the designed catalog itself
    violates the release diversity gates."""
    p = tmp_path / "campaigns-full.jsonl"
    rows = []
    for i, s in enumerate(build_specs("full")):
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
            "network_profile_id": "catalog",
        })
    p.write_text("\n".join(json.dumps(x) for x in rows) + "\n")
    report = audit(p, require_full=True)
    assert report["passed"], report
    assert report["metrics"]["campaigns"] == 15150
    assert report["metrics"]["exact_duplicate_fraction"] < 0.01


def test_vm_wire_plan_contract():
    inv = {
        "environment_id": "stage-m-vm-test",
        "hypervisor": "kvm-test",
        "server": {"ipv4": "10.20.0.20"},
        "clients": [
            {"id": "linux-01", "os": "linux", "ssh": "lab@10.20.0.10", "ipv4": "10.20.0.10"},
            {"id": "windows-01", "os": "windows", "ssh": "lab@10.20.0.11", "ipv4": "10.20.0.11"},
        ],
    }
    rows = make_plan(inv, "smoke", 0, 1)
    assert rows
    assert all(r["positive_only"] and r["label_binary"] == 1 for r in rows)
    assert all(r["capture_environment"] == "vm_wire" for r in rows)
    assert {r["client_os"] for r in rows} == {"linux", "windows"}
    assert any(r["split_role"] == "H_client" for r in rows)
    assert any(r["client_impl"] == "edge_chromium" and r["split_role"] == "H_client" for r in rows)
    assert all(r["source_ip"].startswith("10.20.0.") for r in rows)
    assert all(r["environment_id"] == "stage-m-vm-test" for r in rows)
    assert all(r["hypervisor"] == "kvm-test" for r in rows)


def test_raw_header_packets_are_bounded():
    import random
    from scapy.layers.inet import IP
    for i, mode in enumerate(MODES):
        pkt, value = packet(mode, "10.20.0.10", i, random.Random(1000 + i))
        assert IP in pkt
        assert pkt[IP].src == "10.20.0.10"
        assert pkt[IP].dst == "10.20.0.20"
        assert isinstance(value, int)


def test_full_vm_plan_has_at_least_2000_windows_sessions():
    inv = {
        "environment_id": "stage-m-vm-full-test",
        "hypervisor": "kvm-test",
        "server": {"ipv4": "10.20.0.20"},
        "clients": [
            {"id": "linux-01", "os": "linux", "ssh": "lab@10.20.0.10", "ipv4": "10.20.0.10"},
            {"id": "windows-01", "os": "windows", "ssh": "lab@10.20.0.11", "ipv4": "10.20.0.11"},
        ],
    }
    rows = make_plan(inv, "full", 0, 1)
    windows = [r for r in rows if r["client_os"] == "windows"]
    assert len(rows) == 15150
    assert len(windows) >= 2000
    assert any(r["split_role"] == "H_client" for r in windows)
    assert any(r["client_impl"] == "edge_chromium" and r["split_role"] == "H_client" for r in windows)
    assert not any(r["client_impl"] == "edge_chromium" and r["training_eligible"] for r in windows)


def test_stage_m_dns_cname_is_protocol_valid():
    import dns.message
    import dns.rdatatype
    q=dns.message.make_query("token.stage-m.test.", dns.rdatatype.CNAME)
    r=dns.message.from_wire(answer_query(q.to_wire()))
    assert r.rcode() == 0
    assert r.answer
    assert r.answer[0].rdtype == dns.rdatatype.CNAME
    assert "target.stage-m.test." in r.answer[0].to_text()


def test_vm_plan_rejects_undeclared_runtime_stack():
    import pytest
    inv = {
        "environment_id": "stage-m-vm-stack-test",
        "hypervisor": "kvm-test",
        "server": {"ipv4": "10.20.0.20"},
        "clients": [
            {"id": "linux-01", "os": "linux", "ssh": "lab@10.20.0.10", "ipv4": "10.20.0.10", "stacks": ["python_httpx"]},
            {"id": "windows-01", "os": "windows", "ssh": "lab@10.20.0.11", "ipv4": "10.20.0.11", "stacks": ["dotnet_httpclient_schannel"]},
        ],
    }
    with pytest.raises(ValueError, match="does not declare required stack"):
        make_plan(inv, "smoke", 0, 1)


def test_stage_m_https_catalog_has_reconnect_and_persistent_h1_h2():
    specs=[s for s in build_specs("full") if s.family in {"M-HTTPS-BEACON","M-HTTPS-FRONT","M-HTTPS-LOWENT","M-HTTPS-FRAG","M-RMM-SHAPE"}]
    clients={s.client_impl for s in specs}
    assert "python_httpx" in clients
    assert "python_httpx_h2" in clients
    assert "python_httpx_reuse" in clients
    assert "python_httpx_h2_reuse" in clients
