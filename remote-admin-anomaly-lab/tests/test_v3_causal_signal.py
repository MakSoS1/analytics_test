from __future__ import annotations

from collections import Counter, defaultdict
from datetime import datetime, timedelta, timezone
from pathlib import Path

import yaml

from adminlab.manifest import SessionRecord
from adminlab.v3_signal import (
    audit_causal_observability,
    audit_v3_signal_plan,
    build_v3_causal_plan,
    causal_history_signature,
    v3_current_signature,
)

ROOT = Path(__file__).resolve().parents[1]


def _row(
    session_id: str,
    *,
    label: int,
    src: str,
    dst: str,
    protocol: str = "ssh",
    minute: int = 30,
    pair_id: str = "",
    family: str = "routine_admin",
) -> SessionRecord:
    start = datetime(2026, 6, 10, 12, minute, tzinfo=timezone.utc)
    return SessionRecord(
        campaign_id=f"campaign-{src}-{label}",
        scenario_id=f"causal-{family}",
        session_id=session_id,
        pair_id=pair_id,
        label_binary=label,
        label_family=family,
        mitre_technique="T1021.004",
        src_role="AdminWorkstation" if label == 0 else "Workstation",
        dst_role="Server",
        src_host_id=src,
        dst_host_id=dst,
        src_ip="10.77.0.10",
        dst_ip="10.77.0.200",
        src_port=0,
        dst_port={"ssh": 22, "smb": 445, "rdp": 3389, "vnc": 5900}[protocol],
        protocol=protocol,
        action="bounded_admin_session",
        wire_fidelity="real_wire",
        semantic_fidelity="high",
        ground_truth_source="scenario_orchestrator",
        netem_profile="normal",
        generator_seed=20260816,
        start_ts=start.isoformat(),
        end_ts=(start + timedelta(seconds=90)).isoformat(),
        status="planned",
        persona_id=f"persona-{src}",
        task_id="diagnostics",
        calendar_id="business_hours",
        intent_profile="approved" if label == 0 else "lateral_movement",
        behavior_profile="short_interactive",
        campaign_type=family,
        historical_relation="known_pair" if label == 0 else "novel_pair",
        auth_outcome="success",
        client_stack="openssh",
        server_stack="openssh-server",
        implementation_id=f"{protocol}:client->server",
        simulated_day=9,
        wire_attempts=1,
        wire_transfer_bytes=0,
    )


def test_topology_has_many_production_source_identities_and_compromised_sources():
    topology = yaml.safe_load((ROOT / "configs/topology.yaml").read_text())
    service_roles = {"LinuxServer", "FileServer", "RDPServer", "VNCServer", "RPCServer", "ManagementServer"}
    sources = [host for host in topology["hosts"] if host["role"] not in service_roles]
    assert len(sources) >= 32
    assert sum(host["role"] == "CompromisedWorkstation" for host in sources) >= 4
    assert len({host["ip"] for host in sources}) == len(sources)


def test_counterfactual_pair_must_match_current_session_but_differ_in_causal_history():
    pair_id = "cf-1"
    benign = _row("benign", label=0, src="src-a", dst="dst-known", pair_id=pair_id)
    suspicious = _row("suspicious", label=1, src="src-b", dst="dst-new", pair_id=pair_id, family="rare_pair")
    assert v3_current_signature(benign) == v3_current_signature(suspicious)

    benign_history = [
        _row(f"b-{i}", label=0, src="src-a", dst="dst-known", minute=i + 1)
        for i in range(4)
    ]
    suspicious_history = [
        _row(f"s-{i}", label=0, src="src-b", dst="dst-other", minute=i + 1)
        for i in range(4)
    ]
    left = causal_history_signature(benign, benign_history)
    right = causal_history_signature(suspicious, suspicious_history)
    assert left != right
    assert left["pair_seen_count_prior"] > 0
    assert right["pair_seen_count_prior"] == 0


def test_causal_observability_rejects_semantic_only_opposite_labels():
    pair_id = "cf-semantic-only"
    benign = _row("benign", label=0, src="src-a", dst="dst-a", pair_id=pair_id)
    suspicious = _row("suspicious", label=1, src="src-b", dst="dst-b", pair_id=pair_id, family="rare_pair")
    history = {
        "benign": [_row("bh", label=0, src="src-a", dst="dst-a", minute=1)],
        "suspicious": [_row("sh", label=0, src="src-b", dst="dst-b", minute=1)],
    }
    report = audit_causal_observability([benign, suspicious], history_by_session=history)
    assert report["valid"] is False
    assert report["semantic_only_counterfactual_pairs"] == [pair_id]


def test_causal_observability_accepts_rare_pair_with_real_prior_difference():
    pair_id = "cf-causal"
    benign = _row("benign", label=0, src="src-a", dst="dst-known", pair_id=pair_id)
    suspicious = _row("suspicious", label=1, src="src-b", dst="dst-new", pair_id=pair_id, family="rare_pair")
    history = {
        "benign": [
            _row("b1", label=0, src="src-a", dst="dst-known", minute=1),
            _row("b2", label=0, src="src-a", dst="dst-known", minute=2),
        ],
        "suspicious": [
            _row("s1", label=0, src="src-b", dst="dst-other", minute=1),
            _row("s2", label=0, src="src-b", dst="dst-other", minute=2),
        ],
    }
    report = audit_causal_observability([benign, suspicious], history_by_session=history)
    assert report["valid"] is True
    assert report["causally_separated_counterfactual_pairs"] == 1
    assert report["semantic_only_counterfactual_pairs"] == []


def test_causal_planner_builds_balanced_observable_signal_before_labels():
    topology = yaml.safe_load((ROOT / "configs/topology.yaml").read_text())
    protocols = ("ssh", "smb", "rdp", "vnc")
    rows: list[SessionRecord] = []
    for index in range(80):
        protocol = protocols[index % len(protocols)]
        row = _row(
            f"plan-{index:03d}",
            label=index % 2,
            src="placeholder-src",
            dst="placeholder-dst",
            protocol=protocol,
            minute=1 + (index % 50),
        )
        start = datetime(2026, 6, 1, 8, 0, tzinfo=timezone.utc) + timedelta(hours=index * 4)
        rows.append(
            SessionRecord.from_dict(
                {
                    **row.to_dict(),
                    "start_ts": start.isoformat(),
                    "end_ts": (start + timedelta(seconds=90)).isoformat(),
                    "simulated_day": (start.date() - datetime(2026, 6, 1, tzinfo=timezone.utc).date()).days,
                }
            )
        )

    prepared = build_v3_causal_plan(rows, topology=topology, seed=17, matched_fraction=0.40)
    assert len(prepared) == 80
    assert Counter(row.label_binary for row in prepared) == Counter({0: 40, 1: 40})
    for protocol in protocols:
        part = [row for row in prepared if row.protocol == protocol]
        assert Counter(row.label_binary for row in part) == Counter({0: 10, 1: 10})
    assert len({row.src_host_id for row in prepared}) >= 20
    suspicious_families = {row.campaign_type for row in prepared if row.label_binary == 1}
    assert len(suspicious_families) >= 4

    by_pair = defaultdict(list)
    for row in prepared:
        if row.pair_id:
            by_pair[row.pair_id].append(row)
    assert len(by_pair) >= 16
    for pair in by_pair.values():
        if len(pair) == 2:
            assert v3_current_signature(pair[0]) == v3_current_signature(pair[1])
    signal = audit_v3_signal_plan(prepared)
    assert signal["causal_observability"]["valid"] is True
    assert signal["causal_observability"]["causally_separated_counterfactual_pairs"] >= 16
