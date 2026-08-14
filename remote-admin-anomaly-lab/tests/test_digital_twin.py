from __future__ import annotations

from collections import defaultdict
from datetime import datetime
from pathlib import Path

from adminlab.config import load_yaml
from adminlab.digital_twin import expand_personas, load_digital_twin_bundle, plan_digital_twin_sessions, validate_digital_twin

ROOT = Path(__file__).resolve().parents[1]


def _load():
    topology = load_yaml(ROOT / "configs/topology.yaml")
    scenarios = load_yaml(ROOT / "configs/scenarios.yaml")
    netem = load_yaml(ROOT / "configs/netem.yaml")
    bundle = load_digital_twin_bundle(ROOT / "configs")
    return topology, scenarios, netem, bundle


def test_digital_twin_has_58_personas_bound_to_tasks_and_calendars():
    topology, _, _, bundle = _load()
    validate_digital_twin(bundle, topology)
    personas = expand_personas(bundle["personas"])
    assert len(personas) == 58
    assert len({p["persona_id"] for p in personas}) == 58
    required_roles = {
        "DomainAdmin",
        "ServerAdmin",
        "LinuxAdmin",
        "Developer",
        "Helpdesk",
        "ServiceAccount",
        "RegularUser",
    }
    assert required_roles <= {p["role"] for p in personas}
    assert all(p["calendar_id"] for p in personas)
    assert all(p["task_weights"] for p in personas)
    assert all(p["source_endpoint_roles"] for p in personas)


def test_planner_spans_multi_day_history_and_is_deterministic():
    topology, scenarios, netem, bundle = _load()
    a = plan_digital_twin_sessions(
        topology, scenarios, netem, bundle, seed=20260814, count=600, stage="A"
    )
    b = plan_digital_twin_sessions(
        topology, scenarios, netem, bundle, seed=20260814, count=600, stage="A"
    )
    assert [r.to_dict() for r in a] == [r.to_dict() for r in b]
    timestamps = [datetime.fromisoformat(r.start_ts) for r in a]
    assert (max(timestamps) - min(timestamps)).days >= 30
    assert len({r.persona_id for r in a}) >= 30
    assert len({r.task_id for r in a}) >= 6
    assert len({r.campaign_type for r in a}) >= 6


def test_labels_share_observable_profiles_instead_of_encoding_volume_or_retries():
    topology, scenarios, netem, bundle = _load()
    rows = plan_digital_twin_sessions(
        topology, scenarios, netem, bundle, seed=20260815, count=2400, stage="H"
    )
    by_protocol: dict[str, dict[int, set[str]]] = defaultdict(lambda: {0: set(), 1: set()})
    for row in rows:
        if row.protocol in {"ssh", "smb", "rdp", "vnc"}:
            by_protocol[row.protocol][row.label_binary].add(row.behavior_profile)
    for protocol in ("ssh", "smb", "rdp", "vnc"):
        benign = by_protocol[protocol][0]
        suspicious = by_protocol[protocol][1]
        assert benign and suspicious, protocol
        assert benign & suspicious, (protocol, benign, suspicious)


def test_stage_f_counterfactual_pairs_hold_wire_observables_constant():
    topology, scenarios, netem, bundle = _load()
    rows = plan_digital_twin_sessions(
        topology, scenarios, netem, bundle, seed=20260816, count=400, stage="F"
    )
    pairs: dict[str, list] = defaultdict(list)
    for row in rows:
        assert row.pair_id
        pairs[row.pair_id].append(row)
    assert pairs
    for pair_id, pair in pairs.items():
        assert len(pair) == 2, pair_id
        a, b = sorted(pair, key=lambda r: r.label_binary)
        assert (a.label_binary, b.label_binary) == (0, 1)
        assert a.src_host_id == b.src_host_id
        assert a.dst_host_id == b.dst_host_id
        assert a.protocol == b.protocol
        assert a.action == b.action
        assert a.start_ts == b.start_ts
        assert a.end_ts == b.end_ts
        assert a.netem_profile == b.netem_profile
        assert a.behavior_profile == b.behavior_profile
        assert a.client_stack == b.client_stack
        assert a.auth_outcome == b.auth_outcome
        assert a.intent_profile != b.intent_profile
        assert a.historical_relation != b.historical_relation
