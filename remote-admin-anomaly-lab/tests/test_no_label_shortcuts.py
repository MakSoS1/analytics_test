from collections import defaultdict
from pathlib import Path

from adminlab.config import load_yaml
from adminlab.digital_twin import load_digital_twin_bundle, plan_digital_twin_sessions
from adminlab.wire_controls import materialize_wire_controls

ROOT = Path(__file__).resolve().parents[1]


def test_core_wire_runner_does_not_branch_on_label_for_size_or_attempts():
    text = (ROOT / "scripts/run_scenarios.py").read_text(encoding="utf-8")
    assert ".wire_transfer_bytes" in text
    assert ".wire_attempts" in text
    assert "if record.label_binary" not in text
    assert "if r.label_binary" not in text


def test_extended_wire_runner_does_not_branch_on_label_for_attempts():
    text = (ROOT / "src/adminlab/extended_wire_v2.py").read_text(encoding="utf-8")
    assert ".wire_attempts" in text
    assert "if record.label_binary" not in text
    assert "if r.label_binary" not in text


def test_counterfactual_pairs_get_identical_concrete_wire_controls():
    topology = load_yaml(ROOT / "configs/topology.yaml")
    scenarios = load_yaml(ROOT / "configs/scenarios.yaml")
    netem = load_yaml(ROOT / "configs/netem.yaml")
    bundle = load_digital_twin_bundle(ROOT / "configs")
    planned = plan_digital_twin_sessions(
        topology, scenarios, netem, bundle, seed=20260818, count=200, stage="F"
    )
    rows = materialize_wire_controls(planned, bundle["behavior"], seed=20260818)
    pairs = defaultdict(list)
    for row in rows:
        pairs[row.pair_id].append(row)
    assert pairs
    observed_nontrivial = False
    for pair in pairs.values():
        assert len(pair) == 2
        a, b = sorted(pair, key=lambda r: r.label_binary)
        assert a.wire_attempts == b.wire_attempts
        assert a.wire_transfer_bytes == b.wire_transfer_bytes
        if a.wire_attempts > 1 or a.wire_transfer_bytes > 0:
            observed_nontrivial = True
    assert observed_nontrivial


def test_observable_control_distributions_overlap_between_labels():
    topology = load_yaml(ROOT / "configs/topology.yaml")
    scenarios = load_yaml(ROOT / "configs/scenarios.yaml")
    netem = load_yaml(ROOT / "configs/netem.yaml")
    bundle = load_digital_twin_bundle(ROOT / "configs")
    planned = plan_digital_twin_sessions(
        topology, scenarios, netem, bundle, seed=20260819, count=3000, stage="H"
    )
    rows = materialize_wire_controls(planned, bundle["behavior"], seed=20260819)
    by_protocol = defaultdict(lambda: {0: set(), 1: set()})
    for row in rows:
        if row.protocol in {"ssh", "smb", "rdp", "vnc"}:
            by_protocol[row.protocol][row.label_binary].add(
                (row.behavior_profile, row.wire_attempts, row.wire_transfer_bytes // 65536)
            )
    for protocol in ("ssh", "smb", "rdp", "vnc"):
        assert by_protocol[protocol][0]
        assert by_protocol[protocol][1]
        benign_profiles = {x[0] for x in by_protocol[protocol][0]}
        suspicious_profiles = {x[0] for x in by_protocol[protocol][1]}
        assert benign_profiles & suspicious_profiles
