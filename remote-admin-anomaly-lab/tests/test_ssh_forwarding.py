from collections import defaultdict
from pathlib import Path

from adminlab.config import load_yaml
from adminlab.digital_twin import load_digital_twin_bundle, plan_digital_twin_sessions

ROOT = Path(__file__).resolve().parents[1]


def test_proxyjump_is_bounded_to_lab_and_has_no_dynamic_socks():
    text = (ROOT / "scripts/run_scenarios.py").read_text(encoding="utf-8")
    assert "bounded_proxyjump" in text
    assert "ProxyCommand=ssh" in text
    assert "-W %h:%p" in text
    assert "10.77.0.21" in text and "10.77.0.22" in text
    assert " -D " not in text
    assert "0.0.0.0:" not in text


def test_forwarding_profile_is_available_to_both_labels():
    topology = load_yaml(ROOT / "configs/topology.yaml")
    scenarios = load_yaml(ROOT / "configs/scenarios.yaml")
    netem = load_yaml(ROOT / "configs/netem.yaml")
    bundle = load_digital_twin_bundle(ROOT / "configs")
    rows = plan_digital_twin_sessions(
        topology, scenarios, netem, bundle, seed=20260820, count=5000, stage="H"
    )
    labels = defaultdict(set)
    for row in rows:
        if row.action == "bounded_proxyjump":
            labels[row.protocol].add(row.label_binary)
    assert labels["ssh"] == {0, 1}
