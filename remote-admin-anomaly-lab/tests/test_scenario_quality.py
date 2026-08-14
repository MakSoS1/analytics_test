from pathlib import Path

from adminlab.config import load_yaml
from adminlab.digital_twin import load_digital_twin_bundle, plan_digital_twin_sessions
from adminlab.scenario_quality import evaluate_scenario_quality

ROOT = Path(__file__).resolve().parents[1]


def test_large_plan_has_semantic_diversity_not_just_row_count():
    topology = load_yaml(ROOT / "configs/topology.yaml")
    scenarios = load_yaml(ROOT / "configs/scenarios.yaml")
    netem = load_yaml(ROOT / "configs/netem.yaml")
    bundle = load_digital_twin_bundle(ROOT / "configs")
    rows = plan_digital_twin_sessions(
        topology, scenarios, netem, bundle, seed=20260821, count=12000, stage="H"
    )
    report = evaluate_scenario_quality(rows)
    assert report["ok"], report
    assert report["semantic_families"] >= 25
    assert report["personas"] >= 40
    assert report["host_relations"] >= 12
    assert report["campaign_types"] >= 8
    assert report["simulated_days"] >= 30
    assert report["protocols"] >= 4
    assert report["hard_benign_sessions"] > 0
    assert report["hard_suspicious_sessions"] > 0


def test_row_count_alone_cannot_pass_quality_gate():
    topology = load_yaml(ROOT / "configs/topology.yaml")
    scenarios = load_yaml(ROOT / "configs/scenarios.yaml")
    netem = load_yaml(ROOT / "configs/netem.yaml")
    bundle = load_digital_twin_bundle(ROOT / "configs")
    rows = plan_digital_twin_sessions(
        topology, scenarios, netem, bundle, seed=20260822, count=5000, stage="B"
    )
    cloned = [rows[0] for _ in range(5000)]
    report = evaluate_scenario_quality(cloned)
    assert report["ok"] is False
    assert "semantic_families" in report["failed_gates"]
    assert report["rows"] == 5000
