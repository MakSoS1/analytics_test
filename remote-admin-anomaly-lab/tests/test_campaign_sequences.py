from collections import defaultdict
from pathlib import Path

from adminlab.campaign_sequences import organize_campaign_sequences
from adminlab.config import load_yaml
from adminlab.digital_twin import load_digital_twin_bundle, plan_digital_twin_sessions

ROOT = Path(__file__).resolve().parents[1]


def _planned(count=8000, seed=20260823):
    topology = load_yaml(ROOT / "configs/topology.yaml")
    scenarios = load_yaml(ROOT / "configs/scenarios.yaml")
    netem = load_yaml(ROOT / "configs/netem.yaml")
    bundle = load_digital_twin_bundle(ROOT / "configs")
    rows = plan_digital_twin_sessions(topology, scenarios, netem, bundle, seed=seed, count=count, stage="H")
    return organize_campaign_sequences(rows, bundle["campaigns"], seed=seed)


def test_campaign_sequences_have_multiple_sessions_and_protocol_diversity():
    rows = _planned()
    campaigns = defaultdict(list)
    for row in rows:
        campaigns[row.campaign_id].append(row)
    multi = [items for items in campaigns.values() if len(items) >= 3]
    assert multi
    diverse = [items for items in multi if len({x.protocol for x in items}) >= 2]
    assert len(diverse) >= 20
    assert any(len({x.protocol for x in items}) >= 3 for items in diverse)


def test_campaign_members_stay_within_one_simulated_day():
    rows = _planned()
    campaigns = defaultdict(list)
    for row in rows:
        campaigns[row.campaign_id].append(row)
    for items in campaigns.values():
        assert len({x.simulated_day for x in items}) == 1
        assert {x.campaign_position for x in items} == set(range(len(items)))
        assert all(x.campaign_size == len(items) for x in items)


def test_counterfactual_pair_campaigns_are_not_rewritten():
    topology = load_yaml(ROOT / "configs/topology.yaml")
    scenarios = load_yaml(ROOT / "configs/scenarios.yaml")
    netem = load_yaml(ROOT / "configs/netem.yaml")
    bundle = load_digital_twin_bundle(ROOT / "configs")
    rows = plan_digital_twin_sessions(topology, scenarios, netem, bundle, seed=7, count=100, stage="F")
    before = [(r.session_id, r.campaign_id, r.pair_id) for r in rows]
    after_rows = organize_campaign_sequences(rows, bundle["campaigns"], seed=7)
    after = [(r.session_id, r.campaign_id, r.pair_id) for r in after_rows]
    assert before == after
