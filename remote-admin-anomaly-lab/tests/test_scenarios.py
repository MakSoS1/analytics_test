from ipaddress import ip_address, ip_network
from pathlib import Path

from adminlab.config import load_yaml
from adminlab.scenarios import plan_sessions

ROOT = Path(__file__).resolve().parents[1]


def configs():
    return (
        load_yaml(ROOT / "configs/topology.yaml"),
        load_yaml(ROOT / "configs/scenarios.yaml"),
        load_yaml(ROOT / "configs/netem.yaml"),
    )


def test_same_seed_produces_identical_plan():
    topology, scenarios, netem = configs()
    a = plan_sessions(topology, scenarios, netem, seed=41, count=100, stage="A")
    b = plan_sessions(topology, scenarios, netem, seed=41, count=100, stage="A")
    assert [x.to_dict() for x in a] == [x.to_dict() for x in b]


def test_plan_has_unique_session_ids_and_lab_only_destinations():
    topology, scenarios, netem = configs()
    records = plan_sessions(topology, scenarios, netem, seed=42, count=200, stage="A")
    assert len(records) == 200
    assert len({r.session_id for r in records}) == 200
    lab = ip_network(topology["lab"]["cidr"])
    assert all(ip_address(r.dst_ip) in lab for r in records)
    assert all(ip_address(r.src_ip) in lab for r in records)


def test_nuisance_profiles_overlap_labels():
    topology, scenarios, netem = configs()
    records = plan_sessions(topology, scenarios, netem, seed=43, count=360, stage="A")
    benign = {r.netem_profile for r in records if r.label_binary == 0}
    suspicious = {r.netem_profile for r in records if r.label_binary == 1}
    assert benign
    assert suspicious
    assert len(benign & suspicious) >= 5


def test_counterfactual_pair_members_share_observational_context():
    topology, scenarios, netem = configs()
    records = plan_sessions(topology, scenarios, netem, seed=44, count=400, stage="F")
    pairs = {}
    for r in records:
        if r.pair_id:
            pairs.setdefault(r.pair_id, []).append(r)
    complete = [rows for rows in pairs.values() if len(rows) == 2]
    assert complete
    for left, right in complete[:20]:
        assert {left.label_binary, right.label_binary} == {0, 1}
        assert left.protocol == right.protocol
        assert left.dst_host_id == right.dst_host_id
        assert left.netem_profile == right.netem_profile
