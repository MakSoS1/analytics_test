from collections import defaultdict
from pathlib import Path

from adminlab.config import load_yaml
from adminlab.digital_twin import load_digital_twin_bundle, plan_digital_twin_sessions
from adminlab.implementation_variants import materialize_implementation_variants
from adminlab.splits import assign_grouped_splits

ROOT = Path(__file__).resolve().parents[1]


def _rows(stage="G", count=5000):
    topology = load_yaml(ROOT / "configs/topology.yaml")
    scenarios = load_yaml(ROOT / "configs/scenarios.yaml")
    netem = load_yaml(ROOT / "configs/netem.yaml")
    bundle = load_digital_twin_bundle(ROOT / "configs")
    planned = plan_digital_twin_sessions(topology, scenarios, netem, bundle, seed=20260824, count=count, stage=stage)
    return materialize_implementation_variants(planned, stage=stage, seed=20260824)


def test_stage_g_has_two_actual_client_implementations_for_ssh_and_smb():
    rows = _rows()
    stacks = defaultdict(set)
    for row in rows:
        stacks[row.protocol].add(row.client_stack)
    assert {"openssh", "paramiko"} <= stacks["ssh"]
    assert {"smbclient", "smbprotocol"} <= stacks["smb"]
    assert stacks["rdp"] <= {"freerdp"}
    assert stacks["vnc"] <= {"rfb-python"}


def test_implementation_choice_is_label_neutral_for_counterfactual_pairs():
    rows = _rows(stage="F", count=200)
    by_pair = defaultdict(list)
    for row in rows:
        by_pair[row.pair_id].append(row)
    for pair in by_pair.values():
        assert len(pair) == 2
        assert pair[0].client_stack == pair[1].client_stack
        assert pair[0].implementation_id == pair[1].implementation_id


def test_split_reports_unseen_client_implementation_when_available():
    rows = _rows(stage="G", count=5000)
    import pandas as pd
    frame = pd.DataFrame([row.to_dict() for row in rows])
    splits, report = assign_grouped_splits(frame, seed=20260824)
    assert report["heldout_client_implementations"]
    assert report["challenge_reason_counts"].get("unseen_client_implementation", 0) > 0
    challenge = splits[splits["challenge_reason"].str.contains("unseen_client_implementation", na=False)]
    assert not challenge.empty
