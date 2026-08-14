from pathlib import Path

import pandas as pd

from adminlab.campaign_sequences import organize_campaign_sequences
from adminlab.config import load_yaml
from adminlab.digital_twin import load_digital_twin_bundle, plan_digital_twin_sessions
from adminlab.implementation_variants import materialize_implementation_variants
from adminlab.splits import assign_grouped_splits, audit_leakage

ROOT = Path(__file__).resolve().parents[1]


def _frame():
    topology = load_yaml(ROOT / "configs/topology.yaml")
    scenarios = load_yaml(ROOT / "configs/scenarios.yaml")
    netem = load_yaml(ROOT / "configs/netem.yaml")
    bundle = load_digital_twin_bundle(ROOT / "configs")
    rows = plan_digital_twin_sessions(topology, scenarios, netem, bundle, seed=20260825, count=6000, stage="H")
    rows = organize_campaign_sequences(rows, bundle["campaigns"], seed=20260825)
    rows = materialize_implementation_variants(rows, stage="H", seed=20260825)
    return pd.DataFrame([r.to_dict() for r in rows])


def test_unseen_personas_are_challenge_only():
    frame = _frame()
    splits, report = assign_grouped_splits(frame, seed=20260825)
    held = set(report["heldout_personas"])
    assert held
    assert report["challenge_reason_counts"].get("unseen_persona", 0) > 0
    assigned = frame[["session_id", "persona_id"]].merge(splits, on="session_id", validate="one_to_one")
    assert not (set(assigned.loc[assigned["split"] == "train", "persona_id"].astype(str)) & held)
    challenge = assigned[assigned["challenge_reason"].fillna("").str.contains("unseen_persona")]
    assert not challenge.empty
    assert set(challenge["persona_id"].astype(str)) & held


def test_leakage_audit_checks_persona_holdout():
    frame = _frame()
    splits, report = assign_grouped_splits(frame, seed=20260825)
    # The real model columns are checked elsewhere; here an empty feature set is
    # enough to exercise group leakage invariants without introducing metadata.
    contract = load_yaml(ROOT / "configs/feature_contract.yaml")
    result = audit_leakage(frame, splits, [], contract, report)
    assert result["ok"], result
    assert result["heldout_personas_in_train"] == []
