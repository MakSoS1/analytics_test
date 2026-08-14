from collections import defaultdict
from pathlib import Path

import pandas as pd

from adminlab.campaign_sequences import organize_campaign_sequences
from adminlab.config import load_yaml
from adminlab.digital_twin import load_digital_twin_bundle, plan_digital_twin_sessions
from adminlab.implementation_variants import materialize_implementation_variants
from adminlab.splits import assign_grouped_splits

ROOT = Path(__file__).resolve().parents[1]
PROTOCOLS = ("ssh", "smb", "rdp", "vnc")


def _balanced(records, count=1000):
    buckets = defaultdict(list)
    for record in records:
        if record.protocol in PROTOCOLS:
            buckets[record.protocol].append(record)
    base = count // len(PROTOCOLS)
    output = []
    for protocol in PROTOCOLS:
        assert len(buckets[protocol]) >= base
        output.extend(buckets[protocol][:base])
    return sorted(output, key=lambda record: (record.start_ts, record.session_id))


def test_research_1k_plan_keeps_viable_two_class_train_validation_test_and_challenge():
    topology = load_yaml(ROOT / "configs/topology.yaml")
    scenarios = load_yaml(ROOT / "configs/scenarios.yaml")
    netem = load_yaml(ROOT / "configs/netem.yaml")
    bundle = load_digital_twin_bundle(ROOT / "configs")

    planned = plan_digital_twin_sessions(
        topology,
        scenarios,
        netem,
        bundle,
        seed=2026082602,
        count=16000,
        stage="H",
    )
    selected = _balanced(planned, 1000)
    selected = organize_campaign_sequences(selected, bundle["campaigns"], seed=2026082602)
    selected = materialize_implementation_variants(selected, stage="H", seed=2026082602)
    frame = pd.DataFrame([record.to_dict() for record in selected])

    splits, report = assign_grouped_splits(frame, seed=20260826)
    joined = frame[["session_id", "label_binary", "implementation_id", "persona_id"]].merge(
        splits, on="session_id", validate="one_to_one"
    )

    for split in ("train", "validation", "test", "challenge"):
        part = joined[joined["split"] == split]
        assert len(part) >= 20, (split, report)
        assert set(part["label_binary"].astype(int)) == {0, 1}, (split, part["label_binary"].value_counts().to_dict(), report)

    reasons = report["challenge_reason_counts"]
    for reason in ("unseen_persona", "unseen_host_pair", "temporal_future", "unseen_client_implementation"):
        assert reasons.get(reason, 0) > 0, (reason, report)

    assert report["heldout_personas"], report
    assert any("paramiko" in value for value in report["heldout_client_implementations"]), report
    assert any("smbprotocol" in value for value in report["heldout_client_implementations"]), report

    train_impl = set(joined.loc[joined["split"] == "train", "implementation_id"].astype(str))
    assert not (train_impl & set(report["heldout_client_implementations"])), report
