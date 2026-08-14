from datetime import datetime, timedelta, timezone

import pandas as pd

from adminlab.splits import assign_grouped_splits, audit_leakage


def dataset() -> pd.DataFrame:
    base = datetime(2026, 8, 1, 9, 0, tzinfo=timezone.utc)
    rows = []
    for campaign in range(20):
        for offset in range(4):
            i = campaign * 4 + offset
            pair_id = f"pair-{campaign}" if offset < 2 else ""
            rows.append(
                {
                    "session_id": f"s{i:03d}",
                    "campaign_id": f"c{campaign:02d}",
                    "pair_id": pair_id,
                    "src_host_id": f"src{campaign % 8}",
                    "dst_host_id": f"dst{(campaign + offset) % 10}",
                    "start_ts": (base + timedelta(hours=i)).isoformat(),
                }
            )
    return pd.DataFrame(rows)


def test_campaigns_and_counterfactual_pairs_never_cross_splits():
    sessions = dataset()
    splits, report = assign_grouped_splits(sessions, seed=17)
    merged = sessions.merge(splits[["session_id", "split"]], on="session_id")
    assert merged.groupby("campaign_id")["split"].nunique().max() == 1
    paired = merged[merged["pair_id"] != ""]
    assert paired.groupby("pair_id")["split"].nunique().max() == 1
    assert set(splits["split"]) <= {"train", "validation", "test", "challenge"}
    assert report["temporal_holdout_groups"]


def test_declared_user_and_host_pair_holdouts_do_not_leak_to_train():
    sessions = dataset()
    splits, report = assign_grouped_splits(sessions, seed=18)
    merged = sessions.merge(splits[["session_id", "split"]], on="session_id")
    train = merged[merged["split"] == "train"]
    assert not (set(train["src_host_id"]) & set(report["heldout_src_hosts"]))
    train_pairs = set(train["src_host_id"] + "->" + train["dst_host_id"])
    assert not (train_pairs & set(report["heldout_host_pairs"]))


def test_leakage_audit_rejects_generator_and_ground_truth_columns():
    sessions = dataset()
    splits, report = assign_grouped_splits(sessions, seed=19)
    contract = {
        "production_allowlist": ["flow_count", "duration"],
        "training_only": ["label_binary", "split"],
        "forbidden": ["scenario_id", "netem_profile", "generator_seed"],
    }
    good = audit_leakage(sessions, splits, ["flow_count", "duration", "label_binary", "split"], contract, report)
    assert good["ok"] is True
    bad = audit_leakage(sessions, splits, ["flow_count", "scenario_id", "netem_profile"], contract, report)
    assert bad["ok"] is False
    assert "scenario_id" in bad["forbidden_model_columns"]
    assert "netem_profile" in bad["forbidden_model_columns"]
