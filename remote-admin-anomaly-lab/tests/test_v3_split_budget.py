import pandas as pd

from adminlab.v3_splits import assign_grouped_splits_v3


def _frame(n: int = 1000) -> pd.DataFrame:
    rows = []
    protocols = ("ssh", "smb", "rdp", "vnc")
    for idx in range(n):
        label = idx % 2
        protocol = protocols[(idx // 2) % 4]
        campaign = f"camp-{idx // 4:04d}"
        pair = f"pair-{idx // 20:03d}" if idx % 20 in (0, 1) else ""
        client = "alt" if idx % 17 == 0 else "primary"
        rows.append({
            "session_id": f"s-{idx:04d}",
            "campaign_id": campaign,
            "pair_id": pair,
            "label_binary": label,
            "src_host_id": f"src-{idx % 11}",
            "dst_host_id": f"dst-{idx % 31}",
            "persona_id": f"persona-{idx % 29}",
            "protocol": protocol,
            "client_stack": client,
            "implementation_id": f"{protocol}:{client}->server",
            "start_ts": f"2026-06-{1 + (idx % 28):02d}T{8 + (idx % 12):02d}:00:00+00:00",
        })
    return pd.DataFrame(rows)


def test_v3_split_budget_keeps_generic_splits_large_and_challenge_bounded():
    splits, report = assign_grouped_splits_v3(_frame(), seed=20260814)
    counts = report["split_counts"]
    total = sum(counts.values())
    assert counts["validation"] >= 120
    assert counts["test"] >= 120
    challenge_fraction = counts["challenge"] / total
    assert 0.15 <= challenge_fraction <= 0.25
    assert not splits["split"].isna().any()


def test_v3_split_keeps_campaigns_and_pairs_atomic():
    frame = _frame()
    splits, _ = assign_grouped_splits_v3(frame, seed=7)
    merged = frame.merge(splits[["session_id", "split"]], on="session_id", validate="one_to_one")
    assert merged.groupby("campaign_id")["split"].nunique().max() == 1
    nonempty = merged[merged["pair_id"] != ""]
    assert nonempty.groupby("pair_id")["split"].nunique().max() == 1


def test_v3_holdouts_never_exceed_declared_dimension_budget():
    _, report = assign_grouped_splits_v3(_frame(), seed=99)
    for name, detail in report["holdout_impact"].items():
        if detail["status"].startswith("selected"):
            assert detail["fraction"] <= detail["max_fraction"] + 1e-12, name
