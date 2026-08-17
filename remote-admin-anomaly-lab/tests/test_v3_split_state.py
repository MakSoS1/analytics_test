import pandas as pd

from adminlab.session_gold import build_session_gold
from adminlab.v3_split_state import apply_research_session_splits, build_split_isolated_session_gold


def _fixture():
    flows = pd.DataFrame([
        {"flow_uid":"f1","session_id":"train-s","duration":10.0,"bytes_total":100.0,"packets_total":10.0,"src_bytes":60.0,"dst_bytes":40.0},
        {"flow_uid":"f2","session_id":"val-s","duration":10.0,"bytes_total":100.0,"packets_total":10.0,"src_bytes":60.0,"dst_bytes":40.0},
    ])
    labels = pd.DataFrame([
        {"flow_uid":"f1","session_id":"train-s","label_binary":0,"split":"train","challenge_reason":"","campaign_id":"c1","protocol":"ssh","src_host_id":"src1","dst_host_id":"dst1","start_ts":"2026-06-01T10:00:00+00:00","end_ts":"2026-06-01T10:01:00+00:00"},
        {"flow_uid":"f2","session_id":"val-s","label_binary":1,"split":"validation","challenge_reason":"","campaign_id":"c2","protocol":"ssh","src_host_id":"src1","dst_host_id":"dst1","start_ts":"2026-06-01T10:30:00+00:00","end_ts":"2026-06-01T10:31:00+00:00"},
    ])
    return flows, labels


def test_global_replay_would_let_train_history_change_validation():
    flows, labels = _fixture()
    global_features, _ = build_session_gold(flows, labels)
    val = global_features.loc[global_features.session_id == "val-s"].iloc[0]
    assert int(val["prior_sessions_1h"]) == 1
    assert int(val["pair_seen_count_prior"]) == 1


def test_primary_v3_replay_is_split_isolated():
    flows, labels = _fixture()
    features, out_labels = build_split_isolated_session_gold(flows, labels, environment_id="linux_v3")
    train = features.loc[features.session_id == "train-s"].iloc[0]
    val = features.loc[features.session_id == "val-s"].iloc[0]
    assert int(train["prior_sessions_1h"]) == 0
    assert int(val["prior_sessions_1h"]) == 0
    assert int(val["pair_seen_count_prior"]) == 0
    assert int(val["new_dst_prior"]) == 1
    assert set(out_labels["environment_id"]) == {"linux_v3"}


def test_split_isolation_is_independent_of_other_split_rows():
    flows, labels = _fixture()
    before, _ = build_split_isolated_session_gold(flows, labels, environment_id="linux_v3")
    extra_flow = pd.DataFrame([{"flow_uid":"f3","session_id":"train-extra","duration":5.0,"bytes_total":50.0,"packets_total":5.0,"src_bytes":30.0,"dst_bytes":20.0}])
    extra_label = pd.DataFrame([{"flow_uid":"f3","session_id":"train-extra","label_binary":0,"split":"train","challenge_reason":"","campaign_id":"c3","protocol":"smb","src_host_id":"src1","dst_host_id":"dst2","start_ts":"2026-06-01T10:20:00+00:00","end_ts":"2026-06-01T10:21:00+00:00"}])
    after, _ = build_split_isolated_session_gold(
        pd.concat([flows, extra_flow], ignore_index=True),
        pd.concat([labels, extra_label], ignore_index=True),
        environment_id="linux_v3",
    )
    cols = [col for col in before.columns if col != "session_id"]
    pd.testing.assert_series_equal(
        before.loc[before.session_id == "val-s", cols].iloc[0],
        after.loc[after.session_id == "val-s", cols].iloc[0],
        check_names=False,
    )


def test_research_session_splits_are_detached_from_production_flow_labels():
    _, production = _fixture()
    original = production.copy(deep=True)
    session_splits = pd.DataFrame([
        {"session_id":"train-s","split":"challenge","challenge_reason":"unseen_src_host"},
        {"session_id":"val-s","split":"test","challenge_reason":""},
    ])
    research = apply_research_session_splits(production, session_splits)

    # Production flow-primary labels remain byte-for-byte equivalent at the
    # dataframe level; only the detached research copy receives new splits.
    pd.testing.assert_frame_equal(production, original)
    assert research.set_index("session_id").loc["train-s", "split"] == "challenge"
    assert research.set_index("session_id").loc["val-s", "split"] == "test"
    assert production.set_index("session_id").loc["train-s", "split"] == "train"
    assert production.set_index("session_id").loc["val-s", "split"] == "validation"


def test_research_session_splits_fail_closed_on_missing_session():
    _, production = _fixture()
    incomplete = pd.DataFrame([
        {"session_id":"train-s","split":"train","challenge_reason":""},
    ])
    try:
        apply_research_session_splits(production, incomplete)
    except ValueError as exc:
        assert "incomplete" in str(exc)
    else:
        raise AssertionError("missing research split assignment must fail closed")
