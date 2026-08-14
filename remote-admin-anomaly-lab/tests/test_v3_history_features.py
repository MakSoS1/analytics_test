import pandas as pd

from adminlab.session_gold import build_session_gold


def _frames(include_future: bool = False):
    sessions = [
        ("s1", "2026-06-01T10:00:00+00:00", "2026-06-01T10:02:00+00:00", "src-a", "dst-1", "ssh"),
        ("s2", "2026-06-02T10:00:00+00:00", "2026-06-02T10:02:00+00:00", "src-a", "dst-2", "smb"),
        ("s3", "2026-06-03T10:00:00+00:00", "2026-06-03T10:02:00+00:00", "src-a", "dst-3", "ssh"),
        ("s4", "2026-06-04T10:00:00+00:00", "2026-06-04T10:02:00+00:00", "src-a", "dst-3", "ssh"),
    ]
    if include_future:
        sessions.extend([
            ("future-1", "2026-07-20T10:00:00+00:00", "2026-07-20T10:02:00+00:00", "src-a", "dst-99", "vnc"),
            ("future-2", "2026-07-21T10:00:00+00:00", "2026-07-21T10:02:00+00:00", "src-a", "dst-100", "rdp"),
        ])
    features = []
    labels = []
    for idx, (sid, start, end, src, dst, protocol) in enumerate(sessions):
        uid = f"flow-{sid}"
        features.append({
            "flow_uid": uid,
            "session_id": sid,
            "bytes_total": 1000 + idx,
            "packets_total": 20,
            "duration": 120.0,
            "src_bytes": 600,
            "dst_bytes": 400,
        })
        labels.append({
            "flow_uid": uid,
            "session_id": sid,
            "label_binary": idx % 2,
            "split": "train",
            "campaign_id": f"camp-{sid}",
            "protocol": protocol,
            "src_host_id": src,
            "dst_host_id": dst,
            "start_ts": start,
            "end_ts": end,
        })
    return pd.DataFrame(features), pd.DataFrame(labels)


def test_v3_history_features_are_strictly_causal_under_future_append():
    base_f, base_l = _frames(False)
    future_f, future_l = _frames(True)
    base, _ = build_session_gold(base_f, base_l)
    extended, _ = build_session_gold(future_f, future_l)
    cols = [
        "src_distinct_dst_24h_prior",
        "src_distinct_dst_7d_prior",
        "src_distinct_dst_30d_prior",
        "pair_seen_count_prior",
        "time_since_pair_seen_seconds_prior",
        "new_destination_for_source",
        "new_protocol_for_source",
        "src_protocol_diversity_7d_prior",
        "src_new_target_count_24h_prior",
        "src_graph_expansion_rate_24h_prior",
        "recent_protocol_switch_count_prior",
        "recent_remote_admin_attempt_count_prior",
    ]
    b = base.set_index("session_id")[cols].sort_index()
    e = extended.set_index("session_id").loc[b.index, cols].sort_index()
    pd.testing.assert_frame_equal(b, e, check_dtype=False)


def test_v3_history_features_capture_graph_expansion_not_current_bytes():
    features, labels = _frames(False)
    sessions, _ = build_session_gold(features, labels)
    rows = sessions.set_index("session_id")
    # s3 sees two distinct prior destinations in the previous seven/thirty days.
    assert rows.loc["s3", "src_distinct_dst_7d_prior"] == 2
    assert rows.loc["s3", "src_distinct_dst_30d_prior"] == 2
    assert rows.loc["s3", "new_destination_for_source"] == 1
    assert rows.loc["s3", "new_protocol_for_source"] == 0
    # s4 repeats dst-3 and therefore has prior pair evidence/recency.
    assert rows.loc["s4", "pair_seen_count_prior"] == 1
    assert rows.loc["s4", "time_since_pair_seen_seconds_prior"] > 0
    assert rows.loc["s4", "new_destination_for_source"] == 0
    # The sequence ssh -> smb -> ssh contains protocol changes in prior context.
    assert rows.loc["s4", "recent_protocol_switch_count_prior"] >= 2
