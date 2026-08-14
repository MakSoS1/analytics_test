import pandas as pd

from adminlab.campaign_gold import build_campaign_gold


def test_campaign_gold_aggregates_session_sequence_without_semantic_feature_leakage():
    session_features = pd.DataFrame(
        [
            {"session_id": "s1", "flow_count": 2, "session_total_bytes": 300.0, "session_total_packets": 30.0, "new_dst_prior": 0, "new_protocol_prior": 0, "prior_sessions_1h": 0},
            {"session_id": "s2", "flow_count": 1, "session_total_bytes": 50.0, "session_total_packets": 5.0, "new_dst_prior": 1, "new_protocol_prior": 1, "prior_sessions_1h": 1},
            {"session_id": "s3", "flow_count": 1, "session_total_bytes": 70.0, "session_total_packets": 7.0, "new_dst_prior": 1, "new_protocol_prior": 0, "prior_sessions_1h": 2},
        ]
    )
    session_labels = pd.DataFrame(
        [
            {"session_id": "s1", "campaign_id": "c1", "label_binary": 1, "split": "validation", "challenge_reason": "unseen_host_pair", "protocol": "ssh", "src_host_id": "src1", "dst_host_id": "dst1", "start_ts": "2026-06-01T10:00:00+00:00", "campaign_type": "target_chain", "behavior_profile": "interactive"},
            {"session_id": "s2", "campaign_id": "c1", "label_binary": 1, "split": "validation", "challenge_reason": "unseen_host_pair", "protocol": "smb", "src_host_id": "src1", "dst_host_id": "dst2", "start_ts": "2026-06-01T10:10:00+00:00", "campaign_type": "target_chain", "behavior_profile": "interactive"},
            {"session_id": "s3", "campaign_id": "c1", "label_binary": 1, "split": "validation", "challenge_reason": "unseen_host_pair", "protocol": "rdp", "src_host_id": "src1", "dst_host_id": "dst3", "start_ts": "2026-06-01T10:20:00+00:00", "campaign_type": "target_chain", "behavior_profile": "interactive"},
        ]
    )
    features, labels = build_campaign_gold(session_features, session_labels)
    assert len(features) == 1
    row = features.iloc[0]
    assert int(row["session_count"]) == 3
    assert int(row["target_count"]) == 3
    assert int(row["protocol_count"]) == 3
    assert int(row["protocol_transition_count"]) == 2
    assert float(row["new_target_ratio"]) == 2 / 3
    assert "campaign_type" not in features.columns
    assert "behavior_profile" not in features.columns
    assert labels.iloc[0]["campaign_id"] == "c1"
    assert labels.iloc[0]["environment_id"] == "linux_v2"
