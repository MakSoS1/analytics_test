import pandas as pd

from adminlab.session_gold import build_session_gold


def _fixture():
    flows = pd.DataFrame(
        [
            {"flow_uid": "f1", "session_id": "s1", "duration": 10.0, "bytes_total": 100.0, "packets_total": 10.0, "src_bytes": 60.0, "dst_bytes": 40.0, "connections_1h": 0, "unique_dst_ip_24h": 0, "new_dst_for_src": 1, "new_src_dst_pair": 1, "pair_seen_count": 0, "protocol_entropy_1h": 0.0},
            {"flow_uid": "f2", "session_id": "s1", "duration": 20.0, "bytes_total": 200.0, "packets_total": 20.0, "src_bytes": 100.0, "dst_bytes": 100.0, "connections_1h": 1, "unique_dst_ip_24h": 1, "new_dst_for_src": 0, "new_src_dst_pair": 0, "pair_seen_count": 1, "protocol_entropy_1h": 0.0},
            {"flow_uid": "f3", "session_id": "s2", "duration": 15.0, "bytes_total": 50.0, "packets_total": 5.0, "src_bytes": 30.0, "dst_bytes": 20.0, "connections_1h": 2, "unique_dst_ip_24h": 1, "new_dst_for_src": 0, "new_src_dst_pair": 0, "pair_seen_count": 2, "protocol_entropy_1h": 0.0},
        ]
    )
    labels = pd.DataFrame(
        [
            {"flow_uid": "f1", "session_id": "s1", "label_binary": 0, "split": "train", "challenge_reason": "", "campaign_id": "c1", "protocol": "ssh", "src_host_id": "src1", "dst_host_id": "dst1", "start_ts": "2026-06-01T10:00:00+00:00", "end_ts": "2026-06-01T10:02:00+00:00", "persona_id": "p1", "implementation_id": "ssh:openssh->openssh-server"},
            {"flow_uid": "f2", "session_id": "s1", "label_binary": 0, "split": "train", "challenge_reason": "", "campaign_id": "c1", "protocol": "ssh", "src_host_id": "src1", "dst_host_id": "dst1", "start_ts": "2026-06-01T10:00:00+00:00", "end_ts": "2026-06-01T10:02:00+00:00", "persona_id": "p1", "implementation_id": "ssh:openssh->openssh-server"},
            {"flow_uid": "f3", "session_id": "s2", "label_binary": 1, "split": "validation", "challenge_reason": "", "campaign_id": "c2", "protocol": "smb", "src_host_id": "src1", "dst_host_id": "dst2", "start_ts": "2026-06-01T10:30:00+00:00", "end_ts": "2026-06-01T10:31:00+00:00", "persona_id": "p1", "implementation_id": "smb:smbclient->samba"},
        ]
    )
    return flows, labels


def test_session_gold_aggregates_multiple_parser_flows():
    features, labels = build_session_gold(*_fixture())
    s1 = features.loc[features["session_id"] == "s1"].iloc[0]
    assert int(s1["flow_count"]) == 2
    assert float(s1["session_total_bytes"]) == 300.0
    assert float(s1["session_total_packets"]) == 30.0
    assert int(s1["prior_sessions_1h"]) == 0
    assert set(labels["environment_id"]) == {"linux_v2"}


def test_session_gold_uses_only_strictly_prior_sessions_for_history():
    features, _ = build_session_gold(*_fixture())
    s2 = features.loc[features["session_id"] == "s2"].iloc[0]
    assert int(s2["prior_sessions_1h"]) == 1
    assert int(s2["prior_unique_dst_24h"]) == 1
    assert int(s2["new_dst_prior"]) == 1
    assert int(s2["new_protocol_prior"]) == 1


def test_adding_future_session_cannot_change_earlier_session_features():
    flows, labels = _fixture()
    before, _ = build_session_gold(flows, labels)
    future_flow = pd.DataFrame([{"flow_uid": "f4", "session_id": "s3", "duration": 5.0, "bytes_total": 9999.0, "packets_total": 99.0, "src_bytes": 9000.0, "dst_bytes": 999.0, "connections_1h": 99, "unique_dst_ip_24h": 99, "new_dst_for_src": 1, "new_src_dst_pair": 1, "pair_seen_count": 0, "protocol_entropy_1h": 2.0}])
    future_label = pd.DataFrame([{"flow_uid": "f4", "session_id": "s3", "label_binary": 1, "split": "test", "challenge_reason": "temporal_future", "campaign_id": "c3", "protocol": "rdp", "src_host_id": "src1", "dst_host_id": "dst3", "start_ts": "2026-06-02T10:00:00+00:00", "end_ts": "2026-06-02T10:01:00+00:00", "persona_id": "p1", "implementation_id": "rdp:freerdp->xrdp"}])
    after, _ = build_session_gold(pd.concat([flows, future_flow], ignore_index=True), pd.concat([labels, future_label], ignore_index=True))
    cols = [c for c in before.columns if c != "session_id"]
    pd.testing.assert_series_equal(
        before.loc[before.session_id == "s1", cols].iloc[0],
        after.loc[after.session_id == "s1", cols].iloc[0],
        check_names=False,
    )
