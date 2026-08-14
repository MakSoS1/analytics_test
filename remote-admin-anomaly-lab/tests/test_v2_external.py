import pandas as pd

from adminlab.v2_external import align_external_features, build_lanl_session_features


def test_lanl_external_features_are_causal_and_network_only():
    net = pd.DataFrame(
        [
            {"time": 100, "duration": 10, "src_device": "A", "dst_device": "B", "protocol": "6", "src_port": 50000, "dst_port": 22, "src_packets": 4, "dst_packets": 3, "src_bytes": 400, "dst_bytes": 300},
            {"time": 200, "duration": 20, "src_device": "A", "dst_device": "C", "protocol": "6", "src_port": 50001, "dst_port": 445, "src_packets": 5, "dst_packets": 4, "src_bytes": 500, "dst_bytes": 400},
        ]
    )
    frame = build_lanl_session_features(net)
    assert len(frame) == 2
    first, second = frame.iloc[0], frame.iloc[1]
    assert int(first["prior_sessions_1h"]) == 0
    assert int(second["prior_sessions_1h"]) == 1
    assert int(second["prior_unique_dst_24h"]) == 1
    assert int(second["new_dst_prior"]) == 1
    assert int(second["new_protocol_prior"]) == 1
    assert float(first["session_total_bytes"]) == 700.0
    assert "label_binary" not in frame.columns
    assert "src_device" not in frame.columns
    assert "dst_device" not in frame.columns


def test_align_external_features_reports_imputation_without_leaking_identity():
    frame = pd.DataFrame({"flow_count": [1.0, 2.0], "session_total_bytes": [10.0, 20.0]})
    aligned, report = align_external_features(frame, ["flow_count", "session_total_bytes", "prior_sessions_1h"])
    assert list(aligned.columns) == ["flow_count", "session_total_bytes", "prior_sessions_1h"]
    assert aligned["prior_sessions_1h"].tolist() == [0.0, 0.0]
    assert report["derived_feature_count"] == 2
    assert report["imputed_feature_count"] == 1
    assert report["coverage_fraction"] == 2 / 3
