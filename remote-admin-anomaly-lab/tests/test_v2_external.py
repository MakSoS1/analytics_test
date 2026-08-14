import pandas as pd

from adminlab.v2_external import (
    align_external_features,
    build_lanl_session_features,
    parse_pktmon_text_sessions,
)


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


def test_pktmon_text_fallback_maps_real_port_evidence_to_session_like_rows():
    text = "\n".join(
        [
            "[00]AAAA.BBBB::2026-08-14 19:09:36.000000000 [Microsoft-Windows-PktMon] PktGroupId 1, PktNumber 1",
            "\tip: 127.0.0.1.50001 > 127.0.0.1.22: Flags [P.], seq 1:101, ack 1, win 1, length 100",
            "[00]AAAA.BBBB::2026-08-14 19:09:36.100000000 [Microsoft-Windows-PktMon] PktGroupId 1, PktNumber 2",
            "\tip: 127.0.0.1.22 > 127.0.0.1.50001: Flags [.], ack 101, win 1, length 50",
            "[00]AAAA.BBBB::2026-08-14 19:09:37.000000000 [Microsoft-Windows-PktMon] PktGroupId 2, PktNumber 1",
            "\tip: ::1.50002 > ::1.5985: Flags [P.], seq 1:201, ack 1, win 1, length 200",
            "[00]AAAA.BBBB::2026-08-14 19:09:37.250000000 [Microsoft-Windows-PktMon] PktGroupId 2, PktNumber 2",
            "\tip: ::1.5985 > ::1.50002: Flags [P.], seq 1:301, ack 201, win 1, length 300",
            "[00]AAAA.BBBB::2026-08-14 19:09:38.000000000 [Microsoft-Windows-PktMon] PktGroupId 3, PktNumber 1",
            "\tip: 127.0.0.1.50003 > 127.0.0.1.445: Flags [P.], seq 1:21, ack 1, win 1, length 20",
        ]
    )
    frame, evidence = parse_pktmon_text_sessions(text, {"openssh", "smb", "winrm"})
    assert len(frame) == 3
    assert set(frame["native_protocol"].astype(str)) == {"openssh", "smb", "winrm"}
    ssh = frame[frame["native_protocol"] == "openssh"].iloc[0]
    assert int(ssh["src_packets"]) == 1
    assert int(ssh["dst_packets"]) == 1
    assert int(ssh["src_bytes"]) == 100
    assert int(ssh["dst_bytes"]) == 50
    assert abs(float(ssh["duration"]) - 0.1) < 1e-6
    assert evidence["transport"] == "pktmon_formatted_text"
    assert evidence["sessions_by_protocol"] == {"openssh": 1, "smb": 1, "winrm": 1}
