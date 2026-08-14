from dataclasses import replace
from pathlib import Path

import pandas as pd

from adminlab.manifest import SessionRecord
from adminlab.pcap_slicing import (
    PcapEvidence,
    build_campaign_pcaps,
    build_pcap_index,
    session_relative_path,
    slice_session_pcaps,
)


def _row(*, session_id: str, label: int, protocol: str, campaign: str, start: str, end: str) -> SessionRecord:
    port = {"ssh": 22, "smb": 445}[protocol]
    return SessionRecord(
        campaign_id=campaign, scenario_id="v3", session_id=session_id, pair_id="",
        label_binary=label, label_family="benign" if label == 0 else "rare_pair",
        mitre_technique="T1021.004", src_role="AdminWorkstation", dst_role="Server",
        src_host_id="src-1", dst_host_id="dst-1", src_ip="10.77.0.10", dst_ip="10.77.0.30",
        src_port=0, dst_port=port, protocol=protocol, action="bounded_admin_session",
        wire_fidelity="real_wire", semantic_fidelity="high", ground_truth_source="scenario_orchestrator",
        netem_profile="normal", generator_seed=1, start_ts=start, end_ts=end, status="success",
        persona_id="persona-1", task_id="diagnostics", calendar_id="business_hours",
        intent_profile="approved" if label == 0 else "lateral", behavior_profile="interactive",
        campaign_type="routine_admin" if label == 0 else "rare_pair", historical_relation="known_pair",
        auth_outcome="success", client_stack="client", server_stack="server",
        implementation_id=f"{protocol}:client->server", simulated_day=1,
        execution_start_ts=start, execution_end_ts=end,
    )


def test_session_path_is_human_browsable():
    row = _row(session_id="abc", label=1, protocol="ssh", campaign="camp-a", start="2026-06-01T10:00:00+00:00", end="2026-06-01T10:01:00+00:00")
    assert session_relative_path(row).as_posix() == "sessions/suspicious/ssh/abc.pcap.zst"


def test_slice_and_campaign_builder_create_indexable_authoritative_tree(tmp_path, monkeypatch):
    merged = tmp_path / "ephemeral-merged.pcap"
    merged.write_bytes(b"temporary merged capture")
    sessions = [
        _row(session_id="b-1", label=0, protocol="ssh", campaign="camp-b", start="2026-06-01T10:00:00+00:00", end="2026-06-01T10:01:00+00:00"),
        _row(session_id="s-1", label=1, protocol="smb", campaign="camp-s", start="2026-06-01T11:00:00+00:00", end="2026-06-01T11:01:00+00:00"),
    ]

    def fake_slice(source, destination, start_ts, end_ts):
        assert source == merged
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_bytes(f"slice:{start_ts}:{end_ts}".encode())

    def fake_merge(inputs, destination):
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_bytes(b"".join(path.read_bytes() for path in inputs))

    monkeypatch.setattr("adminlab.pcap_slicing._slice_pcap", fake_slice)
    monkeypatch.setattr("adminlab.pcap_slicing._merge_pcaps", fake_merge)
    monkeypatch.setattr("adminlab.pcap_slicing._packet_count", lambda path: 7)

    evidence = slice_session_pcaps(merged, sessions, tmp_path / "bronze")
    assert len(evidence) == 2
    assert all(item.packet_count == 7 for item in evidence)
    assert all(item.pcap_bytes > 0 for item in evidence)
    assert all(len(item.sha256) == 64 for item in evidence)
    campaign_evidence = build_campaign_pcaps(evidence, sessions, tmp_path / "bronze")
    assert len(campaign_evidence) == 2

    frame = build_pcap_index(evidence + campaign_evidence, sessions)
    assert isinstance(frame, pd.DataFrame)
    assert {"kind", "label_name", "protocol", "session_id", "campaign_id", "relative_pcap_path", "packet_count", "pcap_bytes", "sha256"} <= set(frame.columns)
    assert set(frame["kind"]) == {"session", "campaign"}
    # The source merged capture is outside the authoritative Bronze tree.
    assert not any("merged" in item.relative_path for item in evidence + campaign_evidence)
