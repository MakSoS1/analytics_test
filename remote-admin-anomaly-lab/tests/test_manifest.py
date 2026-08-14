import json
from pathlib import Path

from adminlab.manifest import SessionRecord, write_sessions


def sample_record() -> SessionRecord:
    return SessionRecord(
        campaign_id="cmp-001",
        scenario_id="ssh_admin",
        session_id="ses-001",
        pair_id="",
        label_binary=0,
        label_family="benign",
        mitre_technique="T1021.004",
        src_role="DomainAdmin",
        dst_role="LinuxServer",
        src_host_id="paw01",
        dst_host_id="linux01",
        src_ip="10.77.0.11",
        dst_ip="10.77.0.21",
        src_port=51001,
        dst_port=22,
        protocol="ssh",
        action="harmless_exec",
        wire_fidelity="real_ssh",
        semantic_fidelity="high",
        ground_truth_source="scenario_orchestrator",
        netem_profile="clean",
        generator_seed=7,
        start_ts="2026-08-14T09:00:00+00:00",
        end_ts="2026-08-14T09:00:03+00:00",
        status="planned",
    )


def test_session_record_has_independent_ground_truth():
    record = sample_record()
    data = record.to_dict()
    assert data["ground_truth_source"] == "scenario_orchestrator"
    assert "expected_sid" not in data
    assert data["label_binary"] == 0


def test_write_sessions_jsonl_round_trip(tmp_path: Path):
    out = tmp_path / "sessions.jsonl"
    write_sessions([sample_record()], out)
    rows = [json.loads(line) for line in out.read_text(encoding="utf-8").splitlines()]
    assert len(rows) == 1
    assert rows[0]["session_id"] == "ses-001"
    assert rows[0]["dst_ip"] == "10.77.0.21"
