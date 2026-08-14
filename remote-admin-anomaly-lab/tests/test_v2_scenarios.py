from dataclasses import replace

from adminlab.manifest import SessionRecord
from adminlab.v2_scenarios import (
    V2_BENIGN_FAMILIES,
    V2_SUSPICIOUS_FAMILIES,
    counterfactual_signature,
    summarize_v2_plan,
)


def _row(*, label: int, session_id: str, pair_id: str = "pair-1", day: int = 4, protocol: str = "ssh") -> SessionRecord:
    return SessionRecord(
        campaign_id="camp-1",
        scenario_id="scenario-1",
        session_id=session_id,
        pair_id=pair_id,
        label_binary=label,
        label_family="benign" if label == 0 else "suspicious",
        mitre_technique="T1021.004",
        src_role="AdminWorkstation",
        dst_role="LinuxServer",
        src_host_id="src-1",
        dst_host_id="dst-1",
        src_ip="10.0.0.10",
        dst_ip="10.0.0.20",
        src_port=0,
        dst_port=22,
        protocol=protocol,
        action="harmless_exec",
        wire_fidelity="real_ssh",
        semantic_fidelity="high",
        ground_truth_source="scenario_orchestrator",
        netem_profile="normal",
        generator_seed=20260814,
        start_ts=f"2026-06-{day + 1:02d}T10:00:00+00:00",
        end_ts=f"2026-06-{day + 1:02d}T10:02:00+00:00",
        status="planned",
        persona_id="admin-01",
        task_id="diagnostics",
        calendar_id="business_hours",
        intent_profile="approved" if label == 0 else "credential_abuse",
        behavior_profile="interactive",
        campaign_type="routine_admin" if label == 0 else "low_slow_lateral",
        historical_relation="known_pair" if label == 0 else "rare_pair",
        auth_outcome="success",
        client_stack="openssh",
        server_stack="openssh-server",
        implementation_id="ssh:openssh->openssh-server",
        simulated_day=day,
    )


def test_v2_has_required_semantic_families():
    assert {
        "routine_admin",
        "scheduled_patch_fanout",
        "backup_burst",
        "helpdesk",
        "incident_response",
        "new_server",
        "new_admin",
        "service_automation",
        "jump_host",
        "offhours_emergency",
        "mass_diagnostics",
        "benign_first_seen",
    } <= V2_BENIGN_FAMILIES
    assert {
        "low_slow_lateral",
        "sudden_fanout",
        "rare_pair",
        "new_protocol",
        "protocol_switch",
        "failed_then_success",
        "target_chain",
        "credential_hop_like",
        "small_copy_then_admin",
        "offhours_lateral",
    } <= V2_SUSPICIOUS_FAMILIES


def test_counterfactual_signature_excludes_label_and_intent_semantics():
    benign = _row(label=0, session_id="benign")
    suspicious = replace(
        benign,
        session_id="suspicious",
        label_binary=1,
        label_family="low_slow_lateral",
        intent_profile="credential_abuse",
        campaign_type="low_slow_lateral",
        historical_relation="rare_pair",
    )
    assert counterfactual_signature(benign) == counterfactual_signature(suspicious)


def test_v2_plan_summary_counts_true_counterfactual_pairs_and_timeline():
    rows = []
    for day in range(30):
        protocol = ("ssh", "smb", "rdp", "vnc")[day % 4]
        benign = _row(label=0, session_id=f"b-{day}", pair_id=f"p-{day}", day=day, protocol=protocol)
        suspicious = replace(
            benign,
            session_id=f"s-{day}",
            label_binary=1,
            label_family="low_slow_lateral",
            intent_profile="credential_abuse",
            campaign_type="low_slow_lateral",
            historical_relation="rare_pair",
        )
        rows.extend([benign, suspicious])
    report = summarize_v2_plan(rows)
    assert report["rows"] == 60
    assert report["counterfactual_pair_fraction"] == 1.0
    assert set(report["per_protocol_label_counts"]) == {"ssh", "smb", "rdp", "vnc"}
    assert min(report["timeline_days_by_protocol"].values()) >= 7
