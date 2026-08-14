from adminlab.windows_v3 import validate_v3_windows_report


def _base():
    return {
        "protocols": {
            "openssh": {"tool_present": True, "session_completed": True, "wire_observed": True},
            "smb": {"tool_present": True, "session_completed": True, "wire_observed": True},
            "winrm": {"tool_present": True, "session_completed": True, "wire_observed": True},
            "dcom": {"tool_present": True, "session_completed": True, "wire_observed": False},
            "rdp": {"tool_present": True, "session_completed": False, "wire_observed": False},
        }
    }


def test_dcom_completion_without_tcp135_stays_unverified():
    report = validate_v3_windows_report(_base(), extra_port_counts={"135": 0, "3389": 0}, extra_dcom_completed=True)
    assert report["protocols"]["dcom"]["fidelity_status"] == "attempted_unverified"
    assert "dcom" not in report["validated_protocols"]


def test_dcom_requires_completed_query_and_tcp135_wire_evidence():
    report = validate_v3_windows_report(_base(), extra_port_counts={"135": 4, "3389": 0}, extra_dcom_completed=True)
    assert report["protocols"]["dcom"]["fidelity_status"] == "native_windows_validated"
    assert report["protocols"]["dcom"]["endpoint_mapper_wire_observed"] is True
    assert "dcom" in report["validated_protocols"]


def test_rdp_handshake_is_useful_evidence_but_not_full_validation():
    report = validate_v3_windows_report(_base(), extra_port_counts={"135": 0, "3389": 8}, extra_dcom_completed=False)
    rdp = report["protocols"]["rdp"]
    assert rdp["handshake_wire_observed"] is True
    assert rdp["fidelity_status"] == "attempted_unverified"
    assert "rdp" not in report["validated_protocols"]
