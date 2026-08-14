from __future__ import annotations

from copy import deepcopy
from typing import Any


def validate_v3_windows_report(
    base_report: dict[str, Any],
    *,
    extra_port_counts: dict[str, int],
    extra_dcom_completed: bool,
) -> dict[str, Any]:
    """Normalize V3 Windows fidelity without upgrading unsupported claims.

    DCOM requires a completed bounded CIM/DCOM operation and endpoint-mapper
    TCP/135 wire evidence. RDP wire evidence without a completed authenticated
    session is recorded as a useful native-handshake observation, not full RDP
    semantic validation.
    """
    report = deepcopy(base_report)
    protocols = report.setdefault("protocols", {})
    validated: list[str] = []

    for name in ("openssh", "smb", "winrm"):
        item = protocols.setdefault(name, {})
        triple = bool(item.get("tool_present")) and bool(item.get("session_completed")) and bool(item.get("wire_observed"))
        item["fidelity_status"] = "native_windows_validated" if triple else "attempted_unverified"
        if triple:
            validated.append(name)

    dcom = protocols.setdefault("dcom", {})
    dcom_135 = int(extra_port_counts.get("135", 0) or 0)
    dcom["endpoint_mapper_wire_count"] = dcom_135
    dcom["endpoint_mapper_wire_observed"] = dcom_135 > 0
    dcom["v3_network_dcom_completed"] = bool(extra_dcom_completed)
    dcom_completed = bool(dcom.get("session_completed")) or bool(extra_dcom_completed)
    dcom_ok = bool(dcom.get("tool_present")) and dcom_completed and dcom_135 > 0
    dcom["wire_observed"] = bool(dcom.get("wire_observed")) or dcom_135 > 0
    dcom["session_completed"] = dcom_completed
    dcom["fidelity_status"] = "native_windows_validated" if dcom_ok else "attempted_unverified"
    if dcom_ok:
        validated.append("dcom")

    rdp = protocols.setdefault("rdp", {})
    rdp_3389 = int(extra_port_counts.get("3389", 0) or 0)
    rdp["handshake_wire_count"] = rdp_3389
    rdp["handshake_wire_observed"] = rdp_3389 > 0
    rdp["wire_observed"] = bool(rdp.get("wire_observed")) or rdp_3389 > 0
    rdp_ok = bool(rdp.get("tool_present")) and bool(rdp.get("session_completed")) and bool(rdp.get("wire_observed"))
    if rdp_ok:
        rdp["fidelity_status"] = "native_windows_validated"
        validated.append("rdp")
    elif rdp_3389 > 0:
        rdp["fidelity_status"] = "attempted_unverified"
        rdp["failure_reason"] = "native mstsc/TermService wire handshake observed, but authenticated interactive hosted-runner session was not proven"
    else:
        rdp["fidelity_status"] = "unavailable_hosted_runner"

    report["schema_version"] = 3
    report["validated_protocols"] = validated
    report["v3_extra_port_counts"] = {str(key): int(value) for key, value in extra_port_counts.items()}
    report["v3_policy"] = {
        "dcom_requires_tcp_135": True,
        "rdp_handshake_is_not_full_session": True,
        "hosted_runner_only": True,
    }
    return report
