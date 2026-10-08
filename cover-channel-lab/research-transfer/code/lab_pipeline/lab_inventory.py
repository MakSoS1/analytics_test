#!/usr/bin/env python3
"""Build a WSL-local, metadata-only inventory for the canonical full68 scope.

The inventory deliberately records neither packet captures nor feature rows.
It turns lab metadata and protocol-QC verdicts into a reviewable account of
which *canonical* families have candidate evidence.  A similarly named alias
is an observation, never evidence for another family.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from itertools import product
from pathlib import Path
from typing import Any

from .campaign_contract import (
    classify_contract_cell,
    load_campaign_contract,
    target_cells,
    validate_campaign_contract,
)
from .full_scope import required_families, validate_scope


QC_VERDICTS = frozenset({"confirmed", "contradicted", "no_server_traffic", "indeterminate"})
ACCEPTED_QC_VERDICTS = frozenset({"confirmed", "indeterminate"})
ENDPOINT_EVIDENCE = frozenset({"confirmed", "failed", "unavailable"})
_RECORD_FIELDS = (
    "session_id", "family", "campaign_id", "workload", "netem_profile",
    "capture_source", "version", "duration_s", "qc_verdict", "endpoint_evidence",
    "campaign_contract", "profile_id", "server_endpoint_id", "tool_versions",
)
MATRIX_FIELDS = ("campaign_id", "workload", "netem_profile", "duration_s", "version")


def _as_text(value: object) -> str:
    return str(value or "")


def _blank_family() -> dict[str, Any]:
    return {
        "sessions": 0,
        "accepted_sessions": 0,
        "qc_verdicts": {verdict: 0 for verdict in sorted(QC_VERDICTS)},
        "endpoint_evidence": {state: 0 for state in sorted(ENDPOINT_EVIDENCE)},
        "captured_cells": [],
        "missing_cells": [],
    }


def _qc_by_session(qc: dict[str, Any] | None) -> dict[str, dict[str, str]]:
    if not qc:
        return {}
    rows = qc.get("session_verdicts")
    if rows is None:
        rows = qc.get("sessions", [])
    if not isinstance(rows, list):
        raise ValueError("QC session_verdicts must be a list")

    out: dict[str, dict[str, str]] = {}
    for row in rows:
        if not isinstance(row, dict):
            raise ValueError("QC session verdict must be an object")
        sid = _as_text(row.get("session_id") or row.get("session"))
        family = _as_text(row.get("family"))
        verdict = _as_text(row.get("verdict"))
        endpoint_evidence = _as_text(row.get("endpoint_evidence")) or "unavailable"
        if not sid or not family or verdict not in QC_VERDICTS or endpoint_evidence not in ENDPOINT_EVIDENCE:
            raise ValueError("QC session verdict is incomplete or invalid")
        value = {"family": family, "verdict": verdict, "endpoint_evidence": endpoint_evidence}
        if sid in out and out[sid] != value:
            raise ValueError(f"QC has conflicting verdicts for session {sid}")
        out[sid] = value
    return out


def _increment(slot: dict[str, Any], verdict: str, endpoint_evidence: str) -> None:
    slot["sessions"] += 1
    if verdict in QC_VERDICTS:
        slot["qc_verdicts"][verdict] += 1
    slot["endpoint_evidence"][endpoint_evidence] += 1
    if verdict in ACCEPTED_QC_VERDICTS:
        slot["accepted_sessions"] += 1


def _tool_versions(meta: dict[str, Any]) -> str:
    """Serialize a version declaration without keeping arbitrary metadata."""
    raw = meta.get("tool_versions")
    if raw is None:
        return ""
    if isinstance(raw, (str, int, float)):
        return str(raw)
    if isinstance(raw, (dict, list)):
        return json.dumps(raw, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
    return ""


def build_inventory(
    metadata_dir: Path,
    scope: dict,
    qc: dict[str, Any] | None,
    contract: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Produce a deterministic full68 evidence inventory from session metadata.

    Files without valid tunnel metadata are reported by filename and ignored;
    duplicate session IDs and QC/family disagreement fail closed rather than
    inflating a family count.
    """
    validate_scope(scope)
    if contract is not None:
        validate_campaign_contract(contract)
    canonical = required_families(scope)
    canonical_set = set(canonical)
    qc_by_session = _qc_by_session(qc)
    families = {family: _blank_family() for family in canonical}
    observed: dict[str, dict[str, Any]] = {}
    unknown: dict[str, dict[str, Any]] = {}
    records: list[dict[str, str]] = []
    invalid_metadata_files: list[str] = []
    seen_session_ids: set[str] = set()
    target = target_cells(contract) if contract is not None else set()
    target_cells_by_family: dict[str, set[tuple[str, str, str, str]]] = {
        family: set() for family in canonical
    }
    tool_versions_by_family: dict[str, set[str]] = {family: set() for family in canonical}
    server_endpoints_by_family: dict[str, set[str]] = {family: set() for family in canonical}

    for path in sorted(Path(metadata_dir).glob("*.json")):
        try:
            meta = json.loads(path.read_text())
        except (OSError, ValueError, json.JSONDecodeError):
            invalid_metadata_files.append(path.name)
            continue
        if not isinstance(meta, dict) or _as_text(meta.get("label_binary")) != "tunnel":
            continue
        sid = _as_text(meta.get("session_id"))
        family = _as_text(meta.get("label_family"))
        if not sid or not family:
            invalid_metadata_files.append(path.name)
            continue
        if sid in seen_session_ids:
            raise ValueError(f"duplicate metadata session_id: {sid}")
        seen_session_ids.add(sid)

        qc_result = qc_by_session.get(sid)
        if qc_result and qc_result["family"] != family:
            raise ValueError(f"QC family disagrees with metadata for session {sid}")
        verdict = qc_result["verdict"] if qc_result else "unreviewed"
        endpoint_evidence = qc_result["endpoint_evidence"] if qc_result else "unavailable"
        observed_slot = observed.setdefault(family, _blank_family())
        _increment(observed_slot, verdict, endpoint_evidence)
        if family in canonical_set:
            _increment(families[family], verdict, endpoint_evidence)
        else:
            _increment(unknown.setdefault(family, _blank_family()), verdict, endpoint_evidence)

        record = {
            "session_id": sid,
            "family": family,
            "campaign_id": _as_text(meta.get("campaign_id")),
            "workload": _as_text(meta.get("workload")),
            "netem_profile": _as_text(meta.get("netem_profile")),
            "capture_source": _as_text(meta.get("capture_source")),
            "version": _as_text(meta.get("version")),
            "duration_s": _as_text(meta.get("planned_duration_s")),
            "qc_verdict": verdict,
            "endpoint_evidence": endpoint_evidence,
            "campaign_contract": _as_text(meta.get("campaign_contract")),
            "profile_id": _as_text(meta.get("profile_id")),
            "server_endpoint_id": _as_text(meta.get("server_endpoint_id")),
            "tool_versions": _tool_versions(meta),
        }
        records.append(record)

        if contract is not None and family in canonical_set:
            cell = classify_contract_cell(meta, contract)
            if cell is not None and verdict in ACCEPTED_QC_VERDICTS and endpoint_evidence == "confirmed":
                target_cells_by_family[family].add(cell)
                if record["tool_versions"]:
                    tool_versions_by_family[family].add(record["tool_versions"])
                if record["server_endpoint_id"]:
                    server_endpoints_by_family[family].add(record["server_endpoint_id"])

    dimensions = {
        field: sorted({record[field] for record in records}) for field in MATRIX_FIELDS
    }
    expected_cells = set(product(*(dimensions[field] for field in MATRIX_FIELDS))) if records else set()
    cells_by_family: dict[str, set[tuple[str, ...]]] = {family: set() for family in canonical}
    for record in records:
        family = record["family"]
        if family in cells_by_family:
            cells_by_family[family].add(tuple(record[field] for field in MATRIX_FIELDS))

    def cell_document(cell: tuple[str, ...]) -> dict[str, str]:
        return dict(zip(MATRIX_FIELDS, cell, strict=True))

    aliases_by_family = {
        row["family"]: row["aliases"] for row in scope["families"]
    }
    for family, slot in families.items():
        observed_cells = cells_by_family[family]
        slot["captured_cells"] = [cell_document(cell) for cell in sorted(observed_cells)]
        slot["missing_cells"] = [
            cell_document(cell) for cell in sorted(expected_cells - observed_cells)
        ]
        slot["alias_candidates"] = sorted(
            alias for alias in aliases_by_family[family]
            if observed.get(alias, {}).get("sessions", 0)
        )
        qc_reviewed = sum(slot["qc_verdicts"].values())
        if not slot["sessions"]:
            slot["state"] = "alias_candidate_only" if slot["alias_candidates"] else "missing"
        elif qc_reviewed < slot["sessions"]:
            slot["state"] = "captured"
        elif (slot["accepted_sessions"] and
              slot["endpoint_evidence"]["confirmed"] == slot["accepted_sessions"]):
            slot["state"] = "eligible_for_split"
        else:
            slot["state"] = "qc_complete"

        if contract is not None:
            observed_target_cells = target_cells_by_family[family]
            slot["captured_target_cells"] = [
                {
                    "campaign_id": cell[0],
                    "workload": cell[1],
                    "netem_profile": cell[2],
                    "duration_s": cell[3],
                }
                for cell in sorted(observed_target_cells)
            ]
            slot["missing_target_cells"] = [
                {
                    "campaign_id": cell[0],
                    "workload": cell[1],
                    "netem_profile": cell[2],
                    "duration_s": cell[3],
                }
                for cell in sorted(target - observed_target_cells)
            ]
            slot["tool_versions"] = sorted(tool_versions_by_family[family])
            slot["server_endpoints"] = sorted(server_endpoints_by_family[family])

    inventory = {
        "format": "full68-lab-inventory-v1",
        "scope_version": scope.get("scope_version", ""),
        "matrix_dimensions": dimensions,
        "families": families,
        "observed": dict(sorted(observed.items())),
        "unknown_families": dict(sorted(unknown.items())),
        "invalid_metadata_files": sorted(invalid_metadata_files),
        "session_records": sorted(records, key=lambda row: row["session_id"]),
    }
    if contract is not None:
        inventory["campaign_target"] = {
            "contract_id": contract["contract_id"],
            "target_cell_count": len(target),
            "required_tool_versions_per_family": contract["required_tool_versions_per_family"],
            "required_distinct_server_endpoints_per_family": contract[
                "required_distinct_server_endpoints_per_family"
            ],
        }
    return inventory


def freeze_manifest(
    inventory: dict[str, Any],
    roles: dict[str, list[str]],
    code_hash: str,
    schema_hashes: dict[str, str],
) -> dict[str, Any]:
    """Freeze a group-disjoint lab split without claiming office acceptance."""
    available = {str(row["session_id"]) for row in inventory.get("session_records") or []}
    assigned: dict[str, str] = {}
    normalized_roles: dict[str, list[str]] = {}
    for role, ids in sorted(roles.items()):
        if not isinstance(role, str) or not role or not isinstance(ids, list):
            raise ValueError("roles must map non-empty names to session ID lists")
        normalized = sorted(str(sid) for sid in ids)
        if len(normalized) != len(set(normalized)):
            raise ValueError(f"role {role} lists a session more than once")
        for sid in normalized:
            if sid not in available:
                raise ValueError(f"session {sid} is not present in inventory")
            if sid in assigned:
                raise ValueError(f"session {sid} appears in more than one role")
            assigned[sid] = role
        normalized_roles[role] = normalized
    if not code_hash:
        raise ValueError("code_hash is required")
    if not all(isinstance(key, str) and key and isinstance(value, str) and value
               for key, value in schema_hashes.items()):
        raise ValueError("schema_hashes must map non-empty names to non-empty hashes")

    inventory_hash = hashlib.sha256(
        json.dumps(inventory, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()
    return {
        "format": "full68-freeze-manifest-v1",
        "scope_version": inventory.get("scope_version", ""),
        "inventory_sha256": inventory_hash,
        "code_sha256": code_hash,
        "schema_hashes": dict(sorted(schema_hashes.items())),
        "roles": normalized_roles,
        "release_state": "lab_ready_office_acceptance_pending",
        "office_acceptance": {
            "status": "pending",
            "reason": "office traffic has not been evaluated in this release",
        },
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--metadata-dir", type=Path, required=True)
    parser.add_argument("--scope", type=Path, default=None)
    parser.add_argument("--qc", type=Path, default=None)
    parser.add_argument("--campaign-contract", type=Path, default=None)
    parser.add_argument("--out-json", type=Path, required=True)
    args = parser.parse_args()
    from .full_scope import load_full_scope

    scope = load_full_scope(args.scope) if args.scope else load_full_scope()
    qc = json.loads(args.qc.read_text()) if args.qc else None
    contract = load_campaign_contract(args.campaign_contract) if args.campaign_contract else None
    inventory = build_inventory(args.metadata_dir, scope, qc, contract=contract)
    args.out_json.write_text(json.dumps(inventory, ensure_ascii=False, indent=2) + "\n")
    print(json.dumps({
        "status": "ok",
        "families_with_accepted_sessions": sum(
            1 for slot in inventory["families"].values() if slot["accepted_sessions"]
        ),
        "out": str(args.out_json),
    }))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
