"""Immutable target matrix for the fresh full68 laboratory campaign.

Historical metadata is an observation record, not a campaign specification.
In particular, a tool-version value can demonstrate diversity but must never
multiply a planned workload/netem/duration coverage matrix.
"""
from __future__ import annotations

import argparse
import itertools
import json
from pathlib import Path
from typing import Any


CAMPAIGN_CONTRACT_PATH = (
    Path(__file__).resolve().parent.parent / "docs" / "full68_campaign_contract.json"
)
_FORMAT = "full68-campaign-contract-v1"
_ROLES = {
    "full68_c1": "train",
    "full68_c2": "train",
    "full68_c3": "validation",
    "full68_c4": "test",
}
_WORKLOADS = ("interactive", "browse", "bulk_download", "idle", "mixed")
_NETEMS = ("clean", "wan", "lossy", "mobile")
_DURATIONS = (45, 90, 150)


def _exact_list(value: object, expected: tuple[object, ...], name: str) -> None:
    if not isinstance(value, list) or tuple(value) != expected:
        raise ValueError(f"{name} must equal {list(expected)!r}")
    if len(value) != len(set(value)):
        raise ValueError(f"{name} must not contain duplicate values")


def validate_campaign_contract(contract: dict[str, Any]) -> None:
    """Reject an ambiguous or mutable-looking full68 campaign specification."""
    if not isinstance(contract, dict):
        raise ValueError("campaign contract must be an object")
    if contract.get("format") != _FORMAT:
        raise ValueError(f"format must be {_FORMAT!r}")
    if contract.get("contract_id") != "full68-v1":
        raise ValueError("contract_id must be 'full68-v1'")
    if contract.get("campaign_roles") != _ROLES:
        raise ValueError("campaign_roles must define the four full68 roles")
    _exact_list(contract.get("workloads"), _WORKLOADS, "workloads")
    _exact_list(contract.get("netem_profiles"), _NETEMS, "netem_profiles")
    _exact_list(contract.get("durations_s"), _DURATIONS, "durations_s")
    for field in (
        "required_tool_versions_per_family",
        "required_distinct_server_endpoints_per_family",
    ):
        if contract.get(field) != 2:
            raise ValueError(f"{field} must be 2")


def load_campaign_contract(path: Path = CAMPAIGN_CONTRACT_PATH) -> dict[str, Any]:
    """Load and validate the versioned, portable campaign contract."""
    contract = json.loads(Path(path).read_text())
    validate_campaign_contract(contract)
    return contract


def target_cells(contract: dict[str, Any]) -> set[tuple[str, str, str, str]]:
    """Return the 4×5×4×3 release target, independent of tool versions."""
    validate_campaign_contract(contract)
    return {
        (campaign, workload, netem, str(duration))
        for campaign, workload, netem, duration in itertools.product(
            contract["campaign_roles"],
            contract["workloads"],
            contract["netem_profiles"],
            contract["durations_s"],
        )
    }


def classify_contract_cell(
    meta: dict[str, object], contract: dict[str, Any],
) -> tuple[str, str, str, str] | None:
    """Return a target cell only for metadata explicitly tied to this contract."""
    validate_campaign_contract(contract)
    if meta.get("campaign_contract") != contract["contract_id"]:
        return None
    cell = (
        str(meta.get("campaign_id") or ""),
        str(meta.get("workload") or ""),
        str(meta.get("netem_profile") or ""),
        str(meta.get("planned_duration_s") or ""),
    )
    return cell if cell in target_cells(contract) else None


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--contract", type=Path, default=CAMPAIGN_CONTRACT_PATH)
    args = parser.parse_args()
    contract = load_campaign_contract(args.contract)
    print(json.dumps({
        "contract_id": contract["contract_id"],
        "target_cells": len(target_cells(contract)),
    }, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
