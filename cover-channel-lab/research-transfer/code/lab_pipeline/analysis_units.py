"""Strict full68 analysis-unit contract for grouped WSL-only notebooks.

Grouping reduces duplicated analysis work, never the number of canonical
families which must independently carry evidence and a release state.
"""
from __future__ import annotations

import json
from pathlib import Path

from lab_pipeline.full_scope import load_full_scope, required_families, validate_scope


ANALYSIS_UNITS_PATH = Path(__file__).resolve().parent.parent / "docs" / "full68_analysis_units.json"
ANALYSIS_UNITS_FORMAT = "full68-analysis-units-v1"
EVIDENCE_MODE = "per_canonical_family"
EXPECTED_UNIT_COUNT = 28
_REQUIRED_UNIT_FIELDS = frozenset({"unit_id", "title", "reason", "evidence_mode", "families"})


def load_analysis_units(path: Path = ANALYSIS_UNITS_PATH, scope: dict | None = None) -> dict:
    """Load the portable full68 analysis grouping and reject incomplete maps."""
    contract = json.loads(path.read_text())
    checked_scope = load_full_scope() if scope is None else scope
    validate_analysis_units(contract, checked_scope)
    return contract


def validate_analysis_units(contract: dict, scope: dict | None = None) -> None:
    """Reject unit maps that could conceal a missing, duplicate, or aliased family."""
    checked_scope = load_full_scope() if scope is None else scope
    validate_scope(checked_scope)
    if not isinstance(contract, dict):
        raise ValueError("analysis unit contract must be an object")
    if contract.get("format") != ANALYSIS_UNITS_FORMAT:
        raise ValueError("unexpected analysis unit contract format")
    if contract.get("scope_version") != checked_scope.get("scope_version"):
        raise ValueError("analysis unit contract scope_version mismatch")
    if contract.get("unit_count") != EXPECTED_UNIT_COUNT:
        raise ValueError("analysis unit contract must declare exactly 28 units")
    units = contract.get("units")
    if not isinstance(units, list) or len(units) != EXPECTED_UNIT_COUNT:
        raise ValueError("analysis unit contract must contain exactly 28 units")

    unit_ids: list[str] = []
    memberships: list[str] = []
    for unit in units:
        if not isinstance(unit, dict) or _REQUIRED_UNIT_FIELDS - set(unit):
            raise ValueError("every analysis unit must contain its complete contract")
        unit_id = unit["unit_id"]
        if not isinstance(unit_id, str) or not unit_id:
            raise ValueError("analysis unit IDs must be non-empty strings")
        unit_ids.append(unit_id)
        for field in ("title", "reason"):
            if not isinstance(unit[field], str) or not unit[field].strip():
                raise ValueError(f"{unit_id}: {field} must be a non-empty string")
        if unit["evidence_mode"] != EVIDENCE_MODE:
            raise ValueError(f"{unit_id}: evidence must stay per canonical family")
        families = unit["families"]
        if not isinstance(families, list) or not families or not all(
            isinstance(family, str) and family for family in families
        ):
            raise ValueError(f"{unit_id}: families must be a non-empty string list")
        memberships.extend(families)

    if len(unit_ids) != len(set(unit_ids)):
        raise ValueError("analysis unit IDs must be unique")
    canonical = set(required_families(checked_scope))
    if len(memberships) != len(canonical) or set(memberships) != canonical or len(set(memberships)) != len(memberships):
        raise ValueError("analysis units must exactly partition canonical full68 families")


def unit_for_family(family: str, contract: dict | None = None, scope: dict | None = None) -> dict:
    """Return the analysis unit for one exact canonical family.

    Aliases are intentionally not resolved: callers must use the canonical
    family identity that also appears in capture and evaluation provenance.
    """
    checked_scope = load_full_scope() if scope is None else scope
    canonical = set(required_families(checked_scope))
    if family not in canonical:
        raise ValueError(f"{family!r} is not a canonical full68 family")
    checked_contract = load_analysis_units(scope=checked_scope) if contract is None else contract
    validate_analysis_units(checked_contract, checked_scope)
    for unit in checked_contract["units"]:
        if family in unit["families"]:
            return unit
    raise ValueError(f"{family!r} has no analysis unit")
