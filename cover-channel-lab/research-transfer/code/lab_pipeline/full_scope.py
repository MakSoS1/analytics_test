"""Portable contract for the complete laboratory tunnel scope.

This is intentionally separate from ``supported_tunnels``.  The latter preserves
the historic run2 evidence registry; this module defines what a future release
must prove before it can claim full-scope coverage.
"""
from __future__ import annotations

import json
from pathlib import Path


FULL_SCOPE_PATH = Path(__file__).resolve().parent.parent / "docs" / "full_scope_catalogue.json"
# Mirrors route_contract.ROUTES: three reachable routes. The declared route of
# a family is what `classify_route` actually does with its traffic, verified
# against the `router_route` column of the feature table — not an intention.
ROUTES = frozenset({"tcp_tls_fast", "quic_udp", "special_transport"})
_REQUIRED_ROW_FIELDS = frozenset({
    "family", "source_sets", "route", "aliases", "aliases_satisfy_evidence", "status", "evidence",
})


def load_full_scope(path: Path = FULL_SCOPE_PATH) -> dict:
    """Load and validate the portable, canonical full68 release contract."""
    scope = json.loads(path.read_text())
    validate_scope(scope)
    return scope


def required_families(scope: dict | None = None) -> list[str]:
    """Return every canonical family that a full-scope release must evidence."""
    checked = load_full_scope() if scope is None else scope
    validate_scope(checked)
    return sorted(row["family"] for row in checked["families"])


def validate_scope(scope: dict) -> None:
    """Reject incomplete, ambiguous, or alias-backed full-scope contracts."""
    legacy = scope.get("legacy54")
    extensions = scope.get("operational_extensions")
    rows = scope.get("families")
    if not isinstance(legacy, list) or len(legacy) != 54 or len(set(legacy)) != 54:
        raise ValueError("legacy54 must contain exactly 54 unique canonical families")
    if not isinstance(extensions, list) or len(extensions) != 14 or len(set(extensions)) != 14:
        raise ValueError("operational_extensions must contain exactly 14 unique canonical families")
    if set(legacy) & set(extensions):
        raise ValueError("legacy54 and operational_extensions must not overlap")
    if not isinstance(rows, list):
        raise ValueError("families must be a list")

    names = [str(row.get("family") or "") for row in rows if isinstance(row, dict)]
    if len(rows) != 68 or len(names) != 68 or len(set(names)) != 68 or any(not name for name in names):
        raise ValueError("full scope must contain exactly 68 unique canonical families")
    expected = set(legacy) | set(extensions)
    if set(names) != expected:
        raise ValueError("family rows must exactly equal legacy54 plus operational_extensions")

    for row in rows:
        if not isinstance(row, dict) or _REQUIRED_ROW_FIELDS - set(row):
            raise ValueError("every family row must contain the complete evidence contract")
        family = row["family"]
        source_sets = row["source_sets"]
        expected_source = "legacy54" if family in legacy else "operational_extension"
        if source_sets != [expected_source]:
            raise ValueError(f"{family}: source_sets does not identify its canonical source")
        if row["route"] not in ROUTES:
            raise ValueError(f"{family}: invalid route")
        if not isinstance(row["aliases"], list) or not all(isinstance(alias, str) and alias for alias in row["aliases"]):
            raise ValueError(f"{family}: aliases must be non-empty strings")
        if row["aliases_satisfy_evidence"] is not False:
            raise ValueError(f"{family}: alias evidence is forbidden")
        if row["status"] != "planned":
            raise ValueError(f"{family}: full68 evidence must start as planned")
        if not isinstance(row["evidence"], dict):
            raise ValueError(f"{family}: evidence must be an object")
