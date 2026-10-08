"""Families that cannot be captured on this stand, and why.

A blocker is an admission, not an excuse: the family still counts against the
full68 denominator. This module exists so the reason lives in one validated
place instead of being retold differently in a report, a notebook and a card.
"""
from __future__ import annotations

import json
from pathlib import Path

from lab_pipeline.full_scope import load_full_scope, required_families


BLOCKERS_PATH = Path(__file__).resolve().parent.parent / "docs" / "full68_blockers.json"
_FORMAT = "full68-capture-blockers-v1"
_REQUIRED = frozenset({"family", "reason", "detail", "unblocks_if", "substitute_refused"})
_REASONS = frozenset({
    "upstream_removed",
    "vendor_issued_config_required",
    "no_headless_control_path",
    "no_server_implementation",
})


def validate_blockers(payload: dict, scope: dict | None = None) -> None:
    """Fail closed on an unnamed family, a free-text reason or a missing remedy."""
    if not isinstance(payload, dict) or payload.get("format") != _FORMAT:
        raise ValueError(f"format must be {_FORMAT!r}")
    checked_scope = load_full_scope() if scope is None else scope
    if payload.get("scope_version") != checked_scope.get("scope_version"):
        raise ValueError("blockers scope_version must match the full scope")
    rows = payload.get("blockers")
    if not isinstance(rows, list):
        raise ValueError("blockers must be a list")
    canonical = set(required_families(checked_scope))
    seen: set[str] = set()
    for row in rows:
        if not isinstance(row, dict) or _REQUIRED - set(row):
            raise ValueError("each blocker must name the family, reason, detail, remedy and refused substitute")
        family = row["family"]
        if family not in canonical:
            raise ValueError(f"{family!r} is not a canonical full68 family")
        if family in seen:
            raise ValueError(f"duplicate blocker for {family!r}")
        seen.add(family)
        if row["reason"] not in _REASONS:
            raise ValueError(f"{family}: unsupported blocker reason {row['reason']!r}")
        for field in ("detail", "unblocks_if", "substitute_refused"):
            value = row[field]
            if not isinstance(value, str) or len(value.strip()) < 20:
                raise ValueError(f"{family}: {field} must be a substantive explanation")


def load_blockers(path: Path = BLOCKERS_PATH, scope: dict | None = None) -> dict[str, dict]:
    """Return the validated blocker map keyed by canonical family."""
    payload = json.loads(Path(path).read_text())
    validate_blockers(payload, scope)
    return {row["family"]: row for row in payload["blockers"]}


def blocked_families(path: Path = BLOCKERS_PATH, scope: dict | None = None) -> frozenset[str]:
    return frozenset(load_blockers(path, scope))
