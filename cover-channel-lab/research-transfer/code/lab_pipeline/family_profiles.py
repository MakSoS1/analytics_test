"""Curated per-family wire profiles: the prediction a notebook is checked against.

Each profile states, in advance, which fast-v1 features the protocol's own
mechanism should move and why. That turns a notebook from a rendering of
whatever the data happens to contain into a falsifiable claim: the family's
notebook prints the prediction next to the measurement and reports the misses.
"""
from __future__ import annotations

import json
from pathlib import Path

from lab_pipeline.full_scope import load_full_scope, required_families
from lab_pipeline.online_schema import FEATURE_NAMES


PROFILES_PATH = Path(__file__).resolve().parent.parent / "docs" / "full68_family_profiles.json"
_FORMAT = "full68-family-profiles-v1"
_REQUIRED = frozenset({
    "family", "wire_summary", "mechanism", "expected_features",
    "benign_twin", "confusable_with", "limits",
    # One short Russian sentence. The notebooks are read in Russian and a long
    # English paragraph is not something a reader skims, so this is what they
    # actually show; the English fields stay as the working record.
    "ru_summary",
    # One or two Russian sentences saying why this protocol's design produces an
    # observable difference at all. The notebook prints it next to the features
    # that actually fired, so the reader sees mechanism, not just a ranking.
    "ru_why",
})
_EXPECTED_FIELDS = frozenset({"feature", "expect", "because"})
_MIN_PREDICTIONS = 3


def validate_family_profiles(payload: dict, scope: dict | None = None) -> None:
    """Fail closed on a missing family, an invented feature or an empty claim."""
    if not isinstance(payload, dict) or payload.get("format") != _FORMAT:
        raise ValueError(f"format must be {_FORMAT!r}")
    checked_scope = load_full_scope() if scope is None else scope
    if payload.get("scope_version") != checked_scope.get("scope_version"):
        raise ValueError("family profiles scope_version must match the full scope")
    rows = payload.get("families")
    if not isinstance(rows, list):
        raise ValueError("families must be a list")
    canonical = set(required_families(checked_scope))
    names = [row.get("family") for row in rows if isinstance(row, dict)]
    if len(rows) != len(canonical) or set(names) != canonical or len(set(names)) != len(names):
        raise ValueError("family profiles must cover exactly every canonical full68 family once")
    known_features = set(FEATURE_NAMES)
    for row in rows:
        family = row["family"]
        if _REQUIRED - set(row) or set(row) - _REQUIRED:
            raise ValueError(f"{family}: profile must have exactly the declared fields")
        for field in ("wire_summary", "mechanism", "benign_twin", "limits"):
            value = row[field]
            if not isinstance(value, str) or len(value.strip()) < 40:
                raise ValueError(f"{family}: {field} must be a substantive explanation")
        for field, ceiling in (("ru_summary", 220), ("ru_why", 320)):
            russian = row[field]
            if not isinstance(russian, str) or len(russian.strip()) < 30:
                raise ValueError(f"{family}: {field} must be a short sentence")
            if len(russian) > ceiling:
                raise ValueError(f"{family}: {field} must stay short enough to skim")
            if not any("\u0430" <= ch.lower() <= "\u044f" for ch in russian):
                raise ValueError(f"{family}: {field} must actually be in Russian")
        predictions = row["expected_features"]
        if not isinstance(predictions, list) or len(predictions) < _MIN_PREDICTIONS:
            raise ValueError(f"{family}: at least {_MIN_PREDICTIONS} feature predictions are required")
        seen: set[str] = set()
        for prediction in predictions:
            if not isinstance(prediction, dict) or set(prediction) != _EXPECTED_FIELDS:
                raise ValueError(f"{family}: each prediction needs feature, expect and because")
            feature = prediction["feature"]
            if feature not in known_features:
                raise ValueError(f"{family}: {feature!r} is not in the fast-v1 feature contract")
            if feature in seen:
                raise ValueError(f"{family}: duplicate prediction for {feature!r}")
            seen.add(feature)
            for field in ("expect", "because"):
                if not isinstance(prediction[field], str) or not prediction[field].strip():
                    raise ValueError(f"{family}: prediction {field} must not be empty")
        confusable = row["confusable_with"]
        if not isinstance(confusable, list) or len(set(confusable)) != len(confusable):
            raise ValueError(f"{family}: confusable_with must be a list without repeats")
        if family in confusable:
            raise ValueError(f"{family}: a family cannot be confusable with itself")
        unknown = [name for name in confusable if name not in canonical]
        if unknown:
            raise ValueError(f"{family}: confusable_with names non-canonical families {unknown}")


def load_family_profiles(path: Path = PROFILES_PATH, scope: dict | None = None) -> dict[str, dict]:
    """Return the validated per-family profile map keyed by canonical family."""
    payload = json.loads(Path(path).read_text())
    validate_family_profiles(payload, scope)
    return {row["family"]: row for row in payload["families"]}
