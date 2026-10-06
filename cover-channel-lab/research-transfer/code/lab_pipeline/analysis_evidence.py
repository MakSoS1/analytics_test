"""Aggregate-only evidence reader for grouped full68 analysis notebooks.

This module deliberately accepts counts and metrics, not raw PCAP/EVE paths,
flow rows, packet values, addresses, or session identifiers.  The executed
notebooks live on WSL and obtain their aggregate input from WSL-local release
manifests.
"""
from __future__ import annotations

import json
import math
import re
from pathlib import Path

from lab_pipeline.full_scope import load_full_scope, required_families, validate_scope


ANALYSIS_EVIDENCE_FORMAT = "full68-analysis-evidence-v1"
SOURCE_KINDS = frozenset({"lab_capture", "public_source"})
PROVENANCE_STATUSES = frozenset({"verified", "candidate", "rejected"})
FROZEN_ROLES = frozenset({"train", "validation", "test"})
_SOURCE_FIELDS = frozenset({
    "source_kind",
    "provenance_status",
    "accepted_sessions",
    "excluded_sessions",
    "endpoint_confirmed_sessions",
    "frozen_roles",
    "held_out_metrics",
})
_FAMILY_FIELDS = frozenset({
    "sources", "feature_summary", "benign_feature_summary", "discriminative_features",
    "model_feature_importances",
})
_EFFECT_FIELDS = frozenset({"name", "tunnel_mean", "benign_mean", "effect_size"})
_IMPORTANCE_FIELDS = frozenset({"name", "importance"})
_FEATURE_FIELDS = frozenset({"name", "non_null_count", "mean", "p05", "p50", "p95"})
_FEATURE_NAME = re.compile(r"^[a-z][a-z0-9_]{0,127}$")


def load_analysis_evidence(path: Path, scope: dict | None = None) -> dict:
    """Load a WSL-produced aggregate evidence file without exposing raw data."""
    evidence = json.loads(path.read_text())
    validate_analysis_evidence(evidence, scope)
    return evidence


def validate_analysis_evidence(evidence: dict, scope: dict | None = None) -> None:
    """Validate a data-free full68 evidence summary and reject raw leakage."""
    checked_scope = load_full_scope() if scope is None else scope
    validate_scope(checked_scope)
    if not isinstance(evidence, dict):
        raise ValueError("analysis evidence must be an object")
    if evidence.get("format") != ANALYSIS_EVIDENCE_FORMAT:
        raise ValueError("unexpected analysis evidence format")
    if evidence.get("scope_version") != checked_scope.get("scope_version"):
        raise ValueError("analysis evidence scope_version mismatch")
    if not isinstance(evidence.get("campaign_contract"), str) or not evidence["campaign_contract"]:
        raise ValueError("analysis evidence must declare its campaign_contract")
    families = evidence.get("families")
    if not isinstance(families, dict):
        raise ValueError("analysis evidence families must be an object")
    canonical = set(required_families(checked_scope))
    if set(families) - canonical:
        raise ValueError("analysis evidence may contain only canonical full68 families")
    for family, row in families.items():
        _validate_family_row(family, row)


def _validate_family_row(family: str, row: object) -> None:
    if not isinstance(row, dict) or not {"sources"} <= set(row) or set(row) - _FAMILY_FIELDS:
        raise ValueError(f"{family}: evidence row must contain only aggregate sources and feature_summary")
    sources = row["sources"]
    if not isinstance(sources, list):
        raise ValueError(f"{family}: sources must be a list")
    for source in sources:
        if not isinstance(source, dict) or set(source) - _SOURCE_FIELDS:
            raise ValueError(f"{family}: evidence must be aggregate-only")
        required = _SOURCE_FIELDS - {"held_out_metrics"}
        if required - set(source):
            raise ValueError(f"{family}: incomplete aggregate source record")
        if source["source_kind"] not in SOURCE_KINDS:
            raise ValueError(f"{family}: invalid source_kind")
        if source["provenance_status"] not in PROVENANCE_STATUSES:
            raise ValueError(f"{family}: invalid provenance_status")
        for field in ("accepted_sessions", "excluded_sessions", "endpoint_confirmed_sessions"):
            value = source[field]
            if not isinstance(value, int) or isinstance(value, bool) or value < 0:
                raise ValueError(f"{family}: {field} must be a non-negative integer")
        if source["endpoint_confirmed_sessions"] > source["accepted_sessions"]:
            raise ValueError(f"{family}: endpoint-confirmed sessions exceed accepted sessions")
        roles = source["frozen_roles"]
        if not isinstance(roles, dict) or set(roles) - FROZEN_ROLES:
            raise ValueError(f"{family}: invalid frozen_roles")
        for role, value in roles.items():
            if not isinstance(value, int) or isinstance(value, bool) or value < 0:
                raise ValueError(f"{family}: {role} count must be a non-negative integer")
        if "held_out_metrics" in source:
            _validate_metrics(family, source["held_out_metrics"])
    if "feature_summary" in row:
        _validate_feature_summary(family, row["feature_summary"])
    if "benign_feature_summary" in row:
        _validate_feature_summary(family, row["benign_feature_summary"])
    if "discriminative_features" in row:
        _validate_discriminative_features(family, row)
    if "model_feature_importances" in row:
        _validate_model_importances(family, row["model_feature_importances"])


def _validate_discriminative_features(family: str, row: dict) -> None:
    """Effect sizes must describe features this family actually measured.

    A name that is absent from ``feature_summary`` would let a notebook rank a
    feature the family never observed, which reads as evidence but is not.
    """
    ranked = row["discriminative_features"]
    if not isinstance(ranked, list) or not ranked:
        raise ValueError(f"{family}: discriminative_features must be a non-empty list")
    summary = row.get("feature_summary")
    if not isinstance(summary, dict):
        raise ValueError(f"{family}: discriminative_features need a feature_summary")
    measured = {feature["name"] for feature in summary["features"]}
    seen: set[str] = set()
    for entry in ranked:
        if not isinstance(entry, dict) or set(entry) != _EFFECT_FIELDS:
            raise ValueError(f"{family}: discriminative_features must be aggregate-only")
        name = entry["name"]
        if not isinstance(name, str) or not _FEATURE_NAME.fullmatch(name):
            raise ValueError(f"{family}: invalid discriminative feature name")
        if name not in measured:
            raise ValueError(f"{family}: discriminative feature {name!r} is not in feature_summary")
        if name in seen:
            raise ValueError(f"{family}: duplicate discriminative feature {name!r}")
        seen.add(name)
        for field in ("tunnel_mean", "benign_mean", "effect_size"):
            value = entry[field]
            if not isinstance(value, (int, float)) or isinstance(value, bool) or not math.isfinite(value):
                raise ValueError(f"{family}: invalid discriminative feature statistic")
        if entry["effect_size"] < 0:
            raise ValueError(f"{family}: effect_size is a magnitude and cannot be negative")


def _validate_model_importances(family: str, ranked: object) -> None:
    """What the trained route model weighs, as reported by that model.

    Kept separate from ``discriminative_features``: one is a property of the
    corpus and the other of the detector, and a notebook that conflated them
    would claim the model learned something it may not have.
    """
    if not isinstance(ranked, list) or not ranked:
        raise ValueError(f"{family}: model_feature_importances must be a non-empty list")
    seen: set[str] = set()
    for entry in ranked:
        if not isinstance(entry, dict) or set(entry) != _IMPORTANCE_FIELDS:
            raise ValueError(f"{family}: model_feature_importances must be aggregate-only")
        name = entry["name"]
        if not isinstance(name, str) or not _FEATURE_NAME.fullmatch(name):
            raise ValueError(f"{family}: invalid model importance feature name")
        if name in seen:
            raise ValueError(f"{family}: duplicate model importance for {name!r}")
        seen.add(name)
        value = entry["importance"]
        if not isinstance(value, (int, float)) or isinstance(value, bool) or not 0 <= value <= 1:
            raise ValueError(f"{family}: model importance must be within [0, 1]")


def _validate_metrics(family: str, metrics: object) -> None:
    if not isinstance(metrics, dict) or not metrics:
        raise ValueError(f"{family}: held_out_metrics must be a non-empty object")
    # `precision`/`recall`/`f1` are retained for an independently evaluated
    # family classifier.  fast-v1 is a binary detector, whose frozen evaluator
    # emits both flow and session recall; the latter is the release-floor unit.
    # Keep names explicit rather than relabelling a session result as generic
    # "recall" in a notebook.
    allowed = {
        "precision", "recall", "f1",
        "flow_recall", "session_recall", "first_decision_recall",
    }
    if set(metrics) - allowed:
        raise ValueError(f"{family}: unsupported held-out metric")
    for name, value in metrics.items():
        if not isinstance(value, (int, float)) or isinstance(value, bool) or not 0 <= value <= 1:
            raise ValueError(f"{family}: {name} must be within [0, 1]")


def _validate_feature_summary(family: str, summary: object) -> None:
    if not isinstance(summary, dict):
        raise ValueError(f"{family}: feature_summary must be an object")
    required = {"schema_sha256", "feature_count", "feature_rows", "features"}
    if set(summary) != required:
        raise ValueError(f"{family}: invalid feature_summary fields")
    schema_hash = summary["schema_sha256"]
    if not isinstance(schema_hash, str) or not re.fullmatch(r"[0-9a-f]{64}", schema_hash):
        raise ValueError(f"{family}: feature_summary schema_sha256 must be a SHA256 hex digest")
    for field in ("feature_count", "feature_rows"):
        value = summary[field]
        if not isinstance(value, int) or isinstance(value, bool) or value < 0:
            raise ValueError(f"{family}: feature_summary {field} must be a non-negative integer")
    features = summary["features"]
    if not isinstance(features, list) or len(features) != summary["feature_count"]:
        raise ValueError(f"{family}: feature_summary count mismatch")
    names: list[str] = []
    for feature in features:
        if not isinstance(feature, dict) or set(feature) != _FEATURE_FIELDS:
            raise ValueError(f"{family}: feature_summary must be aggregate-only")
        name = feature["name"]
        if not isinstance(name, str) or not _FEATURE_NAME.fullmatch(name):
            raise ValueError(f"{family}: invalid aggregate feature name")
        names.append(name)
        non_null = feature["non_null_count"]
        if not isinstance(non_null, int) or isinstance(non_null, bool) or not 0 <= non_null <= summary["feature_rows"]:
            raise ValueError(f"{family}: invalid aggregate feature non_null_count")
        quantiles = []
        for field in ("mean", "p05", "p50", "p95"):
            value = feature[field]
            if not isinstance(value, (int, float)) or isinstance(value, bool) or not math.isfinite(value):
                raise ValueError(f"{family}: invalid aggregate feature statistic")
            quantiles.append(value)
        if not quantiles[1] <= quantiles[2] <= quantiles[3]:
            raise ValueError(f"{family}: invalid aggregate feature quantile order")
    if len(names) != len(set(names)):
        raise ValueError(f"{family}: aggregate feature names must be unique")


def family_analysis_summary(family: str, evidence: dict, scope: dict | None = None) -> dict:
    """Return a non-sensitive, per-canonical evidence state for one family."""
    checked_scope = load_full_scope() if scope is None else scope
    validate_analysis_evidence(evidence, checked_scope)
    if family not in set(required_families(checked_scope)):
        raise ValueError(f"{family!r} is not a canonical full68 family")
    family_row = evidence["families"].get(family)
    if family_row is None or not family_row["sources"]:
        return {
            "family": family,
            "analysis_state": "blocked",
            "blocking_reasons": ["no_evidence"],
            "lab_capture": None,
            "public_source": None,
            "held_out_metrics": None,
            "feature_summary": None,
            "benign_feature_summary": None,
            "discriminative_features": None,
            "model_feature_importances": None,
        }

    source_groups = {kind: [] for kind in SOURCE_KINDS}
    for source in family_row["sources"]:
        source_groups[source["source_kind"]].append(source)
    lab = _aggregate_sources(source_groups["lab_capture"])
    public = _aggregate_sources(source_groups["public_source"])

    if lab is None:
        return {
            "family": family,
            "analysis_state": "public_research_only" if public is not None else "blocked",
            "blocking_reasons": ["no_lab_capture"],
            "lab_capture": None,
            "public_source": public,
            "held_out_metrics": None,
            "feature_summary": family_row.get("feature_summary"),
            "benign_feature_summary": family_row.get("benign_feature_summary"),
            "discriminative_features": family_row.get("discriminative_features"),
            "model_feature_importances": family_row.get("model_feature_importances"),
        }

    reasons: list[str] = []
    if not lab["all_provenance_verified"]:
        reasons.append("unverified_lab_provenance")
    if lab["accepted_sessions"] == 0:
        reasons.append("no_accepted_lab_sessions")
    if lab["endpoint_confirmed_sessions"] == 0:
        reasons.append("no_endpoint_confirmed_lab_sessions")
    if lab["frozen_test_sessions"] == 0:
        reasons.append("no_frozen_test_sessions")
    metrics = lab["held_out_metrics"]
    if metrics is None:
        reasons.append("no_held_out_metrics")
    return {
        "family": family,
        "analysis_state": "lab_evaluated" if not reasons else "lab_captured",
        "blocking_reasons": reasons,
        "lab_capture": lab,
        "public_source": public,
        "held_out_metrics": metrics,
        "feature_summary": family_row.get("feature_summary"),
        "benign_feature_summary": family_row.get("benign_feature_summary"),
        "discriminative_features": family_row.get("discriminative_features"),
        "model_feature_importances": family_row.get("model_feature_importances"),
    }


def _aggregate_sources(sources: list[dict]) -> dict | None:
    if not sources:
        return None
    metrics = [source["held_out_metrics"] for source in sources if "held_out_metrics" in source]
    shared_metrics = metrics[0] if len(metrics) == 1 else None
    if len(metrics) > 1 and all(metric == metrics[0] for metric in metrics):
        shared_metrics = metrics[0]
    return {
        "source_records": len(sources),
        "accepted_sessions": sum(source["accepted_sessions"] for source in sources),
        "excluded_sessions": sum(source["excluded_sessions"] for source in sources),
        "endpoint_confirmed_sessions": sum(source["endpoint_confirmed_sessions"] for source in sources),
        "frozen_train_sessions": sum(source["frozen_roles"].get("train", 0) for source in sources),
        "frozen_validation_sessions": sum(source["frozen_roles"].get("validation", 0) for source in sources),
        "frozen_test_sessions": sum(source["frozen_roles"].get("test", 0) for source in sources),
        "all_provenance_verified": all(source["provenance_status"] == "verified" for source in sources),
        "held_out_metrics": shared_metrics,
    }
