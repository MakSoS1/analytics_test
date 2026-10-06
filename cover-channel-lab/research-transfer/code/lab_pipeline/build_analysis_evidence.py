#!/usr/bin/env python3
"""Build aggregate-only, WSL-local evidence for the grouped full68 notebooks.

This reads a WSL feature table and a WSL inventory, but it never writes raw
rows, paths, packet values, addresses, flow IDs or session IDs to the evidence
artifact.  It admits into a feature summary only sessions that are simultaneously
canonical, QC-accepted, endpoint-confirmed and members of the frozen split.

The resulting artifact intentionally assigns ``candidate`` provenance.  A
capture's content can be QC-confirmed without yet having a separately frozen
provenance/hash certificate.  Calling that state ``verified`` would let a
notebook overstate the evidence.  A future WSL-only provenance verifier may
upgrade it only after it has checked the raw artifacts in place.
"""
from __future__ import annotations

import argparse
import csv
import gzip
import hashlib
import json
import math
from collections import defaultdict
from pathlib import Path
from typing import Any

from lab_pipeline.analysis_evidence import (
    ANALYSIS_EVIDENCE_FORMAT,
    validate_analysis_evidence,
)
from lab_pipeline.campaign_contract import load_campaign_contract
from lab_pipeline.full_scope import load_full_scope, required_families
from lab_pipeline.lab_inventory import ACCEPTED_QC_VERDICTS
from lab_pipeline.online_schema import FEATURE_NAMES, contract_hash


DEFAULT_WSL_ROOT = Path("/opt/tunnel_lab")
_ROLES = frozenset({"train", "validation", "test"})
_REQUIRED_FEATURE_COLUMNS = frozenset({
    "session_id", "label_family", "label_binary", "y", "scorable",
})


def _ensure_under_wsl(path: Path, wsl_root: Path, *, purpose: str) -> Path:
    resolved = path.resolve()
    try:
        resolved.relative_to(wsl_root.resolve())
    except ValueError as exc:
        raise ValueError(f"{purpose} must be under the declared WSL root") from exc
    return resolved


def _schema_sha256() -> str:
    payload = json.dumps({
        "contract_hash": contract_hash(),
        "features": list(FEATURE_NAMES),
    }, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(payload.encode()).hexdigest()


def _roles_from_manifest(manifest: dict) -> dict[str, set[str]]:
    if not isinstance(manifest, dict):
        raise ValueError("frozen manifest must be an object")
    group_key = manifest.get("group_key", "session_id")
    if group_key != "session_id":
        raise ValueError("frozen manifest group_key must be session_id")
    raw_roles = manifest.get("groups", manifest.get("roles"))
    if not isinstance(raw_roles, dict) or set(raw_roles) - _ROLES:
        raise ValueError("frozen manifest must contain only train/validation/test roles")
    if not _ROLES <= set(raw_roles):
        raise ValueError("frozen manifest must contain train/validation/test roles")
    seen: set[str] = set()
    roles: dict[str, set[str]] = {}
    for role in sorted(_ROLES):
        values = raw_roles[role]
        if not isinstance(values, list):
            raise ValueError(f"frozen manifest {role} must be a session list")
        normal = {str(value) for value in values}
        if "" in normal or len(normal) != len(values):
            raise ValueError(f"frozen manifest {role} has blank or duplicate session IDs")
        if seen & normal:
            raise ValueError("frozen manifest assigns a session to more than one role")
        seen |= normal
        roles[role] = normal
    return roles


def _inventory_records(inventory: dict, scope: dict, contract: dict) -> list[dict[str, str]]:
    if not isinstance(inventory, dict) or inventory.get("format") != "full68-lab-inventory-v1":
        raise ValueError("inventory must be full68-lab-inventory-v1")
    if inventory.get("scope_version") != scope.get("scope_version"):
        raise ValueError("inventory scope_version does not match full scope")
    target = inventory.get("campaign_target")
    if not isinstance(target, dict) or target.get("contract_id") != contract.get("contract_id"):
        raise ValueError("inventory campaign contract does not match the full68 contract")
    raw_records = inventory.get("session_records")
    if not isinstance(raw_records, list):
        raise ValueError("inventory session_records must be a list")
    canonical = set(required_families(scope))
    seen: set[str] = set()
    records: list[dict[str, str]] = []
    for raw in raw_records:
        if not isinstance(raw, dict):
            raise ValueError("inventory session record must be an object")
        sid = str(raw.get("session_id") or "")
        family = str(raw.get("family") or "")
        verdict = str(raw.get("qc_verdict") or "")
        endpoint = str(raw.get("endpoint_evidence") or "")
        if not sid or not family or not verdict or not endpoint:
            raise ValueError("inventory session record is incomplete")
        if sid in seen:
            raise ValueError("inventory repeats a session ID")
        seen.add(sid)
        if family not in canonical:
            # This can be a historical/unknown observation.  It must not get a
            # canonical notebook section or become a source of family evidence.
            continue
        records.append({
            "session_id": sid,
            "family": family,
            "qc_verdict": verdict,
            "endpoint_evidence": endpoint,
        })
    return records


def _is_scorable(value: object) -> bool:
    return str(value).strip().lower() in {"1", "true", "yes"}


def _as_finite_feature(value: object, name: str) -> float:
    raw = "" if value is None else str(value).strip()
    try:
        result = float(raw) if raw else 0.0
    except ValueError as exc:
        raise ValueError(f"feature CSV has a non-numeric {name!r} value") from exc
    if not math.isfinite(result):
        raise ValueError(f"feature CSV has a non-finite {name!r} value")
    return result


def _read_confirmed_frozen_features(
    feature_csv: Path,
    eligible_family_by_session: dict[str, str],
    frozen_ids: set[str],
    known_family_by_session: dict[str, str] | None = None,
) -> tuple[dict[str, list[list[float]]], dict[str, list[list[float]]]]:
    """Return per-family tunnel rows and the rows of their own benign twins.

    The twin is the benign capture the SAME campaign cell produced, so the
    comparison a notebook draws is against matched traffic rather than against
    whatever benign happens to be in the table.
    """
    opener: Any = gzip.open if feature_csv.suffix == ".gz" else open
    by_family: dict[str, list[list[float]]] = defaultdict(list)
    benign_by_family: dict[str, list[list[float]]] = defaultdict(list)
    known = known_family_by_session or eligible_family_by_session
    twin_family = {
        f"{sid}_benign": family for sid, family in eligible_family_by_session.items() if sid in frozen_ids
    }
    twin_family.update({
        sid.replace("_tunnel", "_benign"): family
        for sid, family in eligible_family_by_session.items()
        if sid in frozen_ids and sid.endswith("_tunnel")
    })
    with opener(feature_csv, "rt", newline="", encoding="utf-8") as fh:
        reader = csv.DictReader(fh)
        header = set(reader.fieldnames or [])
        missing = set(FEATURE_NAMES) | _REQUIRED_FEATURE_COLUMNS
        missing -= header
        if missing:
            raise ValueError(f"feature CSV is missing required columns: {sorted(missing)[:5]}")
        for row in reader:
            if None in row:
                raise ValueError("feature CSV contains an over-wide row")
            # A short row shifts the context columns under the wrong headers.  It
            # may otherwise be skipped merely because its missing session ID is
            # not frozen, concealing corruption in the table being cited.
            if any(row.get(name) is None for name in set(FEATURE_NAMES) | _REQUIRED_FEATURE_COLUMNS):
                raise ValueError("feature CSV contains a short row")
            sid = str(row.get("session_id") or "")
            # The twin check comes first: a frozen split covers benign sessions
            # too, so a twin that is also frozen would otherwise be forced
            # through the confirmed-tunnel assertions and abort the build.
            family = twin_family.get(sid)
            if family is not None:
                if str(row.get("label_binary") or "") == "tunnel" or str(row.get("y") or "") != "0":
                    raise ValueError("benign twin row is not labelled negative")
                if not _is_scorable(row.get("scorable")):
                    continue
                benign_by_family[family].append(
                    [_as_finite_feature(row.get(name), name) for name in FEATURE_NAMES]
                )
                continue
            if sid not in frozen_ids:
                continue
            family = str(row.get("label_family") or "")
            expected = eligible_family_by_session.get(sid)
            if expected is None:
                # Not eligible evidence. That is only an error when the row
                # contradicts what the inventory recorded for this session; a
                # session the inventory simply did not accept (QC rejected it,
                # or its endpoint was never confirmed) is skipped, because the
                # split covers every capture, not only the admissible ones.
                recorded = known.get(sid)
                if recorded is not None and str(row.get("label_binary") or "") == "tunnel" and family != recorded:
                    raise ValueError("feature CSV row does not match frozen tunnel metadata")
                continue
            # A confirmed frozen session must not silently acquire a row
            # attributed to a different tunnel family.
            if family != expected:
                raise ValueError("feature CSV row does not match confirmed frozen tunnel metadata")
            if str(row.get("label_binary") or "") != "tunnel" or str(row.get("y") or "") != "1":
                raise ValueError("feature CSV row for a confirmed tunnel must be labelled positive")
            if not _is_scorable(row.get("scorable")):
                continue
            by_family[family].append([_as_finite_feature(row.get(name), name) for name in FEATURE_NAMES])
    return by_family, benign_by_family


def _percentile(values: list[float], q: float) -> float:
    ordered = sorted(values)
    if len(ordered) == 1:
        return ordered[0]
    pos = q * (len(ordered) - 1)
    lo = int(pos)
    hi = min(lo + 1, len(ordered) - 1)
    return ordered[lo] + (ordered[hi] - ordered[lo]) * (pos - lo)


def _feature_summary(rows: list[list[float]]) -> dict | None:
    if not rows:
        return None
    features = []
    for index, name in enumerate(FEATURE_NAMES):
        values = [row[index] for row in rows]
        features.append({
            "name": name,
            "non_null_count": len(values),
            "mean": sum(values) / len(values),
            "p05": _percentile(values, 0.05),
            "p50": _percentile(values, 0.5),
            "p95": _percentile(values, 0.95),
        })
    return {
        "schema_sha256": _schema_sha256(),
        "feature_count": len(FEATURE_NAMES),
        "feature_rows": len(rows),
        "features": features,
    }


def _stdev(values: list[float], mean: float) -> float:
    if len(values) < 2:
        return 0.0
    return math.sqrt(sum((value - mean) ** 2 for value in values) / (len(values) - 1))


# A feature whose two groups have zero spread and different means is perfectly
# separated: the standardized difference is unbounded. Reporting a large finite
# number would read as a Cohen's d that it is not, so the value is a declared
# sentinel and consumers render it as "fully separated".
SEPARATED_SENTINEL = 1e6


def _discriminative_features(
    tunnel_rows: list[list[float]],
    benign_rows: list[list[float]],
) -> list[dict] | None:
    """Rank EVERY informative feature by the standardized tunnel/twin difference.

    The full ranking is kept, not a top-N slice: a notebook that checks a
    protocol-level prediction has to be able to look up the feature it predicted
    and report its real rank. Truncating here turned "ranked 19th" into "not
    measured", which reads as a refutation and is not one. Features with no
    spread and no difference carry no information and are dropped.
    """
    if not tunnel_rows or not benign_rows:
        return None
    ranked: list[dict] = []
    for index, name in enumerate(FEATURE_NAMES):
        tunnel_values = [row[index] for row in tunnel_rows]
        benign_values = [row[index] for row in benign_rows]
        tunnel_mean = sum(tunnel_values) / len(tunnel_values)
        benign_mean = sum(benign_values) / len(benign_values)
        difference = abs(tunnel_mean - benign_mean)
        pooled = math.sqrt(
            (_stdev(tunnel_values, tunnel_mean) ** 2 + _stdev(benign_values, benign_mean) ** 2) / 2
        )
        if pooled > 0:
            effect = difference / pooled
        elif difference > 0:
            effect = SEPARATED_SENTINEL
        else:
            continue
        ranked.append({
            "name": name,
            "tunnel_mean": tunnel_mean,
            "benign_mean": benign_mean,
            "effect_size": effect,
        })
    ranked.sort(key=lambda entry: (-entry["effect_size"], entry["name"]))
    return ranked or None


def _metrics_from_evaluation(evaluation: dict | None, roles: dict[str, set[str]], scope: dict) -> dict[str, dict]:
    if evaluation is None:
        return {}
    if not isinstance(evaluation, dict):
        raise ValueError("evaluation must be an object")
    full_scope = evaluation.get("full_scope")
    split = evaluation.get("split")
    if (
        evaluation.get("evaluation_mode") != "frozen_model_no_retraining"
        or evaluation.get("phase") != "lab"
        or not isinstance(full_scope, dict)
        or full_scope.get("scope_version") != scope.get("scope_version")
        or not isinstance(split, dict)
        or split.get("frozen_manifest") is not True
        or split.get("lab_group_ids") != {role: sorted(values) for role, values in roles.items()}
    ):
        raise ValueError("evaluation must be a frozen full-scope lab evaluation of this split")
    raw = evaluation.get("per_family")
    if not isinstance(raw, list):
        raise ValueError("evaluation per_family must be a list")
    canonical = set(required_families(scope))
    out: dict[str, dict] = {}
    for row in raw:
        if not isinstance(row, dict):
            raise ValueError("evaluation family metric must be an object")
        family = str(row.get("family") or "")
        if family not in canonical:
            raise ValueError("evaluation contains a non-canonical family")
        if family in out:
            raise ValueError("evaluation contains duplicate family metrics")
        metrics: dict[str, float] = {}
        for name in ("flow_recall", "session_recall", "first_decision_recall"):
            value = row.get(name)
            if value is None:
                continue
            if not isinstance(value, (int, float)) or isinstance(value, bool) or not math.isfinite(value) or not 0 <= value <= 1:
                raise ValueError(f"evaluation has an invalid {name}")
            metrics[name] = float(value)
        if metrics:
            out[family] = metrics
    return out


def _importances_from_route_reports(reports: list[dict], scope: dict) -> dict[str, list[dict]]:
    """Map each family to the importances of the route model that scores it.

    A family is served by exactly one route, so a report that does not list the
    family contributes nothing to it: importances are never borrowed from a
    model that never sees this traffic.
    """
    route_by_family = {row["family"]: row["route"] for row in scope["families"]}
    out: dict[str, list[dict]] = {}
    for report in reports:
        if not isinstance(report, dict):
            raise ValueError("route report must be an object")
        route = report.get("route")
        if route is None:
            raise ValueError("route report must name its route")
        ranked = report.get("feature_importances") or []
        if not ranked:
            continue
        for family in report.get("families") or []:
            if route_by_family.get(family) != route:
                raise ValueError(f"route report lists {family!r} under the wrong route")
            out[family] = [
                {"name": entry["name"], "importance": float(entry["importance"])}
                for entry in ranked
            ]
    return out


def build_analysis_evidence(
    inventory: dict,
    feature_csv: Path,
    frozen_manifest: dict,
    out_json: Path,
    *,
    wsl_root: Path = DEFAULT_WSL_ROOT,
    evaluation: dict | None = None,
    scope: dict | None = None,
    contract: dict | None = None,
    route_reports: list[dict] | None = None,
) -> dict:
    """Write a data-free, canonical full68 notebook evidence artifact on WSL."""
    root = wsl_root.resolve()
    feature_csv = _ensure_under_wsl(feature_csv, root, purpose="feature CSV")
    out_json = _ensure_under_wsl(out_json, root, purpose="analysis evidence output")
    checked_scope = load_full_scope() if scope is None else scope
    checked_contract = load_campaign_contract() if contract is None else contract
    records = _inventory_records(inventory, checked_scope, checked_contract)
    roles = _roles_from_manifest(frozen_manifest)
    metrics = _metrics_from_evaluation(evaluation, roles, checked_scope)
    importances = _importances_from_route_reports(route_reports or [], checked_scope)
    canonical = required_families(checked_scope)
    by_family: dict[str, list[dict[str, str]]] = {family: [] for family in canonical}
    for record in records:
        by_family[record["family"]].append(record)

    eligible_family_by_session = {
        record["session_id"]: record["family"]
        for record in records
        if record["qc_verdict"] in ACCEPTED_QC_VERDICTS
        and record["endpoint_evidence"] == "confirmed"
    }
    frozen_ids = set().union(*roles.values())
    feature_rows, benign_rows = _read_confirmed_frozen_features(
        feature_csv, eligible_family_by_session, frozen_ids,
        {record["session_id"]: record["family"] for record in records},
    )

    families: dict[str, dict] = {family: {"sources": []} for family in canonical}
    for family in canonical:
        family_records = by_family[family]
        if not family_records:
            continue
        accepted = [record for record in family_records if record["qc_verdict"] in ACCEPTED_QC_VERDICTS]
        endpoint_confirmed = [record for record in accepted if record["endpoint_evidence"] == "confirmed"]
        frozen_roles = {
            role: len({record["session_id"] for record in endpoint_confirmed} & ids)
            for role, ids in roles.items()
        }
        frozen_roles = {role: count for role, count in frozen_roles.items() if count}
        source = {
            "source_kind": "lab_capture",
            "provenance_status": "candidate",
            "accepted_sessions": len(accepted),
            "excluded_sessions": len(family_records) - len(accepted),
            "endpoint_confirmed_sessions": len(endpoint_confirmed),
            "frozen_roles": frozen_roles,
        }
        if family in metrics:
            source["held_out_metrics"] = metrics[family]
        families[family]["sources"].append(source)
        summary = _feature_summary(feature_rows.get(family, []))
        if summary is not None:
            families[family]["feature_summary"] = summary
            benign_summary = _feature_summary(benign_rows.get(family, []))
            if benign_summary is not None:
                families[family]["benign_feature_summary"] = benign_summary
            ranked = _discriminative_features(
                feature_rows.get(family, []), benign_rows.get(family, []),
            )
            if ranked is not None:
                families[family]["discriminative_features"] = ranked
        if family in importances:
            families[family]["model_feature_importances"] = importances[family]

    evidence = {
        "format": ANALYSIS_EVIDENCE_FORMAT,
        "scope_version": checked_scope.get("scope_version"),
        "campaign_contract": checked_contract["contract_id"],
        "families": families,
    }
    validate_analysis_evidence(evidence, checked_scope)
    out_json.parent.mkdir(parents=True, exist_ok=True)
    out_json.write_text(json.dumps(evidence, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    return evidence


def _parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--inventory", required=True, type=Path)
    parser.add_argument("--features-csv", required=True, type=Path)
    parser.add_argument("--split-manifest", required=True, type=Path)
    parser.add_argument("--evaluation-json", type=Path, default=None,
                        help="optional frozen full-scope lab evaluation; never an office report")
    parser.add_argument("--route-report", type=Path, action="append", default=None,
                        help="a train_route_lab report; repeat once per route")
    parser.add_argument("--out-json", required=True, type=Path)
    parser.add_argument("--wsl-root", type=Path, default=DEFAULT_WSL_ROOT)
    return parser.parse_args()


def main() -> int:
    args = _parse_args()
    root = args.wsl_root.resolve()
    for path, purpose in ((args.inventory, "inventory"), (args.features_csv, "feature CSV"),
                          (args.split_manifest, "split manifest"), (args.out_json, "analysis evidence output")):
        _ensure_under_wsl(path, root, purpose=purpose)
    if args.evaluation_json is not None:
        _ensure_under_wsl(args.evaluation_json, root, purpose="evaluation")
    evidence = build_analysis_evidence(
        json.loads(args.inventory.read_text()),
        args.features_csv,
        json.loads(args.split_manifest.read_text()),
        args.out_json,
        wsl_root=root,
        evaluation=json.loads(args.evaluation_json.read_text()) if args.evaluation_json else None,
        route_reports=[
            json.loads(_ensure_under_wsl(path, root, purpose="route report").read_text())
            for path in (args.route_report or [])
        ],
    )
    print(json.dumps({
        "status": "ok",
        "families_with_lab_capture": sum(1 for row in evidence["families"].values() if row["sources"]),
        "families_with_feature_summary": sum(1 for row in evidence["families"].values() if "feature_summary" in row),
        "families_with_benign_twin": sum(1 for row in evidence["families"].values() if "benign_feature_summary" in row),
        "families_with_model_importances": sum(1 for row in evidence["families"].values() if "model_feature_importances" in row),
    }))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
