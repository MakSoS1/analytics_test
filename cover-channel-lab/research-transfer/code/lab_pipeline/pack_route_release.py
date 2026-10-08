#!/usr/bin/env python3
"""Assemble the portable route-model release folder and prove it loads.

The folder is what goes to Git and MLflow: four route models, the bundle that
binds them, the registry of what each route covers, and a card that states the
phase. Nothing here is a claim about office traffic — the card says so in a
field, not in a footnote, because a folder that merely omits the office result
reads like one that passed it.

Traffic material never enters this folder: only models, reports, hashes and
declarations.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path

from lab_pipeline.capture_blockers import load_blockers
from lab_pipeline.full_scope import load_full_scope, required_families
from lab_pipeline.route_bundle import load_route_bundle
from lab_pipeline.route_contract import ROUTES, route_spec
from lab_pipeline.train_fastv1 import code_sha256


BUNDLE_VERSION = "route-bundle-v1"
PHASE = "lab"


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def pack(
    models_dir: Path,
    out_dir: Path,
    *,
    evidence: dict | None = None,
    scope: dict | None = None,
) -> dict:
    """Copy the route models into a self-contained folder and validate it."""
    checked_scope = load_full_scope() if scope is None else scope
    canonical = list(required_families(checked_scope))
    route_by_family = {row["family"]: row["route"] for row in checked_scope["families"]}
    blockers = load_blockers(scope=checked_scope)

    # Check every input BEFORE creating anything: a half-written release folder
    # is worse than none, because it looks like a release.
    sources: dict[str, tuple[Path, Path]] = {}
    for route in ROUTES:
        source = models_dir / f"{route}.json"
        report_path = models_dir / f"{route}_report.json"
        if not source.is_file():
            raise ValueError(f"no trained model for route {route!r} at {source}")
        if not report_path.is_file():
            raise ValueError(f"no training report for route {route!r} at {report_path}")
        sources[route] = (source, report_path)

    out_dir.mkdir(parents=True, exist_ok=True)
    models_out = out_dir / "models"
    models_out.mkdir(exist_ok=True)

    routes: dict[str, dict] = {}
    reports: dict[str, dict] = {}
    for route in ROUTES:
        source, report_path = sources[route]
        target = models_out / f"{route}.json"
        target.write_bytes(source.read_bytes())
        report = json.loads(report_path.read_text())
        reports[route] = report
        spec = route_spec(route)
        routes[route] = {
            "model": f"models/{route}.json",
            "model_sha256": _sha256(target),
            "schema_version": spec.schema_version,
            "contract_hash": spec.contract_hash,
            "threshold": json.loads(target.read_text()).get("threshold"),
            "threshold_source": report.get("threshold_source"),
            "office_calibrated": bool(report.get("office_calibrated")),
            "families": report.get("families") or [],
            "lab_benign_fpr_test": report.get("lab_benign_fpr_test"),
        }

    bundle = {"bundle_version": BUNDLE_VERSION, "phase": PHASE, "routes": routes}
    bundle_path = out_dir / "route_bundle.json"
    bundle_path.write_text(json.dumps(bundle, indent=2, sort_keys=True) + "\n")
    # Loading it here is the point: a folder that cannot be loaded by the
    # shipped loader is not a release, whatever the card says.
    load_route_bundle(bundle_path)

    covered = {family for route in ROUTES for family in routes[route]["families"]}
    registry = []
    for family in canonical:
        blocker = blockers.get(family)
        registry.append({
            "family": family,
            "route": route_by_family[family],
            "in_trained_model": family in covered,
            "capture_blocked": bool(blocker),
            "blocker_reason": blocker["reason"] if blocker else None,
        })
    (out_dir / "family_registry.json").write_text(
        json.dumps({
            "scope_version": checked_scope.get("scope_version"),
            "families": len(registry),
            "covered_by_a_trained_route_model": len(covered & set(canonical)),
            "capture_blocked": sorted(blockers),
            "registry": registry,
        }, indent=2) + "\n"
    )

    card = {
        "release": "full68-route-lab",
        "phase": PHASE,
        "status": "LAB_ONLY_NOT_PRODUCTION",
        "generated": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "scope_version": checked_scope.get("scope_version"),
        "canonical_families": len(canonical),
        "covered_by_a_trained_route_model": len(covered & set(canonical)),
        "capture_blocked": sorted(blockers),
        "office_acceptance": {
            "run": False,
            "note": "No office traffic was read at any stage. Every threshold in this folder "
                    "was selected on lab benign twins and must be re-derived on office "
                    "negatives before any production claim.",
        },
        "per_route": {
            route: {
                "families": len(routes[route]["families"]),
                "threshold": routes[route]["threshold"],
                "threshold_source": routes[route]["threshold_source"],
                "lab_benign_fpr_test": routes[route]["lab_benign_fpr_test"],
                "families_below_0_95_flow_recall": sorted(
                    family
                    for family, stats in (reports[route].get("per_family") or {}).items()
                    if stats.get("flow_recall", 0.0) < 0.95
                ),
            }
            for route in ROUTES
        },
        "runtime_code_sha256": code_sha256(),
        "bundle_sha256": _sha256(bundle_path),
    }
    if evidence is not None:
        families = evidence.get("families") or {}
        card["evidence"] = {
            "campaign_contract": evidence.get("campaign_contract"),
            "families_with_lab_capture": sum(1 for row in families.values() if row.get("sources")),
            "families_with_benign_twin": sum(1 for row in families.values() if "benign_feature_summary" in row),
        }
    (out_dir / "release_card.json").write_text(json.dumps(card, indent=2) + "\n")
    return card


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--models-dir", required=True, type=Path)
    parser.add_argument("--out-dir", required=True, type=Path)
    parser.add_argument("--evidence-json", type=Path, default=None)
    args = parser.parse_args()
    evidence = json.loads(args.evidence_json.read_text()) if args.evidence_json else None
    card = pack(args.models_dir, args.out_dir, evidence=evidence)
    print(json.dumps({
        "status": "ok",
        "phase": card["phase"],
        "covered_by_a_trained_route_model": card["covered_by_a_trained_route_model"],
        "canonical_families": card["canonical_families"],
        "out_dir": str(args.out_dir),
    }, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
