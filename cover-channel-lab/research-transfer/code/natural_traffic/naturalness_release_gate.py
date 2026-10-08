"""Independent, fail-closed assessment of benign workload evidence.

This module does not generate, modify or replay packets. Software CI success
is never equivalent to a naturalness claim for the target office.
"""
from __future__ import annotations

import argparse
import json
import math
from pathlib import Path
from typing import Mapping


def assess_naturalness_evidence(
    report: Mapping[str, object],
    *,
    external_blind_office_verified: bool = False,
    capture_environment_equivalent: bool = False,
    legitimate_workload_labels_verified: bool = False,
) -> dict[str, object]:
    payload = report.get("payload")
    payload = payload if isinstance(payload, dict) else {}
    distribution = payload.get("distribution")
    distribution = distribution if isinstance(distribution, dict) else {}
    support = report.get("support")
    support = support if isinstance(support, dict) else {}
    measured = payload.get("max_auc")
    auc = None
    if type(measured) in (float, int) and math.isfinite(measured):
        auc = float(measured)
    reasons = []
    if report.get("kind") != "naturalness":
        reasons.append("missing_naturalness_report")
    if report.get("status") != "passed_candidate":
        reasons.append("candidate_naturalness_not_passed")
    if auc is None or auc > 0.65 or auc < 0:
        reasons.append("c2st_threshold_not_met")
    if not distribution.get("passed"):
        reasons.append("feature_family_distribution_not_passed")
    if min(int(support.get("office_groups") or 0),
           int(support.get("control_groups") or 0)) < 30:
        reasons.append("insufficient_independent_groups")
    if not external_blind_office_verified:
        reasons.append("new_blind_office_reference_missing")
    if not capture_environment_equivalent:
        reasons.append("measurement_parity_unverified")
    if not legitimate_workload_labels_verified:
        reasons.append("legitimate_application_ground_truth_missing")
    return {
        "version": "benign-office-release-evidence-gate-v1",
        "status": "ready_for_review" if not reasons else "not_ready",
        "reasons": reasons,
        "candidate_max_auc": auc,
        "new_blind_office_verified": bool(external_blind_office_verified),
        "measurement_parity_verified": bool(capture_environment_equivalent),
        "legitimate_application_labels_verified": bool(legitimate_workload_labels_verified),
        "office_naturalness_proven": not reasons,
        "production_ready": False,
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--naturalness", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()
    report = json.loads(args.naturalness.read_text())
    # Only independently attested data could enable these three flags.
    # They cannot be set through CLI arguments or claimed by this job.
    result = assess_naturalness_evidence(report)
    args.out.write_text(json.dumps(result, sort_keys=True, indent=2) + "\n")
    print("BENIGN_NATURALNESS_RELEASE_GATE", json.dumps(result, sort_keys=True))
    return 0 if result["status"] == "ready_for_review" else 1


if __name__ == "__main__":
    raise SystemExit(main())
