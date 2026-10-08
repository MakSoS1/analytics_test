"""Read-only evidence audit for office application-workload representativeness.

The network-flow table is not a log of user actions. This module blocks the
mistake of inferring a legitimate application mix from destination TCP/443
or from pseudonymized content. No trace synthesis or network I/O occurs.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path

import pandas as pd

from .office_day_transfer import load_additional_days


def _known(value: object) -> bool:
    if not isinstance(value, str):
        return False
    return bool(value.strip()) and not value.strip().lower().startswith(
        ("unknown", "not established", "not independently")
    )


def audit_workload_evidence(
    context: dict[str, object],
    days: tuple[pd.DataFrame, pd.DataFrame],
) -> dict[str, object]:
    capture = dict(context.get("capture_point") or {})
    observation = dict(context.get("measurement_limits") or {})
    annotations = dict(context.get("application_annotations") or {})
    verified_app_categories = bool(
        annotations.get("verified")
        and annotations.get("provenance")
        and annotations.get("user_action_categories")
    )
    topography = {
        field: _known(capture.get(field))
        for field in ("before_or_after_nat", "before_or_after_tls_proxy")
    }
    os_mix = _known(capture.get("client_os_windows_linux_share"))
    tls_rows = []
    nonzero_tls_rows = []
    support = []
    for frame in days:
        versions = pd.to_numeric(frame["tls_version"], errors="coerce")
        tls_rows.append(int(versions.notna().sum()))
        nonzero_tls_rows.append(int(versions.notna().mul(versions.ne(0)).sum()))
        support.append(int(len(frame)))
    tls_usable_across_days = all(0 < n <= total for n, total in zip(tls_rows, support))
    missing = []
    if not verified_app_categories:
        missing.append("verified_application_and_user_action_annotation")
    if not all(topography.values()):
        missing.append("mirror_nat_and_tls_proxy_position")
    if not os_mix:
        missing.append("measured_endpoint_os_population")
    if not tls_usable_across_days:
        missing.append("comparable_observed_tls_across_reference_days")
    # This evidence gate must never use fingerprint, IP, URI, or HMAC tokens.
    return {
        "version": "office-user-workload-evidence-v1",
        "source": "released_pseudonymized_office_reference_only",
        "rows_by_day": support,
        "non_null_tls_version_field_rows_by_day": tls_rows,
        "nonzero_tls_version_rows_by_day": nonzero_tls_rows,
        "verified_application_action_labels": verified_app_categories,
        "capture_position_documented": all(topography.values()),
        "endpoint_os_population_documented": os_mix,
        "tls_observed_on_both_days": tls_usable_across_days,
        "missing_evidence": missing,
        "office_app_mix_inferable_from_port_443": False,
        "office_workload_model_ready": not missing,
        "naturalness_status": "not_passed",
        "production_ready": False,
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()
    context = json.loads((args.root / "capture_context.json").read_text())
    report = audit_workload_evidence(context, load_additional_days(args.root))
    args.out.write_text(json.dumps(report, sort_keys=True, indent=2) + "\n")
    print("OFFICE_WORKLOAD_READINESS", json.dumps(report, sort_keys=True))
    if report["office_workload_model_ready"]:
        print("Application-workload evidence gate complete; independent validation still required.")
    else:
        print("Application-workload adaptation unsupported by these reference data.")


if __name__ == "__main__":
    main()