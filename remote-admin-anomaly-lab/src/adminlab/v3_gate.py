from __future__ import annotations

from typing import Any


DEFAULTS = {
    "max_time_only_pr_auc": 0.55,
    "min_full_over_current_session_margin": 0.05,
    "min_full_over_best_nuisance_margin": 0.05,
    "min_validation_pr_auc": 0.60,
    "min_test_pr_auc": 0.58,
    "min_session_mapping_coverage": 0.98,
    "max_hard_benign_fpr": 0.05,
}


def _f(mapping: dict[str, Any], key: str, default: float = 0.0) -> float:
    value = mapping.get(key, default)
    try:
        return float(value)
    except (TypeError, ValueError):
        return float(default)


def evaluate_v3_gate(
    *,
    metrics: dict[str, Any],
    shortcut: dict[str, Any],
    quality: dict[str, Any],
    external: dict[str, Any],
    thresholds: dict[str, float] | None = None,
) -> dict[str, Any]:
    """Return separate technical and scientific decisions for V3.

    A scientifically weak but reproducible dataset remains technically READY and
    is persisted for audit. Scaling is authorized only when every mandatory V3
    signal-quality gate passes.
    """
    t = dict(DEFAULTS)
    if thresholds:
        t.update({key: float(value) for key, value in thresholds.items()})

    technical_failures: list[str] = []
    failed: list[str] = []

    if quality.get("technical_release_ready") is not True:
        technical_failures.append("technical_release_not_ready")
    if quality.get("leakage_pass") is not True:
        technical_failures.append("leakage_audit")
    mapping = _f(quality, "session_mapping_coverage")
    if mapping < t["min_session_mapping_coverage"]:
        technical_failures.append("session_mapping_coverage")
    external_rows = int(external.get("external_rows_in_train", 0) or 0)
    tuned_external = bool(external.get("threshold_tuning_on_external", False))
    if external_rows != 0:
        technical_failures.append("external_training_contamination")
    if tuned_external:
        technical_failures.append("external_threshold_tuning")

    validation_pr = _f(metrics, "validation_pr_auc")
    test_pr = _f(metrics, "test_pr_auc")
    challenge_recall = _f(metrics, "challenge_recall_fpr_1pct")
    if validation_pr < t["min_validation_pr_auc"]:
        failed.append("validation_pr_auc")
    if test_pr < t["min_test_pr_auc"]:
        failed.append("test_pr_auc")
    if challenge_recall <= 0.0:
        failed.append("challenge_recall_fpr_1pct")

    full_pr = _f(shortcut, "full_model_pr_auc", validation_pr)
    time_pr = _f(shortcut, "time_only_pr_auc", 1.0)
    current_pr = _f(shortcut, "current_session_only_pr_auc", 1.0)
    nuisance_pr = _f(shortcut, "best_nuisance_pr_auc", 1.0)
    if time_pr > t["max_time_only_pr_auc"]:
        failed.append("time_only_shortcut")
    if full_pr - current_pr < t["min_full_over_current_session_margin"]:
        failed.append("current_session_margin")
    if full_pr - nuisance_pr < t["min_full_over_best_nuisance_margin"]:
        failed.append("best_nuisance_margin")

    if _f(quality, "hard_benign_fpr", 1.0) > t["max_hard_benign_fpr"]:
        failed.append("hard_benign_fpr")

    # External contamination is both a technical provenance violation and a
    # scientific failure. Keep explicit research reason for status readers.
    if external_rows != 0:
        failed.append("external_training_contamination")
    if tuned_external:
        failed.append("external_threshold_tuning")

    technical_status = "READY" if not technical_failures else "BROKEN"
    if technical_failures:
        failed.extend(reason for reason in technical_failures if reason not in failed)
    failed = list(dict.fromkeys(failed))
    research_status = "PASS" if technical_status == "READY" and not failed else "FAIL"
    scale_decision = "ALLOW_4K" if research_status == "PASS" else "STOP_AT_1K"

    return {
        "schema_version": 3,
        "technical_status": technical_status,
        "research_status": research_status,
        "scale_decision": scale_decision,
        "technical_failures": technical_failures,
        "failed_gates": failed,
        "observed": {
            "validation_pr_auc": validation_pr,
            "test_pr_auc": test_pr,
            "challenge_recall_fpr_1pct": challenge_recall,
            "full_model_pr_auc": full_pr,
            "time_only_pr_auc": time_pr,
            "current_session_only_pr_auc": current_pr,
            "best_nuisance_pr_auc": nuisance_pr,
            "session_mapping_coverage": mapping,
            "hard_benign_fpr": _f(quality, "hard_benign_fpr", 1.0),
            "external_rows_in_train": external_rows,
            "threshold_tuning_on_external": tuned_external,
        },
        "thresholds": t,
        "policy": "V3 1k may scale only when technical provenance, low-shortcut signal quality, low-FPR challenge recall, hard-benign safety and external isolation all pass",
    }
