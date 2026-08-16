from __future__ import annotations

from typing import Any


DEFAULTS = {
    "max_time_only_pr_auc": 0.55,
    "max_protocol_only_pr_auc": 0.60,
    "min_full_over_current_session_margin": 0.05,
    "min_full_over_best_nuisance_margin": 0.05,
    "min_history_over_prevalence_margin": 0.05,
    "min_validation_pr_auc": 0.70,
    "min_test_pr_auc": 0.65,
    "min_challenge_pr_auc": 0.65,
    "min_session_mapping_coverage": 0.995,
    "min_flow_mapping_coverage": 0.98,
    "min_protocol_mapping_coverage": 0.99,
    "max_hard_benign_fpr": 0.01,
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
    """Evaluate corrected V3 as an NGFW-flow detector and reproducible dataset."""
    t = dict(DEFAULTS)
    if thresholds:
        t.update({key: float(value) for key, value in thresholds.items()})

    technical_failures: list[str] = []
    failed: list[str] = []

    if quality.get("technical_release_ready") is not True:
        technical_failures.append("technical_release_not_ready")
    if quality.get("leakage_pass") is not True:
        technical_failures.append("leakage_audit")
    if quality.get("causal_observability_pass") is not True:
        technical_failures.append("causal_observability")
    if quality.get("candidate_stream_parity") is not True:
        technical_failures.append("candidate_stream_parity")
    if quality.get("cross_heldout_state_dependency") is not False:
        technical_failures.append("cross_heldout_state_dependency")

    session_mapping = _f(quality, "session_mapping_coverage")
    flow_mapping = _f(quality, "flow_mapping_coverage")
    protocol_mapping = _f(quality, "min_protocol_mapping_coverage")
    if session_mapping < t["min_session_mapping_coverage"]:
        technical_failures.append("session_mapping_coverage")
    if flow_mapping < t["min_flow_mapping_coverage"]:
        technical_failures.append("flow_mapping_coverage")
    if protocol_mapping < t["min_protocol_mapping_coverage"]:
        technical_failures.append("protocol_mapping_coverage")

    external_rows = int(external.get("external_rows_in_train", 0) or 0)
    tuned_external = bool(external.get("threshold_tuning_on_external", False))
    if external_rows != 0:
        technical_failures.append("external_training_contamination")
    if tuned_external:
        technical_failures.append("external_threshold_tuning")

    validation_pr = _f(metrics, "validation_pr_auc")
    test_pr = _f(metrics, "test_pr_auc")
    challenge_pr = _f(metrics, "challenge_pr_auc")
    challenge_recall = _f(metrics, "challenge_recall_fpr_1pct")
    if validation_pr < t["min_validation_pr_auc"]:
        failed.append("validation_pr_auc")
    if test_pr < t["min_test_pr_auc"]:
        failed.append("test_pr_auc")
    if challenge_pr < t["min_challenge_pr_auc"]:
        failed.append("challenge_pr_auc")
    if challenge_recall <= 0.0:
        failed.append("challenge_recall_fpr_1pct")

    full_pr = _f(shortcut, "full_model_pr_auc", validation_pr)
    time_pr = _f(shortcut, "time_only_pr_auc", 1.0)
    protocol_pr = _f(shortcut, "protocol_only_pr_auc", 1.0)
    current_pr = _f(shortcut, "current_session_only_pr_auc", 1.0)
    nuisance_pr = _f(shortcut, "best_nuisance_pr_auc", 1.0)
    prevalence_pr = _f(shortcut, "prevalence_pr_auc", 0.5)
    history_pr = _f(shortcut, "history_only_pr_auc", 0.0)
    if time_pr > t["max_time_only_pr_auc"]:
        failed.append("time_only_shortcut")
    if protocol_pr > t["max_protocol_only_pr_auc"]:
        failed.append("protocol_only_shortcut")
    if full_pr - current_pr < t["min_full_over_current_session_margin"]:
        failed.append("current_session_margin")
    if full_pr - nuisance_pr < t["min_full_over_best_nuisance_margin"]:
        failed.append("best_nuisance_margin")
    if history_pr - prevalence_pr < t["min_history_over_prevalence_margin"]:
        failed.append("history_signal_margin")

    hard_benign_fpr = _f(quality, "hard_benign_fpr", 1.0)
    if hard_benign_fpr > t["max_hard_benign_fpr"]:
        failed.append("hard_benign_fpr")

    if external_rows != 0:
        failed.append("external_training_contamination")
    if tuned_external:
        failed.append("external_threshold_tuning")

    technical_failures = list(dict.fromkeys(technical_failures))
    technical_status = "READY" if not technical_failures else "BROKEN"
    if technical_failures:
        failed.extend(reason for reason in technical_failures if reason not in failed)
    failed = list(dict.fromkeys(failed))
    research_status = "PASS" if technical_status == "READY" and not failed else "FAIL"
    scale_decision = "ALLOW_4K" if research_status == "PASS" else "STOP_AT_1K"

    return {
        "schema_version": 4,
        "primary_unit": "suricata_eve_flow",
        "technical_status": technical_status,
        "research_status": research_status,
        "scale_decision": scale_decision,
        "technical_failures": technical_failures,
        "failed_gates": failed,
        "observed": {
            "validation_pr_auc": validation_pr,
            "test_pr_auc": test_pr,
            "challenge_pr_auc": challenge_pr,
            "challenge_recall_fpr_1pct": challenge_recall,
            "full_model_pr_auc": full_pr,
            "time_only_pr_auc": time_pr,
            "protocol_only_pr_auc": protocol_pr,
            "current_session_only_pr_auc": current_pr,
            "best_nuisance_pr_auc": nuisance_pr,
            "prevalence_pr_auc": prevalence_pr,
            "history_only_pr_auc": history_pr,
            "session_mapping_coverage": session_mapping,
            "flow_mapping_coverage": flow_mapping,
            "min_protocol_mapping_coverage": protocol_mapping,
            "hard_benign_fpr": hard_benign_fpr,
            "external_rows_in_train": external_rows,
            "threshold_tuning_on_external": tuned_external,
        },
        "thresholds": t,
        "policy": "Corrected V3 may scale only when causal NGFW flow signal beats nuisance baselines, low-FPR challenge detection works, hard-benign FPR is <=1%, mapping/parity are production-grade, and external holdouts remain isolated",
    }
