from __future__ import annotations

from collections.abc import Mapping


DEFAULT_THRESHOLDS = {
    "validation_pr_auc_min": 0.65,
    "test_pr_auc_min": 0.60,
    "shortcut_margin_min": 0.05,
    "hard_benign_fpr_max": 0.05,
    "challenge_recall_at_fpr_1pct_min_exclusive": 0.0,
    "learning_curve_delta_for_scale": 0.005,
    "windows_mapped_native_protocols_min": 1,
}


def decide_v2(values: Mapping[str, object], thresholds: Mapping[str, object] | None = None) -> dict:
    cfg = dict(DEFAULT_THRESHOLDS)
    if thresholds:
        cfg.update(thresholds)

    val = float(values.get("validation_pr_auc", 0.0))
    test = float(values.get("test_pr_auc", 0.0))
    recall = float(values.get("challenge_recall_at_fpr_1pct", 0.0))
    hard_fpr = float(values.get("hard_benign_fpr", 1.0))
    shortcut = float(values.get("best_shortcut_pr_auc", 1.0))
    windows_count = int(values.get("windows_mapped_native_protocols", 0))
    windows_finite = bool(values.get("windows_score_distribution_finite", False))
    lanl_complete = bool(values.get("lanl_reference_complete", False))
    curve_delta = float(values.get("last_delta_pr_auc", 0.0))

    failures: list[str] = []
    if val < float(cfg["validation_pr_auc_min"]):
        failures.append("validation_pr_auc")
    if test < float(cfg["test_pr_auc_min"]):
        failures.append("test_pr_auc")
    if recall <= float(cfg["challenge_recall_at_fpr_1pct_min_exclusive"]):
        failures.append("challenge_recall_at_fpr_1pct")
    if hard_fpr > float(cfg["hard_benign_fpr_max"]):
        failures.append("hard_benign_fpr")
    if val - shortcut < float(cfg["shortcut_margin_min"]):
        failures.append("shortcut_margin")
    if windows_count < int(cfg["windows_mapped_native_protocols_min"]) or not windows_finite:
        failures.append("windows_native")
    if not lanl_complete:
        failures.append("lanl_reference")

    automatic_gate_pass = not failures
    allow_scale = automatic_gate_pass and curve_delta > float(cfg["learning_curve_delta_for_scale"])
    return {
        "schema_version": 2,
        "automatic_gate_pass": automatic_gate_pass,
        "automatic_failures": failures,
        "allow_scale": allow_scale,
        "scale_decision": "ALLOW_4K" if allow_scale else "STOP_AT_1K",
        "metrics": {
            "validation_pr_auc": val,
            "test_pr_auc": test,
            "challenge_recall_at_fpr_1pct": recall,
            "hard_benign_fpr": hard_fpr,
            "best_shortcut_pr_auc": shortcut,
            "shortcut_margin": val - shortcut,
            "windows_mapped_native_protocols": windows_count,
            "windows_score_distribution_finite": windows_finite,
            "lanl_reference_complete": lanl_complete,
            "last_delta_pr_auc": curve_delta,
        },
        "thresholds": cfg,
    }
