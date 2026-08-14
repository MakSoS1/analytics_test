import numpy as np
import pandas as pd

from adminlab.evaluation import (
    campaign_bootstrap_ci,
    evaluate_operating_points,
    prevalence_precision,
    shortcut_audit,
)


def test_operating_points_include_low_fpr_and_fp_per_10k():
    y = np.array([0] * 1000 + [1] * 100)
    score = np.concatenate([np.linspace(0.0, 0.4, 1000), np.linspace(0.3, 1.0, 100)])
    report = evaluate_operating_points(y, score, probability_scores=True)
    assert {"fpr_1pct", "fpr_0_1pct"} <= set(report["operating_points"])
    for point in report["operating_points"].values():
        assert "recall" in point
        assert "fp_per_10k_benign" in point
        assert point["fp_per_10k_benign"] >= 0
    assert "pr_auc" in report and "roc_auc" in report and "brier" in report
    assert "precision_at_prevalence" in report
    assert {"0.1%", "1%"} <= set(report["precision_at_prevalence"])


def test_prevalence_precision_matches_bayes_formula():
    value = prevalence_precision(tpr=0.8, fpr=0.01, prevalence=0.001)
    expected = (0.8 * 0.001) / (0.8 * 0.001 + 0.01 * 0.999)
    assert abs(value - expected) < 1e-12


def test_campaign_bootstrap_returns_95pct_interval():
    rows = []
    for campaign in range(20):
        for i in range(10):
            label = int(i >= 7)
            rows.append({"campaign_id": f"c{campaign}", "label_binary": label, "score": 0.8 if label else 0.2})
    frame = pd.DataFrame(rows)
    report = campaign_bootstrap_ci(frame, n_bootstrap=200, seed=7)
    assert report["campaigns"] == 20
    assert 0 <= report["pr_auc_ci95"][0] <= report["pr_auc_ci95"][1] <= 1
    assert 0 <= report["roc_auc_ci95"][0] <= report["roc_auc_ci95"][1] <= 1


def test_shortcut_audit_flags_bytes_only_dataset():
    train = pd.DataFrame({
        "bytes_total": [1, 2, 3, 4, 100, 110, 120, 130],
        "duration": [5] * 8,
        "dst_port": [22] * 8,
        "connections_1m": [0] * 8,
        "app_proto": ["ssh"] * 8,
        "label_binary": [0, 0, 0, 0, 1, 1, 1, 1],
        "split": ["train"] * 8,
    })
    val = train.copy()
    val["split"] = "validation"
    frame = pd.concat([train, val], ignore_index=True)
    report = shortcut_audit(frame, full_model_pr_auc=1.0)
    assert report["baselines"]["bytes_only"]["pr_auc"] > 0.95
    assert report["shortcut_risk"] is True


def test_shortcut_audit_handles_unavailable_time_features():
    frame = pd.DataFrame({
        "bytes_total": [1, 2, 3, 4],
        "label_binary": [0, 1, 0, 1],
        "split": ["train", "train", "validation", "validation"],
    })
    report = shortcut_audit(frame, full_model_pr_auc=0.5)
    assert report["baselines"]["time_only"]["status"] == "unavailable"
