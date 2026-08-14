from adminlab.v2_gate import decide_v2


BASE = {
    "validation_pr_auc": 0.72,
    "test_pr_auc": 0.68,
    "challenge_recall_at_fpr_1pct": 0.20,
    "hard_benign_fpr": 0.01,
    "best_shortcut_pr_auc": 0.60,
    "windows_mapped_native_protocols": 2,
    "windows_score_distribution_finite": True,
    "lanl_reference_complete": True,
    "last_delta_pr_auc": 0.02,
}


def test_v2_gate_passes_research_and_scale_only_when_all_conditions_hold():
    result = decide_v2(BASE)
    assert result["automatic_gate_pass"] is True
    assert result["allow_scale"] is True


def test_v2_gate_blocks_good_internal_model_when_shortcut_margin_fails():
    values = dict(BASE, best_shortcut_pr_auc=0.70)
    result = decide_v2(values)
    assert result["automatic_gate_pass"] is False
    assert result["allow_scale"] is False
    assert "shortcut_margin" in result["automatic_failures"]


def test_v2_gate_blocks_missing_external_reference_and_native_holdout():
    values = dict(BASE, lanl_reference_complete=False, windows_mapped_native_protocols=0)
    result = decide_v2(values)
    assert result["automatic_gate_pass"] is False
    assert "lanl_reference" in result["automatic_failures"]
    assert "windows_native" in result["automatic_failures"]


def test_v2_gate_can_pass_research_but_stop_scale_on_saturated_curve():
    result = decide_v2(dict(BASE, last_delta_pr_auc=0.001))
    assert result["automatic_gate_pass"] is True
    assert result["allow_scale"] is False
    assert result["scale_decision"] == "STOP_AT_1K"
