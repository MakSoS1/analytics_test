from adminlab.v3_gate import evaluate_v3_gate


def _base():
    return dict(
        metrics={
            "validation_pr_auc": 0.70,
            "test_pr_auc": 0.68,
            "challenge_recall_fpr_1pct": 0.20,
        },
        shortcut={
            "time_only_pr_auc": 0.51,
            "current_session_only_pr_auc": 0.55,
            "best_nuisance_pr_auc": 0.56,
            "full_model_pr_auc": 0.70,
        },
        quality={
            "session_mapping_coverage": 0.99,
            "hard_benign_fpr": 0.01,
            "leakage_pass": True,
            "technical_release_ready": True,
        },
        external={"external_rows_in_train": 0, "threshold_tuning_on_external": False},
    )


def test_v3_gate_passes_only_when_signal_beats_shortcuts():
    decision = evaluate_v3_gate(**_base())
    assert decision["technical_status"] == "READY"
    assert decision["research_status"] == "PASS"
    assert decision["scale_decision"] == "ALLOW_4K"
    assert decision["failed_gates"] == []


def test_v3_gate_rejects_time_only_shortcut_even_with_high_full_pr_auc():
    values = _base()
    values["shortcut"]["time_only_pr_auc"] = 0.60
    decision = evaluate_v3_gate(**values)
    assert decision["technical_status"] == "READY"
    assert decision["research_status"] == "FAIL"
    assert decision["scale_decision"] == "STOP_AT_1K"
    assert "time_only_shortcut" in decision["failed_gates"]


def test_v3_gate_rejects_full_model_that_does_not_beat_current_session_or_nuisance():
    values = _base()
    values["shortcut"].update(
        full_model_pr_auc=0.60,
        current_session_only_pr_auc=0.57,
        best_nuisance_pr_auc=0.56,
    )
    decision = evaluate_v3_gate(**values)
    assert "current_session_margin" in decision["failed_gates"]
    assert "best_nuisance_margin" in decision["failed_gates"]


def test_v3_gate_rejects_external_contamination_and_zero_challenge_recall():
    values = _base()
    values["metrics"]["challenge_recall_fpr_1pct"] = 0.0
    values["external"]["external_rows_in_train"] = 1
    decision = evaluate_v3_gate(**values)
    assert "challenge_recall_fpr_1pct" in decision["failed_gates"]
    assert "external_training_contamination" in decision["failed_gates"]


def test_v3_gate_separates_technical_failure_from_scientific_failure():
    values = _base()
    values["quality"]["technical_release_ready"] = False
    decision = evaluate_v3_gate(**values)
    assert decision["technical_status"] == "BROKEN"
    assert decision["research_status"] == "FAIL"
    assert decision["scale_decision"] == "STOP_AT_1K"
