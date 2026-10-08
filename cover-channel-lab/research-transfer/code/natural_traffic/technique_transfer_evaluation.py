"""Independent evaluation of defender technique signals and office transfer.

Office data have no confirmed benign/attack labels: only alert *fractions*
can be reported. Technique recall is measured on independently held-out,
explicitly corroborated scenario/control sessions, not office uploads.
"""

from __future__ import annotations

from hashlib import sha256
import json
from pathlib import Path

import joblib
import numpy as np
import pandas as pd
from sklearn.metrics import average_precision_score, roc_auc_score

from .corpus_splits import assert_split_independence, connected_component_ids
from .office_reference import freeze_feature_contract


# Frozen research gates. These are not to be tuned against the final test split.
MIN_TEST_ROC_AUC = .70
MIN_TEST_PR_AUC = .60
MIN_TEST_RECALL = .50
MAX_PROVENANCE_AUC = .60
MAX_SHUFFLED_AUC = .65


def _sha(path: Path) -> str:
    h = sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def _verify_checksum(path: Path, expected: str) -> None:
    if not path.is_file() or _sha(path) != expected:
        raise ValueError(f"evaluation artifact checksum mismatch: {path.name}")


def _assert_same_validation_metric(reported: float, computed: float, name: str) -> None:
    """Editable report numbers cannot override measurements from frozen models."""
    if not np.isfinite(computed) or not np.isfinite(reported) or not np.isclose(
        reported, computed, rtol=1e-10, atol=1e-12,
    ):
        raise ValueError(f"validation {name} mismatch between report and measured model")


def evaluate_technique_transfer(
    prepared_dir: Path, model_dir: Path, office_days: dict[str, pd.DataFrame], out: Path,
) -> dict:
    """Compute frozen test metrics and office alert fractions; never refit."""
    prepared = Path(prepared_dir)
    root = Path(model_dir)
    out = Path(out)
    if out.exists():
        raise FileExistsError(out)
    manifest_path = prepared / "corpus_manifest.json"
    manifest_hash = _sha(manifest_path)
    corpus = json.loads(manifest_path.read_text())
    for file in ("features.parquet", "labels_metadata.parquet"):
        _verify_checksum(prepared / file, corpus["outputs"][file])
    training = json.loads((root / "training_report.json").read_text())
    if training.get("source_corpus_sha256") != manifest_hash:
        raise ValueError("training/corpus checksum mismatch")
    _verify_checksum(root / "splits.parquet", training["split_checksum"])
    for technique, details in training["techniques"].items():
        relative = f"models/{technique}.joblib"
        _verify_checksum(root / relative, training["model_checksums"][relative])
    x = pd.read_parquet(prepared / "features.parquet")
    meta = pd.read_parquet(prepared / "labels_metadata.parquet")
    split_frame = pd.read_parquet(root / "splits.parquet")
    if len(x) != len(meta) or len(meta) != len(split_frame) or (
        list(split_frame["row_index"]) != list(range(len(meta)))
    ):
        raise ValueError("evaluation row/label/split alignment mismatch")
    actual_techniques = set(meta.loc[meta["label_binary"].eq(1), "technique_id"].dropna().astype(str))
    if set(training["techniques"]) != actual_techniques:
        raise ValueError("training technique list mismatch with verified corpus")
    splits = pd.Series(split_frame["split"].to_numpy(), index=meta.index)
    assert_split_independence(meta, splits)
    features = training["feature_columns"]
    frozen = freeze_feature_contract(x, office_days)
    if features != frozen["feature_columns"] or (
        training["feature_schema_sha256"] != frozen["feature_schema_sha256"]
    ):
        raise ValueError("frozen office feature schema checksum mismatch")
    components = connected_component_ids(meta)
    per_technique = {}
    fitted = {}
    for technique, detail in sorted(training["techniques"].items()):
        bundle = joblib.load(root / "models" / f"{technique}.joblib")
        if bundle["technique_id"] != technique or bundle["feature_order"] != features or (
            bundle["source_corpus_sha256"] != manifest_hash
        ):
            raise ValueError("loaded model contract checksum mismatch")
        eligible = meta["technique_id"].eq(technique) & meta["label_binary"].isin((0, 1))
        evidence_tiers = set(meta.loc[eligible, "evidence_tier"])
        research_evidence_eligible = evidence_tiers == {"independently_verified"}
        val_mask = eligible & splits.eq("validation")
        val_y = meta.loc[val_mask, "label_binary"].astype(int).to_numpy()
        if len(set(val_y)) != 2:
            raise ValueError(f"validation technique {technique} requires both classes")
        val_x = x.loc[val_mask, features]
        val_scores = bundle["model"].predict_proba(val_x)[:, 1]
        val_shuffled = bundle["shuffled_label_model"].predict_proba(val_x)[:, 1]
        origin_val = meta.loc[val_mask, bundle["origin_fields"]].fillna("unknown").astype(str)
        val_provenance = bundle["provenance_only_model"].predict_proba(origin_val)[:, 1]
        measured_prov_auc = float(roc_auc_score(val_y, val_provenance))
        measured_shuffled_auc = float(roc_auc_score(val_y, val_shuffled))
        _assert_same_validation_metric(detail["provenance_only_validation_auc"],
                                       measured_prov_auc, "provenance AUC")
        _assert_same_validation_metric(detail["shuffled_label_validation_auc"],
                                       measured_shuffled_auc, "shuffled-label AUC")
        budget = bundle["validation_control_alert_budget"]
        if not isinstance(budget, (float, int)) or not .001 <= budget <= .1 or (
            not np.isclose(budget, training["validation_control_alert_budget"])
        ):
            raise ValueError("validation control alert budget mismatch")
        expected_threshold = float(np.quantile(val_scores[val_y == 0], 1 - budget))
        _assert_same_validation_metric(bundle["validation_threshold"], expected_threshold,
                                       "model threshold")
        _assert_same_validation_metric(detail["validation_threshold"], expected_threshold,
                                       "report threshold")
        mask = (meta["technique_id"].eq(technique) &
                meta["label_binary"].isin((0, 1)) & splits.eq("test"))
        y = meta.loc[mask, "label_binary"].astype(int).to_numpy()
        groups = set(components.loc[mask])
        if len(groups) < 2 or len(set(y)) != 2:
            raise ValueError(f"held-out technique {technique} requires >=2 groups and both classes")
        test_x = x.loc[mask, features]
        scores = bundle["model"].predict_proba(test_x)[:, 1]
        baseline_scores = bundle["unweighted_baseline"].predict_proba(test_x)[:, 1]
        shuffled_scores = bundle["shuffled_label_model"].predict_proba(test_x)[:, 1]
        provenance_rows = meta.loc[mask, bundle["origin_fields"]].fillna("unknown").astype(str)
        provenance_scores = bundle["provenance_only_model"].predict_proba(provenance_rows)[:, 1]
        roc = float(roc_auc_score(y, scores))
        pr = float(average_precision_score(y, scores))
        recall = float(np.mean(scores[y == 1] > bundle["validation_threshold"]))
        prov_auc = float(roc_auc_score(y, provenance_scores))
        shuffle_auc = float(roc_auc_score(y, shuffled_scores))
        baseline_auc = float(roc_auc_score(y, baseline_scores))
        reasons = []
        if not research_evidence_eligible:
            reasons.append("evidence_not_independently_verified")
        if roc < MIN_TEST_ROC_AUC or pr < MIN_TEST_PR_AUC or recall < MIN_TEST_RECALL:
            reasons.append("technique_effect_not_confirmed_on_test")
        if max(prov_auc, measured_prov_auc) > MAX_PROVENANCE_AUC:
            reasons.append("provenance_shortcut")
        if max(shuffle_auc, measured_shuffled_auc) > MAX_SHUFFLED_AUC:
            reasons.append("shuffled_label_control_signal")
        per_technique[technique] = {
            "independent_test_groups": len(groups),
            "test_rows": int(mask.sum()),
            "test_positive_rows": int(sum(y == 1)),
            "roc_auc": roc, "pr_auc": pr, "recall_at_validation_threshold": recall,
            "unweighted_baseline_roc_auc": baseline_auc,
            "model_improvement_status": "improved" if roc > baseline_auc else "not_improved",
            "provenance_only_test_auc": prov_auc,
            "provenance_only_validation_auc": measured_prov_auc,
            "shuffled_label_test_auc": shuffle_auc,
            "shuffled_label_validation_auc": measured_shuffled_auc,
            "research_evidence_eligible": research_evidence_eligible,
            "research_validated": not reasons,
            "failure_reasons": reasons,
            "scope": "verified_scenario_vs_matched_control_independent_groups_only",
        }
        fitted[technique] = bundle

    office_report = {}
    for day, frame in sorted(office_days.items()):
        status = frozen["day_status"].get(day, "incompatible_features")
        if status == "incompatible_features":
            office_report[day] = {"status": status, "rows": len(frame)}
            continue
        alert_masks = {}
        for technique, bundle in fitted.items():
            scores = bundle["model"].predict_proba(frame[features])[:, 1]
            alert_masks[technique] = scores > bundle["validation_threshold"]
        combined = np.column_stack(list(alert_masks.values()))
        office_report[day] = {
            "status": status,
            "rows": len(frame),
            "office_alert_fraction": float(combined.any(axis=1).mean()),
            "per_technique_alert_fraction": {
                technique: float(marks.mean()) for technique, marks in alert_masks.items()
            },
            "office_labels": "unknown_unverified",
        }

    report = {
        "version": "defender-mitre-technique-transfer-v1",
        "pipeline_verified": True,
        "technique_research_validated": bool(per_technique) and all(
            d["research_validated"] for d in per_technique.values()
        ),
        "office_transfer_diagnostic": all(
            d in office_report and "office_alert_fraction" in office_report[d]
            for d in ("2026-09-22", "2026-09-28")
        ),
        "per_technique": per_technique,
        "office_days": office_report,
        "feature_schema_sha256": training["feature_schema_sha256"],
        "training_report_sha256": _sha(root / "training_report.json"),
        "corpus_manifest_sha256": manifest_hash,
        "origin_and_shuffled_controls_not_used_for_selection": True,
        "office_labels_verified": False,
        "office_naturalness_proven": False,
        "production_ready": False,
        "naturalness_status": "not_passed",
        "missing_production_evidence": [
            "independent_target_sensor_MITRE_ground_truth",
            "pristine_blinded_future_office_day",
            "target_office_capture_point_parity",
        ],
    }
    _verify_checksum(manifest_path, manifest_hash)
    for file in ("features.parquet", "labels_metadata.parquet"):
        _verify_checksum(prepared / file, corpus["outputs"][file])
    out.mkdir(parents=True)
    (out / "evaluation_report.json").write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")
    return report
