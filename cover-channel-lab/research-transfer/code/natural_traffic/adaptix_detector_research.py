"""Small-sample Adaptix-vs-paired-control detection diagnostic.

One physical capture is ONE observation even if the extractor emits multiple
session rows. Feature selection is re-fit inside every grouped training fold.
No attack packet is edited; no fitted detector or per-session evidence is
exported. This cannot validate office false-positive rates or MITRE transfer.
"""
from __future__ import annotations

import argparse
from collections import Counter
from dataclasses import dataclass
import json
from pathlib import Path
from typing import Sequence

import numpy as np
import pandas as pd
from sklearn.impute import SimpleImputer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import average_precision_score, roc_auc_score
from sklearn.pipeline import make_pipeline
from sklearn.preprocessing import OneHotEncoder, RobustScaler

from .office_day_transfer import TRANSPORT_FEATURES


@dataclass(frozen=True)
class CaptureFeatures:
    pair_id: str
    profile_id: str
    transport: str
    arm: str
    features: pd.DataFrame


def _measured_capture_table(captures: Sequence[CaptureFeatures],
                            columns: list[str]) -> pd.DataFrame:
    rows = []
    for capture in captures:
        values = {}
        for feature in columns:
            numeric = pd.to_numeric(capture.features[feature], errors="coerce")
            finite = numeric.replace([np.inf, -np.inf], np.nan).dropna()
            values[feature] = float(finite.median()) if not finite.empty else np.nan
        rows.append(values)
    return pd.DataFrame(rows, columns=columns)


def _training_feature_rank(x: pd.DataFrame, y: np.ndarray, pairs: list[str],
                           max_features: int) -> list[str]:
    """Rank ONLY training pair differences, never test distribution or labels."""
    candidates: list[tuple[float, str]] = []
    for feature in x.columns:
        deltas = []
        for pair in sorted(set(pairs)):
            indices = [i for i, name in enumerate(pairs) if name == pair]
            pos = [i for i in indices if y[i] == 1]
            neg = [i for i in indices if y[i] == 0]
            if len(pos) != 1 or len(neg) != 1:
                raise ValueError("training fold has incomplete scenario/control pair")
            a, b = x.iloc[pos[0]][feature], x.iloc[neg[0]][feature]
            if np.isfinite(a) and np.isfinite(b):
                deltas.append(float(a - b))
        if len(deltas) < 2:
            continue
        signed = np.asarray(deltas)
        nonzero = signed[signed != 0]
        if len(nonzero) < 2:
            continue
        consistency = abs(float(np.sign(nonzero).mean()))
        if consistency < .75:
            continue
        finite = x[feature].dropna().to_numpy(dtype=float)
        scale = float(np.subtract(*np.percentile(finite, [75, 25]))) if len(finite) else 0
        score = consistency * abs(float(np.median(nonzero))) / max(scale, 1.0)
        if score > 0:
            candidates.append((score, feature))
    candidates.sort(key=lambda item: (-item[0], item[1]))
    return [feature for _, feature in candidates[:max_features]]


def evaluate_paired_detector(
    captures: Sequence[CaptureFeatures], *,
    feature_columns: Sequence[str] | None = None,
    max_features: int = 3,
    office_days: dict[str, pd.DataFrame] | None = None,
) -> dict:
    """Leave-profile/transport-out research metric with strict pair grouping."""
    captures = list(captures)
    if max_features < 1 or max_features > 8:
        raise ValueError("max_features must be within [1, 8]")
    pairs: dict[str, dict[str, CaptureFeatures]] = {}
    for capture in captures:
        if capture.arm not in ("scenario", "control"):
            raise ValueError("capture arm must be scenario or control")
        if capture.features.empty:
            raise ValueError("empty capture feature table")
        arms = pairs.setdefault(capture.pair_id, {})
        if capture.arm in arms:
            raise ValueError("exactly one scenario and control required per pair")
        arms[capture.arm] = capture
    if not pairs or any(set(arms) != {"scenario", "control"} for arms in pairs.values()):
        raise ValueError("exactly one scenario and control required per pair")
    if len(captures) != len(pairs) * 2:
        raise ValueError("capture-pair cardinality mismatch")
    for arms in pairs.values():
        a, b = arms["scenario"], arms["control"]
        if a.profile_id != b.profile_id or a.transport != b.transport:
            raise ValueError("paired captures must share profile and transport")
    if len({c.profile_id for c in captures}) < 3 or len({c.transport for c in captures}) < 2:
        raise ValueError("requires at least three profiles and two transports")

    allowed = set(TRANSPORT_FEATURES)
    requested = list(feature_columns if feature_columns is not None else TRANSPORT_FEATURES)
    if not requested or len(set(requested)) != len(requested):
        raise ValueError("empty or duplicate feature list")
    if any(col not in allowed for col in requested):
        raise ValueError("not an eligible transport feature")
    common = [col for col in requested if all(col in c.features for c in captures)]
    x = _measured_capture_table(captures, common)
    columns = [col for col in x if int(x[col].notna().sum()) == len(captures)]
    if not columns:
        raise ValueError("no eligible numeric transport features with comparable support")
    x = x[columns]
    labels = np.array([int(c.arm == "scenario") for c in captures], dtype=int)
    provenance = pd.DataFrame({
        "profile_id": [c.profile_id for c in captures],
        "transport": [c.transport for c in captures],
    })
    pair_ids = [c.pair_id for c in captures]
    folds: dict[str, list[dict]] = {}
    selection_frequency: Counter[str] = Counter()
    office_fractions: dict[str, list[float]] = {
        day: [] for day in (office_days or {})
    }
    for scheme, group_attr in (("leave_one_profile_out", "profile_id"),
                               ("leave_one_transport_out", "transport")):
        fold_reports = []
        for holdout in sorted({getattr(c, group_attr) for c in captures}):
            test = np.array([getattr(c, group_attr) == holdout for c in captures])
            train = ~test
            tr_pairs = [pair_ids[i] for i in np.flatnonzero(train)]
            te_pairs = [pair_ids[i] for i in np.flatnonzero(test)]
            if set(tr_pairs).intersection(te_pairs):
                raise ValueError("pair leaked across train and test")
            if len(set(labels[train])) != 2 or len(set(labels[test])) != 2:
                raise ValueError("holdout lacks one of scenario/control classes")
            chosen = _training_feature_rank(x.loc[train], labels[train], tr_pairs,
                                            max_features)
            ablations = {}
            if chosen:
                model = make_pipeline(
                    SimpleImputer(strategy="median"), RobustScaler(),
                    LogisticRegression(C=0.1, class_weight="balanced", max_iter=2000,
                                       random_state=20261008),
                )
                model.fit(x.loc[train, chosen], labels[train])
                predictions = model.predict_proba(x.loc[test, chosen])[:, 1]
                measured_auc = float(roc_auc_score(labels[test], predictions))
                # Office rows are read only AFTER feature selection/model fit;
                # this cannot calibrate operational specificity with 4 controls.
                training_control = model.predict_proba(
                    x.loc[train & (labels == 0), chosen])[:, 1]
                weak_threshold = float(np.quantile(training_control, .99))
                for day, office in (office_days or {}).items():
                    if office.empty or any(feature not in office for feature in chosen):
                        continue
                    measured = office[chosen].apply(pd.to_numeric, errors="coerce")
                    measured = measured.replace([np.inf, -np.inf], np.nan)
                    if measured.isna().all().any():
                        continue
                    office_scores = model.predict_proba(measured)[:, 1]
                    office_fractions[day].append(float(np.mean(office_scores > weak_threshold)))
                # Explanatory OUTER-test audit, never used for selection.
                for feature in chosen:
                    masked = x.loc[test, chosen].copy()
                    masked[feature] = float(x.loc[train, feature].median())
                    degraded = model.predict_proba(masked)[:, 1]
                    ablations[feature] = float(measured_auc - roc_auc_score(labels[test], degraded))
            else:
                # A legitimate negative result; don't fail CI or invent signal.
                predictions = np.full(int(test.sum()), .5)
                measured_auc = .5
            origin_encoder = OneHotEncoder(handle_unknown="ignore")
            origin_train = origin_encoder.fit_transform(provenance.loc[train])
            origin_model = LogisticRegression(C=0.1, class_weight="balanced",
                                              max_iter=2000, random_state=20261008)
            origin_model.fit(origin_train, labels[train])
            origin_scores = origin_model.predict_proba(
                origin_encoder.transform(provenance.loc[test]))[:, 1]
            selection_frequency.update(chosen)
            fold_reports.append({
                "held_out_group": holdout,
                "train_pair_ids": sorted(set(tr_pairs)),
                "test_pair_ids": sorted(set(te_pairs)),
                "test_captures": int(test.sum()),
                "selected_features": chosen,
                "roc_auc": measured_auc,
                "average_precision": float(average_precision_score(labels[test], predictions)),
                "origin_only_roc_auc": float(roc_auc_score(labels[test], origin_scores)),
                "feature_ablation_auc_drop": ablations,
            })
        folds[scheme] = fold_reports
    metrics = {
        scheme: {
            "mean_roc_auc": float(np.mean([r["roc_auc"] for r in reports])),
            "worst_roc_auc": float(min(r["roc_auc"] for r in reports)),
            "mean_average_precision": float(np.mean([r["average_precision"] for r in reports])),
            "best_fold_roc_auc": float(max(r["roc_auc"] for r in reports)),
        } for scheme, reports in folds.items()
    }
    office_diagnostic = {
        day: {
            "rows": len((office_days or {})[day]),
            "comparable_folds": len(fractions),
            "mean_alert_fraction": float(np.mean(fractions)) if fractions else None,
            "threshold_source": "training_control_p99_exploratory_only",
        }
        for day, fractions in sorted(office_fractions.items())
    }
    return {
        "version": "adaptix-paired-detection-diagnostic-v1",
        "comparison_scope": "adaptix_vs_isolated_paired_telemetry_control",
        "capture_count": len(captures),
        "measured_session_rows": sum(len(c.features) for c in captures),
        "independent_pairs": len(pairs),
        "independent_profiles": len({c.profile_id for c in captures}),
        "candidate_features": columns,
        "max_features_per_fold": max_features,
        "feature_selection": "training_pairs_only_signed_difference_rank",
        "detector_signal_status": (
            "paired_signal_found" if all(r["selected_features"]
                                         for reports in folds.values() for r in reports)
            else "no_stable_paired_signal"
        ),
        "folds": folds,
        "metrics": metrics,
        "office_labels": "unknown_unverified",
        "office_diagnostic": office_diagnostic,
        "selected_feature_frequency": dict(sorted(selection_frequency.items())),
        "limitations": [
            "six_pairs_are_insufficient_for_independent_research_validation",
            "telemetry_controls_do_not_establish_normal_office_false_positive_rate",
            "no_blind_target_domain_with_confirmed_adaptix_labels",
            "the_same_runtime_can_embed_source_origin_shortcuts",
            "metrics_are_discrete_and_high_variance_due_to_tiny_holdouts",
        ],
        "technique_research_validated": False,
        "office_naturalness_proven": False,
        "production_ready": False,
        "naturalness_status": "not_passed",
    }


def _load_adaptix_extractions(root: Path) -> list[CaptureFeatures]:
    captures = []
    for transport in ("tcp", "mtls"):
        for profile in range(3):
            for arm in ("scenario", "control"):
                path = root / f"{transport}-p{profile}-{arm}" / "parquet" / "office_sessions.parquet"
                if not path.is_file():
                    raise ValueError(f"missing measured Adaptix capture: {transport}-p{profile}-{arm}")
                captures.append(CaptureFeatures(
                    pair_id=f"{transport}-p{profile}", profile_id=f"p{profile}",
                    transport=transport, arm=arm, features=pd.read_parquet(path),
                ))
    return captures


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--extraction-root", type=Path, required=True)
    parser.add_argument("--office-dir", type=Path)
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()
    if args.out.exists():
        raise FileExistsError(args.out)
    office = None
    if args.office_dir is not None:
        from .office_day_transfer import load_additional_days
        first, second = load_additional_days(args.office_dir)
        office = {"2026-09-22": first, "2026-09-28": second}
    report = evaluate_paired_detector(
        _load_adaptix_extractions(args.extraction_root), office_days=office)
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(report, sort_keys=True, indent=2) + "\n")
    print("ADAPTIX_DETECTION_RESEARCH", json.dumps({
        "status": "diagnostic_only", "independent_pairs": report["independent_pairs"],
        "metrics": report["metrics"],
        "selected_feature_frequency": report["selected_feature_frequency"],
        "office_diagnostic": report["office_diagnostic"],
        "production_ready": False,
    }, sort_keys=True))


if __name__ == "__main__":
    main()
