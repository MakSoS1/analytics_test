"""Grouped C2ST diagnostic of verified benign captures vs unlabelled office.

This measures laboratory-vs-office origin differences, NOT a false-positive
rate or evidence that any attack has become indistinguishable from an NDR.
"""
from __future__ import annotations

from typing import Sequence

import numpy as np
import pandas as pd
from sklearn.ensemble import ExtraTreesClassifier, HistGradientBoostingClassifier
from sklearn.impute import SimpleImputer
from sklearn.metrics import roc_auc_score
from sklearn.model_selection import StratifiedGroupKFold
from sklearn.pipeline import make_pipeline

from office_dictionary import group as feature_family

from .office_day_transfer import TRANSPORT_FEATURES


def _group_folds(labels: np.ndarray, groups: Sequence[str]) -> list[tuple[np.ndarray, np.ndarray]]:
    """Deterministic outer splits; group IDs never become model inputs."""
    labels = np.asarray(labels, dtype=int)
    if len(groups) != len(labels):
        raise ValueError("group IDs must align with measured session rows")
    if len(set(groups)) < 6 or len(set(labels)) != 2:
        return []
    splits = StratifiedGroupKFold(n_splits=3, shuffle=True, random_state=20261009)
    folds = []
    for train, test in splits.split(np.zeros((len(labels), 1)), labels, groups):
        if set(np.asarray(groups)[train]) & set(np.asarray(groups)[test]):
            raise AssertionError("independent group leaked between train and test")
        if set(labels[train]) != {0, 1} or set(labels[test]) != {0, 1}:
            continue
        folds.append((train, test))
    return folds


def _comparable_numeric(frame: pd.DataFrame, columns: Sequence[str]) -> pd.DataFrame:
    data = frame.loc[:, columns].apply(pd.to_numeric, errors="coerce")
    return data.replace([np.inf, -np.inf], np.nan)


def _feature_family_shift(
    office: pd.DataFrame, generated: pd.DataFrame, columns: Sequence[str],
) -> dict[str, float]:
    """Descriptive normalized shifts; not used to pick a detector or threshold."""
    result: dict[str, list[float]] = {}
    for name in columns:
        if name not in office or name not in generated:
            continue
        left = pd.to_numeric(office[name], errors="coerce").replace(
            [np.inf, -np.inf], np.nan).dropna()
        right = pd.to_numeric(generated[name], errors="coerce").replace(
            [np.inf, -np.inf], np.nan).dropna()
        if len(left) < .8 * len(office) or len(right) < .8 * len(generated):
            continue
        spread = float(left.quantile(.75) - left.quantile(.25))
        shift = abs(float(left.median()) - float(right.median())) / max(spread, 1.0)
        result.setdefault(feature_family(name), []).append(shift)
    return {family: float(np.mean(values)) for family, values in sorted(result.items())}


def _evaluate_domains(
    reference: pd.DataFrame, target: pd.DataFrame,
    reference_groups: Sequence[str], target_groups: Sequence[str],
    columns: Sequence[str],
) -> dict:
    groups_by_side = [reference_groups, target_groups]
    if len(reference) != len(reference_groups) or len(target) != len(target_groups):
        raise ValueError("independent group count must match table row count")
    if any(any(not isinstance(value, str) or not value.strip() for value in group)
           for group in groups_by_side):
        raise ValueError("independent group names must be nonempty strings")
    support = {"reference_groups": len(set(reference_groups)),
               "target_groups": len(set(target_groups)),
               "reference_rows": int(len(reference)),
               "target_rows": int(len(target))}
    if min(support["reference_groups"], support["target_groups"]) < 4:
        return {"status": "insufficient_support", "reason": "fewer_than_four_groups_per_domain",
                "support": support, "models": None}
    if reference.empty or target.empty or any(name not in frame for frame in
                                             (reference, target) for name in columns):
        return {"status": "insufficient_support", "reason": "missing_measured_columns",
                "support": support, "models": None}
    first = _comparable_numeric(reference, columns)
    second = _comparable_numeric(target, columns)
    if any(float(data.notna().mean().min()) < .8 for data in (first, second)):
        return {"status": "insufficient_support", "reason": "numeric_coverage_below_80_percent",
                "support": support, "models": None}
    data = pd.concat([first, second], ignore_index=True)
    labels = np.concatenate((np.zeros(len(first), dtype=int),
                             np.ones(len(second), dtype=int)))
    groups = [f"reference:{value}" for value in reference_groups] + [
        f"target:{value}" for value in target_groups
    ]
    folds = _group_folds(labels, groups)
    if len(folds) < 2:
        return {"status": "insufficient_support", "reason": "outer_folds_lack_both_domains",
                "support": support, "models": None}

    estimators = {
        "extra_trees": ExtraTreesClassifier(
            n_estimators=90, min_samples_leaf=2, max_depth=8,
            class_weight="balanced", random_state=20261009, n_jobs=1,
        ),
        "hist_gradient_boosting": HistGradientBoostingClassifier(
            max_iter=70, max_leaf_nodes=12, l2_regularization=1.0,
            class_weight="balanced", random_state=20261009,
        ),
    }
    results = {}
    for name, estimator in estimators.items():
        aucs = []
        for train, test in folds:
            model = make_pipeline(SimpleImputer(strategy="median"), estimator)
            model.fit(data.iloc[train], labels[train])
            score = model.predict_proba(data.iloc[test])[:, 1]
            aucs.append(float(roc_auc_score(labels[test], score)))
        results[name] = {"mean_auc": float(np.mean(aucs)),
                         "worst_auc": float(min(aucs)), "fold_auc": aucs}
    return {
        "status": "evaluated", "models": results,
        "support": support, "outer_folds": len(folds), "no_group_leakage": True,
    }


def evaluate_benign_transfer(
    office_days: dict[str, pd.DataFrame], benign: pd.DataFrame, *,
    feature_columns: list[str], benign_group_ids: list[str],
) -> dict:
    """Freeze transport X and evaluate independent capture-group origin shift."""
    if (len(feature_columns) < 12 or len(set(feature_columns)) != len(feature_columns)
            or not set(feature_columns) <= set(TRANSPORT_FEATURES)):
        raise ValueError("feature_columns must have 12+ distinct transport features")
    if any(day not in office_days for day in ("2026-09-22", "2026-09-28")):
        raise ValueError("pinned 22 and 28 September office references required")
    if len(benign) != len(benign_group_ids):
        raise ValueError("benign capture groups must match measured rows")
    first = office_days["2026-09-22"]
    second = office_days["2026-09-28"]
    for day, frame in (("2026-09-22", first), ("2026-09-28", second)):
        if ("independent_source_group" not in frame or
                frame["independent_source_group"].isna().any()):
            raise ValueError(f"office {day} requires independent source groups")
    groups_a = [str(x) for x in first["independent_source_group"]]
    groups_b = [str(x) for x in second["independent_source_group"]]
    office_baseline = _evaluate_domains(first, second, groups_a, groups_b, feature_columns)
    benign_compare = _evaluate_domains(second, benign, groups_b,
                                       benign_group_ids, feature_columns)
    return {
        "version": "benign-office-grouped-transfer-v1",
        "feature_columns": list(feature_columns),
        "reference_day": "2026-09-28",
        "negative_control_days": ["2026-09-22", "2026-09-28"],
        "office_negative_control": office_baseline,
        "generated_vs_office": benign_compare,
        "feature_family_shift": _feature_family_shift(second, benign, feature_columns),
        "office_labels": "unknown_unverified",
        "naturalness_status": "not_proven",
        "office_naturalness_proven": False,
        "production_ready": False,
    }
