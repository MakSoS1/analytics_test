from __future__ import annotations

from dataclasses import dataclass
from collections.abc import Mapping, Sequence
import math

import numpy as np
import pandas as pd
from scipy.stats import ks_2samp
from sklearn.base import clone
from sklearn.ensemble import ExtraTreesClassifier, HistGradientBoostingClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import roc_auc_score
from sklearn.model_selection import StratifiedGroupKFold

from .contracts import FrozenProfileManifest


class ManifestIntegrityError(ValueError):
    """Raised when confirmation is not bound to the frozen calibration hash."""


@dataclass(frozen=True)
class NaturalnessReport:
    status: str
    classifiers: dict[str, dict[str, float]]
    support: dict[str, int]
    distribution: dict[str, object]
    max_auc: float | None

    def as_dict(self) -> dict[str, object]:
        return {
            "status": self.status,
            "classifiers": self.classifiers,
            "support": self.support,
            "distribution": self.distribution,
            "max_auc": self.max_auc,
        }


@dataclass(frozen=True)
class TechniqueSignalReport:
    status: str
    training_eligible: bool
    auc: float | None
    ci_low: float | None
    ci_high: float | None
    pair_groups: int

    def as_dict(self) -> dict[str, object]:
        return {
            "status": self.status,
            "training_eligible": self.training_eligible,
            "auc": self.auc,
            "ci_low": self.ci_low,
            "ci_high": self.ci_high,
            "pair_groups": self.pair_groups,
        }


_ENUM_HINTS = (
    "proto",
    "state",
    "service",
    "version",
    "alpn",
    "method",
    "status",
    "flag",
    "type",
)


def _is_missing(value: object) -> bool:
    if value is None:
        return True
    if isinstance(value, (float, np.floating)):
        return bool(np.isnan(value))
    if value is pd.NA:
        return True
    return False


def _as_sequence(value: object) -> np.ndarray | None:
    if isinstance(value, np.ndarray):
        arr = value
    elif isinstance(value, (list, tuple)):
        arr = np.asarray(value)
    else:
        return None
    try:
        return np.asarray(arr, dtype=float).ravel()
    except (TypeError, ValueError):
        return None


def _sanitize_category(value: object) -> str:
    text = str(value)
    if text.startswith("anon_"):
        return "<redacted>"
    return text


def prepare_diagnostic_frame(
    office: pd.DataFrame,
    control: pd.DataFrame,
    feature_columns: Sequence[str],
) -> tuple[pd.DataFrame, np.ndarray]:
    """Convert heterogeneous retained features to a safe numeric diagnostic X.

    Numeric features and numeric sequence summaries are retained. Small,
    readable enum-like categories are one-hot encoded. Pseudonymized token
    identities and arbitrary free text never become model inputs; only their
    missingness is retained.
    """

    n_office = len(office)
    combined = pd.concat(
        [
            office.reindex(columns=feature_columns),
            control.reindex(columns=feature_columns),
        ],
        ignore_index=True,
    )
    out: dict[str, np.ndarray] = {}

    for col in feature_columns:
        if col not in combined:
            continue
        series = combined[col]
        missing = np.array([_is_missing(v) for v in series.to_numpy(dtype=object)], dtype=float)
        out[f"{col}__missing"] = missing

        if pd.api.types.is_numeric_dtype(series.dtype) or pd.api.types.is_bool_dtype(series.dtype):
            numeric = pd.to_numeric(series, errors="coerce").astype(float)
            numeric = numeric.replace([np.inf, -np.inf], np.nan)
            median = float(numeric.median()) if numeric.notna().any() else 0.0
            out[col] = numeric.fillna(median).to_numpy(dtype=float)
            continue

        values = series.to_numpy(dtype=object)
        sample = next((v for v in values if not _is_missing(v)), None)
        sample_seq = _as_sequence(sample) if sample is not None else None
        if sample_seq is not None:
            stats = {"len": [], "mean": [], "std": [], "min": [], "max": []}
            for value in values:
                arr = _as_sequence(value)
                if arr is None or arr.size == 0:
                    stats["len"].append(0.0)
                    for key in ("mean", "std", "min", "max"):
                        stats[key].append(np.nan)
                    continue
                finite = arr[np.isfinite(arr)]
                stats["len"].append(float(arr.size))
                if finite.size:
                    stats["mean"].append(float(np.mean(finite)))
                    stats["std"].append(float(np.std(finite)))
                    stats["min"].append(float(np.min(finite)))
                    stats["max"].append(float(np.max(finite)))
                else:
                    for key in ("mean", "std", "min", "max"):
                        stats[key].append(np.nan)
            for key, raw in stats.items():
                arr = np.asarray(raw, dtype=float)
                finite = arr[np.isfinite(arr)]
                fill = float(np.median(finite)) if finite.size else 0.0
                arr[~np.isfinite(arr)] = fill
                out[f"{col}__seq_{key}"] = arr
            continue

        strings = [None if _is_missing(v) else str(v) for v in values]
        has_token = any(v is not None and v.startswith("anon_") for v in strings)
        enum_like = any(hint in col.lower() for hint in _ENUM_HINTS)
        non_null = [_sanitize_category(v) for v in strings if v is not None]
        categories = sorted(set(non_null))
        if not has_token and enum_like and 0 < len(categories) <= 32:
            for category in categories:
                out[f"{col}__cat__{category}"] = np.asarray(
                    [1.0 if v is not None and _sanitize_category(v) == category else 0.0 for v in strings],
                    dtype=float,
                )

    if not out:
        raise ValueError("diagnostic feature contract produced no numeric columns")
    matrix = pd.DataFrame(out)
    labels = np.concatenate(
        [np.zeros(n_office, dtype=int), np.ones(len(control), dtype=int)]
    )
    return matrix, labels


def _cluster_bootstrap_auc(
    y: np.ndarray,
    score: np.ndarray,
    groups: np.ndarray,
    *,
    reps: int,
    random_state: int,
) -> tuple[float, float]:
    rng = np.random.default_rng(random_state)
    unique_by_class = {
        klass: np.unique(groups[y == klass])
        for klass in (0, 1)
    }
    values: list[float] = []
    for _ in range(max(1, int(reps))):
        selected_indices: list[int] = []
        for klass in (0, 1):
            source = unique_by_class[klass]
            sampled = rng.choice(source, size=len(source), replace=True)
            for group in sampled:
                candidates = np.flatnonzero((groups == group) & (y == klass))
                if candidates.size:
                    selected_indices.extend(candidates.tolist())
        if not selected_indices:
            continue
        idx = np.asarray(selected_indices, dtype=int)
        if len(np.unique(y[idx])) != 2:
            continue
        values.append(float(roc_auc_score(y[idx], score[idx])))
    if not values:
        return float("nan"), float("nan")
    return (float(np.quantile(values, 0.025)), float(np.quantile(values, 0.975)))


def _models(random_state: int) -> dict[str, object]:
    return {
        "hist_gradient_boosting": HistGradientBoostingClassifier(
            max_iter=100,
            random_state=random_state,
            class_weight="balanced",
        ),
        "extra_trees": ExtraTreesClassifier(
            n_estimators=160,
            min_samples_leaf=1,
            class_weight="balanced",
            random_state=random_state,
            n_jobs=1,
        ),
        "logistic": LogisticRegression(
            class_weight="balanced",
            max_iter=1000,
            random_state=random_state,
        ),
    }


def _evaluate_numeric_matrix(
    matrix: pd.DataFrame,
    y: np.ndarray,
    groups: np.ndarray,
    *,
    bootstrap_reps: int,
    random_state: int,
) -> dict[str, dict[str, float]]:
    unique0 = len(np.unique(groups[y == 0]))
    unique1 = len(np.unique(groups[y == 1]))
    n_splits = min(5, unique0, unique1)
    if n_splits < 2:
        raise ValueError("at least two groups per class required for grouped evaluation")

    splitter = StratifiedGroupKFold(
        n_splits=n_splits,
        shuffle=True,
        random_state=random_state,
    )
    splits = list(splitter.split(matrix, y, groups))
    results: dict[str, dict[str, float]] = {}
    for offset, (name, prototype) in enumerate(_models(random_state).items()):
        pred = np.full(len(y), np.nan, dtype=float)
        for train_idx, test_idx in splits:
            model = clone(prototype)
            model.fit(matrix.iloc[train_idx], y[train_idx])
            if hasattr(model, "predict_proba"):
                pred[test_idx] = model.predict_proba(matrix.iloc[test_idx])[:, 1]
            else:
                raw = model.decision_function(matrix.iloc[test_idx])
                pred[test_idx] = 1.0 / (1.0 + np.exp(-raw))
        if not np.isfinite(pred).all():
            raise RuntimeError(f"{name} did not produce complete out-of-fold scores")
        auc = float(roc_auc_score(y, pred))
        low, high = _cluster_bootstrap_auc(
            y,
            pred,
            groups,
            reps=bootstrap_reps,
            random_state=random_state + offset + 101,
        )
        results[name] = {"auc": auc, "ci_low": low, "ci_high": high}
    return results


def evaluate_c2st(
    office: pd.DataFrame,
    control: pd.DataFrame,
    groups: Mapping[str, Sequence[object]],
    *,
    feature_columns: Sequence[str],
    min_groups: int = 30,
    bootstrap_reps: int = 200,
    random_state: int = 0,
) -> dict[str, object]:
    if len(groups.get("office", ())) != len(office):
        raise ValueError("office group vector length mismatch")
    if len(groups.get("controls", ())) != len(control):
        raise ValueError("control group vector length mismatch")

    office_groups = np.asarray([f"office:{g}" for g in groups["office"]], dtype=object)
    control_groups = np.asarray([f"control:{g}" for g in groups["controls"]], dtype=object)
    support = {
        "office_groups": len(np.unique(office_groups)),
        "control_groups": len(np.unique(control_groups)),
    }
    if min(support.values()) < int(min_groups):
        return {"status": "insufficient_data", "support": support, "classifiers": {}}

    matrix, y = prepare_diagnostic_frame(office, control, feature_columns)
    all_groups = np.concatenate([office_groups, control_groups])
    metrics = _evaluate_numeric_matrix(
        matrix,
        y,
        all_groups,
        bootstrap_reps=bootstrap_reps,
        random_state=random_state,
    )
    return {"status": "ok", "support": support, "classifiers": metrics}


def _univariate_distance(a: pd.Series, b: pd.Series) -> float | None:
    miss_a = float(a.isna().mean())
    miss_b = float(b.isna().mean())
    missing_gap = abs(miss_a - miss_b)

    if pd.api.types.is_numeric_dtype(a.dtype) and pd.api.types.is_numeric_dtype(b.dtype):
        aa = pd.to_numeric(a, errors="coerce").replace([np.inf, -np.inf], np.nan).dropna()
        bb = pd.to_numeric(b, errors="coerce").replace([np.inf, -np.inf], np.nan).dropna()
        if len(aa) and len(bb):
            return max(missing_gap, float(ks_2samp(aa, bb).statistic))
        return missing_gap

    def safe_values(series: pd.Series) -> list[str]:
        vals: list[str] = []
        for value in series.to_numpy(dtype=object):
            if _is_missing(value):
                vals.append("<missing>")
            elif _as_sequence(value) is not None:
                vals.append(f"<seq:{len(_as_sequence(value))}>")
            else:
                text = str(value)
                vals.append("<redacted>" if text.startswith("anon_") else text)
        return vals

    va = safe_values(a)
    vb = safe_values(b)
    if not va and not vb:
        return None
    cats = sorted(set(va).union(vb))
    if len(cats) > 64:
        return missing_gap
    pa = pd.Series(va).value_counts(normalize=True)
    pb = pd.Series(vb).value_counts(normalize=True)
    tv = 0.5 * sum(abs(float(pa.get(c, 0.0)) - float(pb.get(c, 0.0))) for c in cats)
    return max(missing_gap, float(tv))


def evaluate_family_distances(
    office: pd.DataFrame,
    control: pd.DataFrame,
    office_groups: Sequence[object],
    feature_families: Mapping[str, Sequence[str]],
    *,
    random_state: int = 17,
    reference_splits: int = 24,
) -> dict[str, object]:
    if len(office_groups) != len(office):
        raise ValueError("office group vector length mismatch")
    unique_groups = np.asarray(sorted(set(map(str, office_groups))), dtype=object)
    if len(unique_groups) < 4:
        return {
            "passed": False,
            "status": "insufficient_data",
            "families": {},
            "failed_families": list(feature_families),
        }

    group_array = np.asarray(list(map(str, office_groups)), dtype=object)
    rng = np.random.default_rng(random_state)
    baseline: dict[str, list[float]] = {name: [] for name in feature_families}

    for _ in range(max(4, int(reference_splits))):
        shuffled = unique_groups.copy()
        rng.shuffle(shuffled)
        cut = max(1, len(shuffled) // 2)
        left_groups = set(shuffled[:cut])
        left = office[np.asarray([g in left_groups for g in group_array])]
        right = office[np.asarray([g not in left_groups for g in group_array])]
        if left.empty or right.empty:
            continue
        for family, cols in feature_families.items():
            distances = [
                d
                for col in cols
                if col in left.columns and col in right.columns
                for d in [_univariate_distance(left[col], right[col])]
                if d is not None
            ]
            if distances:
                baseline[family].append(max(distances))

    family_rows: dict[str, dict[str, float | bool]] = {}
    failed: list[str] = []
    at_reference = 0
    measurable = 0
    for family, cols in feature_families.items():
        distances = [
            d
            for col in cols
            if col in office.columns and col in control.columns
            for d in [_univariate_distance(office[col], control[col])]
            if d is not None
        ]
        refs = baseline.get(family, [])
        if not distances or not refs:
            continue
        measurable += 1
        distance = float(max(distances))
        p95 = float(np.quantile(refs, 0.95))
        at_p95 = distance <= p95 + 1e-12
        hard_limit = max(1.5 * p95, 0.05)
        hard_ok = distance <= hard_limit + 1e-12
        if at_p95:
            at_reference += 1
        if not hard_ok:
            failed.append(family)
        family_rows[family] = {
            "distance": distance,
            "office_reference_p95": p95,
            "within_reference_p95": at_p95,
            "within_1_5x_reference": hard_ok,
        }

    share = (at_reference / measurable) if measurable else 0.0
    passed = measurable > 0 and share >= 0.90 and not failed
    return {
        "passed": bool(passed),
        "status": "ok" if measurable else "insufficient_data",
        "families": family_rows,
        "failed_families": failed,
        "within_reference_share": share,
        "measurable_families": measurable,
    }


def confirm_naturalness(
    manifest: FrozenProfileManifest,
    office_confirm: pd.DataFrame,
    benign_confirm: pd.DataFrame,
    groups: Mapping[str, Sequence[object]],
    *,
    expected_manifest_sha: str,
    feature_columns: Sequence[str],
    feature_families: Mapping[str, Sequence[str]] | None = None,
    bootstrap_reps: int = 200,
    random_state: int = 0,
) -> NaturalnessReport:
    if manifest.sha256 != expected_manifest_sha:
        raise ManifestIntegrityError(
            f"frozen manifest hash mismatch: {manifest.sha256} != {expected_manifest_sha}"
        )

    office_n = len(set(map(str, groups.get("office", ()))))
    control_n = len(set(map(str, groups.get("controls", ()))))
    support = {"office_groups": office_n, "control_groups": control_n}
    if min(office_n, control_n) < 30:
        return NaturalnessReport(
            status="insufficient_data",
            classifiers={},
            support=support,
            distribution={"status": "insufficient_data"},
            max_auc=None,
        )

    c2st = evaluate_c2st(
        office_confirm,
        benign_confirm,
        groups,
        feature_columns=feature_columns,
        min_groups=30,
        bootstrap_reps=bootstrap_reps,
        random_state=random_state,
    )
    metrics = c2st["classifiers"]
    worst_name, worst = max(metrics.items(), key=lambda item: item[1]["auc"])
    max_auc = float(worst["auc"])
    primary = max_auc <= 0.65 or (
        float(worst["ci_low"]) <= 0.50 <= float(worst["ci_high"])
        and float(worst["ci_high"]) <= 0.70
    )

    families = feature_families or {"all": list(feature_columns)}
    distribution = evaluate_family_distances(
        office_confirm,
        benign_confirm,
        groups["office"],
        families,
        random_state=random_state + 19,
    )
    status = "passed_candidate" if primary and distribution["passed"] else "not_passed"
    return NaturalnessReport(
        status=status,
        classifiers=metrics,
        support=support,
        distribution=distribution,
        max_auc=max_auc,
    )


def _paired_signal_matrix(
    control: pd.DataFrame,
    scenario: pd.DataFrame,
    feature_columns: Sequence[str],
    pair_groups: Sequence[object],
    *,
    bootstrap_reps: int,
    random_state: int,
) -> tuple[float, float, float]:
    if len(control) != len(scenario) or len(pair_groups) != len(control):
        raise ValueError("scenario/control/pair lengths must match")
    matrix, y = prepare_diagnostic_frame(control, scenario, feature_columns)
    groups = np.asarray(list(map(str, pair_groups)) * 2, dtype=object)
    n_splits = min(5, len(set(map(str, pair_groups))))
    if n_splits < 2:
        raise ValueError("at least two independent pairs required")

    model = LogisticRegression(class_weight="balanced", max_iter=1000, random_state=random_state)
    splitter = StratifiedGroupKFold(
        n_splits=n_splits,
        shuffle=True,
        random_state=random_state,
    )
    pred = np.full(len(y), np.nan, dtype=float)
    for train_idx, test_idx in splitter.split(matrix, y, groups):
        fitted = clone(model).fit(matrix.iloc[train_idx], y[train_idx])
        pred[test_idx] = fitted.predict_proba(matrix.iloc[test_idx])[:, 1]
    auc = float(roc_auc_score(y, pred))
    low, high = _cluster_bootstrap_auc(
        y,
        pred,
        groups,
        reps=bootstrap_reps,
        random_state=random_state + 211,
    )
    return auc, low, high


def evaluate_technique_signal(
    manifest: FrozenProfileManifest,
    scenario: pd.DataFrame,
    control: pd.DataFrame,
    pair_groups: Sequence[object],
    *,
    naturalness_status: str,
    feature_columns: Sequence[str],
    bootstrap_reps: int = 200,
    random_state: int = 31,
) -> TechniqueSignalReport:
    independent_pairs = len(set(map(str, pair_groups)))
    if naturalness_status != "passed_candidate":
        return TechniqueSignalReport(
            status="blocked_by_naturalness",
            training_eligible=False,
            auc=None,
            ci_low=None,
            ci_high=None,
            pair_groups=independent_pairs,
        )
    if independent_pairs < 30:
        return TechniqueSignalReport(
            status="insufficient_data",
            training_eligible=False,
            auc=None,
            ci_low=None,
            ci_high=None,
            pair_groups=independent_pairs,
        )

    auc, low, high = _paired_signal_matrix(
        control,
        scenario,
        feature_columns,
        pair_groups,
        bootstrap_reps=bootstrap_reps,
        random_state=random_state,
    )
    eligible = bool(np.isfinite(low) and low > 0.60)
    return TechniqueSignalReport(
        status="passed" if eligible else "not_passed",
        training_eligible=eligible,
        auc=auc,
        ci_low=low,
        ci_high=high,
        pair_groups=independent_pairs,
    )
