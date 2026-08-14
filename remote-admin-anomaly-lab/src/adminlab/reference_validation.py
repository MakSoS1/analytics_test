from __future__ import annotations

from typing import Any

import numpy as np
import pandas as pd
from scipy.stats import ks_2samp, wasserstein_distance


def _numeric(series: pd.Series) -> np.ndarray:
    values = pd.to_numeric(series, errors="coerce").dropna().to_numpy(dtype=float)
    return values[np.isfinite(values)]


def _mean_diff_ci(a: np.ndarray, b: np.ndarray, *, bootstrap: int, seed: int) -> list[float]:
    rng = np.random.default_rng(seed)
    diffs: list[float] = []
    for _ in range(int(bootstrap)):
        sa = rng.choice(a, size=len(a), replace=True)
        sb = rng.choice(b, size=len(b), replace=True)
        diffs.append(float(np.mean(sa) - np.mean(sb)))
    return [float(np.quantile(diffs, 0.025)), float(np.quantile(diffs, 0.975))]


def compare_reference_distributions(
    generated: pd.DataFrame,
    reference: pd.DataFrame | None,
    *,
    columns: list[str] | None = None,
    bootstrap: int = 1000,
    seed: int = 20260814,
) -> dict[str, Any]:
    if reference is None:
        return {
            "reference_available": False,
            "status": "not_evaluated",
            "reason": "no reference dataframe supplied; do not infer distribution validity from synthetic data alone",
            "features": {},
        }
    common = sorted(set(generated.columns) & set(reference.columns))
    selected = columns if columns is not None else common
    selected = [c for c in selected if c in common]
    report: dict[str, Any] = {
        "reference_available": True,
        "status": "evaluated",
        "generated_rows": int(len(generated)),
        "reference_rows": int(len(reference)),
        "features": {},
    }
    for index, column in enumerate(selected):
        a = _numeric(generated[column]); b = _numeric(reference[column])
        if len(a) < 5 or len(b) < 5:
            report["features"][column] = {"status": "insufficient_numeric_samples", "generated_n": int(len(a)), "reference_n": int(len(b))}
            continue
        ks = ks_2samp(a, b, alternative="two-sided", method="auto")
        wd = float(wasserstein_distance(a, b))
        scale = float(np.subtract(*np.percentile(b, [75, 25])))
        if not np.isfinite(scale) or scale <= 0:
            scale = float(np.std(b))
        if not np.isfinite(scale) or scale <= 0:
            scale = 1.0
        report["features"][column] = {
            "status": "ok",
            "generated_n": int(len(a)),
            "reference_n": int(len(b)),
            "generated_mean": float(np.mean(a)),
            "reference_mean": float(np.mean(b)),
            "ks_statistic": float(ks.statistic),
            "ks_pvalue": float(ks.pvalue),
            "wasserstein": wd,
            "wasserstein_normalized_by_reference_iqr_or_std": float(wd / scale),
            "mean_difference_ci95": _mean_diff_ci(a, b, bootstrap=bootstrap, seed=seed + index),
        }
    report["evaluated_feature_count"] = int(sum(1 for x in report["features"].values() if x.get("status") == "ok"))
    return report
