"""Train-only office feature-distribution baseline (NOT a PCAP generator).

Unlabeled office observations may contain unknown attacks, so this component
must not certify benign labels, wire fidelity, or scenario training eligibility.
The fitted model and generated rows are never published by the default CLI.
"""
from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
from pathlib import Path

import numpy as np
import pandas as pd
from scipy.stats import norm

from .behavior import select_office_web_slice
from .evaluation import evaluate_c2st
from .reference import model_feature_columns


@dataclass(frozen=True)
class NumericCopula:
    names: tuple[str, ...]
    sorted_values: tuple[np.ndarray, ...]
    transform: np.ndarray
    missing_patterns: np.ndarray
    integer_columns: frozenset[str]
    train_rows: int

    def sample(self, count: int, seed: int) -> pd.DataFrame:
        if count < 1:
            raise ValueError("count must be positive")
        rng = np.random.default_rng(int(seed))
        z = rng.standard_normal((count, len(self.names))) @ self.transform.T
        q = np.clip(norm.cdf(z), 1e-8, 1 - 1e-8)
        masks = self.missing_patterns[
            rng.integers(0, len(self.missing_patterns), size=count)
        ]
        generated: dict[str, np.ndarray] = {}
        for j, (name, empirical) in enumerate(zip(self.names, self.sorted_values)):
            if not len(empirical):
                generated[name] = np.full(count, np.nan, dtype=float)
                continue
            values = np.interp(
                q[:, j], np.linspace(0, 1, len(empirical)), empirical
            )
            if name in self.integer_columns:
                values = np.rint(values)
            values[masks[:, j]] = np.nan
            generated[name] = values
        return pd.DataFrame(generated)


def numeric_feature_columns(df: pd.DataFrame, dictionary: list[dict]) -> list[str]:
    return [
        col for col in model_feature_columns(df, dictionary)
        if pd.api.types.is_numeric_dtype(df[col].dtype)
        or pd.api.types.is_bool_dtype(df[col].dtype)
    ]


def fit_numeric_office_copula(
    office_train: pd.DataFrame,
    feature_columns: list[str],
    *,
    shrinkage: float = 0.25,
) -> NumericCopula:
    if not feature_columns:
        raise ValueError("at least one numeric feature required")
    if len(office_train) < 30:
        raise ValueError("at least 30 training rows required")
    if not 0 <= shrinkage <= 1:
        raise ValueError("shrinkage must be in [0, 1]")
    names = tuple(feature_columns)
    if len(names) != len(set(names)):
        raise ValueError("duplicate features")
    observed = office_train.loc[:, names]
    if not all(pd.api.types.is_numeric_dtype(observed[c]) for c in names):
        raise ValueError("model accepts numeric features only")

    n, p = observed.shape
    z = np.zeros((n, p), dtype=float)
    missing_patterns = np.zeros((n, p), dtype=bool)
    sorted_values: list[np.ndarray] = []
    integer_columns: set[str] = set()
    for j, name in enumerate(names):
        col = pd.to_numeric(observed[name], errors="coerce")
        arr = col.to_numpy(dtype=float, na_value=np.nan)
        miss = ~np.isfinite(arr)
        missing_patterns[:, j] = miss
        empirical = np.sort(arr[~miss])
        sorted_values.append(empirical)
        if pd.api.types.is_integer_dtype(col.dtype) or pd.api.types.is_bool_dtype(col.dtype):
            integer_columns.add(name)
        if len(empirical) <= 1 or float(empirical[-1]) == float(empirical[0]):
            continue
        # Average ties avoid random linkages between categorical/integer bins.
        values = pd.Series(arr[~miss]).rank(method="average").to_numpy(dtype=float)
        u = np.clip((values - 0.5) / len(empirical), 1e-4, 1 - 1e-4)
        z[~miss, j] = norm.ppf(u)
    if p == 1:
        corr = np.array([[1.0]])
    else:
        corr = np.corrcoef(z, rowvar=False)
        corr = np.nan_to_num(corr, nan=0.0, posinf=0.0, neginf=0.0)
        np.fill_diagonal(corr, 1.0)
    corr = (1 - shrinkage) * corr + shrinkage * np.eye(p)
    eigenvalues, eigenvectors = np.linalg.eigh((corr + corr.T) / 2)
    # This is positive semidefinite by construction, even under constant columns.
    root = (eigenvectors * np.sqrt(np.maximum(eigenvalues, 1e-7))) @ eigenvectors.T
    return NumericCopula(
        names=names,
        sorted_values=tuple(sorted_values),
        transform=root,
        missing_patterns=missing_patterns,
        integer_columns=frozenset(integer_columns),
        train_rows=n,
    )


def _numeric_exact_match_fraction(
    generated: pd.DataFrame,
    training: pd.DataFrame,
    cols: list[str],
) -> float:
    # Disclosure diagnostic only. A zero here does not imply privacy.
    def hashes(frame: pd.DataFrame) -> set[str]:
        x = frame.loc[:, cols].round(6)
        return set(
            hashlib.sha256(line.encode("utf-8")).hexdigest()
            for line in x.to_csv(index=False, header=False, na_rep="<missing>").splitlines()
        )
    observed = hashes(training)
    samples = generated.loc[:, cols].round(6).to_csv(
        index=False, header=False, na_rep="<missing>"
    ).splitlines()
    if not samples:
        return 0.0
    return sum(
        hashlib.sha256(row.encode("utf-8")).hexdigest() in observed
        for row in samples
    ) / len(samples)


def office_feature_baseline(
    office: pd.DataFrame,
    dictionary: list[dict],
    *,
    seed: int = 20261008,
    max_evaluation_rows: int = 1600,
    bootstrap_reps: int = 30,
) -> dict[str, object]:
    """One frozen train-only fit and one grouped out-of-sample evaluation.

    Only aggregate diagnostics are returned. No raw/replicated office rows,
    host identifiers, model parameters, or generated rows are serialized.
    """
    office = select_office_web_slice(office)
    if "host_key" not in office:
        raise ValueError("missing host_key")
    host_ids = sorted(office["host_key"].dropna().astype(str).unique())
    if len(host_ids) < 60:
        return {
            "version": "office-feature-baseline-v1",
            "status": "insufficient_data",
            "host_groups": len(host_ids),
            "reason": "requires >=60 host groups for disjoint split",
        }
    train_ids = set(host_ids[::2])
    confirm_ids = set(host_ids[1::2])
    assert not train_ids.intersection(confirm_ids)
    tr = office.loc[office["host_key"].astype(str).isin(train_ids)]
    te = office.loc[office["host_key"].astype(str).isin(confirm_ids)]
    cols = numeric_feature_columns(office, dictionary)
    # Columns are defined by a committed dictionary before any confirmation
    # diagnostics. This avoids picking a favorable subset by observed AUC.
    model = fit_numeric_office_copula(tr, cols)
    rng = np.random.default_rng(seed)
    if len(te) > max_evaluation_rows:
        indices = np.sort(rng.choice(len(te), max_evaluation_rows, replace=False))
        confirm = te.iloc[indices].copy()
    else:
        confirm = te.copy()
    simulation = model.sample(len(confirm), seed=seed)
    c2st = evaluate_c2st(
        confirm.loc[:, cols],
        simulation.loc[:, cols],
        {
            "office": confirm["host_key"].astype(str).tolist(),
            "controls": [f"simulation:{i}" for i in range(len(simulation))],
        },
        feature_columns=cols,
        min_groups=30,
        bootstrap_reps=bootstrap_reps,
        random_state=seed,
    )
    metrics = c2st.get("classifiers", {})
    max_auc = max((float(v["auc"]) for v in metrics.values()), default=None)
    # Negative control: two real, group-disjoint office cohorts. This measures
    # how separable office hosts are even before any synthetic baseline exists.
    # The holdout is used ONLY for evaluation, never parameter fitting.
    real_control = evaluate_c2st(
        tr.loc[:, cols],
        te.loc[:, cols],
        {
            "office": tr["host_key"].astype(str).tolist(),
            "controls": te["host_key"].astype(str).tolist(),
        },
        feature_columns=cols,
        min_groups=30,
        bootstrap_reps=bootstrap_reps,
        random_state=seed + 1,
    )
    real_metrics = real_control.get("classifiers", {})
    real_max_auc = max(
        (float(v["auc"]) for v in real_metrics.values()), default=None
    )
    return {
        "version": "office-feature-baseline-v1",
        "status": "evaluated" if c2st["status"] == "ok" else "insufficient_data",
        "scope": "unlabeled_office_numeric_features_only_not_pcap",
        "training_rows": len(tr),
        "training_host_groups": len(train_ids),
        "confirmation_rows": len(confirm),
        "confirmation_host_groups": len(confirm_ids),
        "numeric_features": len(cols),
        "synthetic_rows": len(simulation),
        "model": "train_only_rank_gaussian_copula",
        "split_policy": "disjoint_sorted_host_key_even_odd",
        "max_origin_auc_numeric_only": max_auc,
        "classifiers": metrics,
        "office_to_office_grouped_negative_control": {
            "status": real_control["status"],
            "max_auc": real_max_auc,
            "classifiers": real_metrics,
            "interpretation": "independent office train groups vs office holdout groups, not a synthetic naturalness pass",
        },
        "exact_numeric_training_row_fraction": _numeric_exact_match_fraction(
            simulation, tr, cols
        ),
        "policy": {
            "training_eligible": False,
            "naturalness_calibration_eligible": False,
            "packet_level_fidelity": False,
            "labels_are_benign": False,
            "production_ready": False,
            "scenarios_used_to_fit": False,
            "generated_rows_published": False,
        },
    }


def main() -> None:
    import argparse
    p = argparse.ArgumentParser(description="Evaluate unlabeled office numeric feature model")
    p.add_argument("--reference", type=Path, required=True)
    p.add_argument("--out", type=Path, required=True)
    p.add_argument("--seed", type=int, default=20261008)
    a = p.parse_args()
    root = a.reference
    dictionary = json.loads((root / "pipeline_column_dictionary.json").read_text())
    office = pd.read_parquet(root / "pipeline_office_full.parquet")
    report = office_feature_baseline(office, dictionary, seed=a.seed)
    a.out.parent.mkdir(parents=True, exist_ok=True)
    a.out.write_text(json.dumps(report, sort_keys=True, indent=2) + "\n")
    print(json.dumps(report, sort_keys=True))
    # AUC alone never promotes this baseline to packet-level naturalness.
    if report["status"] != "evaluated":
        raise SystemExit("insufficient reference support for feature baseline")


if __name__ == "__main__":
    main()