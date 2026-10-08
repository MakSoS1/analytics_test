"""Bounded adaptive fitting of the DEFENDER, never modification of traffic.

Candidate models are selected against a group-disjoint validation slice of
the office TRAIN day only. The independent later office day and uploaded
source are evaluated once AFTER selection, and never steer the search.
"""
from __future__ import annotations

import argparse
from hashlib import sha256
import json
from pathlib import Path

import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest
from sklearn.impute import SimpleImputer
from sklearn.model_selection import GroupShuffleSplit
from sklearn.pipeline import make_pipeline
from sklearn.preprocessing import RobustScaler

# Fixed in source, not adjusted after looking at test or submitted captures.
CANDIDATES = (
    ("isoforest-96-128", 96, 128),
    ("isoforest-128-256", 128, 256),
    ("isoforest-160-512", 160, 512),
)
FORBIDDEN = {
    "domain", "group_id", "label", "label_policy", "capture_day",
    "source_role", "pair_id", "profile_id", "origin", "global_session_uid",
}


def _sha(path: Path) -> str:
    h = sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1 << 20), b""):
            h.update(block)
    return h.hexdigest()


def _estimator(trees: int, samples: int, seed: int):
    return make_pipeline(
        SimpleImputer(strategy="median", keep_empty_features=True),
        RobustScaler(),
        IsolationForest(n_estimators=trees, max_samples=samples,
                        random_state=seed, n_jobs=1),
    )


def _load_verified_tables(root: Path):
    manifest = json.loads((root / "manifest.json").read_text())
    files = ("train_candidates.parquet", "office_holdout.parquet", "user_input.parquet")
    for filename in files:
        if _sha(root / filename) != manifest["outputs"].get(filename):
            raise ValueError("prepared table checksum mismatch: " + filename)
    cols = manifest["feature_columns"]
    if not cols or len(set(cols)) != len(cols) or FORBIDDEN.intersection(cols):
        raise ValueError("model feature schema is missing, duplicated or contains origin metadata")
    train = pd.read_parquet(root / files[0])
    holdout = pd.read_parquet(root / files[1])
    source = pd.read_parquet(root / files[2])
    office = train.loc[train["domain"].eq("office_train")]
    if office.empty or len(office) != manifest["office_train_rows"]:
        raise ValueError("office training rows inconsistent with manifest")
    if len(holdout) != manifest["office_holdout_rows"] or len(source) != manifest["source_rows"]:
        raise ValueError("source or holdout row counts inconsistent with manifest")
    if not holdout["domain"].eq("office_holdout").all() or not source["domain"].eq("user_input").all():
        raise ValueError("dataset origin drift")
    if not office["label"].eq(-1).all() or not holdout["label"].eq(-1).all():
        raise ValueError("unverified office data must remain unlabeled")
    if set(office["group_id"]) & set(holdout["group_id"]):
        raise ValueError("train-holdout office grouping leakage")
    for table in (office, holdout, source):
        if any(col not in table for col in cols):
            raise ValueError("missing declared ML feature")
        if table[cols].isna().all(axis=0).any():
            raise ValueError("entire feature absent in a model domain")
    return manifest, cols, office, holdout, source


def fit_until_validated(
    prepared: Path,
    *,
    seed: int = 20261008,
    alert_budget: float = 0.01,
    validation_tolerance: float = 0.02,
    max_attempts: int = 3,
) -> dict[str, object]:
    """Try bounded model candidates; only OFFICE TRAIN validation drives choice.

    A pass is explicitly limited to consistency of an *unlabeled office
    alert budget*. It NEVER means that uploaded PCAPs look natural or that
    the office holdout has verified benign ground truth.
    """
    if not 0.001 <= alert_budget <= 0.10:
        raise ValueError("alert_budget outside the allowed diagnostic range")
    if not 0 < validation_tolerance <= 0.10:
        raise ValueError("validation_tolerance must be in (0, 0.1]")
    if not 1 <= max_attempts <= len(CANDIDATES):
        raise ValueError("max_attempts exceeds the fixed candidate budget")
    root = Path(prepared)
    manifest, cols, office, holdout, source = _load_verified_tables(root)
    groups = office["group_id"].astype(str).to_numpy()
    if len(np.unique(groups)) < 20:
        raise ValueError("at least 20 independent office train groups required")

    splitter = GroupShuffleSplit(n_splits=1, test_size=0.25, random_state=seed)
    inner_train_idx, inner_valid_idx = next(splitter.split(office, groups=groups))
    if set(groups[inner_train_idx]) & set(groups[inner_valid_idx]):
        raise RuntimeError("inner office groups leaked")
    train_sub = office.iloc[inner_train_idx][cols]
    validation = office.iloc[inner_valid_idx][cols]

    attempts: list[dict[str, object]] = []
    chosen = None
    # Never examine the source or external holdout in this search.
    for name, trees, samples in CANDIDATES[:max_attempts]:
        model = _estimator(trees, samples, seed)
        model.fit(train_sub)
        scores_train = -model.score_samples(train_sub)
        threshold = float(np.quantile(scores_train, 1-alert_budget))
        rate = float(np.mean(-model.score_samples(validation) > threshold))
        gap = abs(rate-alert_budget)
        row = {
            "candidate": name,
            "validation_alert_fraction": rate,
            "absolute_alert_budget_gap": gap,
            "inner_train_groups": int(len(np.unique(groups[inner_train_idx]))),
            "inner_validation_groups": int(len(np.unique(groups[inner_valid_idx]))),
            "passed_office_train_validation": bool(gap <= validation_tolerance),
        }
        attempts.append(row)
        if chosen is None or gap < chosen[0]:
            chosen = (gap, name, trees, samples)
        if gap <= validation_tolerance:
            break
    assert chosen is not None
    _, selected, trees, samples = chosen
    selected_row = next(r for r in attempts if r["candidate"] == selected)

    # One final fit on office TRAIN only; holdout and source are strictly
    # inference-only. Do not select on their scores or adjust the threshold.
    final = _estimator(trees, samples, seed)
    final.fit(office[cols])
    fitted_scores = -final.score_samples(office[cols])
    threshold = float(np.quantile(fitted_scores, 1-alert_budget))
    office_rate = float(np.mean(-final.score_samples(holdout[cols]) > threshold))
    input_rate = float(np.mean(-final.score_samples(source[cols]) > threshold))

    # Model bundle is reusable for future defensive scoring. Loading joblib
    # should only be done for files from a trusted provenance.
    import joblib
    model_path = root / "defender_model.joblib"
    if model_path.exists():
        raise FileExistsError(model_path)
    joblib.dump({
        "estimator": final, "feature_columns": tuple(cols),
        "alert_threshold": threshold,
        "training_source_sha256": manifest["source_sha256"],
        "model_training_domain": "office_train_only",
    }, model_path)
    report = {
        "version": "defender-office-bounded-model-adaptation-v1",
        "status": "train_day_validated" if selected_row["passed_office_train_validation"] else "train_day_validation_not_passed",
        "max_attempts": max_attempts,
        "attempts_executed": len(attempts),
        "candidate_history": attempts,
        "selected_candidate": selected,
        "selected_validation_passed": selected_row["passed_office_train_validation"],
        "validation_uses_only_office_train_groups": True,
        "holdout_or_source_used_for_selection": False,
        "train_holdout_groups_disjoint": True,
        "feature_count": len(cols),
        "requested_train_alert_budget": alert_budget,
        "validation_tolerance": validation_tolerance,
        "train_alert_fraction": float(np.mean(fitted_scores > threshold)),
        "office_holdout_alert_fraction": office_rate,
        "user_input_alert_fraction": input_rate,
        "model_sha256": _sha(model_path),
        "input_sha256": manifest["source_sha256"],
        "source_label": manifest["source_label"],
        "all_reference_office_labels_unverified": True,
        "reported_alert_rate_is_not_fpr": True,
        "office_naturalness_proven": False,
        "original_pcap_modified": False,
        "production_ready": False,
    }
    (root / "model_selection_report.json").write_text(
        json.dumps(report, sort_keys=True, indent=2) + "\n",
    )
    return report


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--prepared", type=Path, required=True)
    parser.add_argument("--seed", type=int, default=20261008)
    parser.add_argument("--alert-budget", type=float, default=0.01)
    parser.add_argument("--validation-tolerance", type=float, default=0.02)
    parser.add_argument("--max-attempts", type=int, default=3)
    args = parser.parse_args()
    report = fit_until_validated(
        args.prepared, seed=args.seed, alert_budget=args.alert_budget,
        validation_tolerance=args.validation_tolerance,
        max_attempts=args.max_attempts,
    )
    print("DEFENDER_MODEL_ADAPTATION", json.dumps(report, sort_keys=True))


if __name__ == "__main__":
    main()
