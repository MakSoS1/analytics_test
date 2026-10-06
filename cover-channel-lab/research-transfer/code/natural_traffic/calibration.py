from __future__ import annotations

import hashlib
import json
from collections.abc import Mapping, Sequence

import numpy as np
import pandas as pd

from .contracts import FrozenProfileManifest
from .profiles import ProfileRegistry


class CalibrationLeakageError(ValueError):
    """Raised when scenario/positive rows reach benign-only calibration."""


class GroupLeakageError(ValueError):
    """Raised when one source ancestor crosses train/confirmation."""


def validate_group_disjointness(
    train_groups: Sequence[object],
    confirmation_groups: Sequence[object],
) -> None:
    overlap = set(map(str, train_groups)).intersection(map(str, confirmation_groups))
    if overlap:
        preview = ", ".join(sorted(overlap)[:5])
        raise GroupLeakageError(f"group leakage across calibration/confirmation: {preview}")


def _validate_calibration_inputs(
    office_train: pd.DataFrame,
    benign_controls_train: pd.DataFrame,
    groups: Mapping[str, Sequence[object]],
) -> None:
    if "role" in benign_controls_train:
        roles = set(benign_controls_train["role"].dropna().astype(str))
        if roles - {"control"}:
            raise CalibrationLeakageError(
                f"benign calibration received non-control roles: {sorted(roles - {'control'})}"
            )
    if "scenario" in benign_controls_train.columns:
        values = benign_controls_train["scenario"].fillna(False).astype(bool)
        if bool(values.any()):
            raise CalibrationLeakageError("scenario rows are forbidden in benign calibration")
    if len(groups.get("office", ())) != len(office_train):
        raise ValueError("office group vector length mismatch")
    if len(groups.get("controls", ())) != len(benign_controls_train):
        raise ValueError("control group vector length mismatch")
    if "profile_id" not in benign_controls_train:
        raise ValueError("benign controls require profile_id")


def _profile_distance(
    office: pd.DataFrame,
    control: pd.DataFrame,
    feature_columns: Sequence[str],
) -> float:
    # Import lazily to keep the contracts/reference layer lightweight.
    from .evaluation import prepare_diagnostic_frame

    matrix, labels = prepare_diagnostic_frame(office, control, feature_columns)
    left = matrix.loc[labels == 0]
    right = matrix.loc[labels == 1]
    scores: list[float] = []
    for col in matrix.columns:
        a = left[col].to_numpy(dtype=float)
        b = right[col].to_numpy(dtype=float)
        scale = float(np.nanstd(np.concatenate([a, b])))
        delta = abs(float(np.nanmean(a)) - float(np.nanmean(b)))
        if not np.isfinite(delta):
            continue
        scores.append(delta / max(scale, 1e-9))
    return float(np.mean(scores)) if scores else float("inf")


def calibrate_profiles(
    office_train: pd.DataFrame,
    benign_controls_train: pd.DataFrame,
    groups: Mapping[str, Sequence[object]],
    registry: ProfileRegistry,
    seed: int,
    *,
    feature_columns: Sequence[str],
) -> FrozenProfileManifest:
    """Select a frozen benign runtime profile without seeing scenario rows.

    The first implementation deliberately prefers the single closest profile.
    A one-profile mixture is the simplest valid mixture and prevents a weak
    profile from being hidden by post-hoc weighting. The selection objective is
    deterministic and train-only; confirmation never calls this function.
    """

    _validate_calibration_inputs(office_train, benign_controls_train, groups)
    if not feature_columns:
        raise ValueError("feature_columns must be non-empty")

    scored: list[tuple[float, str]] = []
    for profile_id, frame in benign_controls_train.groupby("profile_id", sort=True):
        profile_id = str(profile_id)
        registry.resolve(profile_id)
        if frame.empty:
            continue
        score = _profile_distance(office_train, frame.reset_index(drop=True), feature_columns)
        scored.append((score, profile_id))
    if not scored:
        raise ValueError("no benign runtime profiles available for calibration")

    score, best = min(scored, key=lambda item: (item[0], item[1]))
    fingerprint = hashlib.sha256(
        json.dumps(
            {
                "profile": best,
                "score": round(float(score), 12),
                "features": list(feature_columns),
                "office_groups": len(set(map(str, groups["office"]))),
                "control_groups": len(set(map(str, groups["controls"]))),
                "seed": int(seed),
            },
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
    ).hexdigest()
    return FrozenProfileManifest(
        seed=int(seed),
        profile_weights=((best, 1.0),),
        reference_id=f"calibration:{fingerprint}",
    )
