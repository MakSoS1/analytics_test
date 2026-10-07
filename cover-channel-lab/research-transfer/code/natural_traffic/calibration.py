from __future__ import annotations

import hashlib
import json
from collections.abc import Mapping, Sequence

import numpy as np
import pandas as pd
from scipy.optimize import minimize

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


def derive_temporal_environment(
    office_train: pd.DataFrame,
    *,
    pool_size: int = 64,
) -> dict[str, object]:
    """Freeze a representative timestamp pool from office-train only."""
    if "session_start_epoch" not in office_train:
        return {}
    values = pd.to_numeric(office_train["session_start_epoch"], errors="coerce")
    values = np.sort(values[np.isfinite(values)].to_numpy(dtype=float))
    if not len(values):
        return {}
    take = min(max(1, int(pool_size)), len(values))
    indices = np.rint(np.linspace(0, len(values) - 1, take)).astype(int)
    pool = [round(float(values[i]), 6) for i in indices]
    return {
        "temporal_source": "office_train_empirical_quantiles",
        "temporal_start_epoch_pool": pool,
    }


def assign_temporal_starts(
    manifest: FrozenProfileManifest,
    group_ids: Sequence[object],
) -> dict[str, float]:
    pool = list(manifest.environment.get("temporal_start_epoch_pool", ()))
    if not pool:
        raise ValueError("frozen manifest has no temporal_start_epoch_pool")
    result: dict[str, float] = {}
    for group in group_ids:
        key = str(group)
        digest = hashlib.sha256(
            f"{manifest.seed}:{manifest.reference_id}:{key}:temporal".encode("utf-8")
        ).digest()
        index = int.from_bytes(digest[:8], "big") % len(pool)
        result[key] = float(pool[index])
    return result


def _mixture_weights(
    office: pd.DataFrame,
    controls: pd.DataFrame,
    profile_ids: Sequence[str],
    feature_columns: Sequence[str],
) -> tuple[tuple[str, float], ...]:
    from .evaluation import prepare_diagnostic_frame

    matrix, labels = prepare_diagnostic_frame(office, controls, feature_columns)
    office_matrix = matrix.loc[labels == 0].to_numpy(dtype=float)
    control_matrix = matrix.loc[labels == 1].reset_index(drop=True)
    target = np.mean(office_matrix, axis=0)
    combined = matrix.to_numpy(dtype=float)
    scale = np.std(combined, axis=0)
    scale[~np.isfinite(scale) | (scale < 1e-9)] = 1.0
    target = target / scale

    profiles = controls["profile_id"].astype(str).reset_index(drop=True)
    means: list[np.ndarray] = []
    names: list[str] = []
    for profile_id in sorted(set(map(str, profile_ids))):
        mask = profiles.eq(profile_id).to_numpy()
        if not mask.any():
            continue
        means.append(np.mean(control_matrix.loc[mask].to_numpy(dtype=float), axis=0) / scale)
        names.append(profile_id)
    if not means:
        raise ValueError("no profile means available")
    matrix_means = np.vstack(means)

    def objective(weights: np.ndarray) -> float:
        delta = weights @ matrix_means - target
        return float(np.dot(delta, delta))

    single_scores = [objective(np.eye(len(names))[i]) for i in range(len(names))]
    best_index = int(np.argmin(single_scores))
    if len(names) == 1:
        return ((names[0], 1.0),)

    result = minimize(
        objective,
        np.full(len(names), 1.0 / len(names)),
        method="SLSQP",
        bounds=[(0.0, 1.0)] * len(names),
        constraints={"type": "eq", "fun": lambda w: float(np.sum(w) - 1.0)},
        options={"ftol": 1e-12, "maxiter": 500},
    )
    if not result.success:
        return ((names[best_index], 1.0),)
    weights = np.clip(np.asarray(result.x, dtype=float), 0.0, 1.0)
    weights[weights < 1e-4] = 0.0
    total = float(weights.sum())
    if total <= 0:
        return ((names[best_index], 1.0),)
    weights /= total
    optimized = objective(weights)
    if single_scores[best_index] <= optimized + 1e-10:
        return ((names[best_index], 1.0),)
    return tuple(
        (name, float(weight))
        for name, weight in zip(names, weights)
        if weight > 0.0
    )


def calibrate_profiles(
    office_train: pd.DataFrame,
    benign_controls_train: pd.DataFrame,
    groups: Mapping[str, Sequence[object]],
    registry: ProfileRegistry,
    seed: int,
    *,
    feature_columns: Sequence[str],
) -> FrozenProfileManifest:
    """Freeze a benign-only convex runtime mixture and office-train environment."""

    _validate_calibration_inputs(office_train, benign_controls_train, groups)
    if not feature_columns:
        raise ValueError("feature_columns must be non-empty")

    profile_ids = sorted(set(benign_controls_train["profile_id"].astype(str)))
    for profile_id in profile_ids:
        registry.resolve(profile_id)
    weights = _mixture_weights(
        office_train.reset_index(drop=True),
        benign_controls_train.reset_index(drop=True),
        profile_ids,
        feature_columns,
    )
    environment = derive_temporal_environment(office_train)
    environment_json = json.dumps(
        environment, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    )
    fingerprint = hashlib.sha256(
        json.dumps(
            {
                "profile_weights": [
                    [profile_id, round(float(weight), 12)]
                    for profile_id, weight in weights
                ],
                "environment": environment,
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
        profile_weights=weights,
        reference_id=f"calibration:{fingerprint}",
        environment_json=environment_json,
    )