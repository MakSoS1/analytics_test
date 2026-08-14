from __future__ import annotations

from dataclasses import dataclass
from typing import Any

import numpy as np
import pandas as pd
from lightgbm import LGBMClassifier
from sklearn.compose import ColumnTransformer
from sklearn.ensemble import IsolationForest
from sklearn.impute import SimpleImputer
from sklearn.metrics import average_precision_score, brier_score_loss, confusion_matrix, f1_score, precision_score, recall_score, roc_auc_score
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import OneHotEncoder, RobustScaler

from .evaluation import evaluate_operating_points

LABEL = "label_binary"
SPLIT = "split"
PRIMARY_MAX_FPR = 0.01


def deterministic_score(frame: pd.DataFrame) -> np.ndarray:
    score = np.zeros(len(frame), dtype=float)
    def values(name: str) -> np.ndarray:
        if name not in frame.columns:
            return np.zeros(len(frame), dtype=float)
        return pd.to_numeric(frame[name], errors="coerce").fillna(0.0).to_numpy(dtype=float)
    score += 0.20 * (values("connections_1m") >= 4)
    score += 0.15 * (values("connections_15m") >= 6)
    score += 0.10 * (values("connections_24h") >= 12)
    score += 0.20 * (values("new_dst_for_src") >= 1)
    score += 0.15 * (values("new_src_dst_pair") >= 1)
    score += 0.10 * (values("src_out_degree_1h") >= 3)
    score += 0.10 * (values("new_edge_count_1h") >= 2)
    return np.clip(score, 0.0, 1.0)


def _metrics(y: np.ndarray, score: np.ndarray, threshold: float, *, probability_scores: bool = False) -> dict[str, Any]:
    pred = (score >= threshold).astype(int)
    tn, fp, fn, tp = confusion_matrix(y, pred, labels=[0, 1]).ravel()
    fpr = float(fp / (fp + tn)) if fp + tn else 0.0
    result: dict[str, Any] = {
        "n": int(len(y)), "positive": int(y.sum()), "negative": int((1 - y).sum()), "threshold": float(threshold),
        "precision": float(precision_score(y, pred, zero_division=0)), "recall": float(recall_score(y, pred, zero_division=0)), "f1": float(f1_score(y, pred, zero_division=0)),
        "fpr": fpr, "fp_per_10k_benign": float(10000.0 * fpr), "tp": int(tp), "fp": int(fp), "tn": int(tn), "fn": int(fn),
    }
    if len(np.unique(y)) == 2:
        result["pr_auc"] = float(average_precision_score(y, score)); result["roc_auc"] = float(roc_auc_score(y, score))
        if probability_scores:
            result["brier"] = float(brier_score_loss(y, np.clip(score, 0.0, 1.0)))
        result["strict_operating_points"] = evaluate_operating_points(y, score, probability_scores=probability_scores)
    return result


def choose_threshold(y: np.ndarray, score: np.ndarray, *, max_fpr: float = PRIMARY_MAX_FPR) -> float:
    candidates = np.unique(np.concatenate(([float(np.max(score)) + 1e-12], score, [float(np.min(score)) - 1e-12])))
    best: tuple[float, float, float] | None = None; best_threshold = float(np.max(score)) + 1e-12
    for threshold in candidates:
        metrics = _metrics(y, score, float(threshold))
        if metrics["fpr"] > max_fpr: continue
        candidate = (metrics["f1"], metrics["recall"], -float(threshold))
        if best is None or candidate > best: best = candidate; best_threshold = float(threshold)
    return best_threshold


def _split_xy(frame: pd.DataFrame, split: str) -> tuple[pd.DataFrame, np.ndarray]:
    subset = frame[frame[SPLIT].astype(str) == split].copy()
    if subset.empty: raise ValueError(f"split is empty: {split}")
    y = subset.pop(LABEL).astype(int).to_numpy(); subset.pop(SPLIT); return subset, y


def build_supervised_pipeline(x: pd.DataFrame, *, seed: int) -> Pipeline:
    categorical = [c for c in x.columns if x[c].dtype == "object" or str(x[c].dtype).startswith("string")]; numeric = [c for c in x.columns if c not in categorical]
    transform = ColumnTransformer([
        ("num", Pipeline([("impute", SimpleImputer(strategy="median"))]), numeric),
        ("cat", Pipeline([("impute", SimpleImputer(strategy="most_frequent")), ("onehot", OneHotEncoder(handle_unknown="ignore", sparse_output=False))]), categorical),
    ], remainder="drop", verbose_feature_names_out=False)
    model = LGBMClassifier(n_estimators=400, learning_rate=0.035, num_leaves=31, max_depth=-1, subsample=0.85, colsample_bytree=0.85, reg_lambda=1.5, random_state=seed, n_jobs=-1, verbosity=-1)
    return Pipeline([("preprocess", transform), ("model", model)])


def train_supervised(frame: pd.DataFrame, *, seed: int = 20260814) -> tuple[Pipeline, dict[str, Any]]:
    x_train, y_train = _split_xy(frame, "train"); x_val, y_val = _split_xy(frame, "validation")
    if len(np.unique(y_train)) < 2: raise ValueError("supervised train split needs both classes")
    pipeline = build_supervised_pipeline(x_train, seed=seed); pipeline.fit(x_train, y_train); val_score = pipeline.predict_proba(x_val)[:, 1]
    threshold = choose_threshold(y_val, val_score, max_fpr=PRIMARY_MAX_FPR)
    report: dict[str, Any] = {"model": "LightGBM", "threshold_policy": "max validation F1 subject to FPR<=0.01", "threshold": threshold, "splits": {"validation": _metrics(y_val, val_score, threshold, probability_scores=True)}}
    for split in ("test", "challenge"):
        try: x, y = _split_xy(frame, split)
        except ValueError: continue
        score = pipeline.predict_proba(x)[:, 1]; report["splits"][split] = _metrics(y, score, threshold, probability_scores=True)
    return pipeline, report


@dataclass
class BenignOnlyModel:
    columns: list[str]
    scaler: RobustScaler
    model: IsolationForest
    threshold: float
    def score(self, frame: pd.DataFrame) -> np.ndarray:
        x = frame[self.columns].apply(pd.to_numeric, errors="coerce").fillna(0.0).to_numpy(dtype=float); return -self.model.score_samples(self.scaler.transform(x))


def train_benign_only(frame: pd.DataFrame, *, seed: int = 20260814) -> tuple[BenignOnlyModel, dict[str, Any]]:
    numeric_cols = [c for c in frame.columns if c not in {LABEL, SPLIT} and pd.api.types.is_numeric_dtype(frame[c])]
    if not numeric_cols: raise ValueError("no numeric production features for benign-only model")
    train = frame[(frame[SPLIT] == "train") & (frame[LABEL] == 0)]
    if len(train) < 20: raise ValueError("benign-only model needs at least 20 benign train rows")
    x_train = train[numeric_cols].fillna(0.0).to_numpy(dtype=float); scaler = RobustScaler().fit(x_train); model = IsolationForest(n_estimators=400, contamination="auto", random_state=seed, n_jobs=-1).fit(scaler.transform(x_train))
    val = frame[frame[SPLIT] == "validation"]
    if val.empty or val[LABEL].nunique() < 2: raise ValueError("benign-only validation requires both classes")
    temp = BenignOnlyModel(numeric_cols, scaler, model, threshold=0.0); val_score = temp.score(val); threshold = choose_threshold(val[LABEL].astype(int).to_numpy(), val_score, max_fpr=PRIMARY_MAX_FPR); temp.threshold = threshold
    report: dict[str, Any] = {"model": "IsolationForest-benign-only", "features": numeric_cols, "threshold_policy": "max validation F1 subject to FPR<=0.01", "threshold": threshold, "splits": {"validation": _metrics(val[LABEL].astype(int).to_numpy(), val_score, threshold)}}
    for split in ("test", "challenge"):
        subset = frame[frame[SPLIT] == split]
        if subset.empty: continue
        report["splits"][split] = _metrics(subset[LABEL].astype(int).to_numpy(), temp.score(subset), threshold)
    return temp, report


def evaluate_deterministic(frame: pd.DataFrame) -> dict[str, Any]:
    val = frame[frame[SPLIT] == "validation"]
    if val.empty: raise ValueError("validation split empty")
    threshold = choose_threshold(val[LABEL].astype(int).to_numpy(), deterministic_score(val), max_fpr=PRIMARY_MAX_FPR)
    report: dict[str, Any] = {"model": "deterministic-behavior-baseline", "threshold_policy": "max validation F1 subject to FPR<=0.01", "threshold": threshold, "splits": {}}
    for split in ("validation", "test", "challenge"):
        subset = frame[frame[SPLIT] == split]
        if subset.empty: continue
        report["splits"][split] = _metrics(subset[LABEL].astype(int).to_numpy(), deterministic_score(subset), threshold)
    return report
