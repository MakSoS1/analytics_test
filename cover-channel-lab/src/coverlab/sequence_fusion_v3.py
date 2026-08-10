from __future__ import annotations

import argparse
import hashlib
import json
import math
from pathlib import Path
from typing import Iterable

import joblib
import numpy as np
import pandas as pd
import torch
from sklearn.isotonic import IsotonicRegression
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import average_precision_score, confusion_matrix, precision_score, recall_score, roc_auc_score
from torch import nn
from torch.utils.data import DataLoader, TensorDataset

from . import train_baseline as _base
from . import train_baseline_v2 as _v2
from .research_contract_v3 import validation_role
from .train_baseline_v3 import availability_flags_v3  # installs v3 baseline overlay

MAX_SEQ_LEN = 64
SEQ_CHANNELS = ("direction", "size", "delta_t", "protocol", "status", "transaction_type")


def _stable_unit(value: object, salt: str) -> float:
    h = hashlib.sha256((salt + ":" + str(value)).encode()).digest()
    return int.from_bytes(h[:4], "big") / 2**32


def _numeric(series: pd.Series | None, n: int) -> np.ndarray:
    if series is None:
        return np.zeros(n, dtype=np.float32)
    return pd.to_numeric(series, errors="coerce").fillna(0).to_numpy(dtype=np.float32)


def encode_sequence(group: pd.DataFrame, max_len: int = MAX_SEQ_LEN) -> tuple[np.ndarray, np.ndarray]:
    g = group.sort_values("ts") if "ts" in group else group.copy()
    if len(g) > max_len:
        # Keep both beginning and end: registration/first poll and final task/result
        # are both useful lifecycle positions.
        head = max_len // 2
        g = pd.concat([g.iloc[:head], g.iloc[-(max_len-head):]], ignore_index=True)
    n = len(g)
    out = np.zeros((len(SEQ_CHANNELS), max_len), dtype=np.float32)
    mask = np.zeros(max_len, dtype=np.float32)
    if n == 0:
        return out, mask
    req = _numeric(g.get("request_body_length"), n)
    resp = _numeric(g.get("response_body_length"), n)
    total = req + resp
    direction = np.where(req > resp, 1.0, np.where(resp > req, -1.0, 0.0)).astype(np.float32)
    size = np.log1p(total) / np.float32(math.log1p(1_000_000))
    if "ts" in g:
        ts = pd.to_numeric(g["ts"], errors="coerce").ffill().fillna(0).to_numpy(dtype=np.float64)
        dt = np.diff(ts, prepend=ts[0])
    else:
        dt = np.zeros(n, dtype=np.float64)
    delta = (np.log1p(np.maximum(dt, 0)) / math.log1p(3600)).astype(np.float32)
    protocol = np.array([_stable_unit(v, "protocol") for v in g.get("protocol", pd.Series([""]*n))], dtype=np.float32)
    status_raw = pd.to_numeric(g.get("response_status", pd.Series([0]*n)), errors="coerce").fillna(0).to_numpy(dtype=np.float32)
    status = np.clip(status_raw / 599.0, 0, 1)
    kind = np.array([_stable_unit(v, "kind") for v in g.get("kind", pd.Series([""]*n))], dtype=np.float32)
    vals = (direction, size, delta, protocol, status, kind)
    for i, v in enumerate(vals):
        out[i, :n] = v[:n]
    mask[:n] = 1
    return out, mask


class TinyTCN(nn.Module):
    def __init__(self, channels: int = len(SEQ_CHANNELS)):
        super().__init__()
        self.net = nn.Sequential(
            nn.Conv1d(channels, 24, 3, padding=1), nn.ReLU(),
            nn.Conv1d(24, 24, 3, padding=2, dilation=2), nn.ReLU(),
            nn.Conv1d(24, 16, 3, padding=4, dilation=4), nn.ReLU(),
        )
        self.head = nn.Sequential(nn.Linear(16, 16), nn.ReLU(), nn.Dropout(0.10), nn.Linear(16, 1))

    def forward(self, x: torch.Tensor, mask: torch.Tensor) -> torch.Tensor:
        z = self.net(x)
        m = mask.unsqueeze(1)
        pooled = (z * m).sum(dim=2) / m.sum(dim=2).clamp_min(1.0)
        return self.head(pooled).squeeze(1)


def load_sequence_table(root: Path) -> tuple[pd.DataFrame, pd.DataFrame]:
    tx = _base.load_parquets(root, "transaction_features.parquet")
    session = _base.load_parquets(root, "session_features.parquet")
    splits = _base.split_map(root)
    if session.empty:
        return tx, session
    session = session.drop_duplicates("campaign_id", keep="last").merge(splits, on="campaign_id", how="left")
    session["split"] = session["split"].fillna("challenge")
    session = availability_flags_v3(session)
    return tx, session


def build_sequence_arrays(tx: pd.DataFrame, session: pd.DataFrame, ids: Iterable[str]) -> tuple[np.ndarray, np.ndarray, np.ndarray, list[str]]:
    ids = [str(x) for x in ids]
    labels = session.set_index(session.campaign_id.astype(str))["label_binary"].to_dict()
    grouped = {str(k): v for k, v in tx.groupby(tx.campaign_id.astype(str))} if not tx.empty else {}
    xs, ms, ys, kept = [], [], [], []
    for cid in ids:
        g = grouped.get(cid)
        if g is None or cid not in labels:
            continue
        x, m = encode_sequence(g)
        xs.append(x); ms.append(m); ys.append(int(labels[cid])); kept.append(cid)
    if not xs:
        return np.zeros((0, len(SEQ_CHANNELS), MAX_SEQ_LEN), np.float32), np.zeros((0, MAX_SEQ_LEN), np.float32), np.zeros(0, np.int64), []
    return np.stack(xs), np.stack(ms), np.asarray(ys, np.int64), kept


def _metrics(y: np.ndarray, p: np.ndarray, threshold: float) -> dict:
    pred = (p >= threshold).astype(int)
    tn, fp, fn, tp = confusion_matrix(y, pred, labels=[0, 1]).ravel()
    out = {
        "rows": int(len(y)), "positives": int(y.sum()), "threshold": float(threshold),
        "precision": float(precision_score(y, pred, zero_division=0)),
        "recall": float(recall_score(y, pred, zero_division=0)),
        "fpr": float(fp / max(1, fp + tn)), "fp_per_million": float(fp / max(1, fp + tn) * 1_000_000),
        "confusion_matrix": [[int(tn), int(fp)], [int(fn), int(tp)]],
    }
    if len(np.unique(y)) > 1:
        out["roc_auc"] = float(roc_auc_score(y, p)); out["pr_auc"] = float(average_precision_score(y, p))
    return out


def _threshold_for_recall(y: np.ndarray, p: np.ndarray, target=.95) -> float:
    return _base.threshold_for_recall(y, p, target)


def train_sequence(root: Path, out: Path, seed: int = 23, epochs: int = 10) -> tuple[dict, dict[str, float]]:
    torch.manual_seed(seed); np.random.seed(seed)
    tx, session = load_sequence_table(root)
    split = session.set_index(session.campaign_id.astype(str))["split"].to_dict()
    train_ids = [c for c, s in split.items() if s == "train"]
    val_ids = [c for c, s in split.items() if s == "validation"]
    test_ids = [c for c, s in split.items() if s == "test"]
    challenge_ids = [c for c, s in split.items() if s == "challenge"]
    cal_ids = [c for c in val_ids if validation_role(c) == "expert_calibration"]
    tune_ids = [c for c in val_ids if validation_role(c) == "expert_threshold"]

    xtr, mtr, ytr, kept_train = build_sequence_arrays(tx, session, train_ids)
    if len(ytr) < 10 or len(np.unique(ytr)) < 2:
        raise RuntimeError("insufficient sequence training campaigns")
    model = TinyTCN()
    pos = max(1, int(ytr.sum())); neg = max(1, len(ytr)-pos)
    loss_fn = nn.BCEWithLogitsLoss(pos_weight=torch.tensor(float(neg/pos)))
    opt = torch.optim.AdamW(model.parameters(), lr=2e-3, weight_decay=1e-3)
    ds = TensorDataset(torch.tensor(xtr), torch.tensor(mtr), torch.tensor(ytr, dtype=torch.float32))
    loader = DataLoader(ds, batch_size=min(128, len(ds)), shuffle=True, generator=torch.Generator().manual_seed(seed))
    model.train()
    for _ in range(max(1, epochs)):
        for xb, mb, yb in loader:
            opt.zero_grad(); logits = model(xb, mb); loss = loss_fn(logits, yb); loss.backward(); opt.step()

    def raw_scores(ids):
        x, m, y, kept = build_sequence_arrays(tx, session, ids)
        if len(y) == 0: return y, np.zeros(0), kept
        model.eval()
        with torch.no_grad(): p = torch.sigmoid(model(torch.tensor(x), torch.tensor(m))).numpy()
        return y, p, kept

    calibrator = None
    ycal, pcal_raw, _ = raw_scores(cal_ids)
    if len(ycal) and len(np.unique(ycal)) > 1:
        calibrator = IsotonicRegression(out_of_bounds="clip").fit(pcal_raw, ycal)
    def calibrate(p): return calibrator.predict(p) if calibrator is not None and len(p) else p
    yt, pt_raw, _ = raw_scores(tune_ids); pt = calibrate(pt_raw)
    threshold = _threshold_for_recall(yt, pt, .95) if len(yt) and len(np.unique(yt)) > 1 else .5

    all_ids = session.campaign_id.astype(str).tolist()
    ya, pa_raw, kept = raw_scores(all_ids); pa = calibrate(pa_raw)
    score_map = {cid: float(p) for cid, p in zip(kept, pa)}

    def part_report(ids):
        y, p, _ = raw_scores(ids); p = calibrate(p)
        return _metrics(y, p, threshold) if len(y) else {"rows": 0}

    bundle = {
        "architecture": "tiny_tcn_1d_cnn", "channels": list(SEQ_CHANNELS), "max_len": MAX_SEQ_LEN,
        "threshold": float(threshold), "calibrator": calibrator, "state_dict": model.state_dict(),
        "seed": seed, "training_campaigns": len(kept_train),
    }
    torch.save(bundle, out / "B2-sequence.pt")
    report = {
        "name": "B2-sequence", "status": "ok", "architecture": "tiny_tcn_1d_cnn",
        "train": {"rows": len(ytr), "positives": int(ytr.sum())},
        "test": part_report(test_ids), "challenge": part_report(challenge_ids), "threshold": float(threshold),
    }
    return report, score_map


def _bundle_probability(bundle: dict, frame: pd.DataFrame) -> np.ndarray:
    if frame.empty: return np.zeros(0)
    x, _ = _v2.numeric_matrix(frame, bundle["features"])
    raw = bundle["model"].predict_proba(x)[:, 1]
    cal = bundle.get("calibrator")
    return cal.predict(raw) if cal is not None else raw


def expert_probability_table(root: Path, models: Path, sequence_scores: dict[str, float]) -> pd.DataFrame:
    frames = _v2.build_frames(root)
    session = _base.load_parquets(root, "session_features.parquet")
    splits = _base.split_map(root)
    session = session.drop_duplicates("campaign_id", keep="last").merge(splits, on="campaign_id", how="left")
    session["split"] = session["split"].fillna("challenge")
    session = availability_flags_v3(session)
    base = session[[c for c in session.columns if c in {"campaign_id","label_binary","split"} or c.startswith("availability_") or c.startswith("missing_reason_\")]].copy()
    base["campaign_id"] = base.campaign_id.astype(str)

    # B2/B3 are campaign-level.
    for name, col in (("B2-session", "p_b2"), ("B3-opaque", "p_b3")):
        bundle = joblib.load(models / f"{name}.joblib")
        f = frames[name].copy(); f["campaign_id"] = f.campaign_id.astype(str)
        f[col] = _bundle_probability(bundle, f)
        base = base.merge(f[["campaign_id", col]], on="campaign_id", how="left")

    # B1 predicts transactions. Aggregate to campaign. It is disabled when payload
    # visibility is absent rather than silently treating zero as content evidence.
    b1 = frames["B1-content"].copy()
    if not b1.empty:
        bundle = joblib.load(models / "B1-content.joblib")
        b1["p"] = _bundle_probability(bundle, b1); b1["campaign_id"] = b1.campaign_id.astype(str)
        agg = b1.groupby("campaign_id").p.agg([("p_b1_mean","mean"),("p_b1_max","max")]).reset_index()
        base = base.merge(agg, on="campaign_id", how="left")
    else:
        base["p_b1_mean"] = np.nan; base["p_b1_max"] = np.nan
    base["p_b2_seq"] = base.campaign_id.map(sequence_scores)
    encrypted = base.get("availability_encrypted", pd.Series([0]*len(base))).fillna(0).astype(int).eq(1)
    base["b1_available"] = ((~encrypted) & base.p_b1_mean.notna()).astype(int)
    base.loc[base.b1_available.eq(0), ["p_b1_mean", "p_b1_max"]] = np.nan
    return base


def train_fusion(root: Path, models: Path, out: Path, sequence_scores: dict[str, float], seed=23) -> dict:
    table = expert_probability_table(root, models, sequence_scores)
    val = table[table.split.eq("validation")].copy()
    test = table[table.split.eq("test")].copy(); challenge = table[table.split.eq("challenge")].copy()
    train_mask = val.campaign_id.map(validation_role).eq("fusion_train")
    tune_mask = val.campaign_id.map(validation_role).eq("fusion_threshold")
    fit = val[train_mask].copy(); tune = val[tune_mask].copy()
    feature_cols = [c for c in table.columns if c.startswith("p_") or c.startswith("availability_") or c.startswith("missing_reason_") or c == "b1_available"]
    if fit.empty or len(fit.label_binary.unique()) < 2:
        raise RuntimeError("insufficient disjoint validation campaigns for fusion")

    medians = {c: float(pd.to_numeric(fit[c], errors="coerce").median()) if pd.to_numeric(fit[c], errors="coerce").notna().any() else 0.0 for c in feature_cols}
    def matrix(df):
        x = df[feature_cols].apply(pd.to_numeric, errors="coerce").copy()
        for c in feature_cols: x[c] = x[c].fillna(medians[c])
        return x
    fusion = LogisticRegression(max_iter=1000, class_weight="balanced", random_state=seed).fit(matrix(fit), fit.label_binary.astype(int))
    threshold = .5
    if not tune.empty and len(tune.label_binary.unique()) > 1:
        p = fusion.predict_proba(matrix(tune))[:, 1]
        threshold = _threshold_for_recall(tune.label_binary.astype(int).to_numpy(), p, .95)
    def report(df):
        if df.empty: return {"rows": 0}
        p = fusion.predict_proba(matrix(df))[:,1]
        return _metrics(df.label_binary.astype(int).to_numpy(), p, threshold)
    bundle = {
        "model": fusion, "features": feature_cols, "medians": medians, "threshold": float(threshold),
        "router_policy": "B1 excluded when encrypted/opaque; B2 engineered + B2 sequence + B3 remain available",
        "validation_policy": "fusion_train/fusion_threshold disjoint from expert calibration and threshold campaigns",
    }
    joblib.dump(bundle, out / "fusion-router.joblib")
    table.to_parquet(out / "fusion_probability_table.parquet", index=False)
    return {"name": "fusion-router", "status": "ok", "features": feature_cols, "threshold": float(threshold), "test": report(test), "challenge": report(challenge)}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--dataset-root", required=True); ap.add_argument("--models", required=True); ap.add_argument("--out", required=True)
    ap.add_argument("--seed", type=int, default=23); ap.add_argument("--epochs", type=int, default=10)
    args = ap.parse_args(); root = Path(args.dataset_root); models = Path(args.models); out = Path(args.out); out.mkdir(parents=True, exist_ok=True)
    seq_report, seq_scores = train_sequence(root, out, args.seed, args.epochs)
    fusion_report = train_fusion(root, models, out, seq_scores, args.seed)
    report = {"sequence": seq_report, "fusion": fusion_report}
    (out / "advanced_v3_report.json").write_text(json.dumps(report, indent=2))
    print(json.dumps({"sequence":"ok","fusion":"ok","out":str(out)}))


if __name__ == "__main__": main()
