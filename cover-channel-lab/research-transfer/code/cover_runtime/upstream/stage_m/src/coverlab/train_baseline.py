from __future__ import annotations

import argparse
import json
from pathlib import Path

import joblib
import numpy as np
import pandas as pd
from lightgbm import LGBMClassifier
from sklearn.isotonic import IsotonicRegression
from sklearn.metrics import average_precision_score, confusion_matrix, f1_score, precision_recall_curve, precision_score, recall_score, roc_auc_score


DROP_IDENTITY = {"campaign_id", "label_binary", "label_family", "protocol", "persona", "client_impl", "visibility_mode", "inspection_policy", "sni_visibility"}


def load_parquets(root: Path, name: str) -> pd.DataFrame:
    frames = []
    for p in root.rglob(name):
        try: frames.append(pd.read_parquet(p))
        except Exception as exc: print(f"skip {p}: {exc}")
    if not frames: return pd.DataFrame()
    out = pd.concat(frames, ignore_index=True)
    if "campaign_id" in out.columns:
        keys = ["campaign_id"] + (["ts"] if "ts" in out.columns else [])
        out = out.drop_duplicates(subset=keys)
    return out


def split_map(root: Path) -> pd.DataFrame:
    frames = []
    for p in root.rglob("campaign_splits.parquet"):
        try: frames.append(pd.read_parquet(p))
        except Exception: pass
    if not frames: return pd.DataFrame(columns=["campaign_id", "split"])
    return pd.concat(frames, ignore_index=True).drop_duplicates("campaign_id", keep="last")


def numeric_matrix(df: pd.DataFrame, feature_cols: list[str] | None = None) -> tuple[pd.DataFrame, list[str]]:
    x = df.drop(columns=[c for c in DROP_IDENTITY if c in df.columns], errors="ignore")
    x = x.drop(columns=[c for c in ("split", "ts", "kind", "method") if c in x.columns], errors="ignore")
    x = x.select_dtypes(include=[np.number, "bool"]).replace([np.inf, -np.inf], np.nan).fillna(0)
    if feature_cols is None: feature_cols = sorted(x.columns)
    for c in feature_cols:
        if c not in x: x[c] = 0
    return x[feature_cols], feature_cols


def threshold_for_recall(y: np.ndarray, p: np.ndarray, target_recall: float = .95) -> float:
    if len(np.unique(y)) < 2: return .5
    precision, recall, thresholds = precision_recall_curve(y, p)
    candidates = [(precision[i], float(t)) for i, t in enumerate(thresholds) if recall[i] >= target_recall]
    return max(candidates)[1] if candidates else .5


def metrics(y: np.ndarray, p: np.ndarray, threshold: float) -> dict:
    pred = (p >= threshold).astype(int)
    out = {"rows": int(len(y)), "positives": int(y.sum()), "threshold": float(threshold),
           "precision": float(precision_score(y, pred, zero_division=0)), "recall": float(recall_score(y, pred, zero_division=0)),
           "f1": float(f1_score(y, pred, zero_division=0)), "confusion_matrix": confusion_matrix(y, pred, labels=[0, 1]).tolist()}
    if len(np.unique(y)) > 1:
        out["roc_auc"] = float(roc_auc_score(y, p)); out["pr_auc"] = float(average_precision_score(y, p))
    return out


def fit_one(name: str, df: pd.DataFrame, out: Path, seed: int) -> dict:
    if df.empty: return {"name": name, "status": "empty"}
    if "split" not in df or "label_binary" not in df: return {"name": name, "status": "missing_split_or_label"}
    train = df[df.split == "train"].copy(); val = df[df.split == "validation"].copy(); test = df[df.split == "test"].copy(); challenge = df[df.split == "challenge"].copy()
    if train.empty or len(train.label_binary.unique()) < 2: return {"name": name, "status": "insufficient_train"}
    x_train, cols = numeric_matrix(train); y_train = train.label_binary.astype(int).to_numpy()
    model = LGBMClassifier(n_estimators=350, learning_rate=.04, num_leaves=31, subsample=.85, colsample_bytree=.85,
                           reg_lambda=1.0, class_weight="balanced", random_state=seed, n_jobs=-1, verbosity=-1)
    model.fit(x_train, y_train)
    calibrator = None; threshold = .5; val_metrics = {}
    if not val.empty and len(val.label_binary.unique()) > 1:
        x_val, _ = numeric_matrix(val, cols); y_val = val.label_binary.astype(int).to_numpy(); raw = model.predict_proba(x_val)[:, 1]
        calibrator = IsotonicRegression(out_of_bounds="clip"); calibrator.fit(raw, y_val); p_val = calibrator.predict(raw)
        threshold = threshold_for_recall(y_val, p_val, .95); val_metrics = metrics(y_val, p_val, threshold)
    def score(part: pd.DataFrame) -> dict:
        if part.empty: return {"rows": 0}
        x, _ = numeric_matrix(part, cols); raw = model.predict_proba(x)[:, 1]; p = calibrator.predict(raw) if calibrator is not None else raw
        return metrics(part.label_binary.astype(int).to_numpy(), p, threshold)
    importance = sorted([{"feature": c, "gain": float(v)} for c, v in zip(cols, model.booster_.feature_importance(importance_type="gain"))], key=lambda x: x["gain"], reverse=True)
    joblib.dump({"model": model, "calibrator": calibrator, "threshold": threshold, "features": cols, "name": name}, out / f"{name}.joblib")
    (out / f"{name}_feature_importance.json").write_text(json.dumps(importance[:100], indent=2))
    shap_summary = []
    try:
        import shap
        sample = train.sample(min(1000, len(train)), random_state=seed); sx, _ = numeric_matrix(sample, cols)
        values = shap.TreeExplainer(model).shap_values(sx); values = values[-1] if isinstance(values, list) else values
        mean_abs = np.abs(np.asarray(values)).mean(axis=0)
        shap_summary = sorted([{"feature": c, "mean_abs_shap": float(v)} for c, v in zip(cols, mean_abs)], key=lambda x: x["mean_abs_shap"], reverse=True)[:100]
        (out / f"{name}_shap.json").write_text(json.dumps(shap_summary, indent=2))
    except Exception as exc: (out / f"{name}_shap_error.txt").write_text(str(exc))
    return {"name": name, "status": "ok", "features": len(cols), "train": {"rows": len(train), "positives": int(train.label_binary.sum())},
            "validation": val_metrics, "test": score(test), "challenge": score(challenge), "threshold": threshold,
            "top_features": importance[:20], "top_shap": shap_summary[:20]}


def build_frames(root: Path) -> dict[str, pd.DataFrame]:
    session = load_parquets(root, "session_features.parquet"); splits = split_map(root)
    if session.empty: return {"B1-content": pd.DataFrame(), "B2-session": pd.DataFrame(), "B3-opaque": pd.DataFrame()}
    session = session.merge(splits, on="campaign_id", how="left"); session["split"] = session["split"].fillna("challenge")
    tx = load_parquets(root, "transaction_features.parquet")
    if not tx.empty:
        numeric = [c for c in tx.select_dtypes(include=[np.number, "bool"]).columns if c != "ts"]
        agg = tx.groupby("campaign_id")[numeric].agg(["mean", "std", "min", "max"]); agg.columns = ["tx_" + "_".join(c).strip("_") for c in agg.columns.to_flat_index()]
        agg = agg.reset_index().fillna(0); b2 = session.merge(agg, on="campaign_id", how="left").fillna(0)
        b1 = tx.merge(session[["campaign_id", "label_binary", "split"]].drop_duplicates("campaign_id"), on="campaign_id", how="inner")
    else: b2 = session.copy(); b1 = pd.DataFrame()
    allowed = ("campaign_id", "label_binary", "split", "packet_", "wire_duration", "interarrival_", "up_", "down_", "tcp_", "udp_", "syn_", "rst_", "suricata_", "zeek_", "tls_", "dns_", "quic_", "websocket_", "flow_", "app_proto_", "service_", "sni_", "host_", "ja4", "http_status_")
    b3_cols = [c for c in session.columns if c.startswith(allowed)]
    for required in ("campaign_id", "label_binary", "split"):
        if required not in b3_cols: b3_cols.append(required)
    return {"B1-content": b1, "B2-session": b2, "B3-opaque": session[b3_cols].copy()}


def main():
    ap = argparse.ArgumentParser(); ap.add_argument("--dataset-root", required=True); ap.add_argument("--out", required=True); ap.add_argument("--seed", type=int, default=23)
    args = ap.parse_args(); root = Path(args.dataset_root); out = Path(args.out); out.mkdir(parents=True, exist_ok=True)
    reports = {name: fit_one(name, frame, out, args.seed) for name, frame in build_frames(root).items()}
    ok = [r for r in reports.values() if r.get("status") == "ok"]
    report = {"models": reports, "successful_models": len(ok), "intended_serving": {"B1-content": "TLS-inspected/plain HTTP transactions", "B2-session": "campaign/session correlation", "B3-opaque": "TLS/flow/parser metadata without decrypted payload"}}
    (out / "baseline_report.json").write_text(json.dumps(report, indent=2))
    if len(ok) < 2: raise SystemExit("fewer than two baseline experts could be trained")
    print(json.dumps({"successful_models": len(ok), "out": str(out)}))


if __name__ == "__main__": main()
