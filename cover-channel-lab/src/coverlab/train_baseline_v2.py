from __future__ import annotations

"""Model-pipeline correctness overlay.

Removes laboratory/rule leakage, preserves telemetry missingness, feeds
field-level content into B1, gives B2 order-sensitive temporal features, and
separates probability calibration from threshold selection.
"""

import hashlib
import json
import math
from collections import Counter
from pathlib import Path

import joblib
import numpy as np
import pandas as pd

from . import train_baseline as _base

FORBIDDEN_MODEL_FEATURES = {
    "expected_events",
    "seed",
    "plaintext_sha256",
    "generator_version",
    "generator_commit",
    "configuration_id",
    "mixed_capture_index",
    "logical_capture_minutes",
    # Signature/rule output is intentionally excluded from the ML-only experts.
    # A rule+ML hybrid can be evaluated separately without contaminating the
    # baseline claim.
    "suricata_alerts",
}


def numeric_matrix(df: pd.DataFrame, feature_cols: list[str] | None = None):
    drop = set(_base.DROP_IDENTITY) | FORBIDDEN_MODEL_FEATURES
    x = df.drop(columns=[c for c in drop if c in df.columns], errors="ignore")
    x = x.drop(columns=[c for c in ("split", "ts", "kind", "method") if c in x.columns], errors="ignore")
    raw = x.select_dtypes(include=[np.number, "bool"]).replace([np.inf, -np.inf], np.nan).copy()

    if feature_cols is None:
        base_cols = sorted(raw.columns)
        for c in base_cols:
            raw[f"{c}__missing"] = raw[c].isna().astype("int8")
        raw = raw.fillna(0)
        feature_cols = sorted(raw.columns)
    else:
        requested_base = sorted({c[:-9] for c in feature_cols if c.endswith("__missing")})
        for c in requested_base:
            raw[f"{c}__missing"] = raw[c].isna().astype("int8") if c in raw else 1
        raw = raw.fillna(0)
        for c in feature_cols:
            if c not in raw:
                raw[c] = 0

    forbidden_leak = sorted(set(feature_cols) & FORBIDDEN_MODEL_FEATURES)
    if forbidden_leak:
        raise RuntimeError(f"forbidden laboratory/rule features reached model matrix: {forbidden_leak}")
    return raw[feature_cols], feature_cols


def _entropy(values) -> float:
    vals = [str(v) for v in values if pd.notna(v)]
    if not vals:
        return 0.0
    counts = Counter(vals)
    n = len(vals)
    return float(-sum((c / n) * math.log2(c / n) for c in counts.values()))


def _lag_corr(values: np.ndarray, lag: int) -> float:
    values = np.asarray(values, dtype=float)
    if len(values) <= lag or np.nanstd(values) == 0:
        return 0.0
    a, b = values[:-lag], values[lag:]
    mask = np.isfinite(a) & np.isfinite(b)
    if mask.sum() < 3 or np.std(a[mask]) == 0 or np.std(b[mask]) == 0:
        return 0.0
    return float(np.corrcoef(a[mask], b[mask])[0, 1])


def _temporal_features(group: pd.DataFrame) -> pd.Series:
    g = group.sort_values("ts") if "ts" in group else group.copy()
    ts = pd.to_numeric(g.get("ts", pd.Series(dtype=float)), errors="coerce").dropna().to_numpy(dtype=float)
    inter = np.diff(ts) if len(ts) > 1 else np.array([], dtype=float)
    req = pd.to_numeric(g.get("request_body_length", 0), errors="coerce").fillna(0).to_numpy(dtype=float)
    resp = pd.to_numeric(g.get("response_body_length", 0), errors="coerce").fillna(0).to_numpy(dtype=float)
    sizes = req + resp
    methods = g.get("method", pd.Series([""] * len(g))).astype(str).tolist()
    kinds = g.get("kind", pd.Series([""] * len(g))).astype(str).tolist()
    status = g.get("response_status", pd.Series([0] * len(g))).astype(str).tolist()

    def change_rate(vals: list[str]) -> float:
        if len(vals) < 2:
            return 0.0
        return sum(a != b for a, b in zip(vals, vals[1:])) / (len(vals) - 1)

    median_inter = float(np.median(inter)) if len(inter) else 0.0
    p95_inter = float(np.quantile(inter, 0.95)) if len(inter) else 0.0
    burst_fraction = float(np.mean(inter <= median_inter * 0.5)) if len(inter) and median_inter > 0 else 0.0
    silence_fraction = float(np.mean(inter >= median_inter * 2.0)) if len(inter) and median_inter > 0 else 0.0
    duration = float(ts[-1] - ts[0]) if len(ts) > 1 else 0.0

    return pd.Series(
        {
            "seq_tx_count": int(len(g)),
            "seq_duration_s": duration,
            "seq_inter_mean": float(inter.mean()) if len(inter) else 0.0,
            "seq_inter_std": float(inter.std()) if len(inter) else 0.0,
            "seq_inter_cv": float(inter.std() / inter.mean()) if len(inter) > 1 and inter.mean() > 0 else 0.0,
            "seq_inter_p95": p95_inter,
            "seq_burst_fraction": burst_fraction,
            "seq_silence_fraction": silence_fraction,
            "seq_method_entropy": _entropy(methods),
            "seq_kind_entropy": _entropy(kinds),
            "seq_status_entropy": _entropy(status),
            "seq_method_change_rate": change_rate(methods),
            "seq_kind_change_rate": change_rate(kinds),
            "seq_status_change_rate": change_rate(status),
            "seq_size_lag1_corr": _lag_corr(sizes, 1),
            "seq_size_lag2_corr": _lag_corr(sizes, 2),
            "seq_inter_lag1_corr": _lag_corr(inter, 1),
            "seq_inter_lag2_corr": _lag_corr(inter, 2),
        }
    )


def _field_aggregate(root: Path) -> pd.DataFrame:
    fields = _base.load_parquets(root, "field_features.parquet")
    if fields.empty:
        return pd.DataFrame()
    f = fields.copy()
    name = f.get("field_name", pd.Series([""] * len(f))).fillna("").astype(str).str.lower()
    role = f.get("field_role", pd.Series([""] * len(f))).fillna("").astype(str).str.lower()
    f["field_is_authorization"] = name.eq("authorization").astype(int)
    f["field_is_cookie"] = name.eq("cookie").astype(int)
    f["field_is_etag"] = name.isin(["etag", "if-none-match"]).astype(int)
    f["field_is_range"] = name.eq("range").astype(int)
    f["field_is_referer"] = name.eq("referer").astype(int)
    f["field_is_custom_header"] = (role.eq("request_header") & name.str.startswith("x-")).astype(int)
    f["field_is_body"] = role.eq("request_body").astype(int)
    numeric = [
        c for c in (
            "raw_length", "byte_length", "entropy", "printable_ratio", "unique_char_ratio",
            "digit_ratio", "alpha_ratio", "hex_ratio", "b64_ratio", "b64url_ratio",
            "delimiter_ratio", "uuid_like", "jwt_like", "etag_like", "encoded_token_like",
            "field_is_authorization", "field_is_cookie", "field_is_etag", "field_is_range",
            "field_is_referer", "field_is_custom_header", "field_is_body",
        ) if c in f.columns
    ]
    keys = ["campaign_id"] + (["ts"] if "ts" in f.columns else [])
    agg = f.groupby(keys)[numeric].agg(["mean", "max", "sum"])
    agg.columns = ["field_" + "_".join(map(str, col)).strip("_") for col in agg.columns.to_flat_index()]
    return agg.reset_index()


def _series_or_default(df: pd.DataFrame, column: str, default: str | int | float) -> pd.Series:
    if column in df:
        return df[column]
    return pd.Series([default] * len(df), index=df.index)


def _availability_flags(session: pd.DataFrame) -> pd.DataFrame:
    s = session.copy()
    s["availability_encrypted"] = _series_or_default(s, "visibility_mode", "").astype(str).str.contains("opaque|encrypted", case=False, regex=True).astype(int)
    s["availability_inspection_bypassed"] = _series_or_default(s, "inspection_policy", "").astype(str).eq("bypass").astype(int)
    s["availability_sni_hidden"] = (~_series_or_default(s, "sni_visibility", "clear").astype(str).str.lower().isin(["clear", "visible"])).astype(int)
    suri = pd.to_numeric(_series_or_default(s, "suricata_events", 0), errors="coerce").fillna(0)
    zeek = pd.to_numeric(_series_or_default(s, "zeek_events", 0), errors="coerce").fillna(0)
    s["availability_parser_any"] = ((suri + zeek) > 0).astype(int)
    return s


def build_frames(root: Path):
    session = _base.load_parquets(root, "session_features.parquet")
    splits = _base.split_map(root)
    if session.empty:
        return {"B1-content": pd.DataFrame(), "B2-session": pd.DataFrame(), "B3-opaque": pd.DataFrame()}
    session = session.merge(splits, on="campaign_id", how="left")
    session["split"] = session["split"].fillna("challenge")
    session = _availability_flags(session)

    tx = _base.load_parquets(root, "transaction_features.parquet")
    fields = _field_aggregate(root)
    if not tx.empty:
        tx_enriched = tx.copy()
        if not fields.empty:
            join_keys = ["campaign_id"] + (["ts"] if "ts" in tx.columns and "ts" in fields.columns else [])
            tx_enriched = tx_enriched.merge(fields, on=join_keys, how="left")

        numeric = [c for c in tx.select_dtypes(include=[np.number, "bool"]).columns if c != "ts"]
        agg = tx.groupby("campaign_id")[numeric].agg(["mean", "std", "min", "max"])
        agg.columns = ["tx_" + "_".join(map(str, c)).strip("_") for c in agg.columns.to_flat_index()]
        agg = agg.reset_index()
        temporal = tx.groupby("campaign_id", group_keys=False).apply(_temporal_features, include_groups=False).reset_index()
        b2 = session.merge(agg, on="campaign_id", how="left").merge(temporal, on="campaign_id", how="left")
        b1 = tx_enriched.merge(
            session[["campaign_id", "label_binary", "split"]].drop_duplicates("campaign_id"),
            on="campaign_id", how="inner",
        )
    else:
        b2 = session.copy()
        b1 = pd.DataFrame()

    allowed = (
        "campaign_id", "label_binary", "split", "packet_", "wire_duration", "interarrival_",
        "up_", "down_", "tcp_", "udp_", "syn_", "rst_", "suricata_", "zeek_", "tls_",
        "dns_", "quic_", "websocket_", "flow_", "app_proto_", "service_", "sni_", "host_",
        "ja4", "http_status_", "availability_",
    )
    b3_cols = [c for c in session.columns if c.startswith(allowed)]
    for required in ("campaign_id", "label_binary", "split"):
        if required not in b3_cols:
            b3_cols.append(required)
    return {"B1-content": b1, "B2-session": b2, "B3-opaque": session[b3_cols].copy()}


def _validation_parts(val: pd.DataFrame) -> tuple[pd.DataFrame, pd.DataFrame]:
    """Split validation by campaign, stratified by label, into calibration/tuning."""
    if val.empty:
        return val.copy(), val.copy()
    camp = val[["campaign_id", "label_binary"]].drop_duplicates("campaign_id").copy()
    cal_ids: set[str] = set()
    tune_ids: set[str] = set()
    for _label, group in camp.groupby("label_binary"):
        ids = sorted(
            group.campaign_id.astype(str).tolist(),
            key=lambda cid: hashlib.sha256(("calibration-v1:" + cid).encode()).hexdigest(),
        )
        for idx, cid in enumerate(ids):
            (cal_ids if idx % 2 == 0 else tune_ids).add(cid)
    cal = val[val.campaign_id.astype(str).isin(cal_ids)].copy()
    tune = val[val.campaign_id.astype(str).isin(tune_ids)].copy()
    return cal, tune


def fit_one(name: str, df: pd.DataFrame, out: Path, seed: int) -> dict:
    if df.empty:
        return {"name": name, "status": "empty"}
    if "split" not in df or "label_binary" not in df:
        return {"name": name, "status": "missing_split_or_label"}
    train = df[df.split == "train"].copy()
    val = df[df.split == "validation"].copy()
    test = df[df.split == "test"].copy()
    challenge = df[df.split == "challenge"].copy()
    if train.empty or len(train.label_binary.unique()) < 2:
        return {"name": name, "status": "insufficient_train"}

    x_train, cols = numeric_matrix(train)
    y_train = train.label_binary.astype(int).to_numpy()
    model = _base.LGBMClassifier(
        n_estimators=350, learning_rate=.04, num_leaves=31, subsample=.85,
        colsample_bytree=.85, reg_lambda=1.0, class_weight="balanced",
        random_state=seed, n_jobs=-1, verbosity=-1,
    )
    model.fit(x_train, y_train)

    calibrator = None
    threshold = .5
    calibration_metrics: dict = {"rows": 0}
    threshold_metrics: dict = {"rows": 0}
    cal, tune = _validation_parts(val)

    if not cal.empty and len(cal.label_binary.unique()) > 1:
        x_cal, _ = numeric_matrix(cal, cols)
        y_cal = cal.label_binary.astype(int).to_numpy()
        raw_cal = model.predict_proba(x_cal)[:, 1]
        calibrator = _base.IsotonicRegression(out_of_bounds="clip")
        calibrator.fit(raw_cal, y_cal)
        p_cal = calibrator.predict(raw_cal)
        calibration_metrics = _base.metrics(y_cal, p_cal, .5)

    if not tune.empty and len(tune.label_binary.unique()) > 1:
        x_tune, _ = numeric_matrix(tune, cols)
        y_tune = tune.label_binary.astype(int).to_numpy()
        raw_tune = model.predict_proba(x_tune)[:, 1]
        p_tune = calibrator.predict(raw_tune) if calibrator is not None else raw_tune
        threshold = _base.threshold_for_recall(y_tune, p_tune, .95)
        threshold_metrics = _base.metrics(y_tune, p_tune, threshold)

    def score(part: pd.DataFrame) -> dict:
        if part.empty:
            return {"rows": 0}
        x, _ = numeric_matrix(part, cols)
        raw = model.predict_proba(x)[:, 1]
        p = calibrator.predict(raw) if calibrator is not None else raw
        return _base.metrics(part.label_binary.astype(int).to_numpy(), p, threshold)

    importance = sorted(
        [{"feature": c, "gain": float(v)} for c, v in zip(cols, model.booster_.feature_importance(importance_type="gain"))],
        key=lambda x: x["gain"], reverse=True,
    )
    bundle = {
        "model": model, "calibrator": calibrator, "threshold": threshold,
        "features": cols, "name": name,
        "calibration_policy": "validation_campaign_stratified_half",
        "threshold_policy": "disjoint_validation_campaign_half_target_recall_0.95",
        "ml_only": True,
        "forbidden_features": sorted(FORBIDDEN_MODEL_FEATURES),
    }
    joblib.dump(bundle, out / f"{name}.joblib")
    (out / f"{name}_feature_importance.json").write_text(json.dumps(importance[:100], indent=2))

    shap_summary = []
    try:
        import shap
        sample = train.sample(min(1000, len(train)), random_state=seed)
        sx, _ = numeric_matrix(sample, cols)
        values = shap.TreeExplainer(model).shap_values(sx)
        values = values[-1] if isinstance(values, list) else values
        mean_abs = np.abs(np.asarray(values)).mean(axis=0)
        shap_summary = sorted(
            [{"feature": c, "mean_abs_shap": float(v)} for c, v in zip(cols, mean_abs)],
            key=lambda x: x["mean_abs_shap"], reverse=True,
        )[:100]
        (out / f"{name}_shap.json").write_text(json.dumps(shap_summary, indent=2))
    except Exception as exc:
        (out / f"{name}_shap_error.txt").write_text(str(exc))

    return {
        "name": name,
        "status": "ok",
        "features": len(cols),
        "train": {"rows": len(train), "positives": int(train.label_binary.sum())},
        "calibration": calibration_metrics,
        "threshold_selection": threshold_metrics,
        # Keep a compact compatibility summary while making it explicit that
        # validation is not final evidence.
        "validation": {"rows": int(len(val)), "role": "calibration_and_threshold_selection_disjoint_by_campaign"},
        "test": score(test),
        "challenge": score(challenge),
        "threshold": threshold,
        "top_features": importance[:20],
        "top_shap": shap_summary[:20],
        "ml_only": True,
    }


_base.numeric_matrix = numeric_matrix
_base.build_frames = build_frames
_base.fit_one = fit_one


if __name__ == "__main__":
    _base.main()
