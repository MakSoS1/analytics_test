from __future__ import annotations

import hashlib
import json
from typing import Iterable

import numpy as np
import pandas as pd


_NUMERIC_FEATURES = (
    "flow_duration",
    "pkt_count",
    "up_pkt_count",
    "down_pkt_count",
    "up_bytes",
    "down_bytes",
    "data_pkt_up",
    "data_pkt_down",
    "direction_changes",
    "pkt_len_mean",
    "pkt_len_p90",
    "iat_p50",
    "iat_p90",
    "tls_ext_count",
    "tls_cipher_count",
    "tls_group_count",
    "tls_sigalg_count",
    "tls_sni_len",
)
_CATEGORICAL_FEATURES = (
    "closed_cleanly",
    "conn_state",
    "tls_version",
    "tls_alpn_h2",
    "tls_alpn_http11",
    "tls_alpn_h3",
)
_QUANTILES = (
    ("p10", 0.10),
    ("p25", 0.25),
    ("p50", 0.50),
    ("p75", 0.75),
    ("p90", 0.90),
)


def select_office_web_slice(
    frame: pd.DataFrame,
    *,
    min_host_groups: int = 60,
) -> pd.DataFrame:
    if "ip_protocol" not in frame or "host_key" not in frame:
        raise ValueError("office frame requires ip_protocol and host_key")
    proto = pd.to_numeric(frame["ip_protocol"], errors="coerce")
    tcp = frame.loc[proto.eq(6)].copy()
    if "destination_port" not in tcp:
        return tcp
    dport = pd.to_numeric(tcp["destination_port"], errors="coerce")
    web = tcp.loc[dport.isin((443, 8443, 9443))].copy()
    if int(web["host_key"].astype(str).nunique()) >= int(min_host_groups):
        return web
    return tcp


def _finite_series(frame: pd.DataFrame, column: str) -> pd.Series:
    if column not in frame:
        return pd.Series(dtype=float)
    values = pd.to_numeric(frame[column], errors="coerce").astype(float)
    return values[np.isfinite(values.to_numpy(dtype=float))]


def _quantile_map(values: pd.Series) -> dict[str, float]:
    if values.empty:
        return {}
    arr = np.sort(values.to_numpy(dtype=float))
    return {
        name: round(float(np.quantile(arr, q, method="linear")), 9)
        for name, q in _QUANTILES
    }


def _categorical_distribution(values: pd.Series) -> dict[str, float]:
    clean = values.dropna().astype(str)
    if clean.empty:
        return {}
    counts = clean.value_counts(sort=False)
    total = float(counts.sum())
    return {
        str(key): round(float(value) / total, 12)
        for key, value in sorted(counts.items(), key=lambda item: str(item[0]))
    }


def _ratio_quantiles(
    numerator: pd.Series,
    denominator: pd.Series,
    *,
    minimum: float,
    maximum: float,
) -> dict[str, float]:
    if numerator.empty or denominator.empty:
        return {}
    aligned = pd.concat(
        [numerator.rename("num"), denominator.rename("den")],
        axis=1,
        join="inner",
    ).dropna()
    aligned = aligned.loc[aligned["den"] > 0]
    if aligned.empty:
        return {}
    values = (aligned["num"] / aligned["den"]).clip(lower=minimum, upper=maximum)
    return _quantile_map(values)


def _bounded_int(value: float, minimum: int, maximum: int) -> int:
    return max(minimum, min(maximum, int(round(float(value)))))


def derive_behavior_envelope(
    office_train: pd.DataFrame,
    *,
    seed: int,
) -> dict[str, object]:
    if office_train.empty:
        raise ValueError("office_train must not be empty")
    if "host_key" not in office_train:
        raise ValueError("office_train requires host_key")

    numeric: dict[str, dict[str, float]] = {}
    for column in _NUMERIC_FEATURES:
        quantiles = _quantile_map(_finite_series(office_train, column))
        if quantiles:
            numeric[column] = quantiles

    categorical: dict[str, dict[str, float]] = {}
    for column in _CATEGORICAL_FEATURES:
        if column in office_train:
            dist = _categorical_distribution(office_train[column])
            if dist:
                categorical[column] = dist

    data_up = _finite_series(office_train, "data_pkt_up")
    data_down = _finite_series(office_train, "data_pkt_down")
    up_bytes = _finite_series(office_train, "up_bytes")
    down_bytes = _finite_series(office_train, "down_bytes")
    iat = _finite_series(office_train, "iat_p50")
    iat = iat.loc[iat > 0]

    event_q = _quantile_map(data_up.clip(lower=1, upper=20))
    event_values = [
        _bounded_int(v, 1, 20)
        for v in event_q.values()
    ] or [3]
    request_bytes = _ratio_quantiles(
        up_bytes, data_up, minimum=16.0, maximum=8192.0
    )
    response_bytes = _ratio_quantiles(
        down_bytes, data_down, minimum=32.0, maximum=65536.0
    )
    iat_q = _quantile_map(iat.clip(lower=0.001, upper=30.0))

    close_dist = categorical.get("closed_cleanly", {})
    close_probability = float(close_dist.get("1", 0.0))
    h2_dist = categorical.get("tls_alpn_h2", {})
    h2_probability = float(h2_dist.get("1", 0.0))

    body: dict[str, object] = {
        "version": "natural-office-behavior-v1",
        "source_policy": "office_train_only",
        "seed": int(seed),
        "rows": int(len(office_train)),
        "host_groups": int(office_train["host_key"].astype(str).nunique()),
        "numeric": numeric,
        "categorical": categorical,
        "generation_targets": {
            "events": {
                "min": min(event_values),
                "p50": _bounded_int(
                    event_q.get("p50", float(np.median(event_values))), 1, 20
                ),
                "max": max(event_values),
            },
            "request_bytes": request_bytes,
            "response_bytes": response_bytes,
            "iat_seconds": iat_q,
            "close_cleanly_probability": round(close_probability, 12),
            "prefer_h2_probability": round(h2_probability, 12),
        },
    }
    encoded = json.dumps(
        body, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode("utf-8")
    body["sha256"] = hashlib.sha256(encoded).hexdigest()
    return body
