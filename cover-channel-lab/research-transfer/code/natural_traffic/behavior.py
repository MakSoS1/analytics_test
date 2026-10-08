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
            "session_duration_seconds": _quantile_map(
                _finite_series(office_train, "flow_duration").clip(lower=0.2, upper=60.0)
            ),
            "close_cleanly_probability": round(close_probability, 12),
            "prefer_h2_probability": round(h2_probability, 12),
        },
    }
    encoded = json.dumps(
        body, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode("utf-8")
    body["sha256"] = hashlib.sha256(encoded).hexdigest()
    return body

def freeze_transport_duration_from_day(
    envelope: dict[str, object],
    transport_train: pd.DataFrame,
    *,
    source_id: str,
) -> dict[str, object]:
    """Copy only the observed train-day session duration distribution.

    Never pool TLS or identities across releases, never read holdout,
    and never persist individual training observations.
    """
    if envelope.get("source_policy") != "office_train_only":
        raise ValueError("requires train-only office envelope")
    if not source_id or source_id.strip() != source_id:
        raise ValueError("invalid transport source ID")
    duration = _finite_series(transport_train, "flow_duration")
    duration = duration[duration > 0]
    if len(duration) < 100:
        raise ValueError("insufficient measured transport session duration")
    frozen = json.loads(json.dumps(envelope))
    frozen["generation_targets"]["session_duration_seconds"] = _quantile_map(
        duration.clip(lower=0.2, upper=60.0)
    )
    frozen["transport_duration_provenance"] = {
        "source_id": source_id,
        "rows": int(len(duration)),
        "policy": "numeric_quantiles_train_only",
    }
    frozen.pop("sha256", None)
    encoded = json.dumps(
        frozen, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode("utf-8")
    frozen["sha256"] = hashlib.sha256(encoded).hexdigest()
    return frozen


def _choose_quantile(
    values: dict[str, float],
    identity: str,
    *,
    seed: int,
    field: str,
) -> float:
    if not values:
        raise ValueError(f"behavior envelope has no values for {field}")
    keys = sorted(values)
    digest = hashlib.sha256(
        f"{int(seed)}:{identity}:{field}".encode("utf-8")
    ).digest()
    key = keys[int.from_bytes(digest[:8], "big") % len(keys)]
    return float(values[key])


def _probability_choice(
    probability: float,
    identity: str,
    *,
    seed: int,
    field: str,
) -> bool:
    probability = max(0.0, min(1.0, float(probability)))
    digest = hashlib.sha256(
        f"{int(seed)}:{identity}:{field}:bernoulli".encode("utf-8")
    ).digest()
    value = int.from_bytes(digest[:8], "big") / float(2**64)
    return value < probability


def assign_behavior_targets(
    envelope: dict[str, object],
    identities: Iterable[object],
    *,
    seed: int,
) -> dict[str, dict[str, object]]:
    if str(envelope.get("source_policy")) != "office_train_only":
        raise ValueError("behavior targets require office_train_only envelope")
    profile_sha = str(envelope.get("sha256", ""))
    if len(profile_sha) != 64:
        raise ValueError("behavior envelope requires frozen sha256")
    targets = dict(envelope.get("generation_targets") or {})
    numeric = dict(envelope.get("numeric") or {})
    events = dict(targets.get("events") or {})
    minimum_events = max(2, int(events.get("min", 1)))
    maximum_events = max(minimum_events, min(20, int(events.get("max", minimum_events))))
    raw_event_values = [
        value for key, value in events.items()
        if key in {"min", "p50", "max"}
    ]
    event_choices = sorted(
        set(
            max(minimum_events, min(maximum_events, int(round(float(v)))))
            for v in raw_event_values
        )
    )
    if not event_choices:
        event_choices = [minimum_events]

    sni_quantiles = dict(numeric.get("tls_sni_len") or {})
    result: dict[str, dict[str, object]] = {}
    for identity in sorted({str(x) for x in identities}):
        event_digest = hashlib.sha256(
            f"{int(seed)}:{identity}:runtime_events".encode("utf-8")
        ).digest()
        runtime_events = event_choices[
            int.from_bytes(event_digest[:8], "big") % len(event_choices)
        ]
        sni_len = (
            int(round(_choose_quantile(
                sni_quantiles, identity, seed=seed, field="tls_sni_len"
            )))
            if sni_quantiles
            else 16
        )
        duration_values = dict(targets.get("session_duration_seconds") or {})
        if duration_values:
            requested_duration = _choose_quantile(
                duration_values, identity, seed=seed,
                field="session_duration_seconds",
            )
            # Packet IAT represents within-burst spacing, not app session dwell.
            native_interval = max(
                0.05, min(20.0, requested_duration / max(1, runtime_events - 1))
            )
        else:
            requested_duration = None
            native_interval = _choose_quantile(
                dict(targets.get("iat_seconds") or {}),
                identity, seed=seed, field="iat_seconds",
            )
        result[identity] = {
            "runtime_events": max(2, min(20, int(runtime_events))),
            "native_interval": round(float(native_interval), 6),
            "target_session_duration_seconds": (
                round(float(requested_duration), 6)
                if requested_duration is not None else None
            ),
            "benign_request_bytes": int(round(_choose_quantile(
                dict(targets.get("request_bytes") or {}),
                identity,
                seed=seed,
                field="request_bytes",
            ))),
            "benign_response_bytes": int(round(_choose_quantile(
                dict(targets.get("response_bytes") or {}),
                identity,
                seed=seed,
                field="response_bytes",
            ))),
            "benign_sni_len": max(5, min(253, sni_len)),
            "prefer_h2": _probability_choice(
                float(targets.get("prefer_h2_probability", 0.0)),
                identity,
                seed=seed,
                field="prefer_h2",
            ),
            "target_clean_close": _probability_choice(
                float(targets.get("close_cleanly_probability", 0.0)),
                identity,
                seed=seed,
                field="target_clean_close",
            ),
            "behavior_profile_sha256": profile_sha,
        }
    return result
