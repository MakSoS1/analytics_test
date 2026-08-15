from __future__ import annotations

from copy import deepcopy
from datetime import datetime, timezone
from typing import Any

import pandas as pd

from .online_features import EveFeatureState
from .wire_paths import expected_wire_tuples


def _is_missing(value: Any) -> bool:
    if value is None:
        return True
    try:
        missing = pd.isna(value)
    except (TypeError, ValueError):
        return False
    return bool(missing) if isinstance(missing, bool) else False


def _epoch(value: Any) -> float:
    if _is_missing(value):
        return 0.0
    if isinstance(value, (int, float)):
        return float(value)
    text = str(value).replace("Z", "+00:00")
    return datetime.fromisoformat(text).astimezone(timezone.utc).timestamp()


def _text(value: Any) -> str:
    return "" if _is_missing(value) else str(value)


def _integer(value: Any) -> int:
    if _is_missing(value):
        return 0
    try:
        return int(value)
    except (TypeError, ValueError, OverflowError):
        numeric = pd.to_numeric(pd.Series([value]), errors="coerce").iloc[0]
        return 0 if _is_missing(numeric) else int(numeric)


def normalize_suricata_flow_events(eve: pd.DataFrame) -> pd.DataFrame:
    if eve.empty:
        return pd.DataFrame()
    if "event_type" not in eve.columns:
        raise ValueError("EVE data missing event_type")
    flows = eve[eve["event_type"].astype(str) == "flow"].copy().reset_index(drop=True)
    rows: list[dict[str, Any]] = []
    for index, event in enumerate(flows.to_dict("records")):
        flow_id = event.get("flow_id")
        uid = f"suri:{_text(flow_id)}" if not _is_missing(flow_id) and _text(flow_id) else f"suri-row:{index:012d}"
        flow = event.get("flow") if isinstance(event.get("flow"), dict) else {}
        flow_start = flow.get("start")
        use_flow_start = not _is_missing(flow_start) and bool(_text(flow_start))
        mapping_ts = flow_start if use_flow_start else event.get("timestamp")
        rows.append({
            "uid": uid,
            "ts": _epoch(mapping_ts),
            "mapping_timestamp_source": "flow.start" if use_flow_start else "event.timestamp",
            "id.orig_h": _text(event.get("src_ip")),
            "id.resp_h": _text(event.get("dest_ip")),
            "id.orig_p": _integer(event.get("src_port")),
            "id.resp_p": _integer(event.get("dest_port")),
            "event": event,
        })
    return pd.DataFrame(rows)


def map_suricata_flows_to_sessions(
    sessions: pd.DataFrame,
    normalized_flows: pd.DataFrame,
    *,
    tolerance_seconds: float = 2.0,
) -> tuple[pd.DataFrame, dict[str, Any]]:
    """Map expected remote-admin wire hops and retain background accounting.

    Offline captures legitimately contain NetBIOS helper traffic, IPv6/router
    chatter and other lab background.  Bounded approved SSH forwarding is not
    background: both client->jump and jump->target are explicit expected wire
    hops for the same orchestrated session and are eligible for correspondence.
    """
    from .features import map_zeek_flows_to_sessions

    required_sessions = {"src_ip", "dst_ip", "dst_port", "session_id"}
    missing = required_sessions - set(sessions.columns)
    if missing:
        raise ValueError(f"sessions missing Suricata mapping columns: {sorted(missing)}")
    required_flows = {"id.orig_h", "id.resp_h", "id.resp_p", "ts"}
    missing_flows = required_flows - set(normalized_flows.columns)
    if missing_flows:
        raise ValueError(f"normalized Suricata flows missing columns: {sorted(missing_flows)}")

    expected_tuples = {
        hop
        for row in sessions.to_dict("records")
        for hop in expected_wire_tuples(row)
    }
    if normalized_flows.empty:
        eligible = normalized_flows.copy()
    else:
        mask = normalized_flows.apply(
            lambda row: (str(row["id.orig_h"]), str(row["id.resp_h"]), int(row["id.resp_p"])) in expected_tuples,
            axis=1,
        )
        eligible = normalized_flows[mask].copy().reset_index(drop=True)

    mapped, report = map_zeek_flows_to_sessions(
        sessions,
        eligible,
        tolerance_seconds=tolerance_seconds,
    )
    raw_count = int(len(normalized_flows))
    eligible_count = int(len(eligible))
    mapped_count = int(len(mapped))
    report.update({
        "raw_conn_count": raw_count,
        "eligible_conn_count": eligible_count,
        "background_conn_count": raw_count - eligible_count,
        "mapped_conn_count": mapped_count,
        "unmapped_eligible_conn_count": eligible_count - mapped_count,
        "conn_count": eligible_count,
        "conn_mapping_coverage": float(mapped_count / eligible_count) if eligible_count else 0.0,
        "mapping_scope": "expected_manifest_wire_hops_only",
    })

    session_count_by_protocol: dict[str, int] = {}
    mapped_session_count_by_protocol: dict[str, int] = {}
    coverage_by_protocol: dict[str, float] = {}
    if "protocol" in sessions.columns:
        mapped_ids = set(mapped["session_id"].astype(str)) if not mapped.empty else set()
        for protocol, part in sessions.groupby("protocol", sort=True):
            ids = set(part["session_id"].astype(str))
            mapped_ids_for_protocol = ids & mapped_ids
            key = str(protocol)
            session_count_by_protocol[key] = len(ids)
            mapped_session_count_by_protocol[key] = len(mapped_ids_for_protocol)
            coverage_by_protocol[key] = float(len(mapped_ids_for_protocol) / len(ids)) if ids else 0.0
    report["session_count_by_protocol"] = session_count_by_protocol
    report["mapped_session_count_by_protocol"] = mapped_session_count_by_protocol
    report["session_mapping_coverage_by_protocol"] = coverage_by_protocol
    return mapped, report


def attach_behavior_time(mapped: pd.DataFrame, sessions: pd.DataFrame) -> pd.DataFrame:
    required = {"session_id", "start_ts", "execution_start_ts"}
    missing = required - set(sessions.columns)
    if missing:
        raise ValueError(f"dual-time manifest missing: {sorted(missing)}")
    times = sessions[["session_id", "start_ts", "execution_start_ts"]].copy()
    times["_sim_start"] = pd.to_datetime(times["start_ts"], utc=True).astype("int64") / 1_000_000_000.0
    times["_exec_start"] = pd.to_datetime(times["execution_start_ts"], utc=True).astype("int64") / 1_000_000_000.0
    out = mapped.merge(times[["session_id", "_sim_start", "_exec_start"]], on="session_id", how="left", validate="many_to_one")
    if out[["_sim_start", "_exec_start"]].isna().any().any():
        raise ValueError("cannot project parser flow onto simulated behavior clock")
    out["execution_ts"] = pd.to_numeric(out["ts"], errors="coerce")
    out["behavior_ts"] = out["_sim_start"] + (out["execution_ts"] - out["_exec_start"]).clip(lower=0.0)
    return out.drop(columns=["_sim_start", "_exec_start"])


def _iso_from_epoch(value: float) -> str:
    return datetime.fromtimestamp(float(value), tz=timezone.utc).isoformat()


def _feature_row(state: EveFeatureState, row: dict[str, Any]) -> dict[str, Any]:
    event = deepcopy(row["event"])
    event["timestamp"] = _iso_from_epoch(float(row["behavior_ts"]))
    result = state.consume_flow(event)
    features = dict(result["features"])
    features["flow_uid"] = str(row["uid"])
    features["session_id"] = str(row["session_id"])
    return features


def _validated_feature_frame(mapped_events: pd.DataFrame) -> tuple[pd.DataFrame, dict[str, int]]:
    frame = mapped_events.copy()
    if "uid" not in frame.columns and "flow_uid" in frame.columns:
        frame["uid"] = frame["flow_uid"].astype(str)
    required = {"uid", "session_id", "split", "behavior_ts", "event"}
    missing = required - set(frame.columns)
    if missing:
        raise ValueError(f"mapped Suricata events missing: {sorted(missing)}")
    order = {str(uid): index for index, uid in enumerate(frame["uid"].astype(str).tolist())}
    return frame, order


def _restore_original_order(chunks: list[pd.DataFrame], order: dict[str, int]) -> pd.DataFrame:
    if not chunks:
        return pd.DataFrame()
    result = pd.concat(chunks, ignore_index=True)
    result["_order"] = result["flow_uid"].map(order).fillna(len(order))
    return result.sort_values("_order").drop(columns=["_order"]).reset_index(drop=True)


def build_split_isolated_suricata_features(mapped_events: pd.DataFrame) -> pd.DataFrame:
    """Replay each split from an empty EveFeatureState.

    Retained for explicit experiments and backwards-comparison only. Production
    research Gold uses :func:`build_reference_context_suricata_features` so a
    held-out split is not evaluated with an artificial zero-history baseline.
    """
    frame, order = _validated_feature_frame(mapped_events)
    chunks: list[pd.DataFrame] = []
    preferred = ["train", "validation", "test", "challenge"]
    split_names = preferred + sorted(set(frame["split"].astype(str)) - set(preferred))
    for split in split_names:
        part = frame[frame["split"].astype(str) == split].copy()
        if part.empty:
            continue
        part = part.sort_values(["behavior_ts", "session_id", "uid"])
        state = EveFeatureState()
        rows = [_feature_row(state, row) for row in part.to_dict("records")]
        chunks.append(pd.DataFrame(rows))
    return _restore_original_order(chunks, order)


def build_reference_context_suricata_features(mapped_events: pd.DataFrame) -> pd.DataFrame:
    """Replay held-out splits with causal prior-train network context.

    A deployed EveFeatureState does not reset merely because an evaluator later
    calls a row ``validation`` or ``test``. At the same time, generic evaluation
    must not let validation/test/challenge covariates contaminate one another.

    For each target split we therefore replay the complete chronology but consume
    only prior ``train`` rows plus prior rows from that target split. Features are
    emitted only for the target split. This is causal (no future events), uses no
    labels, preserves the exact online state machine, and gives validation/test/
    challenge a common reference history instead of an artificial empty state.
    """
    frame, order = _validated_feature_frame(mapped_events)
    ordered = frame.sort_values(["behavior_ts", "session_id", "uid"])
    observed_splits = set(ordered["split"].astype(str))
    preferred = ["train", "validation", "test", "challenge"]
    split_names = [split for split in preferred if split in observed_splits]
    split_names.extend(sorted(observed_splits - set(split_names)))

    chunks: list[pd.DataFrame] = []
    rows_as_dicts = ordered.to_dict("records")
    for target_split in split_names:
        state = EveFeatureState()
        emitted: list[dict[str, Any]] = []
        for row in rows_as_dicts:
            row_split = str(row["split"])
            if row_split != "train" and row_split != target_split:
                continue
            features = _feature_row(state, row)
            if row_split == target_split:
                emitted.append(features)
        if emitted:
            chunks.append(pd.DataFrame(emitted))

    result = _restore_original_order(chunks, order)
    if len(result) != len(frame):
        raise ValueError(f"reference-context replay incomplete: {len(result)} != {len(frame)}")
    if result["flow_uid"].astype(str).duplicated().any():
        raise ValueError("reference-context replay emitted duplicate flow_uid")
    return result
