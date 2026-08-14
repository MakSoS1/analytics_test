from __future__ import annotations

from copy import deepcopy
from datetime import datetime, timezone
from typing import Any

import pandas as pd

from .online_features import EveFeatureState


def _epoch(value: Any) -> float:
    if value is None:
        return 0.0
    if isinstance(value, (int, float)):
        return float(value)
    text = str(value).replace("Z", "+00:00")
    return datetime.fromisoformat(text).astimezone(timezone.utc).timestamp()


def normalize_suricata_flow_events(eve: pd.DataFrame) -> pd.DataFrame:
    if eve.empty:
        return pd.DataFrame()
    if "event_type" not in eve.columns:
        raise ValueError("EVE data missing event_type")
    flows = eve[eve["event_type"].astype(str) == "flow"].copy().reset_index(drop=True)
    rows: list[dict[str, Any]] = []
    for index, event in enumerate(flows.to_dict("records")):
        flow_id = event.get("flow_id")
        uid = f"suri:{flow_id}" if flow_id not in (None, "") else f"suri-row:{index:012d}"
        rows.append({
            "uid": uid,
            "ts": _epoch(event.get("timestamp")),
            "id.orig_h": str(event.get("src_ip", "")),
            "id.resp_h": str(event.get("dest_ip", "")),
            "id.orig_p": int(event.get("src_port") or 0),
            "id.resp_p": int(event.get("dest_port") or 0),
            "event": event,
        })
    return pd.DataFrame(rows)


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


def build_split_isolated_suricata_features(mapped_events: pd.DataFrame) -> pd.DataFrame:
    """Replay captured EVE flows through the exact online EveFeatureState.

    `uid` is the mapper-internal name; `flow_uid` is the public Gold name. This
    helper accepts either so train/serve parity tests and pipeline code share one
    stable output schema.
    """
    frame = mapped_events.copy()
    if "uid" not in frame.columns and "flow_uid" in frame.columns:
        frame["uid"] = frame["flow_uid"].astype(str)
    required = {"uid", "session_id", "split", "behavior_ts", "event"}
    missing = required - set(frame.columns)
    if missing:
        raise ValueError(f"mapped Suricata events missing: {sorted(missing)}")
    order = {str(uid): index for index, uid in enumerate(frame["uid"].astype(str).tolist())}
    chunks: list[pd.DataFrame] = []
    preferred = ["train", "validation", "test", "challenge"]
    split_names = preferred + sorted(set(frame["split"].astype(str)) - set(preferred))
    for split in split_names:
        part = frame[frame["split"].astype(str) == split].copy()
        if part.empty:
            continue
        part = part.sort_values(["behavior_ts", "session_id", "uid"])
        state = EveFeatureState()
        rows: list[dict[str, Any]] = []
        for row in part.to_dict("records"):
            event = deepcopy(row["event"])
            event["timestamp"] = _iso_from_epoch(float(row["behavior_ts"]))
            result = state.consume_flow(event)
            features = dict(result["features"])
            features["flow_uid"] = str(row["uid"])
            features["session_id"] = str(row["session_id"])
            rows.append(features)
        chunks.append(pd.DataFrame(rows))
    if not chunks:
        return pd.DataFrame()
    result = pd.concat(chunks, ignore_index=True)
    result["_order"] = result["flow_uid"].map(order).fillna(len(order))
    return result.sort_values("_order").drop(columns=["_order"]).reset_index(drop=True)
