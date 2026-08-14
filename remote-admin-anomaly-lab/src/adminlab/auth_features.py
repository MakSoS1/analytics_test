from __future__ import annotations

from collections import defaultdict, deque
from dataclasses import dataclass, field
from typing import Any

import pandas as pd

SUCCESS_STATES = {"SF", "S1", "S2", "S3"}
FAILURE_STATES = {"S0", "REJ", "RSTOS0", "RSTRH", "SH", "SHR"}
WINDOWS = {"15m": 900.0, "1h": 3600.0, "24h": 86400.0}


def enrich_ssh_auth_by_uid(conn: pd.DataFrame, ssh: pd.DataFrame | None) -> pd.DataFrame:
    out = conn.copy()
    out["ssh_auth_observed"] = 0
    out["ssh_auth_success"] = 0
    out["ssh_auth_attempts"] = 0
    if ssh is None or ssh.empty or "uid" not in ssh.columns or "uid" not in out.columns:
        return out
    cols = ["uid"]
    for name in ("auth_success", "auth_attempts"):
        if name in ssh.columns:
            cols.append(name)
    auth = ssh[cols].drop_duplicates("uid", keep="last").copy()
    auth["ssh_auth_observed"] = 1
    if "auth_success" in auth.columns:
        auth["ssh_auth_success"] = auth["auth_success"].map(lambda x: int(bool(x)))
    else:
        auth["ssh_auth_success"] = 0
    if "auth_attempts" in auth.columns:
        auth["ssh_auth_attempts"] = pd.to_numeric(auth["auth_attempts"], errors="coerce").fillna(0).astype(int)
    else:
        auth["ssh_auth_attempts"] = 0
    auth = auth[["uid", "ssh_auth_observed", "ssh_auth_success", "ssh_auth_attempts"]]
    base = out.drop(columns=["ssh_auth_observed", "ssh_auth_success", "ssh_auth_attempts"])
    merged = base.merge(auth, on="uid", how="left", validate="many_to_one")
    for name in ("ssh_auth_observed", "ssh_auth_success", "ssh_auth_attempts"):
        merged[name] = pd.to_numeric(merged[name], errors="coerce").fillna(0).astype(int)
    return merged


def _outcome(state: str) -> tuple[int, int, int]:
    state = str(state or "")
    if state in SUCCESS_STATES:
        return 1, 0, 1
    if state in FAILURE_STATES:
        return 0, 1, 1
    return 0, 0, 0


@dataclass
class OutcomeState:
    history: dict[str, deque[tuple[float, int, int]]] = field(default_factory=lambda: defaultdict(deque))

    def process(self, frame: pd.DataFrame) -> pd.DataFrame:
        required = {"session_id", "id.orig_h", "conn_state"}
        if not required <= set(frame.columns):
            raise ValueError(f"outcome frame missing {sorted(required - set(frame.columns))}")
        time_col = "behavior_ts" if "behavior_ts" in frame.columns else "ts"
        if time_col not in frame.columns:
            raise ValueError("outcome frame missing behavior_ts/ts")
        rows = frame.sort_values([time_col, "session_id"]).to_dict("records")
        output: list[dict[str, Any]] = []
        for index, row in enumerate(rows):
            ts = float(row.get(time_col, 0.0) or 0.0); src = str(row["id.orig_h"]); hist = self.history[src]
            while hist and hist[0][0] < ts - WINDOWS["24h"]:
                hist.popleft()
            current_success, current_failure, current_known = _outcome(str(row.get("conn_state", "")))
            item: dict[str, Any] = {
                "flow_uid": str(row.get("uid") or f"flow-{index:012d}"),
                "session_id": str(row["session_id"]),
                "connection_success": current_success,
                "connection_failure": current_failure,
                "connection_outcome_known": current_known,
                "ssh_auth_observed": int(row.get("ssh_auth_observed", 0) or 0),
                "ssh_auth_success": int(row.get("ssh_auth_success", 0) or 0),
                "ssh_auth_attempts": int(row.get("ssh_auth_attempts", 0) or 0),
            }
            for name, seconds in WINDOWS.items():
                recent = [x for x in hist if x[0] >= ts - seconds]
                known = sum(s + f for _, s, f in recent)
                successes = sum(s for _, s, _ in recent)
                failures = sum(f for _, _, f in recent)
                item[f"successful_connection_rate_{name}"] = float(successes / known) if known else 0.0
                item[f"failed_connection_rate_{name}"] = float(failures / known) if known else 0.0
            output.append(item)
            hist.append((ts, current_success, current_failure))
        return pd.DataFrame(output)


def build_split_isolated_outcome_features(frame: pd.DataFrame) -> pd.DataFrame:
    if "split" not in frame.columns:
        raise ValueError("split required for isolated outcome state")
    chunks: list[pd.DataFrame] = []
    preferred = ["train", "validation", "test", "challenge"]
    for split in preferred + sorted(set(frame["split"].astype(str)) - set(preferred)):
        part = frame[frame["split"].astype(str) == split]
        if part.empty:
            continue
        features = OutcomeState().process(part)
        features["_split"] = split
        chunks.append(features)
    if not chunks:
        return pd.DataFrame()
    result = pd.concat(chunks, ignore_index=True)
    order = {str(uid): i for i, uid in enumerate(frame.get("uid", pd.Series(dtype=str)).astype(str).tolist())}
    result["_order"] = result["flow_uid"].map(order).fillna(len(order))
    return result.sort_values("_order").drop(columns=["_order", "_split"], errors="ignore").reset_index(drop=True)
