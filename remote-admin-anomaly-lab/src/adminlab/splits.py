from __future__ import annotations

import hashlib
from collections import defaultdict
from typing import Any

import pandas as pd


class DSU:
    def __init__(self, n: int) -> None:
        self.parent = list(range(n)); self.rank = [0] * n
    def find(self, x: int) -> int:
        while self.parent[x] != x:
            self.parent[x] = self.parent[self.parent[x]]; x = self.parent[x]
        return x
    def union(self, a: int, b: int) -> None:
        ra, rb = self.find(a), self.find(b)
        if ra == rb: return
        if self.rank[ra] < self.rank[rb]: ra, rb = rb, ra
        self.parent[rb] = ra
        if self.rank[ra] == self.rank[rb]: self.rank[ra] += 1


def _hash_int(value: str, seed: int) -> int:
    return int.from_bytes(hashlib.sha256(f"{seed}|{value}".encode()).digest()[:8], "big")


def _connected_group_ids(sessions: pd.DataFrame) -> list[str]:
    n = len(sessions); dsu = DSU(n); campaign_owner: dict[str, int] = {}; pair_owner: dict[str, int] = {}
    for idx, row in sessions.reset_index(drop=True).iterrows():
        campaign = str(row.get("campaign_id", "")); pair = str(row.get("pair_id", ""))
        if campaign:
            if campaign in campaign_owner: dsu.union(idx, campaign_owner[campaign])
            else: campaign_owner[campaign] = idx
        if pair:
            if pair in pair_owner: dsu.union(idx, pair_owner[pair])
            else: pair_owner[pair] = idx
    roots: dict[int, str] = {}; result: list[str] = []
    for idx in range(n):
        root = dsu.find(idx)
        if root not in roots: roots[root] = f"grp-{len(roots):08d}"
        result.append(roots[root])
    return result


def _choose_holdout(values: list[str], seed: int, fraction: float = 0.10) -> set[str]:
    unique = sorted(set(v for v in values if v))
    if len(unique) < 3: return set()
    count = max(1, round(len(unique) * fraction)); ranked = sorted(unique, key=lambda value: _hash_int(f"holdout|{value}", seed)); return set(ranked[:count])


def assign_grouped_splits(sessions: pd.DataFrame, *, seed: int = 20260814) -> tuple[pd.DataFrame, dict[str, Any]]:
    required = {"session_id", "campaign_id", "pair_id", "src_host_id", "dst_host_id", "start_ts"}; missing = required - set(sessions.columns)
    if missing: raise ValueError(f"sessions missing split columns: {sorted(missing)}")
    frame = sessions.copy().reset_index(drop=True); frame["group_id"] = _connected_group_ids(frame); frame["host_pair"] = frame["src_host_id"].astype(str) + "->" + frame["dst_host_id"].astype(str); frame["_ts"] = pd.to_datetime(frame["start_ts"], utc=True)
    heldout_users = _choose_holdout(frame["src_host_id"].astype(str).tolist(), seed); heldout_pairs = _choose_holdout(frame["host_pair"].astype(str).tolist(), seed + 1)
    group_meta = frame.groupby("group_id", as_index=False).agg(max_ts=("_ts", "max"), min_ts=("_ts", "min"), session_count=("session_id", "count")).sort_values(["max_ts", "group_id"])
    temporal_count = max(1, round(len(group_meta) * 0.10)) if len(group_meta) >= 4 else 0; temporal_groups = set(group_meta.tail(temporal_count)["group_id"].astype(str)) if temporal_count else set()
    group_reasons: dict[str, set[str]] = defaultdict(set)
    for gid in temporal_groups: group_reasons[str(gid)].add("temporal_future")
    for gid, part in frame.groupby("group_id", sort=False):
        gid = str(gid)
        if set(part["src_host_id"].astype(str)) & heldout_users: group_reasons[gid].add("unseen_src_host")
        if set(part["host_pair"].astype(str)) & heldout_pairs: group_reasons[gid].add("unseen_host_pair")
    assignments: dict[str, str] = {}
    for gid in sorted(frame["group_id"].astype(str).unique()):
        if group_reasons.get(gid): assignments[gid] = "challenge"; continue
        bucket = _hash_int(f"split|{gid}", seed) % 100
        if bucket < 60: assignments[gid] = "train"
        elif bucket < 75: assignments[gid] = "validation"
        elif bucket < 90: assignments[gid] = "test"
        else: assignments[gid] = "challenge"; group_reasons[gid].add("hash_challenge")
    out = frame[["session_id", "group_id"]].copy(); out["split"] = out["group_id"].map(assignments); out["challenge_reason"] = out["group_id"].map(lambda gid: ",".join(sorted(group_reasons.get(str(gid), set()))))
    reason_counts = CounterLike(out.loc[out["split"] == "challenge", "challenge_reason"].astype(str).tolist())
    report = {
        "seed": seed,
        "heldout_src_hosts": sorted(heldout_users), "heldout_host_pairs": sorted(heldout_pairs), "temporal_holdout_groups": sorted(temporal_groups),
        "split_counts": {str(k): int(v) for k, v in out["split"].value_counts().to_dict().items()},
        "group_counts": {str(k): int(v) for k, v in out.groupby("split")["group_id"].nunique().to_dict().items()},
        "challenge_reason_counts": reason_counts,
    }
    return out, report


def CounterLike(values: list[str]) -> dict[str, int]:
    result: dict[str, int] = {}
    for value in values:
        if not value: continue
        for reason in value.split(","):
            result[reason] = result.get(reason, 0) + 1
    return dict(sorted(result.items()))


def audit_leakage(sessions: pd.DataFrame, splits: pd.DataFrame, model_columns: list[str], feature_contract: dict[str, Any], split_report: dict[str, Any] | None = None) -> dict[str, Any]:
    forbidden = set(map(str, feature_contract.get("forbidden", []))); training_only = set(map(str, feature_contract.get("training_only", []))); allowlist = set(map(str, feature_contract.get("production_allowlist", []))); columns = set(map(str, model_columns)); errors: list[str] = []
    leaked = sorted(columns & forbidden)
    if leaked: errors.append(f"forbidden model columns: {leaked}")
    unexpected = sorted(columns - allowlist - training_only)
    if unexpected: errors.append(f"model columns outside feature contract: {unexpected}")
    merged = sessions[["session_id", "campaign_id", "pair_id", "src_host_id", "dst_host_id"]].merge(splits[["session_id", "split"]], on="session_id", how="left", validate="one_to_one")
    if merged["split"].isna().any(): errors.append("sessions missing split assignment")
    campaign_leaks = merged.groupby("campaign_id")["split"].nunique(); campaign_leaks = campaign_leaks[campaign_leaks > 1]
    if len(campaign_leaks): errors.append(f"campaigns cross splits: {campaign_leaks.index.astype(str).tolist()[:10]}")
    nonempty_pairs = merged[merged["pair_id"].astype(str) != ""]
    if not nonempty_pairs.empty:
        pair_leaks = nonempty_pairs.groupby("pair_id")["split"].nunique(); pair_leaks = pair_leaks[pair_leaks > 1]
        if len(pair_leaks): errors.append(f"counterfactual pairs cross splits: {pair_leaks.index.astype(str).tolist()[:10]}")
    heldout_users = set(map(str, (split_report or {}).get("heldout_src_hosts", []))); train = merged[merged["split"] == "train"]; leaked_users = sorted(set(train["src_host_id"].astype(str)) & heldout_users)
    if leaked_users: errors.append(f"held-out source hosts leaked into train: {leaked_users}")
    heldout_pairs = set(map(str, (split_report or {}).get("heldout_host_pairs", []))); train_pairs = set(train["src_host_id"].astype(str) + "->" + train["dst_host_id"].astype(str)); leaked_pairs = sorted(train_pairs & heldout_pairs)
    if leaked_pairs: errors.append(f"held-out host pairs leaked into train: {leaked_pairs}")
    return {"ok": not errors, "errors": errors, "forbidden_model_columns": leaked, "unexpected_model_columns": unexpected, "campaigns_crossing_splits": int(len(campaign_leaks)), "pairs_crossing_splits": int(len(pair_leaks)) if not nonempty_pairs.empty else 0, "heldout_users_in_train": leaked_users, "heldout_pairs_in_train": leaked_pairs}
