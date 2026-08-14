from __future__ import annotations

import hashlib
from collections import defaultdict
from typing import Any

import pandas as pd


class DSU:
    def __init__(self, n: int) -> None:
        self.parent = list(range(n))
        self.rank = [0] * n

    def find(self, x: int) -> int:
        while self.parent[x] != x:
            self.parent[x] = self.parent[self.parent[x]]
            x = self.parent[x]
        return x

    def union(self, a: int, b: int) -> None:
        ra, rb = self.find(a), self.find(b)
        if ra == rb:
            return
        if self.rank[ra] < self.rank[rb]:
            ra, rb = rb, ra
        self.parent[rb] = ra
        if self.rank[ra] == self.rank[rb]:
            self.rank[ra] += 1


def _hash_int(value: str, seed: int) -> int:
    return int.from_bytes(hashlib.sha256(f"{seed}|{value}".encode()).digest()[:8], "big")


def _connected_group_ids(sessions: pd.DataFrame) -> list[str]:
    n = len(sessions)
    dsu = DSU(n)
    campaign_owner: dict[str, int] = {}
    pair_owner: dict[str, int] = {}
    for idx, row in sessions.reset_index(drop=True).iterrows():
        campaign = str(row.get("campaign_id", ""))
        pair = str(row.get("pair_id", ""))
        if campaign:
            if campaign in campaign_owner:
                dsu.union(idx, campaign_owner[campaign])
            else:
                campaign_owner[campaign] = idx
        if pair:
            if pair in pair_owner:
                dsu.union(idx, pair_owner[pair])
            else:
                pair_owner[pair] = idx
    roots: dict[int, str] = {}
    result: list[str] = []
    for idx in range(n):
        root = dsu.find(idx)
        if root not in roots:
            roots[root] = f"grp-{len(roots):08d}"
        result.append(roots[root])
    return result


def _choose_group_impact_holdout(
    frame: pd.DataFrame,
    column: str,
    *,
    seed: int,
    target_fraction: float = 0.05,
    max_fraction: float = 0.10,
    min_rows: int = 3,
) -> set[str]:
    """Choose one unseen value by campaign-group impact, not raw frequency."""
    if column not in frame.columns or frame.empty:
        return set()
    total = len(frame)
    candidates = [value for value in sorted(frame[column].fillna("").astype(str).unique()) if value]
    if len(candidates) < 2:
        return set()
    target = max(min_rows, int(round(total * target_fraction)))
    maximum = max(min_rows, int(round(total * max_fraction)))
    impacts: list[tuple[str, int]] = []
    values = frame[column].fillna("").astype(str)
    groups_as_text = frame["group_id"].astype(str)
    for value in candidates:
        groups = set(groups_as_text[values == value])
        impacted = int(frame[groups_as_text.isin(groups)].shape[0])
        if impacted >= min_rows:
            impacts.append((value, impacted))
    if not impacts:
        return set()
    bounded = [item for item in impacts if item[1] <= maximum]
    pool = bounded or impacts
    value, _ = min(
        pool,
        key=lambda item: (
            abs(item[1] - target),
            item[1] > maximum,
            _hash_int(f"impact|{column}|{item[0]}", seed),
        ),
    )
    return {value}


def _infer_heldout_implementations(frame: pd.DataFrame) -> set[str]:
    required = {"protocol", "client_stack", "implementation_id"}
    if not required <= set(frame.columns):
        return set()
    heldout: set[str] = set()
    for _, part in frame.groupby("protocol", sort=True):
        client_counts: dict[str, int] = {}
        for client in part["client_stack"].fillna("").astype(str):
            if client:
                client_counts[client] = client_counts.get(client, 0) + 1
        if len(client_counts) < 2:
            continue
        primary = sorted(client_counts, key=lambda client: (-client_counts[client], client))[0]
        alternatives = part[part["client_stack"].fillna("").astype(str) != primary]
        heldout.update(
            implementation
            for implementation in alternatives["implementation_id"].fillna("").astype(str).unique()
            if implementation
        )
    return heldout


def _stratified_group_assignments(frame: pd.DataFrame, eligible_groups: list[str], seed: int) -> dict[str, str]:
    if not eligible_groups:
        return {}
    meta_rows: list[dict[str, Any]] = []
    eligible_set = set(eligible_groups)
    for gid, part in frame[frame["group_id"].astype(str).isin(eligible_set)].groupby("group_id", sort=False):
        labels = sorted(set(part["label_binary"].astype(int))) if "label_binary" in part.columns else []
        stratum = str(labels[0]) if len(labels) == 1 else ("mixed" if labels else "unlabeled")
        meta_rows.append({"group_id": str(gid), "stratum": stratum, "rows": int(len(part))})
    meta = pd.DataFrame(meta_rows)
    assignments: dict[str, str] = {}
    for stratum, part in meta.groupby("stratum", sort=True):
        groups = sorted(
            part["group_id"].astype(str).tolist(),
            key=lambda gid: _hash_int(f"split|{stratum}|{gid}", seed),
        )
        n = len(groups)
        if n == 1:
            assignments[groups[0]] = "train"
            continue
        if n == 2:
            assignments[groups[0]] = "train"
            assignments[groups[1]] = "validation"
            continue
        validation_n = max(1, round(n * 0.15))
        test_n = max(1, round(n * 0.15))
        if validation_n + test_n >= n:
            validation_n = 1
            test_n = 1
        train_n = n - validation_n - test_n
        for gid in groups[:train_n]:
            assignments[gid] = "train"
        for gid in groups[train_n:train_n + validation_n]:
            assignments[gid] = "validation"
        for gid in groups[train_n + validation_n:]:
            assignments[gid] = "test"
    return assignments


def assign_grouped_splits(sessions: pd.DataFrame, *, seed: int = 20260814) -> tuple[pd.DataFrame, dict[str, Any]]:
    required = {"session_id", "campaign_id", "pair_id", "src_host_id", "dst_host_id", "start_ts"}
    missing = required - set(sessions.columns)
    if missing:
        raise ValueError(f"sessions missing split columns: {sorted(missing)}")

    frame = sessions.copy().reset_index(drop=True)
    frame["group_id"] = _connected_group_ids(frame)
    frame["host_pair"] = frame["src_host_id"].astype(str) + "->" + frame["dst_host_id"].astype(str)
    frame["_ts"] = pd.to_datetime(frame["start_ts"], utc=True)

    heldout_src_hosts = _choose_group_impact_holdout(
        frame, "src_host_id", seed=seed, target_fraction=0.04, max_fraction=0.08
    )
    heldout_pairs = _choose_group_impact_holdout(
        frame, "host_pair", seed=seed + 1, target_fraction=0.04, max_fraction=0.08
    )
    heldout_personas = _choose_group_impact_holdout(
        frame, "persona_id", seed=seed + 2, target_fraction=0.04, max_fraction=0.08
    )
    heldout_implementations = _infer_heldout_implementations(frame)

    group_meta = (
        frame.groupby("group_id", as_index=False)
        .agg(max_ts=("_ts", "max"), min_ts=("_ts", "min"), session_count=("session_id", "count"))
        .sort_values(["max_ts", "group_id"])
    )
    temporal_count = max(1, round(len(group_meta) * 0.10)) if len(group_meta) >= 4 else 0
    temporal_groups = set(group_meta.tail(temporal_count)["group_id"].astype(str)) if temporal_count else set()

    group_reasons: dict[str, set[str]] = defaultdict(set)
    for gid in temporal_groups:
        group_reasons[str(gid)].add("temporal_future")

    for gid, part in frame.groupby("group_id", sort=False):
        gid = str(gid)
        if set(part["src_host_id"].astype(str)) & heldout_src_hosts:
            group_reasons[gid].add("unseen_src_host")
        if set(part["host_pair"].astype(str)) & heldout_pairs:
            group_reasons[gid].add("unseen_host_pair")
        if heldout_personas and "persona_id" in part.columns:
            if set(part["persona_id"].fillna("").astype(str)) & heldout_personas:
                group_reasons[gid].add("unseen_persona")
        if heldout_implementations and "implementation_id" in part.columns:
            if set(part["implementation_id"].fillna("").astype(str)) & heldout_implementations:
                group_reasons[gid].add("unseen_client_implementation")

    all_groups = sorted(frame["group_id"].astype(str).unique())
    explicit_challenge = {gid for gid in all_groups if group_reasons.get(gid)}
    eligible = [gid for gid in all_groups if gid not in explicit_challenge]
    assignments = _stratified_group_assignments(frame, eligible, seed)
    for gid in explicit_challenge:
        assignments[gid] = "challenge"

    out = frame[["session_id", "group_id"]].copy()
    out["split"] = out["group_id"].map(assignments)
    if out["split"].isna().any():
        raise ValueError("split assignment incomplete")
    out["challenge_reason"] = out["group_id"].map(
        lambda gid: ",".join(sorted(group_reasons.get(str(gid), set())))
    )
    reason_counts = CounterLike(out.loc[out["split"] == "challenge", "challenge_reason"].astype(str).tolist())
    report = {
        "seed": seed,
        "heldout_src_hosts": sorted(heldout_src_hosts),
        "heldout_host_pairs": sorted(heldout_pairs),
        "heldout_personas": sorted(heldout_personas),
        "heldout_client_implementations": sorted(heldout_implementations),
        "temporal_holdout_groups": sorted(temporal_groups),
        "split_counts": {str(k): int(v) for k, v in out["split"].value_counts().to_dict().items()},
        "group_counts": {str(k): int(v) for k, v in out.groupby("split")["group_id"].nunique().to_dict().items()},
        "challenge_reason_counts": reason_counts,
        "policy": "explicit group-impact-bounded challenge holdouts; remaining groups class-stratified into train/validation/test",
    }
    return out, report


def CounterLike(values: list[str]) -> dict[str, int]:
    result: dict[str, int] = {}
    for value in values:
        if not value:
            continue
        for reason in value.split(","):
            result[reason] = result.get(reason, 0) + 1
    return dict(sorted(result.items()))


def audit_leakage(
    sessions: pd.DataFrame,
    splits: pd.DataFrame,
    model_columns: list[str],
    feature_contract: dict[str, Any],
    split_report: dict[str, Any] | None = None,
) -> dict[str, Any]:
    forbidden = set(map(str, feature_contract.get("forbidden", [])))
    training_only = set(map(str, feature_contract.get("training_only", [])))
    allowlist = set(map(str, feature_contract.get("production_allowlist", [])))
    columns = set(map(str, model_columns))
    errors: list[str] = []

    leaked = sorted(columns & forbidden)
    if leaked:
        errors.append(f"forbidden model columns: {leaked}")
    unexpected = sorted(columns - allowlist - training_only)
    if unexpected:
        errors.append(f"model columns outside feature contract: {unexpected}")

    merge_columns = ["session_id", "campaign_id", "pair_id", "src_host_id", "dst_host_id"]
    for optional in ("persona_id", "implementation_id"):
        if optional in sessions.columns:
            merge_columns.append(optional)
    merged = sessions[merge_columns].merge(
        splits[["session_id", "split"]], on="session_id", how="left", validate="one_to_one"
    )
    if merged["split"].isna().any():
        errors.append("sessions missing split assignment")

    campaign_leaks = merged.groupby("campaign_id")["split"].nunique()
    campaign_leaks = campaign_leaks[campaign_leaks > 1]
    if len(campaign_leaks):
        errors.append(f"campaigns cross splits: {campaign_leaks.index.astype(str).tolist()[:10]}")

    nonempty_pairs = merged[merged["pair_id"].astype(str) != ""]
    pair_leaks = pd.Series(dtype=int)
    if not nonempty_pairs.empty:
        pair_leaks = nonempty_pairs.groupby("pair_id")["split"].nunique()
        pair_leaks = pair_leaks[pair_leaks > 1]
        if len(pair_leaks):
            errors.append(f"counterfactual pairs cross splits: {pair_leaks.index.astype(str).tolist()[:10]}")

    report = split_report or {}
    train = merged[merged["split"] == "train"]
    heldout_users = set(map(str, report.get("heldout_src_hosts", [])))
    leaked_users = sorted(set(train["src_host_id"].astype(str)) & heldout_users)
    if leaked_users:
        errors.append(f"held-out source hosts leaked into train: {leaked_users}")

    heldout_pairs = set(map(str, report.get("heldout_host_pairs", [])))
    train_pairs = set(train["src_host_id"].astype(str) + "->" + train["dst_host_id"].astype(str))
    leaked_pairs = sorted(train_pairs & heldout_pairs)
    if leaked_pairs:
        errors.append(f"held-out host pairs leaked into train: {leaked_pairs}")

    heldout_personas = set(map(str, report.get("heldout_personas", [])))
    leaked_personas: list[str] = []
    if "persona_id" in train.columns:
        leaked_personas = sorted(set(train["persona_id"].fillna("").astype(str)) & heldout_personas)
        if leaked_personas:
            errors.append(f"held-out personas leaked into train: {leaked_personas}")

    heldout_implementations = set(map(str, report.get("heldout_client_implementations", [])))
    leaked_implementations: list[str] = []
    if "implementation_id" in train.columns:
        leaked_implementations = sorted(
            set(train["implementation_id"].fillna("").astype(str)) & heldout_implementations
        )
        if leaked_implementations:
            errors.append(f"held-out client implementations leaked into train: {leaked_implementations}")

    return {
        "ok": not errors,
        "errors": errors,
        "forbidden_model_columns": leaked,
        "unexpected_model_columns": unexpected,
        "campaigns_crossing_splits": int(len(campaign_leaks)),
        "pairs_crossing_splits": int(len(pair_leaks)),
        "heldout_users_in_train": leaked_users,
        "heldout_pairs_in_train": leaked_pairs,
        "heldout_personas_in_train": leaked_personas,
        "heldout_client_implementations_in_train": leaked_implementations,
    }
