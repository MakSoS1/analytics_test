from __future__ import annotations

from collections import defaultdict
from typing import Any

import pandas as pd

from .splits import _connected_group_ids, _hash_int


def _impact_for_value(frame: pd.DataFrame, column: str, value: str) -> tuple[set[str], int]:
    values = frame[column].fillna("").astype(str)
    groups = set(frame.loc[values == value, "group_id"].astype(str))
    rows = int(frame[frame["group_id"].astype(str).isin(groups)].shape[0])
    return groups, rows


def _candidate_values(frame: pd.DataFrame, column: str) -> list[str]:
    if column not in frame.columns:
        return []
    return [value for value in sorted(frame[column].fillna("").astype(str).unique()) if value]


def _select_value_holdout(
    frame: pd.DataFrame,
    column: str,
    *,
    seed: int,
    challenge_groups: set[str],
    target_fraction: float,
    max_fraction: float,
    candidate_filter: set[str] | None = None,
    cumulative_max_fraction: float = 0.23,
) -> tuple[set[str], dict[str, Any]]:
    total = len(frame)
    candidates = _candidate_values(frame, column)
    if candidate_filter is not None:
        candidates = [value for value in candidates if value in candidate_filter]
    if len(candidates) < 1:
        return set(), {
            "status": "skipped_no_candidates",
            "value": None,
            "rows": 0,
            "fraction": 0.0,
            "max_fraction": max_fraction,
        }

    target_rows = max(1, int(round(total * target_fraction)))
    dimension_max_rows = max(1, int(round(total * max_fraction)))
    cumulative_max_rows = max(1, int(round(total * cumulative_max_fraction)))
    ranked: list[tuple[int, int, str, set[str], int, int]] = []
    group_text = frame["group_id"].astype(str)
    for value in candidates:
        groups, impact_rows = _impact_for_value(frame, column, value)
        if impact_rows <= 0 or impact_rows > dimension_max_rows:
            continue
        new_groups = groups - challenge_groups
        new_rows = int(frame[group_text.isin(new_groups)].shape[0])
        cumulative_groups = challenge_groups | groups
        cumulative_rows = int(frame[group_text.isin(cumulative_groups)].shape[0])
        if cumulative_rows > cumulative_max_rows:
            continue
        ranked.append(
            (
                abs(impact_rows - target_rows),
                _hash_int(f"v3|{column}|{value}", seed),
                value,
                groups,
                impact_rows,
                new_rows,
            )
        )
    if not ranked:
        return set(), {
            "status": "skipped_no_candidate_within_budget",
            "value": None,
            "rows": 0,
            "fraction": 0.0,
            "max_fraction": max_fraction,
        }
    _, _, value, groups, rows, new_rows = min(ranked, key=lambda item: (item[0], item[1]))
    return groups, {
        "status": "selected_within_budget",
        "value": value,
        "rows": int(rows),
        "new_rows": int(new_rows),
        "fraction": rows / total,
        "max_fraction": max_fraction,
    }


def _alternative_implementation_values(frame: pd.DataFrame) -> set[str]:
    required = {"protocol", "client_stack", "implementation_id"}
    if not required <= set(frame.columns):
        return set()
    alternatives: set[str] = set()
    for _, part in frame.groupby("protocol", sort=True):
        counts = part["client_stack"].fillna("").astype(str).value_counts().to_dict()
        counts = {str(key): int(value) for key, value in counts.items() if str(key)}
        if len(counts) < 2:
            continue
        primary = sorted(counts, key=lambda value: (-counts[value], value))[0]
        alt = part[part["client_stack"].fillna("").astype(str) != primary]
        alternatives.update(
            value for value in alt["implementation_id"].fillna("").astype(str).unique() if value
        )
    return alternatives


def _add_temporal_holdout(
    frame: pd.DataFrame,
    challenge_groups: set[str],
    group_reasons: dict[str, set[str]],
    *,
    target_fraction: float = 0.05,
    cumulative_max_fraction: float = 0.23,
) -> dict[str, Any]:
    total = len(frame)
    target = int(round(total * target_fraction))
    cumulative_max = int(round(total * cumulative_max_fraction))
    group_meta = (
        frame.groupby("group_id", as_index=False)
        .agg(max_ts=("_ts", "max"), rows=("session_id", "count"))
        .sort_values(["max_ts", "group_id"], ascending=[False, True])
    )
    added: set[str] = set()
    added_rows = 0
    group_text = frame["group_id"].astype(str)
    for _, row in group_meta.iterrows():
        gid = str(row["group_id"])
        if gid in challenge_groups:
            continue
        trial = challenge_groups | added | {gid}
        cumulative_rows = int(frame[group_text.isin(trial)].shape[0])
        if cumulative_rows > cumulative_max:
            continue
        added.add(gid)
        added_rows += int(row["rows"])
        group_reasons[gid].add("temporal_future")
        if added_rows >= target:
            break
    challenge_groups.update(added)
    return {
        "status": "selected_within_budget" if added else "skipped_no_group_within_budget",
        "rows": int(added_rows),
        "fraction": added_rows / total if total else 0.0,
        "max_fraction": target_fraction + 0.02,
    }


def _fill_challenge_to_minimum(
    frame: pd.DataFrame,
    challenge_groups: set[str],
    group_reasons: dict[str, set[str]],
    *,
    seed: int,
    min_fraction: float = 0.17,
    max_fraction: float = 0.23,
) -> None:
    total = len(frame)
    group_text = frame["group_id"].astype(str)
    min_rows = int(round(total * min_fraction))
    max_rows = int(round(total * max_fraction))
    current_rows = int(frame[group_text.isin(challenge_groups)].shape[0])
    candidates = [gid for gid in sorted(frame["group_id"].astype(str).unique()) if gid not in challenge_groups]
    candidates.sort(key=lambda gid: _hash_int(f"v3-challenge-fill|{gid}", seed))
    for gid in candidates:
        if current_rows >= min_rows:
            break
        gid_rows = int(frame[group_text == gid].shape[0])
        if current_rows + gid_rows > max_rows:
            continue
        challenge_groups.add(gid)
        group_reasons[gid].add("hash_challenge")
        current_rows += gid_rows


def _assign_generic_groups(frame: pd.DataFrame, eligible: list[str], *, seed: int) -> dict[str, str]:
    """Deterministically allocate roughly 60/20/20 by rows within label strata."""
    if not eligible:
        return {}
    eligible_set = set(eligible)
    meta_rows: list[dict[str, Any]] = []
    for gid, part in frame[frame["group_id"].astype(str).isin(eligible_set)].groupby("group_id", sort=False):
        labels = sorted(set(part["label_binary"].astype(int))) if "label_binary" in part.columns else []
        stratum = str(labels[0]) if len(labels) == 1 else ("mixed" if labels else "unlabeled")
        meta_rows.append({"group_id": str(gid), "stratum": stratum, "rows": int(len(part))})
    meta = pd.DataFrame(meta_rows)
    assignments: dict[str, str] = {}
    for stratum, part in meta.groupby("stratum", sort=True):
        groups = part.to_dict("records")
        groups.sort(key=lambda item: _hash_int(f"v3-generic|{stratum}|{item['group_id']}", seed))
        total_rows = sum(int(item["rows"]) for item in groups)
        val_target = total_rows * 0.20
        test_target = total_rows * 0.20
        val_rows = 0
        test_rows = 0
        # First allocate validation/test alternately until both row targets are met.
        remaining: list[dict[str, Any]] = []
        for item in groups:
            rows = int(item["rows"])
            if val_rows < val_target or test_rows < test_target:
                if val_rows <= test_rows and val_rows < val_target:
                    assignments[str(item["group_id"])] = "validation"
                    val_rows += rows
                elif test_rows < test_target:
                    assignments[str(item["group_id"])] = "test"
                    test_rows += rows
                else:
                    remaining.append(item)
            else:
                remaining.append(item)
        for item in remaining:
            assignments[str(item["group_id"])] = "train"
        # A small stratum can otherwise contain no train rows; move the largest
        # deterministic validation/test group back to train.
        stratum_ids = [str(item["group_id"]) for item in groups]
        if stratum_ids and all(assignments.get(gid) != "train" for gid in stratum_ids):
            gid = max(stratum_ids, key=lambda value: int(meta.loc[meta["group_id"] == value, "rows"].iloc[0]))
            assignments[gid] = "train"
    return assignments


def assign_grouped_splits_v3(sessions: pd.DataFrame, *, seed: int = 20260814) -> tuple[pd.DataFrame, dict[str, Any]]:
    required = {
        "session_id", "campaign_id", "pair_id", "label_binary", "src_host_id", "dst_host_id",
        "start_ts", "persona_id", "protocol", "client_stack", "implementation_id",
    }
    missing = required - set(sessions.columns)
    if missing:
        raise ValueError(f"sessions missing V3 split columns: {sorted(missing)}")

    frame = sessions.copy().reset_index(drop=True)
    frame["group_id"] = _connected_group_ids(frame)
    frame["host_pair"] = frame["src_host_id"].astype(str) + "->" + frame["dst_host_id"].astype(str)
    frame["_ts"] = pd.to_datetime(frame["start_ts"], utc=True)
    group_reasons: dict[str, set[str]] = defaultdict(set)
    challenge_groups: set[str] = set()
    holdout_impact: dict[str, dict[str, Any]] = {}

    temporal = _add_temporal_holdout(frame, challenge_groups, group_reasons)
    holdout_impact["temporal_future"] = temporal

    dimensions = [
        ("unseen_client_implementation", "implementation_id", _alternative_implementation_values(frame), seed + 1),
        ("unseen_persona", "persona_id", None, seed + 2),
        ("unseen_host_pair", "host_pair", None, seed + 3),
        ("unseen_src_host", "src_host_id", None, seed + 4),
    ]
    for reason, column, allowed, dim_seed in dimensions:
        groups, detail = _select_value_holdout(
            frame,
            column,
            seed=dim_seed,
            challenge_groups=challenge_groups,
            target_fraction=0.04,
            max_fraction=0.06,
            candidate_filter=allowed,
        )
        holdout_impact[reason] = detail
        if groups:
            for gid in groups:
                group_reasons[str(gid)].add(reason)
            challenge_groups.update(map(str, groups))

    _fill_challenge_to_minimum(frame, challenge_groups, group_reasons, seed=seed + 10)

    all_groups = sorted(frame["group_id"].astype(str).unique())
    eligible = [gid for gid in all_groups if gid not in challenge_groups]
    assignments = _assign_generic_groups(frame, eligible, seed=seed)
    for gid in challenge_groups:
        assignments[str(gid)] = "challenge"

    out = frame[["session_id", "group_id"]].copy()
    out["split"] = out["group_id"].astype(str).map(assignments)
    if out["split"].isna().any():
        raise ValueError("V3 split assignment incomplete")
    out["challenge_reason"] = out["group_id"].map(
        lambda gid: ",".join(sorted(group_reasons.get(str(gid), set())))
    )

    split_counts = {str(key): int(value) for key, value in out["split"].value_counts().to_dict().items()}
    total = len(out)
    challenge_fraction = split_counts.get("challenge", 0) / total if total else 0.0
    reason_counts: dict[str, int] = {}
    for value in out.loc[out["split"] == "challenge", "challenge_reason"].astype(str):
        for reason in filter(None, value.split(",")):
            reason_counts[reason] = reason_counts.get(reason, 0) + 1

    report = {
        "seed": seed,
        "split_counts": split_counts,
        "group_counts": {str(key): int(value) for key, value in out.groupby("split")["group_id"].nunique().to_dict().items()},
        "challenge_fraction": challenge_fraction,
        "challenge_reason_counts": dict(sorted(reason_counts.items())),
        "holdout_impact": holdout_impact,
        "policy": "V3 cumulative impact-budget challenge (17-23% target); connected campaign+pair components; remaining groups roughly 60/20/20 train/validation/test by rows",
    }
    return out, report
