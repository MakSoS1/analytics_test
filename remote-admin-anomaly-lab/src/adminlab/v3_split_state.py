from __future__ import annotations

import pandas as pd

from .session_gold import build_session_gold


def apply_research_session_splits(
    flow_labels: pd.DataFrame,
    session_splits: pd.DataFrame,
) -> pd.DataFrame:
    """Return a research-only flow-label copy with session-level split assignment.

    The production flow labels are the source of truth for the NGFW flow-primary
    benchmark and MUST NOT be mutated or overwritten by session/campaign research
    views. Hierarchical research can use a different grouped session split, but it
    receives that split only on this detached copy.
    """
    required_labels = {"flow_uid", "session_id", "label_binary"}
    missing_labels = required_labels - set(flow_labels.columns)
    if missing_labels:
        raise ValueError(f"flow labels missing research split columns: {sorted(missing_labels)}")
    required_splits = {"session_id", "split", "challenge_reason"}
    missing_splits = required_splits - set(session_splits.columns)
    if missing_splits:
        raise ValueError(f"session splits missing columns: {sorted(missing_splits)}")
    if session_splits["session_id"].astype(str).duplicated().any():
        raise ValueError("session split table contains duplicate session_id")

    out = flow_labels.drop(
        columns=[column for column in ("split", "challenge_reason") if column in flow_labels.columns]
    ).copy()
    split_map = session_splits[["session_id", "split", "challenge_reason"]].copy()
    split_map["session_id"] = split_map["session_id"].astype(str)
    out["session_id"] = out["session_id"].astype(str)
    out = out.merge(split_map, on="session_id", how="left", validate="many_to_one", sort=False)
    if out[["split", "challenge_reason"]].isna().any().any():
        raise ValueError("research flow label split assignment incomplete")
    if len(out) != len(flow_labels):
        raise ValueError("research flow label row count changed")
    return out


def build_split_isolated_session_gold(
    flow_features: pd.DataFrame,
    flow_labels: pd.DataFrame,
    *,
    environment_id: str = "linux_v3",
) -> tuple[pd.DataFrame, pd.DataFrame]:
    """Build primary benchmark session Gold with independent state per split.

    This intentionally differs from deployment replay. The benchmark asks whether
    the learned relation generalizes to independent groups, so validation/test/
    challenge may not inherit source/pair history from train. Each split is
    replayed chronologically using only its own strictly-earlier events.
    """
    required = {"flow_uid", "session_id", "split"}
    missing = required - set(flow_labels.columns)
    if missing:
        raise ValueError(f"flow labels missing split-state columns: {sorted(missing)}")
    if "flow_uid" not in flow_features.columns:
        raise ValueError("flow features missing flow_uid")

    feature_parts: list[pd.DataFrame] = []
    label_parts: list[pd.DataFrame] = []
    seen_flow_uids: set[str] = set()
    for split in sorted(flow_labels["split"].dropna().astype(str).unique()):
        split_labels = flow_labels[flow_labels["split"].astype(str) == split].copy()
        if split_labels.empty:
            continue
        flow_uids = set(split_labels["flow_uid"].astype(str))
        overlap = seen_flow_uids & flow_uids
        if overlap:
            raise ValueError(f"flow UID crosses split partitions: {sorted(overlap)[:5]}")
        seen_flow_uids.update(flow_uids)
        split_features = flow_features[flow_features["flow_uid"].astype(str).isin(flow_uids)].copy()
        if len(split_features) != len(split_labels):
            raise ValueError(
                f"split {split} flow feature/label mismatch: features={len(split_features)} labels={len(split_labels)}"
            )
        features, labels = build_session_gold(
            split_features,
            split_labels,
            environment_id=environment_id,
        )
        feature_parts.append(features)
        label_parts.append(labels)

    if not feature_parts:
        return pd.DataFrame(), pd.DataFrame()
    features = pd.concat(feature_parts, ignore_index=True)
    labels = pd.concat(label_parts, ignore_index=True)
    if features["session_id"].duplicated().any() or labels["session_id"].duplicated().any():
        raise ValueError("session crosses split-isolated replay partitions")
    return features, labels
