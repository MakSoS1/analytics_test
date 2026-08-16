from __future__ import annotations

import pandas as pd

from .session_gold import build_session_gold


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
