"""Leakage-resistant train/validation/test partitions of corroborated captures.

Each identity link forms an undirected edge; splits are assigned to entire
connected components, not individual session segments or file rows.
"""

from __future__ import annotations

from hashlib import sha256
import random

import pandas as pd


_LINK_FIELDS = (
    "parent_campaign_id", "capture_group_id", "runtime_profile_id",
    "pair_id", "source_sha256",
)
_REQUIRED = ("parent_campaign_id", "capture_group_id", "runtime_profile_id", "source_sha256", "source_id")
_SPLITS = frozenset({"train", "validation", "test"})


def connected_component_ids(metadata: pd.DataFrame) -> pd.Series:
    """Return one deterministic identity for each connected capture group."""
    if metadata.empty:
        raise ValueError("empty metadata")
    for col in (*_REQUIRED, "pair_id"):
        if col not in metadata.columns:
            raise ValueError(f"missing required independent group field {col}")
        if col in _REQUIRED:
            values = metadata[col]
            if values.isna().any() or values.astype(str).str.strip().eq("").any():
                raise ValueError(f"empty independent group field {col}")
    n = len(metadata)
    parents = list(range(n))

    def root(i: int) -> int:
        while parents[i] != i:
            parents[i] = parents[parents[i]]
            i = parents[i]
        return i

    def union(i: int, j: int) -> None:
        a, b = root(i), root(j)
        if a != b:
            parents[b] = a

    for col in _LINK_FIELDS:
        head: dict[str, int] = {}
        for i, raw in enumerate(metadata[col]):
            if raw is None or pd.isna(raw) or str(raw).strip() == "":
                continue
            value = str(raw)
            if value in head:
                union(head[value], i)
            else:
                head[value] = i

    groups: dict[int, list[int]] = {}
    for i in range(n):
        groups.setdefault(root(i), []).append(i)
    result = [""] * n
    for members in groups.values():
        fingerprints = sorted({
            f"{metadata.iloc[i]['source_id']}|{metadata.iloc[i]['source_sha256']}"
            for i in members
        })
        digest = sha256("\n".join(fingerprints).encode("utf-8")).hexdigest()[:24]
        for i in members:
            result[i] = digest
    return pd.Series(result, index=metadata.index, name="independent_component_id")


def assign_connected_splits(
    metadata: pd.DataFrame, *, seed: int = 20261008,
) -> pd.Series:
    """Deterministically assign whole components, refusing tiny holdouts."""
    components = connected_component_ids(metadata)
    independent = sorted(components.unique())
    if len(independent) < 10:
        raise ValueError("at least 10 independent connected groups required")
    random.Random(seed).shuffle(independent)
    train_end = max(1, int(.6 * len(independent)))
    val_end = max(train_end + 1, int(.8 * len(independent)))
    group_split = {
        group: "train" if i < train_end else "validation" if i < val_end else "test"
        for i, group in enumerate(independent)
    }
    assigned = components.map(group_split).rename("split")
    assert_split_independence(metadata, assigned)
    return assigned


def assert_split_independence(metadata: pd.DataFrame, splits: pd.Series) -> None:
    """Validate a persisted split before any fitting or feature selection."""
    if len(metadata) != len(splits) or list(metadata.index) != list(splits.index):
        raise ValueError("split/metadata alignment mismatch")
    if not set(splits.astype(str)) <= _SPLITS:
        raise ValueError("unknown split name")
    components = connected_component_ids(metadata)
    counts = pd.DataFrame({"component": components.to_numpy(), "split": splits.to_numpy()})
    if counts.groupby("component", sort=False)["split"].nunique().gt(1).any():
        raise ValueError("capture/campaign/profile group leakage across holdouts")


def assign_research_splits(
    metadata: pd.DataFrame, *, seed: int = 20261008, max_attempts: int = 64,
) -> pd.Series:
    """Stratify independent groups by declared class support, never ML scores.

    This bounded deterministic search checks only technique IDs, existing
    labels and connected ancestry. No feature values or office test data can
    influence the choice, and the resulting map is persisted before fitting.
    """
    if not 1 <= max_attempts <= 256:
        raise ValueError("max_attempts must be in [1, 256]")
    for field in ("technique_id", "label_binary"):
        if field not in metadata:
            raise ValueError(f"missing research split label field {field}")
    techniques = sorted({str(t) for t in metadata.loc[
        metadata["label_binary"].eq(1), "technique_id"
    ].dropna().unique()})
    if not techniques:
        raise ValueError("no verified MITRE techniques eligible for research splitting")
    component_ids = connected_component_ids(metadata)
    for offset in range(max_attempts):
        split = assign_connected_splits(metadata, seed=seed + offset)
        eligible = True
        for technique in techniques:
            for fold in _SPLITS:
                mask = (metadata["technique_id"].eq(technique) &
                        metadata["label_binary"].isin((0, 1)) & split.eq(fold))
                if len(set(metadata.loc[mask, "label_binary"])) != 2 or (
                    component_ids.loc[mask].nunique() < 2
                ):
                    eligible = False
                    break
            if not eligible:
                break
        if eligible:
            return split
    raise ValueError("insufficient independent per-technique split support after bounded stratification")
