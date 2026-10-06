from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
from pathlib import Path
from typing import Iterable

import pandas as pd


_REQUIRED_TABLES = {
    "pipeline_office": ("pipeline_office_full.parquet", (5726, 180)),
    "pipeline_added": ("pipeline_added_full.parquet", (2784, 180)),
    "pipeline_original": ("pipeline_original_155.parquet", (8510, 155)),
    "arkime_office": ("arkime_office_all_fields.parquet", (6053, 833)),
    "arkime_added": ("arkime_added_all_fields.parquet", (2790, 833)),
    "matched_office": ("matched_office_pipeline_arkime.parquet", (5723, 990)),
    "matched_added": ("matched_added_pipeline_arkime.parquet", (2784, 990)),
    "matched_mixed": ("matched_mixed_pipeline_arkime.parquet", (8507, 990)),
    "session_comparison": ("session_comparison.parquet", (8843, 50)),
}

_FORBIDDEN_FRAGMENTS = (
    "label",
    "origin",
    "source_",
    "global_session_uid",
    "global_segment_uid",
    "pair_id",
    "profile_id",
    "capture_id",
)


@dataclass(frozen=True)
class ReferenceDataset:
    root: Path
    pipeline_office: pd.DataFrame
    pipeline_added: pd.DataFrame
    pipeline_original: pd.DataFrame
    arkime_office: pd.DataFrame
    arkime_added: pd.DataFrame
    matched_office: pd.DataFrame
    matched_added: pd.DataFrame
    matched_mixed: pd.DataFrame
    session_comparison: pd.DataFrame
    feature_columns: tuple[str, ...]


def model_feature_columns(df: pd.DataFrame, dictionary: Iterable[dict]) -> list[str]:
    declared = [
        row["column"]
        for row in dictionary
        if row.get("kind") == "feature" and row.get("column") in df.columns
    ]
    result: list[str] = []
    for col in declared:
        low = col.lower()
        if any(fragment in low for fragment in _FORBIDDEN_FRAGMENTS):
            continue
        result.append(col)
    return result


def verify_reference_hashes(root: Path) -> None:
    manifest = json.loads((root / "DATA_MANIFEST.json").read_text())
    for row in manifest.get("tables", []):
        path = root / row["file"]
        if not path.is_file():
            raise FileNotFoundError(path)
        actual = hashlib.sha256(path.read_bytes()).hexdigest()
        expected = row.get("sha256")
        if expected and actual != expected:
            raise ValueError(f"sha256 mismatch for {row['file']}: {actual} != {expected}")


def load_reference(root: Path, *, verify_hashes: bool = False) -> ReferenceDataset:
    root = Path(root)
    if verify_hashes:
        verify_reference_hashes(root)
    loaded: dict[str, pd.DataFrame] = {}
    for attr, (filename, expected_shape) in _REQUIRED_TABLES.items():
        path = root / filename
        if not path.is_file():
            raise FileNotFoundError(path)
        frame = pd.read_parquet(path)
        if tuple(frame.shape) != expected_shape:
            raise ValueError(f"{filename} shape {tuple(frame.shape)} != {expected_shape}")
        loaded[attr] = frame
    dictionary = json.loads((root / "pipeline_column_dictionary.json").read_text())
    features = tuple(model_feature_columns(loaded["pipeline_original"], dictionary))
    if not features:
        raise ValueError("reference dataset exposes no numeric feature columns")
    return ReferenceDataset(root=root, feature_columns=features, **loaded)