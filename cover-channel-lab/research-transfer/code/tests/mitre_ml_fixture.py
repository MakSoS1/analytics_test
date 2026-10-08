"""Synthetic measured-table fixtures; never evidence of actual ATT&CK performance."""

from hashlib import sha256
import json
from pathlib import Path

import numpy as np
import pandas as pd

from natural_traffic.office_day_transfer import TRANSPORT_FEATURES
from natural_traffic.corpus_splits import assert_split_independence


FEATURES = list(TRANSPORT_FEATURES[:18])
TECHNIQUES = ("T1001", "T1071.001")


def sha(path):
    return sha256(Path(path).read_bytes()).hexdigest()


def make_prepared(
    root: Path, *, label_effect: bool = True, evidence_tier: str = "fixture_only",
    provenance_shortcut: bool = False, rows_per_arm: int = 6,
):
    root.mkdir(parents=True)
    rng = np.random.default_rng(16)
    x_rows, metadata, split_values = [], [], []
    for technique in TECHNIQUES:
        for group in range(12):
            split = "train" if group < 8 else "validation" if group < 10 else "test"
            for role in (0, 1):
                for j in range(rows_per_arm):
                    source = f"{technique}-g{group}-role{role}"
                    # Provenance artifact does not enter the measured model X.
                    base = 3.0 + (10.0 * role if label_effect else 0.0)
                    values = rng.normal(base, .35, size=len(FEATURES))
                    x_rows.append({name: float(values[i]) for i, name in enumerate(FEATURES)})
                    metadata.append({
                        "row_index": len(metadata), "source_id": source,
                        "source_sha256": sha256(source.encode()).hexdigest(),
                        "session_key": f"s-{technique}-{group}-{role}-{j}",
                        "technique_id": technique, "label_binary": role,
                        "label_state": "verified_positive" if role else "matched_control",
                        "evidence_tier": evidence_tier,
                        "pair_id": f"{technique}-pair-{group}",
                        "parent_campaign_id": f"{technique}-campaign-{group}",
                        "capture_group_id": source,
                        "runtime_profile_id": f"{technique}-profile-{group}",
                        "capture_day_id": f"2026-09-{23 if role else 22}" if provenance_shortcut else "2026-09-22",
                        "measurement_vantage": "lab-upstream" if provenance_shortcut and role else "lab-nic",
                        "extractor_version": "synthetic-fixture-v1",
                    })
                    split_values.append(split)
    x = pd.DataFrame(x_rows)
    meta = pd.DataFrame(metadata)
    splits = pd.Series(split_values, name="split")
    assert_split_independence(meta, splits)
    x.to_parquet(root / "features.parquet", index=False)
    meta.to_parquet(root / "labels_metadata.parquet", index=False)
    (root / "corpus_manifest.json").write_text(json.dumps({
        "version": "verified-defender-corpus-v1", "feature_columns": FEATURES,
        "outputs": {name: sha(root / name) for name in ("features.parquet", "labels_metadata.parquet")},
        "production_ready": False,
    }))
    schema_hash = sha256(json.dumps(FEATURES, separators=(",", ":")).encode()).hexdigest()
    contract = {"feature_columns": FEATURES, "feature_schema_sha256": schema_hash,
                "office_labels": "unknown_unverified", "production_ready": False}
    return splits, contract
