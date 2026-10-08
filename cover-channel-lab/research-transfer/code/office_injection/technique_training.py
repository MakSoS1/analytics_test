"""Research-only, pair/group-held-out NDR training on corroborated MITRE rows.

This adapts the *defender model*, never original attack packets or office data.
It cannot certify real office attack recall without independent target labels.
"""

from __future__ import annotations

from collections import Counter
from hashlib import sha256
import json
from pathlib import Path

import joblib
import numpy as np
import pandas as pd
from sklearn.ensemble import HistGradientBoostingClassifier
from sklearn.impute import SimpleImputer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import roc_auc_score
from sklearn.pipeline import make_pipeline
from sklearn.preprocessing import OneHotEncoder, RobustScaler

from natural_traffic.corpus_splits import assert_split_independence, connected_component_ids
from natural_traffic.office_day_transfer import TRANSPORT_FEATURES


_ORIGIN_COLUMNS = ("capture_day_id", "measurement_vantage", "extractor_version", "runtime_profile_id")


def _sha(path: Path) -> str:
    h = sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def _measured_model(seed: int):
    return make_pipeline(
        SimpleImputer(strategy="median", keep_empty_features=True),
        RobustScaler(),
        HistGradientBoostingClassifier(
            max_iter=90, max_leaf_nodes=12, min_samples_leaf=8,
            learning_rate=.08, early_stopping=False, random_state=seed,
        ),
    )


def _provenance_model(seed: int):
    return make_pipeline(
        OneHotEncoder(handle_unknown="ignore"),
        LogisticRegression(max_iter=200, class_weight="balanced", random_state=seed),
    )


def train_technique_models(
    prepared_dir: Path, splits: pd.Series, feature_contract: dict, out: Path, *,
    seed: int = 20261008, control_alert_budget: float = .01,
) -> dict:
    """Train one binary technique-vs-matched-control research detector per ID."""
    root = Path(prepared_dir)
    out = Path(out)
    if out.exists():
        raise FileExistsError(out)
    if not .001 <= control_alert_budget <= .1:
        raise ValueError("control_alert_budget outside [0.001, 0.1]")
    saved = json.loads((root / "corpus_manifest.json").read_text())
    for file, expected in saved["outputs"].items():
        if file not in {"features.parquet", "labels_metadata.parquet"} or _sha(root / file) != expected:
            raise ValueError("prepared corpus checksum mismatch")
    x = pd.read_parquet(root / "features.parquet")
    meta = pd.read_parquet(root / "labels_metadata.parquet")
    if len(x) != len(meta) or len(x) != len(splits):
        raise ValueError("feature/label/split alignment mismatch")
    assert_split_independence(meta, splits)
    features = feature_contract.get("feature_columns")
    if not isinstance(features, list) or len(features) < 12 or len(set(features)) != len(features):
        raise ValueError("invalid frozen measured feature contract")
    if any(name not in TRANSPORT_FEATURES or name not in x.columns for name in features):
        raise ValueError("unmeasured or identity features forbidden in model X")
    schema_hash = sha256(json.dumps(features, separators=(",", ":")).encode()).hexdigest()
    if feature_contract.get("feature_schema_sha256") != schema_hash:
        raise ValueError("feature contract checksum mismatch")
    technique_ids = sorted({str(t) for t in meta.loc[
        meta["label_binary"].eq(1), "technique_id"
    ].dropna().unique()})
    if not technique_ids:
        raise ValueError("no verified technique labels")
    independent_components = connected_component_ids(meta)
    sp = np.asarray(splits)
    model_x = x[features].apply(pd.to_numeric, errors="coerce")
    model_x = model_x.replace([np.inf, -np.inf], np.nan)
    validated = {}
    artifacts = {}
    for technique in technique_ids:
        eligible = meta["technique_id"].eq(technique) & meta["label_binary"].isin((0, 1))
        if not eligible.any():
            continue
        technique_report = {"evidence_tiers": sorted(meta.loc[eligible, "evidence_tier"].unique().tolist())}
        for stage in ("train", "validation", "test"):
            mask = eligible.to_numpy() & (sp == stage)
            groups = set(independent_components[mask])
            if len(groups) < 2 or len(set(meta.loc[mask, "label_binary"])) != 2:
                raise ValueError(f"technique {technique} requires both classes and >=2 independent {stage} groups")
            technique_report[f"{stage}_groups"] = len(groups)
            technique_report[f"{stage}_rows"] = int(mask.sum())

        tr = eligible.to_numpy() & (sp == "train")
        va = eligible.to_numpy() & (sp == "validation")
        train_x = model_x.loc[tr, features]
        train_y = meta.loc[tr, "label_binary"].astype(int).to_numpy()
        val_x = model_x.loc[va, features]
        val_y = meta.loc[va, "label_binary"].astype(int).to_numpy()
        components = independent_components[tr]
        group_sizes = Counter(components)
        weight = np.array([1. / group_sizes[c] for c in components], dtype=float)
        weight /= weight.mean()
        technique_report["max_train_group_weight_fraction"] = float(max(
            sum(weight[np.asarray(components) == group]) / weight.sum()
            for group in group_sizes
        ))
        measured = _measured_model(seed)
        measured.fit(train_x, train_y, histgradientboostingclassifier__sample_weight=weight)
        baseline = _measured_model(seed)
        baseline.fit(train_x, train_y)
        val_scores = measured.predict_proba(val_x)[:, 1]
        control_scores = val_scores[val_y == 0]
        threshold = float(np.quantile(control_scores, 1 - control_alert_budget))
        origin_x = meta.loc[:, list(_ORIGIN_COLUMNS)].fillna("unknown").astype(str)
        provenance = _provenance_model(seed)
        provenance.fit(origin_x.loc[tr], train_y)
        provenance_val = provenance.predict_proba(origin_x.loc[va])[:, 1]
        shuffled = _measured_model(seed)
        random_y = np.random.default_rng(seed).permutation(train_y)
        shuffled.fit(train_x, random_y, histgradientboostingclassifier__sample_weight=weight)
        technique_report.update({
            "validation_threshold": threshold,
            "validation_roc_auc": float(roc_auc_score(val_y, val_scores)),
            "unweighted_validation_auc": float(roc_auc_score(val_y, baseline.predict_proba(val_x)[:, 1])),
            "shuffled_label_validation_auc": float(roc_auc_score(val_y, shuffled.predict_proba(val_x)[:, 1])),
            "provenance_only_validation_auc": float(roc_auc_score(val_y, provenance_val)),
            "research_evidence_eligible": technique_report["evidence_tiers"] == ["independently_verified"],
            "feature_count": len(features),
        })
        artifacts[technique] = {
            "model": measured, "unweighted_baseline": baseline,
            "shuffled_label_model": shuffled, "provenance_only_model": provenance,
            "feature_order": features, "origin_fields": list(_ORIGIN_COLUMNS),
            "validation_threshold": threshold,
            "technique_id": technique, "source_corpus_sha256": _sha(root / "corpus_manifest.json"),
            "feature_schema_sha256": schema_hash,
            "production_ready": False,
        }
        validated[technique] = technique_report
    out.mkdir(parents=True)
    (out / "models").mkdir()
    split_rows = pd.DataFrame({"row_index": np.arange(len(sp), dtype="int64"), "split": sp})
    split_rows.to_parquet(out / "splits.parquet", index=False)
    checksums = {}
    for technique, artifact in artifacts.items():
        filename = f"models/{technique}.joblib"
        joblib.dump(artifact, out / filename)
        checksums[filename] = _sha(out / filename)
    report = {
        "version": "defender-mitre-training-v1",
        "method": "group_weighted_HGB_with_frozen_unweighted_and_negative_controls",
        "techniques": validated,
        "feature_columns": features,
        "feature_schema_sha256": schema_hash,
        "threshold_fit": "validation_controls_only",
        "office_holdout_used_for_model_selection": False,
        "sources_immutable": True,
        "source_corpus_sha256": _sha(root / "corpus_manifest.json"),
        "model_checksums": checksums,
        "split_checksum": _sha(out / "splits.parquet"),
        "technique_research_validated": False,  # Evaluator owns this gate.
        "office_naturalness_proven": False,
        "production_ready": False,
    }
    (out / "training_report.json").write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")
    return report
