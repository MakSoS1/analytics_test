"""Read-only, provenance-aware office-domain ML preparation.

A user capture is evidence: never re-time, rewrite, overlay, or camouflage it.
The *defender's* feature representation/model may be adapted to a target office
domain. Unverified office sessions are not automatically labelled benign.
"""
from __future__ import annotations

import argparse
from hashlib import sha256
import json
from pathlib import Path

import numpy as np
import pandas as pd

from .office_day_transfer import TRANSPORT_FEATURES, load_additional_days

LABELS = {"unlabeled": -1, "verified_benign": 0, "verified_malicious": 1}
PROVENANCE = ("domain", "group_id", "label", "label_policy", "capture_day")


def _digest(path: Path) -> str:
    h = sha256()
    with path.open("rb") as f:
        for block in iter(lambda: f.read(1 << 20), b""):
            h.update(block)
    return h.hexdigest()


def _validate_measured_features(table: pd.DataFrame, *, minimum: int = 12) -> None:
    """Reject raw events and sparse/non-numeric tables at the import boundary.

    This cannot establish provenance: a caller must separately attest how
    each field was measured and the authenticity of any claimed labels.
    """
    if table.empty:
        raise ValueError("input generated zero feature rows")
    valid = []
    for column in TRANSPORT_FEATURES:
        if column not in table:
            continue
        numeric = pd.to_numeric(table[column], errors="coerce")
        finite = numeric.replace([np.inf, -np.inf], np.nan).notna()
        if float(finite.mean()) >= 0.8:
            valid.append(column)
    if len(valid) < minimum:
        raise ValueError(
            f"input contains only {len(valid)} well-observed measured transport "
            f"features; at least {minimum} numeric columns with 80% finite "
            "values are required. Raw Zeek/Suricata events require their own "
            "provenance-aware feature extractor"
        )


def load_user_input(path: Path, work: Path, *, min_free_gib: float = 1) -> tuple[pd.DataFrame, dict]:
    """Load immutable measured features or a classic Ethernet PCAP."""
    p = Path(path)
    if not p.is_file():
        raise FileNotFoundError(p)
    source_hash = _digest(p)
    if p.suffix.lower() == ".parquet":
        table = pd.read_parquet(p)
        source_info = {"format": "parquet", "extractor": "already_extracted"}
    elif p.suffix.lower() in {".csv", ".tsv", ".jsonl"}:
        file_format = p.suffix.lower().lstrip(".")
        if file_format == "jsonl":
            table = pd.read_json(p, lines=True, orient="records")
        else:
            table = pd.read_csv(p, sep="\t" if file_format == "tsv" else ",")
        source_info = {
            "format": file_format,
            "extractor": "already_extracted_unverified",
        }
    elif p.suffix.lower() == ".pcap":
        from .pcap_quality import audit_pcap
        from .contracts import CaptureBundle
        from .composition import extract_pipeline_capture
        quality = audit_pcap(p)
        if not quality.accepted:
            raise ValueError(f"invalid PCAP: {quality.reasons}")
        # The production extractor temporarily writes raw packet/payload
        # sidecars. Destroy those intermediates after deriving safe features.
        # Nothing in this tool needs to retain their cleartext contents.
        from tempfile import TemporaryDirectory
        with TemporaryDirectory(prefix="neutral-extract-", dir=work) as scratch:
            scratch = Path(scratch)
            meta = scratch / "neutral_input_metadata.json"
            meta.write_text(json.dumps({
                "role_semantics": "extractor_internal_only_not_a_training_label",
                "uploaded_pcap_sha256": source_hash,
                "version": "neutral-pcap-extraction-v1",
            }) + "\n")
            bundle = CaptureBundle(
                pair_id="input-" + source_hash[:20],
                role="control",  # Extractor contract only; not a benign label.
                profile_id="external-unverified",
                fidelity="untouched-upload",
                pcap_path=p, pcap_sha256=source_hash,
                evidence=(),
                runtime_metadata_path=meta,
                runtime_metadata_sha256=_digest(meta),
            )
            extraction = extract_pipeline_capture(
                bundle, scratch / "extracted",
                run_id="defender-input-" + source_hash[:12],
                min_free_gib=min_free_gib,
            )
            table = pd.read_parquet(extraction.parquet_path)
            extracted_rows = extraction.rows
        source_info = {
            "format": "pcap",
            "extractor": "production_office_sessions_pipeline",
            "physical_frames": quality.packet_count,
            "extraction_rows": extracted_rows,
            "raw_capture_rewritten": False,
            "raw_intermediates_retained": False,
        }
    else:
        raise ValueError(
            "supported inputs: .pcap, .parquet, .csv, .tsv, .jsonl; "
            "unsupported formats fail closed"
        )
    if _digest(p) != source_hash:
        raise RuntimeError("source changed during reading")
    _validate_measured_features(table)
    source_info["source_sha256"] = source_hash
    source_info["rows"] = int(len(table))
    return table, source_info


def _safe_group_ids(frame: pd.DataFrame, domain: str, *, fallback: str) -> pd.Series:
    for column in ("independent_source_group", "capture_group", "global_session_uid"):
        if column in frame and frame[column].notna().all():
            values = frame[column].astype(str)
            if not values.str.strip().eq("").any():
                return values.map(lambda s: domain + ":" + sha256(
                    (fallback + ":" + s).encode("utf-8")
                ).hexdigest()[:24])
    return pd.Series([domain + ":" + fallback[:24]] * len(frame), index=frame.index)


def shared_transport_columns(
    source: pd.DataFrame, office_train: pd.DataFrame, office_holdout: pd.DataFrame,
    *, minimum: int = 12,
) -> list[str]:
    """Predeclared features only: no identities, labels, TLS null-reconstruction."""
    cols = []
    for column in TRANSPORT_FEATURES:
        if any(column not in table for table in (source, office_train, office_holdout)):
            continue
        vectors = [pd.to_numeric(table[column], errors="coerce")
                   for table in (source, office_train, office_holdout)]
        if all(float(v.replace([np.inf, -np.inf], np.nan).notna().mean()) >= 0.8
               for v in vectors):
            cols.append(column)
    if len(cols) < minimum:
        raise ValueError(f"only {len(cols)} comparable observed features; need {minimum}")
    return cols


def prepare_frames(
    source: pd.DataFrame,
    office_train: pd.DataFrame,
    office_holdout: pd.DataFrame,
    *,
    source_sha256: str,
    source_label: str = "unlabeled",
    minimum_features: int = 12,
) -> tuple[pd.DataFrame, pd.DataFrame, pd.DataFrame, dict]:
    if source_label not in LABELS:
        raise ValueError("source label must be explicit: " + ", ".join(LABELS))
    if not source_sha256 or len(source_sha256) != 64:
        raise ValueError("source digest required")
    if any(frame.empty for frame in (source, office_train, office_holdout)):
        raise ValueError("empty source or reference table")
    for name, frame in (("train", office_train), ("holdout", office_holdout)):
        if "independent_source_group" not in frame or frame["independent_source_group"].isna().any():
            raise ValueError(f"office {name} requires independent client groups")
    left_groups = set(office_train["independent_source_group"].astype(str))
    right_groups = set(office_holdout["independent_source_group"].astype(str))
    if left_groups & right_groups:
        raise ValueError("office train/holdout group leakage")
    columns = shared_transport_columns(
        source, office_train, office_holdout, minimum=minimum_features,
    )

    def part(frame: pd.DataFrame, domain: str, label: int, label_policy: str) -> pd.DataFrame:
        result = pd.DataFrame(index=frame.index)
        for col in columns:
            s = pd.to_numeric(frame[col], errors="coerce")
            result[col] = s.replace([np.inf, -np.inf], np.nan).astype("float64")
        result["domain"] = domain
        result["group_id"] = _safe_group_ids(
            frame, domain, fallback=source_sha256
        ).to_numpy()
        result["label"] = int(label)
        result["label_policy"] = label_policy
        result["capture_day"] = domain if domain.startswith("office_") else "unknown"
        return result.reset_index(drop=True)

    office_a = part(office_train, "office_train", -1, "unverified")
    office_b = part(office_holdout, "office_holdout", -1, "unverified")
    user = part(source, "user_input", LABELS[source_label], source_label)
    if office_a["group_id"].nunique() < 10 or office_b["group_id"].nunique() < 10:
        raise ValueError("at least 10 distinct office client groups needed per day")
    train = pd.concat([office_a, user], ignore_index=True)
    manifest = {
        "version": "defender-office-domain-preparation-v1",
        "source_sha256": source_sha256,
        "source_label": source_label,
        "feature_columns": columns,
        "source_rows": int(len(user)),
        "office_train_rows": int(len(office_a)),
        "office_holdout_rows": int(len(office_b)),
        "office_train_groups": int(office_a["group_id"].nunique()),
        "office_holdout_groups": int(office_b["group_id"].nunique()),
        "source_groups": int(user["group_id"].nunique()),
        "office_labels": "unverified_and_unlabeled",
        "source_pcap_rewritten": False,
        "office_holdout_excluded_from_fitting": True,
        "origin_metadata_excluded_from_model_X": True,
        "office_naturalness_proven": False,
        "production_ready": False,
    }
    return train, office_b, user, manifest


def prepare(
    input_path: Path, office_dir: Path, out: Path, *,
    source_label: str = "unlabeled", min_free_gib: float = 1,
) -> dict:
    out = Path(out)
    if out.exists():
        raise FileExistsError(out)
    out.mkdir(mode=0o700, parents=True)
    out.chmod(0o700)
    source, source_info = load_user_input(
        input_path, out, min_free_gib=min_free_gib,
    )
    day_a, day_b = load_additional_days(office_dir, verify_hashes=True)
    train, holdout, user, report = prepare_frames(
        source, day_a, day_b,
        source_sha256=source_info["source_sha256"],
        source_label=source_label,
    )
    for name, frame in (
        ("train_candidates.parquet", train),
        ("office_holdout.parquet", holdout),
        ("user_input.parquet", user),
    ):
        frame.to_parquet(out / name, index=False)
    report["input"] = source_info
    report["outputs"] = {
        name: _digest(out / name) for name in
        ("train_candidates.parquet", "office_holdout.parquet", "user_input.parquet")
    }
    if _digest(Path(input_path)) != source_info["source_sha256"]:
        raise RuntimeError("source changed during dataset preparation")
    (out / "manifest.json").write_text(json.dumps(report, sort_keys=True, indent=2) + "\n")
    return report


def diagnostic_office_baseline(out: Path, *, seed: int = 20261008,
                               train_alert_budget: float = .01) -> dict:
    """Fit a defender-only anomaly detector to office TRAIN, not user packets.

    Since reference office traffic is UNLABELLED, evaluate alert RATE rather
    than falsely reporting false-positive rate or attack recall.
    """
    from sklearn.ensemble import IsolationForest
    from sklearn.impute import SimpleImputer
    from sklearn.pipeline import make_pipeline
    from sklearn.preprocessing import RobustScaler
    if not 0.001 <= train_alert_budget <= 0.1:
        raise ValueError("invalid diagnostic alert budget")
    root = Path(out)
    manifest = json.loads((root / "manifest.json").read_text())
    cols = manifest["feature_columns"]
    for name, digest in manifest["outputs"].items():
        if _digest(root / name) != digest:
            raise ValueError("prepared table checksum mismatch")
    candidates = pd.read_parquet(root / "train_candidates.parquet")
    holdout = pd.read_parquet(root / "office_holdout.parquet")
    uploaded = pd.read_parquet(root / "user_input.parquet")
    office_train = candidates.loc[candidates["domain"].eq("office_train")]
    if office_train["label"].ne(-1).any() or holdout["label"].ne(-1).any():
        raise ValueError("office data must remain unverified")
    model = make_pipeline(
        SimpleImputer(strategy="median", keep_empty_features=True),
        RobustScaler(),
        IsolationForest(n_estimators=120, max_samples=256,
                        random_state=seed, n_jobs=1),
    )
    model.fit(office_train[cols])
    baseline_scores = -model.score_samples(office_train[cols])
    cutoff = float(np.quantile(baseline_scores, 1 - train_alert_budget))
    eval_scores = -model.score_samples(holdout[cols])
    source_scores = -model.score_samples(uploaded[cols])
    result = {
        "version": "defender-office-anomaly-diagnostic-v1",
        "method": "isolation_forest_train_day_only",
        "model_features": len(cols),
        "threshold_fit": "office_train_only",
        "requested_train_alert_budget": train_alert_budget,
        "actual_train_alert_fraction": float(np.mean(baseline_scores > cutoff)),
        "office_holdout_alert_fraction": float(np.mean(eval_scores > cutoff)),
        "uploaded_input_alert_fraction": float(np.mean(source_scores > cutoff)),
        "uploaded_input_label": manifest["source_label"],
        "uploaded_input_group_count": manifest["source_groups"],
        "statistics_are_not_fpr_or_recall": True,
        "holdout_office_traffic_not_verified_benign": True,
        "no_original_traffic_modified": True,
        "office_naturalness_proven": False,
        "production_ready": False,
    }
    (root / "baseline_report.json").write_text(
        json.dumps(result, sort_keys=True, indent=2) + "\n"
    )
    return result


def main() -> None:
    p = argparse.ArgumentParser(description="Prepare immutable user traffic for defensive office-domain ML")
    sub = p.add_subparsers(dest="command", required=True)
    prep = sub.add_parser("prepare")
    prep.add_argument("--input", type=Path, required=True)
    prep.add_argument("--office-dir", type=Path, required=True)
    prep.add_argument("--out", type=Path, required=True)
    prep.add_argument("--source-label", choices=tuple(LABELS), default="unlabeled")
    prep.add_argument("--min-free-gib", type=float, default=1)
    baseline = sub.add_parser("baseline")
    baseline.add_argument("--prepared", type=Path, required=True)
    baseline.add_argument("--alert-budget", type=float, default=.01)
    a = p.parse_args()
    if a.command == "prepare":
        report = prepare(
            a.input, a.office_dir, a.out,
            source_label=a.source_label, min_free_gib=a.min_free_gib,
        )
    else:
        report = diagnostic_office_baseline(
            a.prepared, train_alert_budget=a.alert_budget,
        )
    print(json.dumps(report, sort_keys=True))


if __name__ == "__main__":
    main()
