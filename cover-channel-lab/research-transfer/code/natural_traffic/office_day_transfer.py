"""Measurement-aware evaluation for the additional September office days.

This diagnostic is intentionally not an attack generator, PCAP writer,
naturalness optimizer, or training-permission gate. No record-level data or
HMAC identifiers are written to its output.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path

import numpy as np
import pandas as pd

from .evaluation import evaluate_c2st
from .office_feature_baseline import fit_numeric_office_copula

# Frozen before reading new-day distributions, not selected by favorable AUC.
# Ports/days/identifiers, TLS, SSH, DNS, ICMP and clock features are excluded.
TRANSPORT_FEATURES = (
    "pkt_count", "up_pkt_count", "down_pkt_count",
    "total_bytes", "up_bytes", "down_bytes",
    "flow_duration", "up_down_pkt_ratio", "up_down_bytes_ratio",
    "pkt_rate", "byte_rate",
    "pkt_len_mean", "pkt_len_std", "pkt_len_min", "pkt_len_max",
    "pkt_len_median", "pkt_len_p10", "pkt_len_p90", "pkt_len_entropy",
    "iat_mean", "iat_std", "iat_min", "iat_max", "iat_p90",
    "burst_count", "idle_ratio", "direction_changes",
    "syn_count", "fin_count", "rst_count",
    "iat_entropy", "iat_cv", "iat_p50", "iat_p99", "iat_regularity",
    "len_entropy_up", "len_entropy_down",
    "len_unique_up", "len_unique_down", "small_pkt_share",
    "low_rate_long", "dir_entropy", "idle_gt60_count",
    "up_bytes_per_pkt", "down_bytes_per_pkt", "const_len_share_up",
    "pkt_len_p95", "psh_count", "ack_count", "urg_count",
    "flow_boundary_count", "burst_len_mean", "burst_len_max",
    "dir_burst_count", "dir_burst_len_mean", "dir_burst_len_max",
    "tcp_handshake_rtt_ms", "data_pkt_up", "data_pkt_down",
    "small_data_up_bytes", "closed_cleanly",
)

DERIVED_CHECKS = {
    "packet_count": ("pkt_count", "up_pkt_count", "down_pkt_count"),
    "byte_count": ("total_bytes", "up_bytes", "down_bytes"),
}


def _sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def load_additional_days(root: Path, *, verify_hashes: bool = True) -> tuple[pd.DataFrame, pd.DataFrame]:
    root = Path(root)
    manifest = json.loads((root / "DATA_MANIFEST.json").read_text())
    paths = [root / "office_day_02.parquet", root / "office_day_03.parquet"]
    rows = {entry["file"]: entry for entry in manifest["tables"]}
    frames: list[pd.DataFrame] = []
    for path, expected_rows in zip(paths, (4000, 4002)):
        if verify_hashes and _sha256_file(path) != rows[path.name]["sha256"]:
            raise ValueError(f"reference SHA256 mismatch for {path.name}")
        frame = pd.read_parquet(path)
        if frame.shape != (expected_rows, 158):
            raise ValueError(f"unexpected office snapshot shape: {path.name} {frame.shape}")
        frames.append(frame)
    left, right = frames
    if list(left.columns) != list(right.columns):
        raise ValueError("office days have different column orders")
    if len(set(left["capture_day_id"].astype(str))) != 1 or len(set(right["capture_day_id"].astype(str))) != 1:
        raise ValueError("capture_day_id must be constant within each day")
    if left["capture_day_id"].iloc[0] == right["capture_day_id"].iloc[0]:
        raise ValueError("two files reuse the same capture_day_id")
    if set(left["independent_source_group"].astype(str)).intersection(
        right["independent_source_group"].astype(str)
    ):
        raise ValueError("source groups overlap across days")
    for frame in frames:
        if not (frame["source_session_group"] == frame["global_session_uid"]).all():
            raise ValueError("source_session_group disagrees with global_session_uid")
        if frame["independent_source_group"].isna().any():
            raise ValueError("missing independent_source_group")
    return left, right


def transport_columns(a: pd.DataFrame, b: pd.DataFrame, *, required_present_share: float = 0.9) -> list[str]:
    if not 0 < required_present_share <= 1:
        raise ValueError("required_present_share must be in (0, 1]")
    selected: list[str] = []
    for col in TRANSPORT_FEATURES:
        if col not in a or col not in b:
            continue
        if not pd.api.types.is_numeric_dtype(a[col].dtype) or not pd.api.types.is_numeric_dtype(b[col].dtype):
            continue
        if min(float(a[col].notna().mean()), float(b[col].notna().mean())) < required_present_share:
            continue
        selected.append(col)
    return selected


def _audit_sequences(frame: pd.DataFrame) -> dict[str, int]:
    columns = ("seq_signed_len", "seq_iat_us", "seq_flags")
    if not all(c in frame for c in columns):
        return {"rows": len(frame), "missing_sequence_columns": len(columns)}
    inconsistent = 0
    empty = 0
    count_mismatch = 0
    invalid_counts = 0
    counts = pd.to_numeric(frame["pkt_count"], errors="coerce") if "pkt_count" in frame else None
    for i, (lengths, iats, flags) in enumerate(zip(*(frame[c] for c in columns))):
        sizes = [len(v) if v is not None else 0 for v in (lengths, iats, flags)]
        if len(set(sizes)) != 1:
            inconsistent += 1
        if max(sizes) == 0:
            empty += 1
        if counts is not None:
            raw = counts.iloc[i]
            if pd.isna(raw) or not np.isfinite(float(raw)) or raw < 0 or float(raw) != int(raw):
                invalid_counts += 1
            elif any(size != int(raw) for size in sizes):
                count_mismatch += 1
    return {
        "rows": int(len(frame)),
        "sequence_length_mismatches": inconsistent,
        "sequence_vs_pkt_count_mismatches": count_mismatch,
        "invalid_pkt_counts": invalid_counts,
        "empty_sequences": empty,
    }


def _consistency(frame: pd.DataFrame) -> dict[str, dict[str, int]]:
    report: dict[str, dict[str, int]] = {}
    for title, (total, up, down) in DERIVED_CHECKS.items():
        if not all(c in frame for c in (total, up, down)):
            continue
        vals = frame[[total, up, down]].apply(pd.to_numeric, errors="coerce")
        valid = vals.notna().all(axis=1)
        expected = vals[up] + vals[down]
        mismatch = valid & ~np.isclose(vals[total], expected, rtol=0, atol=1)
        report[title] = {
            "checked_rows": int(valid.sum()),
            "mismatched_rows": int(mismatch.sum()),
        }
    return report


def _evaluate_pair(
    a: pd.DataFrame, b: pd.DataFrame, cols: list[str],
    *, seed: int, rows_per_day: int, bootstrap_reps: int,
) -> dict[str, object]:
    a_sample = a.sample(n=min(len(a), rows_per_day), random_state=seed)
    b_sample = b.sample(n=min(len(b), rows_per_day), random_state=seed + 1)
    result = evaluate_c2st(
        a_sample.loc[:, cols], b_sample.loc[:, cols],
        {
            "office": a_sample["independent_source_group"].astype(str).tolist(),
            "controls": b_sample["independent_source_group"].astype(str).tolist(),
        },
        feature_columns=cols, bootstrap_reps=bootstrap_reps, random_state=seed,
        min_groups=30,
    )
    return {
        "status": result["status"],
        "groups": result["support"],
        "rows": {"day_02": len(a_sample), "day_03": len(b_sample)},
        "classifiers": result["classifiers"],
        "max_auc": max((float(m["auc"]) for m in result["classifiers"].values()), default=None),
    }


def analyze_additional_days(
    day02: pd.DataFrame,
    day03: pd.DataFrame,
    *,
    seed: int = 20261008,
    rows_per_day: int = 1500,
    bootstrap_reps: int = 15,
) -> dict[str, object]:
    if rows_per_day < 100:
        raise ValueError("minimum 100 rows per day")
    cols = transport_columns(day02, day03)
    if len(cols) < 20:
        return {
            "status": "insufficient_comparable_features",
            "n_transport_features": len(cols),
            "packet_level_naturalness": False,
            "production_ready": False,
        }
    # An entirely unmeasured TLS day cannot enter a pooled TLS evaluation.
    tls_day02 = int(pd.to_numeric(day02["tls_version"], errors="coerce").notna().sum())
    tls_day03 = int(pd.to_numeric(day03["tls_version"], errors="coerce").notna().sum())
    report = _evaluate_pair(
        day02, day03, cols, seed=seed, rows_per_day=rows_per_day,
        bootstrap_reps=bootstrap_reps,
    )
    # Grouped within-day holdout; do not join HMAC identities across releases.
    # This is a reference-shift measurement, not C2 origin naturalness.
    result: dict[str, object] = {
        "version": "office-additional-day-transfer-v1",
        "status": report["status"],
        "data_policy": "aggregated diagnostics, source groups held disjoint in folds",
        "scope": "measured_tcp_transport_only",
        "transport_features": cols,
        "days": {
            "day_02": {
                "rows": int(len(day02)),
                "distinct_sessions": int(day02["source_session_group"].nunique()),
                "source_groups": int(day02["independent_source_group"].nunique()),
                "tls_version_observed_rows": tls_day02,
                "sequences": _audit_sequences(day02),
                "arithmetic": _consistency(day02),
            },
            "day_03": {
                "rows": int(len(day03)),
                "distinct_sessions": int(day03["source_session_group"].nunique()),
                "source_groups": int(day03["independent_source_group"].nunique()),
                "tls_version_observed_rows": tls_day03,
                "sequences": _audit_sequences(day03),
                "arithmetic": _consistency(day03),
            },
        },
        "transport_day_02_vs_day_03": report,
        "tls_comparison": {
            "status": "not_comparable_across_days",
            "reason": "day_02_tls_unmeasured" if tls_day02 == 0 else "partial_tls_measurement",
            "missing_values_never_imputed": True,
        },
        "limitations": {
            "port_80_443_only": True,
            "preselected_minimum_six_packets": True,
            "days_previously_seen_in_diagnostics": True,
            "cross_release_hmac_linkage_permitted": False,
            "office_benign_ground_truth": False,
            "actual_tcp_tls_pcap_reconstructed": False,
            "packet_level_naturalness": False,
            "production_ready": False,
        },
    }
    return result


def _rank_transport_differences(
    office: pd.DataFrame, controls: pd.DataFrame, names: list[str]
) -> list[dict[str, object]]:
    """Univariate KS/missingness diagnostics, not a parameter optimizer."""
    from scipy.stats import ks_2samp

    rows = []
    for name in names:
        a = pd.to_numeric(office[name], errors="coerce")
        b = pd.to_numeric(controls[name], errors="coerce")
        a = a.replace([np.inf, -np.inf], np.nan)
        b = b.replace([np.inf, -np.inf], np.nan)
        x, y = a.dropna(), b.dropna()
        rows.append({
            "feature": name,
            "office_missing": round(float(a.isna().mean()), 6),
            "control_missing": round(float(b.isna().mean()), 6),
            "ks": float(ks_2samp(x, y).statistic) if len(x) and len(y) else None,
            "office_p50": float(x.median()) if len(x) else None,
            "control_p50": float(y.median()) if len(y) else None,
        })
    rows.sort(key=lambda row: (
        -max(
            row["ks"] if row["ks"] is not None else 1.,
            abs(row["office_missing"]-row["control_missing"]),
        ),
        row["feature"],
    ))
    return rows[:15]


def _comparable_tcp443_scope(frame: pd.DataFrame) -> pd.DataFrame:
    """Same predeclared 443 and >=6-packet row support for both domains.

    The stored office selection includes 80/443 and at least one >=6-packet
    segment per source session. For a conservative per-segment diagnostic,
    restrict every compared side to 443 and >=6 measured packets. We do not
    claim this reproduces the original whole-session sampling exactly.
    """
    if "dest_port" not in frame or "pkt_count" not in frame:
        raise ValueError("TCP/443 scope needs dest_port and pkt_count")
    ports = pd.to_numeric(frame["dest_port"], errors="coerce")
    counts = pd.to_numeric(frame["pkt_count"], errors="coerce")
    return frame.loc[ports.eq(443) & counts.ge(6)].copy()


def compare_generated_controls_to_office_days(
    day02: pd.DataFrame,
    day03: pd.DataFrame,
    control_confirm: pd.DataFrame,
    *,
    seed: int = 20261008,
    bootstrap_reps: int = 30,
) -> dict[str, object]:
    """Fixed-observable benign-control transfer check; no model selection or tuning.

    The frozen control pool is held fixed. Both days use the same predetermined
    common measured transport features and day-local group identities. This is
    diagnostic and cannot set production_ready or training eligibility.
    """
    names = transport_columns(day02, day03)
    missing = [name for name in names if name not in control_confirm.columns]
    if missing:
        return {
            "status": "unsupported_feature_contract",
            "missing_feature_columns": missing,
            "production_ready": False,
        }
    if "capture_group" not in control_confirm:
        return {"status": "missing_control_ancestry", "production_ready": False}
    scoped_control = _comparable_tcp443_scope(control_confirm)
    n_controls = int(scoped_control["capture_group"].astype(str).nunique())
    if n_controls < 30:
        return {
            "status": "insufficient_comparable_control_groups",
            "independent_controls": n_controls,
            "scope": "tcp_destination_443_and_segment_pkt_count_gte_6",
            "production_ready": False,
        }
    reports: dict[str, object] = {}
    for idx, (day, frame) in enumerate((("2026-09-22", day02), ("2026-09-28", day03))):
        scoped_office = _comparable_tcp443_scope(frame)
        if int(scoped_office["independent_source_group"].nunique()) < 30:
            return {
                "status": "insufficient_comparable_office_groups",
                "day": day,
                "production_ready": False,
            }
        sample = scoped_office.sample(n=min(1500, len(scoped_office)), random_state=seed + idx)
        c2st = evaluate_c2st(
            sample.loc[:, names],
            scoped_control.loc[:, names],
            {
                "office": sample["independent_source_group"].astype(str).tolist(),
                "controls": scoped_control["capture_group"].astype(str).tolist(),
            },
            feature_columns=names,
            min_groups=30,
            bootstrap_reps=bootstrap_reps,
            random_state=seed + idx,
        )
        reports[day] = {
            "status": c2st["status"],
            "support": c2st["support"],
            "office_rows": int(len(sample)),
            "control_rows": int(len(scoped_control)),
            "classifiers": c2st["classifiers"],
            "max_auc": max((float(v["auc"]) for v in c2st["classifiers"].values()), default=None),
            "largest_measured_differences": _rank_transport_differences(
                sample, scoped_control, names,
            ),
        }
    return {
        "version": "additional-day-benign-control-transfer-v1",
        "status": "diagnostic_only",
        "transport_columns": names,
        "independent_control_groups": n_controls,
        "comparison_scope": "tcp_destination_443_and_segment_pkt_count_gte_6",
        "original_session_selection_equivalence": False,
        "evaluations": reports,
        "measurement_policy": {
            "tls_from_day02_imputed": False,
            "same_transport_features_both_days": True,
            "frozen_controls_not_recalibrated": True,
            "office_labels_assumed_benign": False,
            "naturalness_gate_changes": False,
            "attack_scenario_training_allowed": False,
            "production_ready": False,
        },
    }


def main() -> None:
    p = argparse.ArgumentParser()
    p.add_argument("--root", type=Path, required=True)
    p.add_argument("--out", type=Path, required=True)
    p.add_argument("--seed", type=int, default=20261008)
    a = p.parse_args()
    d2, d3 = load_additional_days(a.root)
    report = analyze_additional_days(d2, d3, seed=a.seed)
    a.out.parent.mkdir(parents=True, exist_ok=True)
    a.out.write_text(json.dumps(report, sort_keys=True, indent=2, allow_nan=False) + "\n")
    print(json.dumps({
        "status": report["status"],
        "transport_max_auc": report["transport_day_02_vs_day_03"]["max_auc"] if report["status"] == "ok" else None,
        "transport_features": len(report.get("transport_features", [])),
        "tls": report.get("tls_comparison"),
        "packet_sequence_integrity": {
            day: {
                key: stats["sequences"].get(key, -1)
                for key in (
                    "sequence_length_mismatches",
                    "sequence_vs_pkt_count_mismatches",
                    "invalid_pkt_counts",
                    "empty_sequences",
                )
            }
            for day, stats in report.get("days", {}).items()
        },
    }, sort_keys=True))
    if report["status"] != "ok":
        raise SystemExit("insufficient comparable office reference data")
    for day, stats in report.get("days", {}).items():
        seq = stats["sequences"]
        if any(seq.get(key, 1) for key in (
            "sequence_length_mismatches",
            "sequence_vs_pkt_count_mismatches",
            "invalid_pkt_counts",
            "empty_sequences",
        )):
            raise SystemExit(f"{day}: packet-sequence integrity failure")


if __name__ == "__main__":
    main()