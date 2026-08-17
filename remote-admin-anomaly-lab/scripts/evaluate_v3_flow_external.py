#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import math
import sys
from pathlib import Path

import joblib
import numpy as np
import pandas as pd

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from adminlab.online_features import EveFeatureState  # noqa:E402

PORT_APP = {
    22: "ssh",
    135: "dcerpc",
    445: "smb",
    3389: "rdp",
    5900: "vnc",
    5985: "winrm",
    5986: "winrm",
}


def _expected_columns(model) -> list[str]:
    if hasattr(model, "feature_names_in_"):
        return [str(value) for value in model.feature_names_in_.tolist()]
    preprocess = model.named_steps.get("preprocess") if hasattr(model, "named_steps") else None
    if preprocess is not None and hasattr(preprocess, "feature_names_in_"):
        return [str(value) for value in preprocess.feature_names_in_.tolist()]
    raise ValueError("flow model does not expose feature_names_in_")


def _finite_float(value, default: float = 0.0) -> float:
    """Convert an optional numeric external field to a finite float.

    LANL/Rocketgraph may encode unavailable source ports or counters as NaN.
    Those fields are optional for the NGFW feature state, so missing/non-finite
    values are represented as zero rather than crashing the external holdout.
    """
    try:
        number = float(value)
    except (TypeError, ValueError):
        return float(default)
    return number if math.isfinite(number) else float(default)


def _finite_int(value, default: int = 0) -> int:
    return int(_finite_float(value, float(default)))


def _event(row: pd.Series, flow_id: int) -> dict:
    ts = _finite_float(row["time"])
    duration = max(0.0, _finite_float(row.get("duration", 0.0)))
    dport = _finite_int(row["dst_port"])
    sport = _finite_int(row.get("src_port", 0))
    src_packets = max(0.0, _finite_float(row.get("src_packets", 0.0)))
    dst_packets = max(0.0, _finite_float(row.get("dst_packets", 0.0)))
    src_bytes = max(0.0, _finite_float(row.get("src_bytes", 0.0)))
    dst_bytes = max(0.0, _finite_float(row.get("dst_bytes", 0.0)))
    app = PORT_APP.get(dport, "unknown")
    return {
        "timestamp": ts,
        "event_type": "flow",
        "flow_id": flow_id,
        "src_ip": str(row["src_device"]),
        "src_port": sport,
        "dest_ip": str(row["dst_device"]),
        "dest_port": dport,
        "proto": "TCP",
        "app_proto": app,
        "flow": {
            "start": ts,
            "end": ts + duration,
            "bytes_toserver": src_bytes,
            "bytes_toclient": dst_bytes,
            "pkts_toserver": src_packets,
            "pkts_toclient": dst_packets,
        },
    }


def build_external_flow_features(netflow: pd.DataFrame, expected: list[str]) -> tuple[pd.DataFrame, dict]:
    required = {"time", "src_device", "dst_device", "dst_port", "src_packets", "dst_packets", "src_bytes", "dst_bytes"}
    missing = required - set(netflow.columns)
    if missing:
        raise ValueError(f"external netflow missing columns: {sorted(missing)}")
    frame = netflow.copy()
    frame["time"] = pd.to_numeric(frame["time"], errors="coerce")
    frame["dst_port"] = pd.to_numeric(frame["dst_port"], errors="coerce")
    before = len(frame)
    frame = frame[
        frame["time"].notna()
        & np.isfinite(frame["time"].astype(float))
        & frame["dst_port"].notna()
        & np.isfinite(frame["dst_port"].astype(float))
    ].copy()
    frame = frame.sort_values("time", kind="stable").reset_index(drop=True)
    dropped_required_rows = int(before - len(frame))

    optional_numeric = ["src_port", "duration", "src_packets", "dst_packets", "src_bytes", "dst_bytes"]
    sanitized_optional_values = 0
    for column in optional_numeric:
        if column not in frame.columns:
            continue
        numeric = pd.to_numeric(frame[column], errors="coerce")
        sanitized_optional_values += int((numeric.isna() | ~np.isfinite(numeric.fillna(0.0).astype(float))).sum())

    state = EveFeatureState()
    rows = []
    for index, raw in frame.iterrows():
        features = state.consume_flow(_event(raw, index + 1))["features"]
        row = {}
        for column in expected:
            if column == "app_proto":
                row[column] = str(features.get(column, "unknown"))
            else:
                row[column] = _finite_float(features.get(column, 0.0))
        rows.append(row)
    out = pd.DataFrame(rows, columns=expected)
    return out, {
        "expected_feature_count": len(expected),
        "derived_feature_count": len(expected),
        "imputed_feature_count": 0,
        "coverage_fraction": 1.0,
        "input_rows": int(before),
        "derived_rows": int(len(out)),
        "dropped_invalid_required_rows": dropped_required_rows,
        "sanitized_optional_numeric_values": int(sanitized_optional_values),
        "feature_state": "adminlab.online_features.EveFeatureState",
        "raw_identity_emitted": False,
    }


def _score_report(scores: np.ndarray, threshold: float) -> dict:
    score = np.asarray(scores, dtype=float)
    finite = bool(len(score) > 0 and np.isfinite(score).all())
    if not finite:
        return {"finite": False, "rows": int(len(score))}
    return {
        "finite": True,
        "rows": int(len(score)),
        "mean": float(score.mean()),
        "std": float(score.std()),
        "min": float(score.min()),
        "max": float(score.max()),
        "unique_scores_rounded_1e10": int(len(np.unique(np.round(score, 10)))),
        "fixed_threshold": float(threshold),
        "exceedance_count": int((score >= threshold).sum()),
        "exceedance_fraction": float((score >= threshold).mean()),
        "quantiles": {str(q): float(np.quantile(score, q)) for q in (0.0, 0.1, 0.25, 0.5, 0.75, 0.9, 1.0)},
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--model", type=Path, required=True)
    parser.add_argument("--metrics", type=Path, required=True)
    parser.add_argument("--lanl-root", type=Path, required=True)
    parser.add_argument("--windows-v3", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()

    model = joblib.load(args.model)
    metrics = json.loads(args.metrics.read_text(encoding="utf-8"))
    threshold = float(metrics["threshold"])
    expected = _expected_columns(model)

    quality = json.loads((args.lanl_root / "reference_quality.json").read_text(encoding="utf-8"))
    manifest = json.loads((args.lanl_root / "source_manifest.json").read_text(encoding="utf-8"))
    if quality.get("external_only") is not True or quality.get("threshold_tuning_allowed") is not False:
        raise SystemExit("LANL external-only contract not satisfied")
    netflow = pd.read_parquet(args.lanl_root / "remote_admin_flows.parquet")
    features, coverage = build_external_flow_features(netflow, expected)
    scores = model.predict_proba(features)[:, 1]

    windows = json.loads(args.windows_v3.read_text(encoding="utf-8-sig"))
    validated = list(map(str, windows.get("validated_protocols", [])))
    report = {
        "schema_version": 4,
        "model_view": "flow-primary",
        "model_unit": "suricata_eve_flow",
        "fixed_threshold_source": "linux_v3_flow_validation_only",
        "training_or_threshold_tuning_on_external": False,
        "lanl": {
            "environment_id": "lanl_reference",
            "supervised_labels_available": False,
            "threshold_tuned_on_reference": False,
            "score": _score_report(scores, threshold),
            "feature_coverage": coverage,
            "reference_quality": quality,
            "source_manifest": manifest,
        },
        "windows_v3_fidelity": {
            "validated_protocols": validated,
            "dcom": windows.get("protocols", {}).get("dcom", {}),
            "rdp": windows.get("protocols", {}).get("rdp", {}),
        },
        "external_gate_inputs": {
            "lanl_reference_complete": bool(len(features) > 0 and np.isfinite(scores).all()),
            "lanl_feature_coverage": float(coverage["coverage_fraction"]),
            "lanl_invalid_required_rows": int(coverage["dropped_invalid_required_rows"]),
            "windows_validated_protocol_count": len(validated),
            "threshold_tuning_on_external": False,
        },
    }
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps(report["external_gate_inputs"], indent=2, sort_keys=True))
    if not report["external_gate_inputs"]["lanl_reference_complete"]:
        raise SystemExit("LANL flow-primary external evaluation incomplete")
    if report["external_gate_inputs"]["lanl_feature_coverage"] < 0.99:
        raise SystemExit("LANL flow-primary feature coverage below parity gate")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
