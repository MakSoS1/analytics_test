#!/usr/bin/env python3
from __future__ import annotations

import argparse
import csv
import json
import math
import subprocess
from collections import defaultdict
from io import StringIO
from pathlib import Path

import joblib
import numpy as np
import pandas as pd

from adminlab.v2_external import align_external_features, build_lanl_session_features


PORT_TO_PROTOCOL = {
    22: "openssh",
    135: "dcom",
    445: "smb",
    3389: "rdp",
    5985: "winrm",
    5986: "winrm",
}


def _model_expected_columns(model) -> list[str]:
    preprocess = model.named_steps.get("preprocess") if hasattr(model, "named_steps") else None
    if preprocess is None or not hasattr(preprocess, "feature_names_in_"):
        raise ValueError("session model does not expose preprocess.feature_names_in_")
    return [str(x) for x in preprocess.feature_names_in_.tolist()]


def _score_report(scores: np.ndarray, threshold: float) -> dict:
    score = np.asarray(scores, dtype=float)
    finite = bool(np.isfinite(score).all()) and len(score) > 0
    if not finite:
        return {"finite": False, "rows": int(len(score))}
    quantiles = {str(q): float(np.quantile(score, q)) for q in (0.0, 0.1, 0.25, 0.5, 0.75, 0.9, 1.0)}
    unique = int(len(np.unique(np.round(score, 10))))
    return {
        "finite": True,
        "rows": int(len(score)),
        "mean": float(score.mean()),
        "std": float(score.std()),
        "min": float(score.min()),
        "max": float(score.max()),
        "quantiles": quantiles,
        "unique_scores_rounded_1e10": unique,
        "non_degenerate": unique > 1,
        "fixed_threshold": float(threshold),
        "exceedance_count": int((score >= threshold).sum()),
        "exceedance_fraction": float((score >= threshold).mean()),
    }


def _parse_tshark_windows_sessions(pcapng: Path, validated: set[str]) -> tuple[pd.DataFrame, dict]:
    if not pcapng.exists():
        raise FileNotFoundError(pcapng)
    cmd = [
        "tshark", "-r", str(pcapng), "-Y", "tcp",
        "-T", "fields", "-E", "separator=,", "-E", "quote=d",
        "-e", "tcp.stream", "-e", "frame.time_epoch", "-e", "ip.src", "-e", "ip.dst",
        "-e", "tcp.srcport", "-e", "tcp.dstport", "-e", "frame.len",
    ]
    completed = subprocess.run(cmd, check=True, capture_output=True, text=True)
    streams: dict[str, list[dict]] = defaultdict(list)
    for line in completed.stdout.splitlines():
        if not line.strip():
            continue
        try:
            fields = next(csv.reader(StringIO(line)))
        except csv.Error:
            continue
        if len(fields) != 7 or not fields[0]:
            continue
        try:
            ts = float(fields[1]); sport = int(fields[4]); dport = int(fields[5]); length = int(fields[6])
        except (ValueError, TypeError):
            continue
        proto = PORT_TO_PROTOCOL.get(dport) or PORT_TO_PROTOCOL.get(sport)
        if proto is None or proto not in validated:
            continue
        streams[fields[0]].append(
            {"time": ts, "src": fields[2], "dst": fields[3], "sport": sport, "dport": dport, "len": length, "protocol": proto}
        )

    rows: list[dict] = []
    per_protocol_streams: dict[str, int] = defaultdict(int)
    for stream_id, packets in streams.items():
        packets.sort(key=lambda item: item["time"])
        first = packets[0]
        protocol = first["protocol"]
        per_protocol_streams[protocol] += 1
        # Preserve network identity only inside this temporary reference table;
        # build_lanl_session_features removes it after causal state derivation.
        remote_port = next(port for port, name in PORT_TO_PROTOCOL.items() if name == protocol and (port in {p["sport"] for p in packets} or port in {p["dport"] for p in packets}))
        src_device = first["src"] or "windows_runner"
        dst_device = first["dst"] or f"native_{protocol}"
        rows.append(
            {
                "time": float(first["time"]),
                "duration": max(0.0, float(packets[-1]["time"] - first["time"])),
                "src_device": src_device,
                "dst_device": dst_device,
                "protocol": "6",
                "src_port": int(first["sport"]),
                "dst_port": int(first["dport"] if first["dport"] in PORT_TO_PROTOCOL else remote_port),
                "src_packets": len(packets),
                "dst_packets": 0,
                "src_bytes": int(sum(p["len"] for p in packets)),
                "dst_bytes": 0,
                "native_protocol": protocol,
                "tcp_stream": stream_id,
            }
        )
    frame = pd.DataFrame(rows)
    if frame.empty:
        raise ValueError("no validated native Windows TCP streams were found in PCAPNG")
    return frame, {"tcp_streams_by_protocol": dict(sorted(per_protocol_streams.items())), "tcp_streams_total": len(frame)}


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--model", type=Path, required=True)
    parser.add_argument("--metrics", type=Path, required=True)
    parser.add_argument("--lanl-root", type=Path, required=True)
    parser.add_argument("--windows-root", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()

    model = joblib.load(args.model)
    metrics = json.loads(args.metrics.read_text(encoding="utf-8"))
    threshold = float(metrics["threshold"])
    expected = _model_expected_columns(model)

    lanl_quality = json.loads((args.lanl_root / "reference_quality.json").read_text(encoding="utf-8"))
    lanl_manifest = json.loads((args.lanl_root / "source_manifest.json").read_text(encoding="utf-8"))
    if lanl_quality.get("external_only") is not True or lanl_quality.get("threshold_tuning_allowed") is not False:
        raise SystemExit("LANL external-only contract not satisfied")
    lanl_net = pd.read_parquet(args.lanl_root / "remote_admin_flows.parquet")
    lanl_features = build_lanl_session_features(lanl_net)
    lanl_aligned, lanl_coverage = align_external_features(lanl_features, expected)
    lanl_scores = model.predict_proba(lanl_aligned)[:, 1]
    lanl_report = {
        "environment_id": "lanl_reference",
        "supervised_labels_available": False,
        "threshold_tuned_on_reference": False,
        "score": _score_report(lanl_scores, threshold),
        "feature_coverage": lanl_coverage,
        "reference_quality": lanl_quality,
        "source_manifest": lanl_manifest,
    }

    fidelity = json.loads((args.windows_root / "windows_fidelity.json").read_text(encoding="utf-8-sig"))
    validation_path = args.windows_root / "windows_fidelity_validation.json"
    fidelity_validation = json.loads(validation_path.read_text(encoding="utf-8-sig")) if validation_path.exists() else {}
    validated = set(map(str, fidelity.get("validated_protocols", [])))
    if not validated:
        raise SystemExit("Windows external holdout has no native_windows_validated protocols")
    windows_net, windows_capture = _parse_tshark_windows_sessions(args.windows_root / "capture.pcapng", validated)
    native_protocols = windows_net.pop("native_protocol").astype(str).tolist()
    windows_net = windows_net.drop(columns=["tcp_stream"])
    windows_features = build_lanl_session_features(windows_net)
    windows_aligned, windows_coverage = align_external_features(windows_features, expected)
    windows_scores = model.predict_proba(windows_aligned)[:, 1]
    per_protocol: dict[str, dict] = {}
    protocols = pd.Series(native_protocols, dtype=str)
    for protocol in sorted(set(native_protocols)):
        mask = protocols.eq(protocol).to_numpy()
        per_protocol[protocol] = _score_report(windows_scores[mask], threshold)
    windows_report = {
        "environment_id": "windows_native",
        "supervised_labels_available": False,
        "threshold_tuned_on_holdout": False,
        "validated_protocols": sorted(validated),
        "mapped_native_protocols": sorted(set(native_protocols)),
        "mapped_native_protocol_count": len(set(native_protocols)),
        "score": _score_report(windows_scores, threshold),
        "per_protocol_score": per_protocol,
        "feature_coverage": windows_coverage,
        "capture_evidence": windows_capture,
        "fidelity_validation": fidelity_validation,
    }

    report = {
        "schema_version": 2,
        "model_view": "session-primary",
        "fixed_threshold_source": "linux_v2_validation_only",
        "training_or_threshold_tuning_on_external": False,
        "lanl": lanl_report,
        "windows": windows_report,
        "external_gate_inputs": {
            "lanl_reference_complete": bool(lanl_report["score"].get("finite") and lanl_report["score"].get("rows", 0) > 0),
            "windows_mapped_native_protocols": windows_report["mapped_native_protocol_count"],
            "windows_score_distribution_finite": bool(windows_report["score"].get("finite")),
            "windows_score_distribution_non_degenerate": bool(windows_report["score"].get("non_degenerate")),
        },
    }
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps(report["external_gate_inputs"], indent=2, sort_keys=True))
    if not report["external_gate_inputs"]["lanl_reference_complete"]:
        raise SystemExit("LANL external evaluation incomplete")
    if report["external_gate_inputs"]["windows_mapped_native_protocols"] < 1:
        raise SystemExit("no mapped native Windows protocol in external evaluation")
    if not report["external_gate_inputs"]["windows_score_distribution_finite"]:
        raise SystemExit("Windows external score distribution is not finite")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
