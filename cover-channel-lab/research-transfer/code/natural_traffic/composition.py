from __future__ import annotations

from dataclasses import dataclass
from hashlib import sha256
import json
import os
from pathlib import Path
import subprocess
import sys
from typing import Any

import pandas as pd
import pyarrow as pa
import pyarrow.parquet as pq

from .capture import assert_extraction_input, ensure_resource_budget
from .contracts import CaptureBundle
from .reference import model_feature_columns


ROOT = Path(__file__).resolve().parents[1]


class CompositionIntegrityError(RuntimeError):
    pass


@dataclass(frozen=True)
class PipelineExtractionResult:
    parquet_path: Path
    rows: int
    source_pcap_sha256: str
    manifest_path: Path


def _sha(path: Path) -> str:
    h = sha256()
    with Path(path).open("rb") as fh:
        for block in iter(lambda: fh.read(1 << 20), b""):
            h.update(block)
    return h.hexdigest()


def _type_compatible(left: pa.DataType, right: pa.DataType) -> bool:
    if left.equals(right):
        return True
    if pa.types.is_null(left) or pa.types.is_null(right):
        return True
    if pa.types.is_integer(left) or pa.types.is_floating(left):
        return pa.types.is_integer(right) or pa.types.is_floating(right)
    if pa.types.is_string(left) or pa.types.is_large_string(left):
        return pa.types.is_string(right) or pa.types.is_large_string(right)
    if pa.types.is_list(left) or pa.types.is_large_list(left):
        if not (pa.types.is_list(right) or pa.types.is_large_list(right)):
            return False
        return _type_compatible(left.value_type, right.value_type)
    return False


def _schema_compatible(left: Path, right: Path) -> bool:
    # Pandas round-trips may widen string/list encodings or nullable numerics.
    # The composition contract is the ordered logical column schema, not the
    # physical encoding chosen by one Parquet writer.
    a, b = pq.read_schema(left), pq.read_schema(right)
    if a.names != b.names:
        return False
    return all(_type_compatible(x.type, y.type) for x, y in zip(a, b))


def compose_feature_alternatives(
    office_path: Path,
    scenario_path: Path,
    control_path: Path,
    out_dir: Path,
    *,
    pair_id: str,
) -> dict[str, Any]:
    office_path, scenario_path, control_path = map(Path, (office_path, scenario_path, control_path))
    out = Path(out_dir)
    if out.exists():
        raise FileExistsError(f"composition output already exists: {out}")
    source_hashes = {p: _sha(p) for p in (office_path, scenario_path, control_path)}
    office = pd.read_parquet(office_path)
    arms = {
        "scenario": pd.read_parquet(scenario_path),
        "control": pd.read_parquet(control_path),
    }
    for role, path in (("scenario", scenario_path), ("control", control_path)):
        if not _schema_compatible(office_path, path):
            raise CompositionIntegrityError(f"{role} schema differs from office schema")
    out.mkdir(parents=True)
    report: dict[str, Any] = {
        "version": "natural-feature-composition-v2",
        "pair_id": pair_id,
        "office_rows": int(len(office)),
        "endpoint_collision_check": "not_evaluable_from_pseudonymized_feature_tables",
        "packet_overlay_claim": False,
        "outputs": {},
    }
    for role, label in (("scenario", 1), ("control", 0)):
        office_part = office.copy()
        office_part["_natural_origin"] = None
        office_part["_natural_role"] = None
        office_part["_natural_training_label"] = pd.NA
        office_part["_natural_pair_id"] = None
        generated = arms[role].copy()
        generated["_natural_origin"] = "generated"
        generated["_natural_role"] = role
        generated["_natural_training_label"] = label
        generated["_natural_pair_id"] = pair_id
        mixed = pd.concat([office_part, generated], ignore_index=True, sort=False)
        target = out / f"{role}.parquet"
        mixed.to_parquet(target, index=False)
        report["outputs"][role] = {
            "path": str(target),
            "rows": int(len(mixed)),
            "generated_rows": int(len(generated)),
            "sha256": _sha(target),
        }
    for path, expected in source_hashes.items():
        if _sha(path) != expected:
            raise CompositionIntegrityError(f"source changed during feature composition: {path}")
    (out / "composition.json").write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")
    return report


def validate_pipeline_table(parquet_path: Path, dictionary_path: Path) -> dict[str, Any]:
    table = pq.read_table(parquet_path)
    dictionary = json.loads(Path(dictionary_path).read_text())
    declared = [r["column"] for r in dictionary if r.get("kind") == "feature"]
    missing = sorted(set(declared) - set(table.column_names))
    # This is the model-X contract, not a destructive table projection.
    sample = table.to_pandas()
    x = model_feature_columns(sample, dictionary)
    forbidden_exact = {
        "label", "label_binary", "origin", "source_role",
        "global_session_uid", "global_segment_uid", "pair_id", "profile_id",
    }
    return {
        "rows": int(table.num_rows),
        "columns": int(table.num_columns),
        "declared_features": len(declared),
        "missing_declared_features": missing,
        "model_x_columns": x,
        "metadata_in_model_x": bool(forbidden_exact.intersection(x)),
    }


def validate_arkime_table(parquet_path: Path) -> dict[str, Any]:
    schema = pq.read_schema(parquet_path)
    names = schema.names
    arkime = [n for n in names if n.startswith("arkime.")]
    return {
        "rows": int(pq.read_metadata(parquet_path).num_rows),
        "columns": len(names),
        "arkime_fields": len(arkime),
        "presence_mask": "arkime_present_fields" in names,
    }


def validate_strict_match_table(parquet_path: Path) -> dict[str, Any]:
    schema = pq.read_schema(parquet_path)
    names = schema.names
    direction_fields = {
        "same_direction",
        "arkime_same_direction",
        "direction_match",
        "direction_caveat",
        "comparison.same_direction",
    }
    return {
        "rows": int(pq.read_metadata(parquet_path).num_rows),
        "columns": len(names),
        "direction_caveat_documented": bool(direction_fields.intersection(names))
            or (
                any(n.startswith("arkime.") for n in names)
                and {"pipeline.up_pkt_count", "pipeline.down_pkt_count", "pipeline.up_bytes", "pipeline.down_bytes"}.issubset(names)
            ),
    }


def _run(command: list[object], log: Path) -> None:
    with Path(log).open("a", encoding="utf-8") as fh:
        fh.write("$ " + " ".join(map(str, command)) + "\n")
        fh.flush()
        proc = subprocess.run(
            list(map(str, command)),
            cwd=ROOT,
            env={**os.environ, "PYTHONPATH": str(ROOT) + os.pathsep + os.environ.get("PYTHONPATH", "")},
            stdout=fh,
            stderr=subprocess.STDOUT,
            text=True,
        )
    if proc.returncode:
        raise RuntimeError(f"extractor command failed ({proc.returncode}); see {log}")


def extract_pipeline_capture(
    bundle: CaptureBundle,
    out_dir: Path,
    *,
    run_id: str,
    min_free_gib: float = 15,
    shards: int = 1,
) -> PipelineExtractionResult:
    if shards != 1:
        raise ValueError("standalone capture wrapper currently requires shards=1")
    assert_extraction_input(bundle, bundle.pcap_path)
    out = Path(out_dir)
    if out.exists():
        raise FileExistsError(f"extract output already exists: {out}")
    out.mkdir(parents=True)
    ensure_resource_budget(out, min_free_gib=min_free_gib)
    source_hash = bundle.pcap_sha256
    work = out / "work"
    rows = work / "rows"
    batch = work / "batch"
    parquet = out / "parquet"
    rows.mkdir(parents=True)
    batch.mkdir(parents=True)
    salt = work / "session_salt"
    salt.write_bytes(os.urandom(32))
    salt.chmod(0o600)
    log = out / "steps.log"

    packet_rows = rows / "capture.pkts"
    payload_rows = rows / "capture.pay"
    _run([
        sys.executable, ROOT / "export_full_packets.py",
        "--pcap", bundle.pcap_path,
        "--out", packet_rows,
        "--payload-out", payload_rows,
        "--salt-file", salt,
    ], log)

    raw = work / "sessions.csv"
    lots = work / "lots.csv"
    index = work / "session_index.csv"
    _run([
        sys.executable, ROOT / "extract_office_sessions.py",
        "--pcap-dir", rows,
        "--glob", "*.pkts",
        "--out-sessions", raw,
        "--out-lots-conns", lots,
        "--session-index", index,
        "--stats-json", work / "session_stats.json",
        "--salt-file", salt,
        "--min-packets", "1",
        "--finalize",
    ], log)

    payload = work / "payload.csv"
    _run([
        sys.executable, ROOT / "merge_payload_sidecars.py",
        "--sidecar-dir", rows,
        "--glob", "*.pay",
        "--session-index", index,
        "--out-csv", payload,
        "--stats-json", work / "payload_stats.json",
    ], log)

    final_sessions = batch / "office_sessions.csv"
    _run([
        sys.executable, ROOT / "finalize_tables.py",
        "--sessions", raw,
        "--payload", payload,
        "--lots-conns-in", lots,
        "--out-sessions", final_sessions,
        "--out-lots-conns", batch / "office_lots_conns.csv",
        "--stats-json", work / "finalize_stats.json",
    ], log)

    _run([
        sys.executable, ROOT / "office_to_parquet.py",
        "--batch-dir", batch,
        "--out-dir", parquet,
        "--run-id", run_id,
        "--batch-id", "b00000",
    ], log)
    target = parquet / "office_sessions.parquet"
    if not target.is_file():
        raise RuntimeError("production extractor did not produce office_sessions.parquet")
    if _sha(bundle.pcap_path) != source_hash:
        raise CompositionIntegrityError("source PCAP changed during extraction")
    manifest = parquet / "manifest.json"
    result = PipelineExtractionResult(
        parquet_path=target,
        rows=int(pq.read_metadata(target).num_rows),
        source_pcap_sha256=source_hash,
        manifest_path=manifest,
    )
    audit = {
        "version": "natural-production-extraction-v2",
        "source_pcap_sha256": source_hash,
        "source_pcap_unchanged": True,
        "rows": result.rows,
        "parquet": str(target),
        "parquet_sha256": _sha(target),
        "production_path": [
            "export_full_packets.py",
            "extract_office_sessions.py",
            "merge_payload_sidecars.py",
            "finalize_tables.py",
            "office_to_parquet.py",
        ],
    }
    (out / "extraction.json").write_text(json.dumps(audit, indent=2, sort_keys=True) + "\n")
    return result