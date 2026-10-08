"""Prepare measured defensive ML rows with corroborated session-level labels.

One capture may contain both explicitly verified technique sessions and
unlabeled background. Never copy a file-level label onto every session.
"""

from __future__ import annotations

from collections import Counter
from hashlib import sha256
import json
from pathlib import Path
from tempfile import TemporaryDirectory

import numpy as np
import pandas as pd

from .defender_domain import load_user_input
from .office_day_transfer import TRANSPORT_FEATURES
from .source_manifest import load_source_manifest, verify_sources


def _sha(path: Path) -> str:
    h = sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1 << 20), b""):
            h.update(block)
    return h.hexdigest()


def _session_key(frame: pd.DataFrame, *, requires_membership: bool) -> pd.Series:
    for key in ("global_session_uid", "source_session_uid"):
        if key in frame.columns:
            values = frame[key].astype("string")
            if values.notna().all() and not values.str.strip().eq("").any():
                if requires_membership and values.duplicated().any():
                    raise ValueError("ambiguous measured session identity: duplicate session_key")
                return values.astype(str)
    if requires_membership:
        raise ValueError("session membership requires stable measured session identity")
    return pd.Series([f"unverified-row-{i}" for i in range(len(frame))], index=frame.index)


def _read_membership(source: dict) -> dict[str, tuple[int, str]]:
    if "membership_path" not in source:
        return {}
    if source["label_state"] not in {"verified_positive", "matched_control", "hard_negative"}:
        raise ValueError("membership cannot verify an unverified source")
    mapping: dict[str, tuple[int, str]] = {}
    with Path(source["membership_path"]).open(encoding="utf-8") as file:
        for line in file:
            if not line.strip():
                continue
            try:
                member = json.loads(line)
            except (TypeError, ValueError) as exc:
                raise ValueError("invalid membership JSONL") from exc
            if not isinstance(member, dict):
                raise ValueError("invalid membership entry")
            if member.get("source_id") != source["source_id"]:
                raise ValueError("membership source_id mismatch")
            session = member.get("session_key")
            if not isinstance(session, str) or not session.strip() or session in mapping:
                raise ValueError("membership requires distinct nonempty session_key")
            label = member.get("label_binary")
            expected = 1 if source["label_state"] == "verified_positive" else 0
            if type(label) is not int or label != expected:
                raise ValueError("membership label_binary inconsistent with verified role")
            technique = member.get("technique_id")
            if source["label_state"] == "hard_negative":
                if technique is not None:
                    raise ValueError("hard-negative membership cannot claim a technique")
            elif technique not in source["technique_ids"]:
                raise ValueError("membership technique_id not in verified source")
            mapping[session] = (label, technique)
    return mapping


def build_verified_corpus(
    manifest_path: Path, allowed_root: Path, out: Path, *, min_free_gib: float = 1,
) -> dict:
    """Extract without changing the originals; export X and labels separately."""
    out = Path(out)
    if out.exists():
        raise FileExistsError(out)
    validated = load_source_manifest(manifest_path, allowed_root=allowed_root)
    sources = validated["sources"]
    frames: list[pd.DataFrame] = []
    labels: list[pd.DataFrame] = []
    info_by_source = {}
    with TemporaryDirectory(prefix="ndr-source-extraction-") as temp:
        scratch = Path(temp)
        for source in sources:
            raw, info = load_user_input(source["path"], scratch, min_free_gib=min_free_gib)
            membership = _read_membership(source)
            keys = _session_key(raw, requires_membership=bool(membership))
            if set(membership) - set(keys):
                raise ValueError("membership session_key absent from measured source")
            verified = [membership.get(key, (-1, None)) for key in keys]
            frames.append(raw)
            labels.append(pd.DataFrame({
                "source_id": source["source_id"],
                "source_sha256": source["sha256"],
                "session_key": keys.to_numpy(),
                "label_binary": [item[0] for item in verified],
                "technique_id": [item[1] for item in verified],
                "label_state": source["label_state"],
                "evidence_tier": source["evidence_tier"],
                "pair_id": source["pair_id"],
                "parent_campaign_id": source["parent_campaign_id"],
                "runtime_profile_id": source["runtime_profile_id"],
                "capture_group_id": source["capture_group_id"],
                "capture_day_id": source["capture_day_id"],
                "measurement_vantage": source["measurement_vantage"],
                "extractor_version": source["extractor_version"],
            }))
            info_by_source[source["source_id"]] = info
        verify_sources(validated)

    measured: list[str] = []
    for name in TRANSPORT_FEATURES:
        if all(name in frame for frame in frames):
            cols = [pd.to_numeric(frame[name], errors="coerce") for frame in frames]
            if all(float(v.replace([np.inf, -np.inf], np.nan).notna().mean()) >= .8
                   for v in cols):
                measured.append(name)
    if len(measured) < 12:
        raise ValueError("fewer than 12 compatible measured transport features")
    x = pd.concat([
        pd.DataFrame({name: pd.to_numeric(frame[name], errors="coerce")
                      .replace([np.inf, -np.inf], np.nan).astype("float64")
                      for name in measured})
        for frame in frames
    ], ignore_index=True)
    metadata = pd.concat(labels, ignore_index=True)
    metadata.insert(0, "row_index", range(len(metadata)))
    if len(x) != len(metadata):
        raise RuntimeError("feature/label row alignment changed")
    out.mkdir(parents=True, mode=0o700)
    for name, table in (("features.parquet", x), ("labels_metadata.parquet", metadata)):
        table.to_parquet(out / name, index=False)
    report = {
        "version": "verified-defender-corpus-v1",
        "manifest_sha256": validated["manifest_sha256"],
        "source_hashes": {s["source_id"]: s["sha256"] for s in sources},
        "feature_columns": measured,
        "rows": len(x),
        "label_counts": dict(Counter(str(int(y)) for y in metadata["label_binary"])),
        "source_info": info_by_source,
        "outputs": {name: _sha(out / name) for name in ("features.parquet", "labels_metadata.parquet")},
        "identity_excluded_from_model_X": True,
        "unmatched_sessions_remain_unlabeled": True,
        "office_naturalness_proven": False,
        "production_ready": False,
    }
    verify_sources(validated)
    (out / "corpus_manifest.json").write_text(json.dumps(report, sort_keys=True, indent=2) + "\n")
    return report
