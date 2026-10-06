#!/usr/bin/env python3
"""Load a model only when it provably matches the feature contract.

The failure this prevents is silent, not loud. A forest is a list of feature
names plus trees; feed it a row built by a different extractor and it returns a
confident number computed from the wrong columns. That already happened in this
project in a milder form — offline aggregates spanned a whole session while the
office side spanned a 15-second capture, under identical names.

So loading is a checked operation:

  * the bundle states its schema version and contract hash;
  * the hash must equal the running contract's, which covers the horizon and the
    length unit, not just the ordered names;
  * feature order and count must match exactly — a permutation is rejected;
  * the model file's own checksum is recorded, so a swapped artifact is visible.

A missing field is never zero-filled. Padding is legitimate only where the mask
says the packet slot was never filled.
"""
from __future__ import annotations

import hashlib
import json
import math
from pathlib import Path
from typing import Any

from lab_pipeline.online_schema import (
    FEATURE_NAMES,
    SCHEMA_VERSION,
    contract_hash,
    validate_vector,
)


class BundleError(RuntimeError):
    """The artifact cannot be trusted to score anything."""


class ModelBundle:
    def __init__(self, model: dict[str, Any], model_id: str, source: str | None = None):
        self.model = model
        self.model_id = model_id
        self.source = source
        self.features: list[str] = list(model.get("features") or [])
        self.threshold: float = float(model.get("threshold", 0.5))
        self.schema_version: str = str(model.get("schema_version") or "")
        self.contract_hash: str = str(model.get("contract_hash") or "")

    # ---- construction ----------------------------------------------------
    @classmethod
    def load(cls, path: str | Path, *, strict: bool = True) -> "ModelBundle":
        p = Path(path)
        try:
            raw = p.read_bytes()
        except OSError as exc:
            raise BundleError(f"cannot read model at {p}: {exc}") from exc
        try:
            model = json.loads(raw)
        except ValueError as exc:
            raise BundleError(f"model at {p} is not valid JSON: {exc}") from exc
        if not isinstance(model, dict):
            raise BundleError(f"model at {p} is not an object")
        bundle = cls(model, model_id=hashlib.sha256(raw).hexdigest()[:16], source=str(p))
        bundle.validate(strict=strict)
        return bundle

    # ---- checks ----------------------------------------------------------
    def validate(self, *, strict: bool = True) -> None:
        if not self.features:
            raise BundleError("model declares no features")
        validate_forest(self.model, self.features)
        if not 0.0 <= self.threshold <= 1.0:
            raise BundleError(f"threshold {self.threshold} is outside [0, 1]")

        if not strict:
            return

        if self.schema_version != SCHEMA_VERSION:
            raise BundleError(
                f"schema mismatch: bundle says {self.schema_version!r}, runtime is {SCHEMA_VERSION!r}"
            )
        expected = contract_hash()
        if self.contract_hash != expected:
            raise BundleError(
                "contract hash mismatch: the sensor's observation semantics differ from "
                f"the model's (bundle {self.contract_hash[:12]}…, runtime {expected[:12]}…)"
            )
        if self.features != list(FEATURE_NAMES):
            if sorted(self.features) == sorted(FEATURE_NAMES):
                raise BundleError("feature ORDER differs from the contract; a permutation is not parity")
            missing = [f for f in FEATURE_NAMES if f not in self.features]
            extra = [f for f in self.features if f not in FEATURE_NAMES]
            raise BundleError(f"feature set differs: missing={missing[:4]} extra={extra[:4]}")

    # ---- scoring ---------------------------------------------------------
    def score(self, row: dict[str, Any]) -> float:
        validate_vector(row)
        from lab_pipeline.flow_tier import predict_proba

        return predict_proba(self.model, row)

    def describe(self) -> dict[str, Any]:
        return {
            "model_id": self.model_id,
            "source": self.source,
            "schema_version": self.schema_version,
            "contract_hash": self.contract_hash,
            "n_features": len(self.features),
            "n_trees": len(self.model.get("trees") or []),
            "threshold": self.threshold,
        }


def _validate_tree(index: int, t: dict[str, Any], n_features: int) -> None:
    """Refuse a tree the walker could not survive.

    The walker is `while left[node] != -1`. A child index pointing back up does
    not raise — it spins, in a sensor that sits inline on the traffic path. An
    IndexError found halfway through scoring is only marginally better. Every
    shape checked here is one a file can have after a truncated write, a version
    skew in the exporter, or an edit by hand; none of them were caught by
    checking that the keys existed.
    """
    left = t["children_left"]
    right = t["children_right"]
    feat = t["feature"]
    thr = t["threshold"]
    prob = t["prob"]
    n = len(left)
    if n == 0:
        raise BundleError(f"tree {index} is empty")
    for name, arr in (("children_right", right), ("feature", feat),
                      ("threshold", thr), ("prob", prob)):
        if len(arr) != n:
            raise BundleError(
                f"tree {index}: '{name}' has length {len(arr)}, children_left has {n}")

    for node in range(n):
        lo, ro = left[node], right[node]
        is_leaf = lo == -1
        if is_leaf != (ro == -1):
            raise BundleError(
                f"tree {index} node {node}: one child is a leaf and the other is not")
        if is_leaf:
            p = prob[node]
            if not isinstance(p, (int, float)) or not math.isfinite(p) or not 0.0 <= p <= 1.0:
                raise BundleError(f"tree {index} node {node}: probability {p!r} is not in [0, 1]")
            continue
        for child in (lo, ro):
            if not 0 <= child < n:
                raise BundleError(
                    f"tree {index} node {node}: child index {child} is out of range 0..{n - 1}")
        if not 0 <= feat[node] < n_features:
            raise BundleError(
                f"tree {index} node {node}: feature index {feat[node]} is out of range "
                f"0..{n_features - 1}")
        v = thr[node]
        if not isinstance(v, (int, float)) or not math.isfinite(v):
            raise BundleError(f"tree {index} node {node}: threshold {v!r} is not finite")

    # Termination. A split whose child is not strictly below it in a
    # depth-first numbering is how a cycle gets in; walking it is the only
    # honest check.
    seen: set[int] = set()
    stack = [0]
    while stack:
        node = stack.pop()
        if node in seen:
            raise BundleError(f"tree {index}: node {node} is reachable twice — a cycle")
        seen.add(node)
        if left[node] != -1:
            stack.extend((left[node], right[node]))


def validate_forest(model: dict[str, Any], features: list[str]) -> None:
    """Validate an exported forest against an explicit ordered feature schema.

    Route-specific bundles use the same safe tree representation as fast-v1,
    but not its feature contract.  This shared structural validator avoids a
    permissive second loader while keeping fast-v1's strict schema unchanged.
    """
    trees = model.get("trees")
    if not isinstance(trees, list) or not trees:
        raise BundleError("model declares no trees")
    for index, tree in enumerate(trees):
        if not isinstance(tree, dict):
            raise BundleError(f"tree {index} is not an object")
        for key in ("children_left", "children_right", "feature", "threshold", "prob"):
            if key not in tree:
                raise BundleError(f"tree {index} is missing '{key}'")
        _validate_tree(index, tree, len(features))


def stamp_contract(model: dict[str, Any]) -> dict[str, Any]:
    """Attach the current contract identity to a freshly trained forest."""
    model["schema_version"] = SCHEMA_VERSION
    model["contract_hash"] = contract_hash()
    return model
