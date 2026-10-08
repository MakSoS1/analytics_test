"""Strict portable bundle loader for the multi-route detector skeleton."""
from __future__ import annotations

import hashlib
import json
import math
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from lab_pipeline.flow_tier import predict_proba
from lab_pipeline.model_bundle import BundleError, ModelBundle, validate_forest
from lab_pipeline.route_contract import ROUTES, RouteName, RouteSpec, classify_route, route_spec


@dataclass
class _GenericRouteModel:
    model: dict[str, Any]
    model_id: str
    spec: RouteSpec
    threshold: float

    @classmethod
    def load(cls, path: Path, spec: RouteSpec, expected_sha256: str | None = None) -> "_GenericRouteModel":
        try:
            raw = path.read_bytes()
            model = json.loads(raw)
        except OSError as exc:
            raise BundleError(f"cannot read {spec.route} model at {path}: {exc}") from exc
        except ValueError as exc:
            raise BundleError(f"{spec.route} model at {path} is not valid JSON: {exc}") from exc
        if not isinstance(model, dict):
            raise BundleError(f"{spec.route} model must be a JSON object")
        # A manifest hash nobody verifies is decoration: the bytes could be
        # swapped for another valid forest and the bundle would load happily.
        if expected_sha256 is not None:
            actual = hashlib.sha256(raw).hexdigest()
            if actual != expected_sha256:
                raise BundleError(
                    f"SHA256 mismatch for {spec.route}: manifest says {expected_sha256[:16]}…, "
                    f"file is {actual[:16]}…")
        if model.get("schema_version") != spec.schema_version:
            raise BundleError(f"schema mismatch for {spec.route}: expected {spec.schema_version!r}")
        if model.get("contract_hash") != spec.contract_hash:
            raise BundleError(f"contract hash mismatch for {spec.route}")
        features = list(model.get("features") or [])
        if features != list(spec.features):
            raise BundleError(f"feature order mismatch for {spec.route}")
        threshold = model.get("threshold", 0.5)
        if not isinstance(threshold, (int, float)) or not math.isfinite(threshold) or not 0.0 <= threshold <= 1.0:
            raise BundleError(f"threshold for {spec.route} is outside [0, 1]")
        validate_forest(model, features)
        return cls(model=model, model_id=hashlib.sha256(raw).hexdigest()[:16],
                   spec=spec, threshold=float(threshold))

    def score(self, features: dict[str, Any]) -> float:
        missing = [name for name in self.spec.features if name not in features]
        if missing:
            raise BundleError(f"{self.spec.route} observation misses features: {missing[:4]}")
        checked: dict[str, float] = {}
        for name in self.spec.features:
            value = features[name]
            if not isinstance(value, (int, float)) or not math.isfinite(float(value)):
                raise BundleError(f"{self.spec.route} feature {name!r} is not finite")
            checked[name] = float(value)
        return predict_proba(self.model, checked)


class RouteBundle:
    """One validated model per route; scoring never substitutes another route."""

    def __init__(self, models: dict[RouteName, ModelBundle | _GenericRouteModel]):
        self.models = models

    def score(self, observation: dict[str, object]) -> dict[str, object]:
        route = classify_route(observation)
        model = self.models.get(route)
        if model is None:
            raise BundleError(f"route model missing for {route}")
        features = observation.get("features")
        if not isinstance(features, dict):
            raise BundleError(f"{route} observation has no feature dictionary")
        score = model.score(features)
        spec = route_spec(route)
        return {
            "score": score,
            "threshold": model.threshold,
            "tunnel_detected": bool(score >= model.threshold),
            "detector_route": route,
            "model_id": model.model_id,
            "route_contract_hash": spec.contract_hash,
            "schema_version": spec.schema_version,
            "contract_hash": spec.contract_hash,
        }


def load_route_model(path: Path, route: RouteName) -> "_GenericRouteModel":
    """One route's model, fully validated, without requiring a whole bundle.

    The release path must load a complete bundle and does. This is for callers
    that score a single route deliberately — the pcap demo, a one-route
    experiment — so they get the same schema, contract and forest checks instead
    of reading the JSON themselves.
    """
    return _GenericRouteModel.load(Path(path), route_spec(route))


def _model_path(root: Path, raw: object, route: RouteName) -> Path:
    if not isinstance(raw, str) or not raw:
        raise BundleError(f"{route} bundle entry has no model path")
    path = (root / raw).resolve()
    try:
        path.relative_to(root.resolve())
    except ValueError as exc:
        raise BundleError(f"{route} model path escapes the bundle directory") from exc
    return path


def load_route_bundle(path: Path) -> RouteBundle:
    """Load a complete route bundle, refusing omissions and schema drift."""
    path = Path(path)
    try:
        document = json.loads(path.read_text())
    except OSError as exc:
        raise BundleError(f"cannot read route bundle at {path}: {exc}") from exc
    except ValueError as exc:
        raise BundleError(f"route bundle at {path} is not valid JSON: {exc}") from exc
    if not isinstance(document, dict) or document.get("bundle_version") != "route-bundle-v1":
        raise BundleError("unsupported route bundle version")
    entries = document.get("routes")
    if not isinstance(entries, dict):
        raise BundleError("route bundle routes must be an object")
    names = set(entries)
    missing = sorted(set(ROUTES) - names)
    extra = sorted(names - set(ROUTES))
    if missing or extra:
        raise BundleError(f"route bundle routes mismatch: missing={missing} extra={extra}")

    models: dict[RouteName, ModelBundle | _GenericRouteModel] = {}
    for route in ROUTES:
        entry = entries[route]
        if not isinstance(entry, dict):
            raise BundleError(f"{route} bundle entry must be an object")
        model_path = _model_path(path.parent, entry.get("model"), route)
        spec = route_spec(route)
        declared_sha = entry.get("model_sha256")
        if declared_sha is not None and (not isinstance(declared_sha, str) or len(declared_sha) != 64):
            raise BundleError(f"{route} model_sha256 must be a SHA256 hex digest")
        if route == "tcp_tls_fast":
            if declared_sha is not None:
                actual = hashlib.sha256(model_path.read_bytes()).hexdigest()
                if actual != declared_sha:
                    raise BundleError(
                        f"SHA256 mismatch for {route}: manifest says {declared_sha[:16]}…, "
                        f"file is {actual[:16]}…")
            model = ModelBundle.load(model_path)
            if (model.schema_version != spec.schema_version or model.contract_hash != spec.contract_hash or
                    model.features != list(spec.features)):
                raise BundleError("tcp_tls_fast model does not match the fast-v1 contract")
            models[route] = model
        else:
            models[route] = _GenericRouteModel.load(model_path, spec, declared_sha)
    return RouteBundle(models)
