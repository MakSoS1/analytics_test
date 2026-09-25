from __future__ import annotations

import argparse
import json
import math
from collections import Counter
from itertools import combinations
from pathlib import Path
from typing import Any

from .stage_m import build_specs


FIELDS = (
    "scenario_id",
    "client_impl",
    "server_impl",
    "requested_interval_seconds",
    "jitter_fraction",
    "event_count_target",
    "volume_mode",
    "direction_asymmetry",
    "payload_mode",
)

TARGETS = {
    "max_family_share": 0.15,
    "max_client_share": 0.20,
    "max_implementation_share": 0.20,
    "exact_duplicate_fraction": 0.01,
    "pairwise_catalog_coverage": 0.90,
    "min_network_profiles_full": 5,
}


def _read(path: Path) -> list[dict[str, Any]]:
    return [json.loads(x) for x in path.read_text().splitlines() if x.strip()]


def _entropy(values: list[str]) -> float:
    if not values:
        return 0.0
    counts = Counter(values)
    n = len(values)
    return -sum((c / n) * math.log2(c / n) for c in counts.values())


def _normalized_entropy(values: list[str]) -> float:
    unique = len(set(values))
    if unique <= 1:
        return 0.0
    return _entropy(values) / math.log2(unique)


def _max_share(rows: list[dict], field: str) -> float:
    if not rows:
        return 1.0
    counts = Counter(str(r.get(field, "")) for r in rows)
    return max(counts.values(), default=0) / len(rows)


def _configuration_key(r: dict) -> tuple:
    return tuple(str(r.get(f, "")) for f in FIELDS)


def _spec_as_row(s) -> dict:
    return {
        "scenario_id": s.family,
        "client_impl": s.client_impl,
        "server_impl": s.server_impl,
        "requested_interval_seconds": s.interval_seconds,
        "jitter_fraction": s.jitter_fraction,
        "event_count_target": s.event_count,
        "volume_mode": s.volume_mode,
        "direction_asymmetry": s.asymmetry,
        "payload_mode": s.payload_mode,
    }


def _pairwise_sets(rows: list[dict]) -> dict[tuple[str, str], set[tuple[str, str]]]:
    out: dict[tuple[str, str], set[tuple[str, str]]] = {}
    for a, b in combinations(FIELDS, 2):
        out[(a, b)] = {(str(r.get(a, "")), str(r.get(b, ""))) for r in rows}
    return out


def audit(path: Path, *, require_full: bool = False) -> dict:
    rows = _read(path)
    catalog_rows = [_spec_as_row(s) for s in build_specs("full")]
    expected = _pairwise_sets(catalog_rows)
    observed = _pairwise_sets(rows)

    pair_detail = {}
    expected_total = 0
    observed_total = 0
    for key, exp in expected.items():
        obs = observed.get(key, set())
        hit = len(exp & obs)
        expected_total += len(exp)
        observed_total += hit
        pair_detail[f"{key[0]}×{key[1]}"] = {
            "observed": hit,
            "expected_admissible": len(exp),
            "coverage": round(hit / len(exp), 6) if exp else 1.0,
        }

    config_counts = Counter(_configuration_key(r) for r in rows)
    duplicate_rows = sum(c - 1 for c in config_counts.values() if c > 1)
    duplicate_fraction = duplicate_rows / len(rows) if rows else 1.0

    families = [str(r.get("scenario_id", "")) for r in rows]
    clients = [str(r.get("client_impl", "")) for r in rows]
    impls = [str(r.get("implementation_id", "")) for r in rows]
    servers = [str(r.get("server_impl", "")) for r in rows]
    networks = [str(r.get("network_profile_id", r.get("netem_profile", ""))) for r in rows]

    metrics = {
        "campaigns": len(rows),
        "positive_only": bool(rows) and all(int(r.get("label_binary", 0)) == 1 for r in rows),
        "max_family_share": _max_share(rows, "scenario_id"),
        "max_client_share": _max_share(rows, "client_impl"),
        "max_implementation_share": _max_share(rows, "implementation_id"),
        "exact_duplicate_fraction": duplicate_fraction,
        "pairwise_catalog_coverage": observed_total / expected_total if expected_total else 1.0,
        "entropy": {
            "family": round(_entropy(families), 6),
            "family_normalized": round(_normalized_entropy(families), 6),
            "client": round(_entropy(clients), 6),
            "client_normalized": round(_normalized_entropy(clients), 6),
            "implementation": round(_entropy(impls), 6),
            "implementation_normalized": round(_normalized_entropy(impls), 6),
            "server": round(_entropy(servers), 6),
            "network": round(_entropy(networks), 6),
        },
        "unique": {
            "families": len(set(families)),
            "clients": len(set(clients)),
            "implementations": len(set(impls)),
            "servers": len(set(servers)),
            "networks": len(set(networks)),
            "configurations": len(config_counts),
        },
    }

    checks = {
        "positive_only": metrics["positive_only"],
        "max_family_share": metrics["max_family_share"] <= TARGETS["max_family_share"],
        "max_client_share": metrics["max_client_share"] <= TARGETS["max_client_share"],
        "max_implementation_share": metrics["max_implementation_share"] <= TARGETS["max_implementation_share"],
        "exact_duplicate_fraction": metrics["exact_duplicate_fraction"] < TARGETS["exact_duplicate_fraction"],
        "pairwise_catalog_coverage": metrics["pairwise_catalog_coverage"] >= TARGETS["pairwise_catalog_coverage"],
        "network_profile_diversity": metrics["unique"]["networks"] >= TARGETS["min_network_profiles_full"],
    }
    if not require_full:
        # Smoke is an implementation/protocol health check, not a statistical
        # sample. Only invariants that make sense for a reduced catalog are gates.
        checks["exact_duplicate_fraction"] = True
        checks["pairwise_catalog_coverage"] = True
        checks["max_family_share"] = True
        checks["network_profile_diversity"] = True

    return {
        "passed": all(checks.values()),
        "require_full": require_full,
        "targets": TARGETS,
        "checks": checks,
        "metrics": metrics,
        "pairwise": pair_detail,
    }


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--manifest", required=True)
    ap.add_argument("--out")
    ap.add_argument("--require-full", action="store_true")
    a = ap.parse_args()
    report = audit(Path(a.manifest), require_full=a.require_full)
    text = json.dumps(report, indent=2, sort_keys=True)
    if a.out:
        Path(a.out).parent.mkdir(parents=True, exist_ok=True)
        Path(a.out).write_text(text + "\n")
    print(text)
    if not report["passed"]:
        raise SystemExit("Stage M diversity audit failed")


if __name__ == "__main__":
    main()
