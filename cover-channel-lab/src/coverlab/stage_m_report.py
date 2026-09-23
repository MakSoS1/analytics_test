from __future__ import annotations

import argparse
import json
from collections import Counter, defaultdict
from pathlib import Path

from .stage_m_contract import EXPECTED_TOTAL_CAMPAIGNS, FAMILIES, NETWORK_PROFILES


def _read(path: Path) -> list[dict]:
    if not path.exists():
        return []
    return [json.loads(x) for x in path.read_text(errors="replace").splitlines() if x.strip()]


def build_report(manifest: Path) -> tuple[dict, dict]:
    rows = _read(manifest)
    errors: list[str] = []
    if any(int(r.get("label_binary", -1)) != 1 for r in rows):
        errors.append("Stage M manifest contains a non-positive label")
    if any(r.get("positive_only") is not True for r in rows):
        errors.append("Stage M manifest contains a row without positive_only=true")
    if any(r.get("external_dependency") is not False for r in rows):
        errors.append("Stage M manifest contains an external dependency")
    by_family: dict[str, dict] = {}
    for family in FAMILIES:
        rr = [r for r in rows if r.get("family_id") == family.family_id]
        by_family[family.family_id] = {
            "campaigns": len(rr),
            "implementations": sorted({str(r.get("implementation_id")) for r in rr}),
            "clients": sorted({str(r.get("client_stack")) for r in rr}),
            "servers": sorted({str(r.get("server_stack")) for r in rr}),
            "netem_profiles": sorted({str(r.get("network_profile")) for r in rr}),
            "event_counts": sorted({int(r.get("event_count_target", 0)) for r in rr}),
            "nominal_intervals_seconds": sorted({int(r.get("nominal_interval_seconds", 0)) for r in rr}),
        }
    coverage = {
        "contract_revision": 1,
        "positive_only": True,
        "observed_campaigns": len(rows),
        "full_contract_campaigns": EXPECTED_TOTAL_CAMPAIGNS,
        "labels": dict(Counter(int(r.get("label_binary", -1)) for r in rows)),
        "tiers": dict(Counter(str(r.get("tier")) for r in rows)),
        "network_profiles": sorted({str(r.get("network_profile")) for r in rows}),
        "all_known_network_profiles": list(NETWORK_PROFILES),
        "families": by_family,
        "passed": not errors,
        "errors": errors,
    }
    groups = defaultdict(lambda: defaultdict(list))
    for r in rows:
        cid = str(r.get("campaign_id"))
        for kind, value in (r.get("holdout_groups") or {}).items():
            groups[kind][str(value)].append(cid)
    holdouts = {
        "contract_revision": 1,
        "purpose": "implementation/client/server/network/timing/payload leave-one-group-out evaluation",
        "positive_only": True,
        "explicit_implementation_holdout_campaigns": sorted(str(r.get("campaign_id")) for r in rows if r.get("tier") == "implementation_holdout"),
        "groups": {kind: {name: ids for name, ids in sorted(values.items())} for kind, values in sorted(groups.items())},
    }
    return coverage, holdouts


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--manifest", required=True)
    ap.add_argument("--out-dir", required=True)
    args = ap.parse_args()
    coverage, holdouts = build_report(Path(args.manifest))
    out = Path(args.out_dir); out.mkdir(parents=True, exist_ok=True)
    (out / "stage_m_coverage.json").write_text(json.dumps(coverage, indent=2, sort_keys=True) + "\n")
    (out / "stage_m_holdouts.json").write_text(json.dumps(holdouts, indent=2, sort_keys=True) + "\n")
    print(json.dumps({"campaigns": coverage["observed_campaigns"], "passed": coverage["passed"], "holdout_campaigns": len(holdouts["explicit_implementation_holdout_campaigns"])}, sort_keys=True))
    if not coverage["passed"]:
        raise SystemExit("Stage M positive-only coverage contract failed")


if __name__ == "__main__":
    main()
