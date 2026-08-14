#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from adminlab.campaign_sequences import organize_campaign_sequences  # noqa: E402
from adminlab.config import load_yaml  # noqa: E402
from adminlab.digital_twin import load_digital_twin_bundle, plan_digital_twin_sessions  # noqa: E402
from adminlab.scenario_quality import evaluate_scenario_quality  # noqa: E402


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--stage", choices=list("ABCDEFGH"), default="H")
    parser.add_argument("--count", type=int, default=12000)
    parser.add_argument("--seed", type=int, default=20260821)
    parser.add_argument("--out", type=Path)
    args = parser.parse_args()

    topology = load_yaml(ROOT / "configs/topology.yaml")
    scenarios = load_yaml(ROOT / "configs/scenarios.yaml")
    netem = load_yaml(ROOT / "configs/netem.yaml")
    bundle = load_digital_twin_bundle(ROOT / "configs")
    records = plan_digital_twin_sessions(
        topology, scenarios, netem, bundle, seed=args.seed, count=args.count, stage=args.stage
    )
    records = organize_campaign_sequences(records, bundle["campaigns"], seed=args.seed)
    report = evaluate_scenario_quality(records)
    report.update({"stage": args.stage, "seed": args.seed, "planned_rows": args.count})
    report["multi_session_campaigns"] = len({r.campaign_id for r in records if r.campaign_size >= 3})
    report["multi_protocol_campaigns"] = len({r.campaign_id for r in records if r.sequence_profile == "multi_protocol"})
    payload = json.dumps(report, indent=2, sort_keys=True) + "\n"
    if args.out:
        args.out.parent.mkdir(parents=True, exist_ok=True)
        args.out.write_text(payload, encoding="utf-8")
    print(payload, end="")
    if not report["ok"]:
        raise SystemExit("semantic diversity gate failed; do not start corpus fan-out")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
