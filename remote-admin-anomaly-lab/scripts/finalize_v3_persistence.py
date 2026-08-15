#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
from pathlib import Path

from adminlab.v3_persistence import build_verified_release_status


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--decision", type=Path, required=True)
    parser.add_argument("--hf-verification", type=Path, required=True)
    parser.add_argument("--github-final-run-id", type=int, required=True)
    parser.add_argument("--github-final-artifact-id", type=int, required=True)
    parser.add_argument("--github-artifact-verified", action="store_true")
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()
    decision = json.loads(args.decision.read_text(encoding="utf-8"))
    hf = json.loads(args.hf_verification.read_text(encoding="utf-8"))
    status = build_verified_release_status(
        decision,
        hf,
        github_final_run_id=args.github_final_run_id,
        github_final_artifact_id=args.github_final_artifact_id,
        github_artifact_verified=args.github_artifact_verified,
    )
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(status, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps(status, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
