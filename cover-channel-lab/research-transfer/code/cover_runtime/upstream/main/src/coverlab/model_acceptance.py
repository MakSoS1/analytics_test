from __future__ import annotations

import argparse
import json
from pathlib import Path


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--baseline-report", required=True)
    ap.add_argument("--mixed-report")
    ap.add_argument("--out", required=True)
    ap.add_argument("--min-precision", type=float, default=0.95)
    ap.add_argument("--min-recall", type=float, default=0.95)
    ap.add_argument("--enforce", action="store_true")
    args = ap.parse_args()

    baseline = json.loads(Path(args.baseline_report).read_text())
    checks: list[dict] = []
    models = baseline.get("models", {})
    for name in ("B1-content", "B2-session", "B3-opaque"):
        report = models.get(name, {})
        if report.get("status") != "ok":
            checks.append({"model": name, "partition": "model", "passed": False, "reason": report.get("status")})
            continue
        # Validation chooses the threshold and is not counted as final evidence.
        # Test/challenge are checked only when both classes are represented.
        for partition in ("test", "challenge"):
            metrics = report.get(partition, {}) or {}
            if metrics.get("rows", 0) <= 0 or metrics.get("positives", 0) <= 0:
                continue
            precision = float(metrics.get("precision", 0.0))
            recall = float(metrics.get("recall", 0.0))
            checks.append(
                {
                    "model": name,
                    "partition": partition,
                    "precision": precision,
                    "recall": recall,
                    "passed": precision >= args.min_precision and recall >= args.min_recall,
                }
            )

    mixed = None
    if args.mixed_report and Path(args.mixed_report).exists():
        mixed = json.loads(Path(args.mixed_report).read_text())

    report = {
        "policy_revision": 1,
        "min_precision": args.min_precision,
        "min_recall": args.min_recall,
        "baseline_holdout_checks": checks,
        "baseline_holdout_passed": bool(checks) and all(c.get("passed", False) for c in checks),
        "mixed_session_acceptance": (mixed or {}).get("session_acceptance"),
    }
    # Keep dataset-completion and model-quality concepts separate. A corpus can
    # be complete even when a research model misses a production acceptance bar.
    mixed_ok = True if mixed is None else bool((mixed.get("session_acceptance") or {}).get("passed", False))
    report["model_acceptance_passed"] = report["baseline_holdout_passed"] and mixed_ok
    Path(args.out).parent.mkdir(parents=True, exist_ok=True)
    Path(args.out).write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")
    print(json.dumps(report, sort_keys=True))
    if args.enforce and not report["model_acceptance_passed"]:
        raise SystemExit("model acceptance policy failed")


if __name__ == "__main__":
    main()
