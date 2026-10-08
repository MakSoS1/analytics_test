from __future__ import annotations

import argparse
import json
from collections import defaultdict
from pathlib import Path

from .research_contract_v3 import FRAMEWORKS


def build(root: Path) -> dict:
    manifest = root / "framework_holdout.jsonl"
    if not manifest.exists():
        return {fw: {"status": "missing"} for fw in FRAMEWORKS}
    rows = [json.loads(x) for x in manifest.read_text().splitlines() if x.strip()]
    grouped = defaultdict(list)
    for r in rows:
        if r.get("framework") in FRAMEWORKS:
            grouped[str(r["framework"])].append(r)
    out = {}
    for fw in FRAMEWORKS:
        scored = [r for r in grouped.get(fw, []) if r.get("model_score") is not None and r.get("label_binary") in (0, 1)]
        if not scored:
            out[fw] = {"status": "missing", "rows": 0}
            continue
        tp = fp = tn = fn = 0
        for r in scored:
            y = int(r["label_binary"])
            pred = float(r["model_score"]) >= float(r.get("decision_threshold", 0.5))
            if y == 1 and pred: tp += 1
            elif y == 1: fn += 1
            elif pred: fp += 1
            else: tn += 1
        positives = tp + fn
        negatives = tn + fp
        out[fw] = {
            "status": "ok",
            "rows": len(scored),
            "positives": positives,
            "precision": tp / max(1, tp + fp),
            "recall": tp / max(1, positives),
            "fpr": fp / max(1, negatives) if negatives else 0.0,
            "fp_per_million": (fp / max(1, negatives) * 1_000_000) if negatives else 0.0,
            "confusion_matrix": [[tn, fp], [fn, tp]],
        }
    return out


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--root", required=True)
    ap.add_argument("--out")
    a = ap.parse_args()
    root = Path(a.root)
    report = build(root)
    out = Path(a.out) if a.out else root / "framework_model_metrics.json"
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")
    print(json.dumps(report, sort_keys=True))


if __name__ == "__main__":
    main()
