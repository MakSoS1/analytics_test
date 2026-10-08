"""Immutable MITRE source → paired research model → office transfer diagnostic.

This CLI never replays, executes or camouflages an uploaded activity. Inputs
are evidence for *defender-only* feature extraction and model evaluation.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys

import pandas as pd

from .corpus_splits import assign_research_splits
from .office_reference import freeze_feature_contract, load_office_reference
from .technique_transfer_evaluation import evaluate_technique_transfer
from .verified_corpus import build_verified_corpus


def main(argv: list[str] | None = None) -> dict:
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    prepare = sub.add_parser("prepare", help="verify immutable MITRE files and session membership")
    prepare.add_argument("--manifest", required=True, type=Path)
    prepare.add_argument("--source-root", required=True, type=Path)
    prepare.add_argument("--out", required=True, type=Path)
    prepare.add_argument("--min-free-gib", type=float, default=1)
    train = sub.add_parser("train", help="group-held-out models on verified pairs only")
    train.add_argument("--prepared", required=True, type=Path)
    train.add_argument("--office-dir", required=True, type=Path)
    train.add_argument("--office-cover-dir", type=Path, default=None)
    train.add_argument("--out", required=True, type=Path)
    train.add_argument("--seed", type=int, default=20261008)
    evaluate = sub.add_parser("evaluate", help="immutable test-only MITRE and office metrics")
    evaluate.add_argument("--prepared", required=True, type=Path)
    evaluate.add_argument("--models", required=True, type=Path)
    evaluate.add_argument("--office-dir", required=True, type=Path)
    evaluate.add_argument("--office-cover-dir", type=Path, default=None)
    evaluate.add_argument("--out", required=True, type=Path)
    report = sub.add_parser("report", help="print aggregate evaluation JSON; no raw traffic")
    report.add_argument("--evaluation", required=True, type=Path)
    args = parser.parse_args(argv)

    if args.command == "prepare":
        return build_verified_corpus(
            args.manifest, args.source_root, args.out, min_free_gib=args.min_free_gib,
        )
    if args.command == "train":
        office = load_office_reference(args.office_dir, args.office_cover_dir)
        measured = pd.read_parquet(args.prepared / "features.parquet")
        metadata = pd.read_parquet(args.prepared / "labels_metadata.parquet")
        contract = freeze_feature_contract(measured, office)
        splits = assign_research_splits(metadata, seed=args.seed)
        from office_injection.technique_training import train_technique_models
        result = train_technique_models(args.prepared, splits, contract, args.out, seed=args.seed)
        (args.out / "feature_contract.json").write_text(
            json.dumps(contract, indent=2, sort_keys=True) + "\n"
        )
        return result
    if args.command == "evaluate":
        office = load_office_reference(args.office_dir, args.office_cover_dir)
        return evaluate_technique_transfer(args.prepared, args.models, office, args.out)
    path = args.evaluation / "evaluation_report.json"
    result = json.loads(path.read_text())
    if result.get("version") != "defender-mitre-technique-transfer-v1" or result.get("production_ready") is not False:
        raise ValueError("invalid research evaluation report status")
    return result


if __name__ == "__main__":
    try:
        output = main()
    except (OSError, ValueError, RuntimeError, KeyError, TypeError) as error:
        print(f"defender corpus refused: {error}", file=sys.stderr)
        raise SystemExit(2) from None
    print(json.dumps(output, sort_keys=True))
