#!/usr/bin/env python3
"""Train the host20 level, with the split rules overlapping windows demand.

Two things make host windows harder to split than flows.

**Windows overlap.** A trailing 20-minute window recomputed every minute shares
19 minutes with its neighbour. Putting adjacent windows in train and test is
near-duplication, not generalisation. So splitting is by host AND by time, with
a purge gap of at least one window length plus the fast horizon, and the gap is
dropped rather than assigned.

**The fast score is an input.** If it comes from a model that saw these hosts in
training, the host level inherits optimistic predictions. It must come from a
frozen independent model or from out-of-fold scoring — never from a fast model
fitted on the same rows.

There is no labelled host corpus yet: lab sessions run 45–150 seconds, shorter
than the window itself, so they cannot be assembled into twenty minutes of host
behaviour. This exits with `insufficient_labelled_windows` rather than producing
a model from whatever happens to be present.
"""
from __future__ import annotations

import argparse
import csv
import json
import sys
from pathlib import Path
from typing import Any

_PKG_ROOT = Path(__file__).resolve().parent.parent
if str(_PKG_ROOT) not in sys.path:
    sys.path.insert(0, str(_PKG_ROOT))
from lab_pipeline.host_schema import (  # noqa: E402
    HOST_FEATURES,
    HOST_SCHEMA_VERSION,
    WINDOW_SECONDS,
    contract_hash,
)

MIN_WINDOWS_PER_ROLE = 30
MIN_POSITIVE_HOSTS = 5


class InsufficientHostData(RuntimeError):
    pass


def load(path: Path) -> list[dict[str, Any]]:
    with path.open() as fh:
        return list(csv.DictReader(fh))


def split_by_host_and_time(
    rows: list[dict[str, Any]],
    test_fraction: float = 0.3,
    purge_seconds: float | None = None,
) -> dict[str, list[dict[str, Any]]]:
    """Hosts never span roles, and a purge gap removes window overlap in time."""
    purge = purge_seconds if purge_seconds is not None else WINDOW_SECONDS + 300
    hosts = sorted({r["host_key"] for r in rows})
    if len(hosts) < 2:
        raise InsufficientHostData(f"only {len(hosts)} host(s); cannot split by host")
    cut = max(1, int(len(hosts) * (1 - test_fraction)))
    train_hosts, test_hosts = set(hosts[:cut]), set(hosts[cut:])

    times = sorted(float(r["window_end"]) for r in rows)
    boundary = times[int(len(times) * (1 - test_fraction))]

    train, test, purged = [], [], 0
    for r in rows:
        t = float(r["window_end"])
        host = r["host_key"]
        if host in train_hosts and t < boundary - purge:
            train.append(r)
        elif host in test_hosts and t > boundary + purge:
            test.append(r)
        else:
            purged += 1
    return {"train": train, "test": test, "purged": purged,
            "train_hosts": sorted(train_hosts), "test_hosts": sorted(test_hosts)}


def families_missing_from_train(split: dict[str, Any]) -> list[str]:
    """Families present in test and absent from train.

    A host-disjoint split is not automatically the right split. Here the host
    key is the pseudonym of the client address, and that address is fixed per
    lane: one host runs every amneziawg session, another runs shadowsocks,
    vmess, trojan and vless-reality. Measured on the first 41 windows — 8 hosts,
    one carrying four families. So splitting by host splits by lane, and whole
    families land in test having never been trained on.

    That is a leave-one-family-out measurement. It is worth having and it is not
    what "test performance" means, so the report has to name it rather than let
    the number be read as the other thing.
    """
    tr = {str(r.get("label_family") or "") for r in split.get("train", [])}
    te = {str(r.get("label_family") or "") for r in split.get("test", [])}
    return sorted(f for f in te - tr if f)


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--windows-csv", required=True,
                    help="host windows with host_key, window_end, label, window_status")
    ap.add_argument("--out-model", required=True)
    ap.add_argument("--out-json", required=True)
    ap.add_argument("--trees", type=int, default=60)
    ap.add_argument("--max-depth", type=int, default=8)
    args = ap.parse_args()

    rows = [r for r in load(Path(args.windows_csv)) if r.get("window_status") == "full"]
    labelled = [r for r in rows if r.get("label") in ("0", "1")]
    positives = {r["host_key"] for r in labelled if r["label"] == "1"}

    if len(labelled) < MIN_WINDOWS_PER_ROLE * 2 or len(positives) < MIN_POSITIVE_HOSTS:
        print(json.dumps({
            "status": "insufficient_labelled_windows",
            "full_windows": len(rows),
            "labelled": len(labelled),
            "positive_hosts": len(positives),
            "need": {"windows": MIN_WINDOWS_PER_ROLE * 2, "positive_hosts": MIN_POSITIVE_HOSTS},
            "note": ("lab sessions are 45-150 s, shorter than the 20-minute window; "
                     "a host corpus has to be captured for longer than the window"),
        }))
        return 3

    try:
        split = split_by_host_and_time(labelled)
        unseen = families_missing_from_train(split)
    except InsufficientHostData as exc:
        print(json.dumps({"status": "insufficient_host_groups", "detail": str(exc)}))
        return 3
    if min(len(split["train"]), len(split["test"])) < MIN_WINDOWS_PER_ROLE:
        print(json.dumps({
            "status": "insufficient_labelled_windows",
            "train": len(split["train"]), "test": len(split["test"]),
            "purged_for_overlap": split["purged"],
        }))
        return 3

    from sklearn.ensemble import RandomForestClassifier

    def xy(rs):
        return ([[float(r.get(f) or 0.0) for f in HOST_FEATURES] for r in rs],
                [int(r["label"]) for r in rs])

    xtr, ytr = xy(split["train"])
    xte, yte = xy(split["test"])
    clf = RandomForestClassifier(n_estimators=args.trees, max_depth=args.max_depth,
                                 class_weight="balanced_subsample", n_jobs=-1, random_state=42)
    clf.fit(xtr, ytr)
    scores = [float(v[1]) for v in clf.predict_proba(xte)]

    def at(thr):
        tp = sum(1 for a, b in zip(yte, scores) if b >= thr and a == 1)
        fp = sum(1 for a, b in zip(yte, scores) if b >= thr and a == 0)
        fn = sum(1 for a, b in zip(yte, scores) if b < thr and a == 1)
        tn = sum(1 for a, b in zip(yte, scores) if b < thr and a == 0)
        return {"threshold": thr, "tp": tp, "fp": fp, "fn": fn, "tn": tn,
                "recall": tp / max(tp + fn, 1), "precision": tp / max(tp + fp, 1)}

    from lab_pipeline.flow_tier import export_forest

    model = export_forest(clf, list(HOST_FEATURES))
    model["schema_version"] = HOST_SCHEMA_VERSION
    model["contract_hash"] = contract_hash()
    model["threshold"] = 0.5
    Path(args.out_model).write_text(json.dumps(model) + "\n", encoding="utf-8")

    report = {
        "schema_version": HOST_SCHEMA_VERSION,
        "train_windows": len(split["train"]), "test_windows": len(split["test"]),
        "purged_for_overlap": split["purged"],
        "train_hosts": len(split["train_hosts"]), "test_hosts": len(split["test_hosts"]),
        "families_never_trained_on": unseen,
        "measurement_kind": (
            "leave-one-family-out for the families listed in families_never_trained_on; "
            "in-distribution for the rest" if unseen else "in-distribution"
        ),
        "operating_points": [at(t) for t in (0.3, 0.5, 0.7, 0.9)],
        "caveats": [
            "windows overlap by design; a window count is not an independent-sample count",
            "a flow FPR budget does not transfer to host windows — different denominator",
            "fast_score features must come from a frozen or out-of-fold fast model",
        ] + ([
            "SPLIT AXIS: the host key is the client address, which is fixed per lane, so "
            "splitting by host splits by lane and carries whole families into test unseen. "
            f"These were never trained on: {unseen}. Recall over them is a "
            "leave-one-family-out number, not test performance."
        ] if unseen else []),
    }
    Path(args.out_json).write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({"status": "ok",
                      "families_never_trained_on": unseen,
                      "test_windows": len(split["test"]),
                      "model": args.out_model, "report": args.out_json}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
