#!/usr/bin/env python3
"""Frozen, group-disjoint train / validation / test splits.

Two defects this replaces.

1. The threshold for the hard-negative models was chosen on the office rows the
   forest had just trained on. There was no office validation slice at all, so
   "threshold picked on validation" was not true of those models.

2. When the office CSV held a single time bucket, the code fell back to cutting
   the row list at 70%. It was reported as `capture_window_tail_30pct`, but rows
   carry no capture-window id, so the boundary could run through the middle of
   one capture. Two halves of one capture are not independent samples.

The rule here: split by an explicit group key, never by row position. A group is
whatever must not be shared — a lab session, an office capture window, a day. If
there are too few groups to build disjoint sets, this fails with
`insufficient_split_groups` rather than inventing a boundary.
"""
from __future__ import annotations

import argparse
import csv
import hashlib
import json
import sys
from collections import defaultdict
from pathlib import Path
from typing import Any, Iterable

_PKG_ROOT = Path(__file__).resolve().parent.parent
if str(_PKG_ROOT) not in sys.path:
    sys.path.insert(0, str(_PKG_ROOT))

MIN_GROUPS_PER_ROLE = 2


class InsufficientSplitGroups(RuntimeError):
    """Not enough independent groups to build disjoint sets."""


def _stable_bucket(group: str, salt: str, buckets: int) -> int:
    """Deterministic group -> bucket, so a rerun reproduces the same split."""
    h = hashlib.sha256(f"{salt}:{group}".encode()).hexdigest()
    return int(h[:8], 16) % buckets


def assign_groups(
    groups: Iterable[str],
    fractions: dict[str, float],
    salt: str = "tunnel-detector-v1",
) -> dict[str, list[str]]:
    """Hash each group into exactly one role. Groups never span roles."""
    roles = list(fractions)
    total = sum(fractions.values())
    if total <= 0:
        raise ValueError("fractions must sum above zero")
    edges: list[tuple[str, float]] = []
    acc = 0.0
    for r in roles:
        acc += fractions[r] / total
        edges.append((r, acc))

    out: dict[str, list[str]] = {r: [] for r in roles}
    for g in sorted(set(groups)):
        pos = _stable_bucket(g, salt, 10_000) / 10_000.0
        for role, edge in edges:
            if pos < edge:
                out[role].append(g)
                break
        else:
            out[roles[-1]].append(g)
    return out


def build_split(
    rows: list[dict[str, Any]],
    group_key: str,
    fractions: dict[str, float],
    salt: str = "tunnel-detector-v1",
    min_groups: int = MIN_GROUPS_PER_ROLE,
    stratify_key: str | None = None,
    chronological: bool = False,
) -> dict[str, Any]:
    """Split by group; optionally stratify, or hold out the latest groups.

    Hashing groups globally ignores how they are distributed across families.
    With 12 families that put `socks5_tls` at 47 test sessions against a floor of
    50 — a property of the split, not of the corpus. Stratifying by family hashes
    within each one, so each family lands in every role in proportion.

    Re-rolling the salt until a family passes would be threshold-shopping;
    stratifying is a fixed rule applied before any evaluation.

    `chronological` assigns groups in sorted order instead of by hash, so the
    test slice is the LATEST groups. Office negatives need this. Hashing capture
    windows looks group-disjoint and is not honest: the same office applications
    recur window after window, so a hashed test slice is full of connections
    whose siblings trained the model. Measured — 0 false positives over 5 788
    hashed-split office rows, then 30% of scorable flows alerting on a capture
    from the same link four hours later, every alerting port already present in
    the training data. Sorted group names must order chronologically, which is
    what ISO-8601 time buckets do.
    """
    groups = [str(r.get(group_key) or "") for r in rows]
    missing = sum(1 for g in groups if not g)
    if missing:
        raise InsufficientSplitGroups(
            f"{missing} rows have no '{group_key}'; a row without a group cannot be placed"
        )
    if chronological:
        # No salt, no hash: the ordering IS the split, so it cannot be re-rolled.
        ordered = sorted(set(groups))
        roles = list(fractions)
        total_frac = sum(fractions.values())
        assigned = {role: [] for role in roles}
        n = len(ordered)
        start = 0
        for i, role in enumerate(roles):
            take = n - start if i == len(roles) - 1 else int(round(n * fractions[role] / total_frac))
            assigned[role].extend(ordered[start:start + take])
            start += take
    elif stratify_key:
        # Exact proportions per stratum, not hashing per stratum. Hashing still
        # leaves binomial variance: with 224 sessions and a 25% test share the
        # expectation is 56, and a draw of 47 put a family under the floor of 50
        # twice in a row. Ordering by hash keeps the assignment deterministic and
        # unbiased; slicing by count removes the variance.
        strata: dict[str, set[str]] = defaultdict(set)
        for r in rows:
            strata[str(r.get(stratify_key) or "")].add(str(r.get(group_key) or ""))
        roles = list(fractions)
        total_frac = sum(fractions.values())
        assigned = {role: [] for role in roles}
        for stratum in sorted(strata):
            members = sorted(strata[stratum],
                             key=lambda g: _stable_bucket(g, f"{salt}|{stratum}", 2**31))
            n = len(members)
            start = 0
            for i, role in enumerate(roles):
                take = n - start if i == len(roles) - 1 else int(round(n * fractions[role] / total_frac))
                assigned[role].extend(members[start:start + take])
                start += take
    else:
        assigned = assign_groups(groups, fractions, salt)
    thin = {r: len(g) for r, g in assigned.items() if len(g) < min_groups}
    if thin:
        raise InsufficientSplitGroups(
            f"insufficient_split_groups: {thin} (need >= {min_groups} per role; "
            f"{len(set(groups))} distinct groups available)"
        )
    counts: dict[str, int] = defaultdict(int)
    member: dict[str, str] = {}
    for role, gs in assigned.items():
        for g in gs:
            member[g] = role
    for g in groups:
        counts[member[g]] += 1
    return {
        "group_key": group_key,
        "stratify_key": stratify_key,
        "chronological": chronological,
        "salt": salt,
        "fractions": fractions,
        "groups": {r: sorted(g) for r, g in assigned.items()},
        "group_counts": {r: len(g) for r, g in assigned.items()},
        "row_counts": dict(counts),
        "distinct_groups": len(set(groups)),
    }


def rows_for_role(rows: list[dict[str, Any]], split: dict[str, Any], role: str) -> list[dict[str, Any]]:
    wanted = set(split["groups"][role])
    key = split["group_key"]
    return [r for r in rows if str(r.get(key) or "") in wanted]


def verify_disjoint(split: dict[str, Any]) -> None:
    roles = list(split["groups"])
    for i in range(len(roles)):
        for j in range(i + 1, len(roles)):
            a, b = set(split["groups"][roles[i]]), set(split["groups"][roles[j]])
            overlap = a & b
            if overlap:
                raise AssertionError(f"{roles[i]} and {roles[j]} share groups: {sorted(overlap)[:5]}")


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--csv", required=True)
    ap.add_argument("--group-key", required=True,
                    help="session_id for lab rows, time_bucket/capture_id for office rows")
    ap.add_argument("--roles", default="train=0.6,validation=0.2,test=0.2")
    ap.add_argument("--salt", default="tunnel-detector-v1")
    ap.add_argument("--stratify-key", default=None,
                    help="keep each value of this column proportional in every role")
    ap.add_argument("--chronological", action="store_true",
                    help="hold out the LATEST groups instead of hashing; for office negatives")
    ap.add_argument("--out-json", required=True)
    args = ap.parse_args()

    fractions = {}
    for part in args.roles.split(","):
        name, _, frac = part.partition("=")
        fractions[name.strip()] = float(frac)

    path = Path(args.csv)
    opener: Any = open
    if path.suffix == ".gz":
        import gzip

        opener = gzip.open
    with opener(path, "rt") as fh:
        rows = list(csv.DictReader(fh))

    try:
        split = build_split(rows, args.group_key, fractions, args.salt,
                            stratify_key=args.stratify_key,
                            chronological=args.chronological)
    except InsufficientSplitGroups as exc:
        print(json.dumps({"status": "insufficient_split_groups", "detail": str(exc)}))
        return 3
    verify_disjoint(split)
    split["source_csv"] = str(path)
    split["source_sha256"] = hashlib.sha256(path.read_bytes()).hexdigest()
    Path(args.out_json).write_text(json.dumps(split, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({"status": "ok", "group_counts": split["group_counts"],
                      "row_counts": split["row_counts"], "manifest": args.out_json}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
