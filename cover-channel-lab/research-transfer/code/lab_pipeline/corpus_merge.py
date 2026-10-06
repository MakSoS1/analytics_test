#!/usr/bin/env python3
"""Merge extra lab tables without double-counting sessions.

`--extra-metadata` used to append every extra row onto the main CSV. A session
present in both corpora trained twice, and protocol QC never saw the extra
captures. This module is the merge the acceptance runner actually calls.
"""
from __future__ import annotations

import csv
from pathlib import Path
from typing import Any


QC_VERDICTS = ("confirmed", "contradicted", "no_server_traffic", "indeterminate")
ENDPOINT_EVIDENCE = ("confirmed", "failed", "unavailable")


def keep_new_session_rows(
    main_rows: list[dict[str, Any]],
    extra_rows: list[dict[str, Any]],
    key: str = "session_id",
) -> tuple[list[dict[str, Any]], list[str]]:
    """Keep every flow of an extra session that is not already in main.

    A session id is excluded only when it already exists in `main`. New extra
    sessions keep all of their rows: adding the id to `seen` while walking extra
    used to drop the second flow of a newly introduced session.
    """
    seen_main = {str(r.get(key) or "") for r in main_rows if r.get(key)}
    kept: list[dict[str, Any]] = []
    dropped: list[str] = []
    for row in extra_rows:
        sid = str(row.get(key) or "")
        if sid and sid in seen_main:
            dropped.append(sid)
            continue
        kept.append(row)
    return kept, dropped


def merge_lab_csv(main: Path, extra: Path) -> dict[str, Any]:
    """Append extra rows whose session_id is not already in `main`.

    Rewrites `main` in place. Duplicate session ids from `extra` are dropped
    and listed so a silent concat cannot inflate the training set.
    """
    main = Path(main)
    extra = Path(extra)
    with main.open(newline="", encoding="utf-8") as fh:
        reader = csv.DictReader(fh)
        cols = list(reader.fieldnames or [])
        existing = list(reader)
    with extra.open(newline="", encoding="utf-8") as fh:
        extra_rows = list(csv.DictReader(fh))
    kept_extra, dropped = keep_new_session_rows(existing, extra_rows)
    with main.open("w", newline="", encoding="utf-8") as fh:
        writer = csv.DictWriter(fh, fieldnames=cols)
        writer.writeheader()
        for row in existing:
            writer.writerow(row)
        for row in kept_extra:
            writer.writerow({k: row.get(k, "") for k in cols})
    unique_dropped = sorted(set(dropped))
    return {
        "dropped_duplicate_sessions": unique_dropped,
        "extra_rows_kept": len(kept_extra),
        "extra_rows_dropped": len(dropped),
    }


def merge_qc_reports(first: dict[str, Any], second: dict[str, Any]) -> dict[str, Any]:
    """Add two protocol-QC reports. Verdicts stay named; nothing is folded."""
    totals = {
        k: int((first.get("totals") or {}).get(k) or 0)
        + int((second.get("totals") or {}).get(k) or 0)
        for k in QC_VERDICTS
    }
    rejected = list(first.get("rejected") or []) + list(second.get("rejected") or [])
    by_family: dict[str, dict[str, int]] = {}
    for src in (first, second):
        for fam, counts in (src.get("by_family") or {}).items():
            slot = by_family.setdefault(fam, {k: 0 for k in QC_VERDICTS})
            for k in QC_VERDICTS:
                slot[k] += int((counts or {}).get(k) or 0)
    sources = int(first.get("sources") or 1) + int(second.get("sources") or 1)
    session_verdicts: dict[str, dict[str, str]] = {}
    for src in (first, second):
        rows = src.get("session_verdicts") or []
        if not isinstance(rows, list):
            raise ValueError("QC session_verdicts must be a list")
        for row in rows:
            if not isinstance(row, dict):
                raise ValueError("QC session verdict must be an object")
            sid = str(row.get("session_id") or "")
            family = str(row.get("family") or "")
            verdict = str(row.get("verdict") or "")
            endpoint_evidence = str(row.get("endpoint_evidence") or "unavailable")
            if (not sid or not family or verdict not in QC_VERDICTS or
                    endpoint_evidence not in ENDPOINT_EVIDENCE):
                raise ValueError("QC session verdict is incomplete or invalid")
            current = {
                "session_id": sid,
                "family": family,
                "verdict": verdict,
                "endpoint_evidence": endpoint_evidence,
            }
            if sid in session_verdicts and session_verdicts[sid] != current:
                raise ValueError(f"conflicting QC verdict for session {sid}")
            session_verdicts[sid] = current
    merged = {
        "totals": totals,
        "rejected": rejected,
        "by_family": by_family,
        "sources": sources,
    }
    if session_verdicts:
        merged["session_verdicts"] = [session_verdicts[sid] for sid in sorted(session_verdicts)]
    return merged


def main() -> int:
    import argparse
    import json

    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--main-csv", required=True)
    ap.add_argument("--extra-csv", required=True)
    ap.add_argument("--out-json", default=None)
    args = ap.parse_args()
    report = merge_lab_csv(Path(args.main_csv), Path(args.extra_csv))
    text = json.dumps(report, ensure_ascii=False)
    if args.out_json:
        Path(args.out_json).write_text(text + "\n", encoding="utf-8")
    print(text)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
