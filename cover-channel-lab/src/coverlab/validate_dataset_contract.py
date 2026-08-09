from __future__ import annotations

import argparse
import json
from collections import Counter
from pathlib import Path

from .scenarios import BY_ID


def _read_jsonl(path: Path) -> list[dict]:
    rows: list[dict] = []
    if not path.exists():
        return rows
    for line in path.read_text(errors="replace").splitlines():
        if not line.strip():
            continue
        rows.append(json.loads(line))
    return rows


def validate(stage_dir: Path) -> dict:
    campaigns_path = stage_dir / "manifests" / "campaigns.jsonl"
    events_path = stage_dir / "manifests" / "events.jsonl"
    if not campaigns_path.exists():
        campaigns_path = stage_dir / "campaigns.jsonl"
    if not events_path.exists():
        events_path = stage_dir / "events.jsonl"

    campaigns = _read_jsonl(campaigns_path)
    events = _read_jsonl(events_path)
    errors: list[str] = []
    warnings: list[str] = []

    if not campaigns:
        errors.append("campaign manifest is empty")

    by_id: dict[str, dict] = {}
    for row in campaigns:
        cid = str(row.get("campaign_id") or "")
        if not cid:
            errors.append("campaign without campaign_id")
            continue
        if cid in by_id:
            errors.append(f"duplicate campaign_id: {cid}")
        by_id[cid] = row

        stage = str(row.get("experiment_stage") or "")
        role = str(row.get("dataset_role") or "")
        label = int(row.get("label_binary") or 0)
        intent = str(row.get("label_intent") or "")
        mapping = row.get("attack_mapping") or []

        if cid.startswith("g-") or stage == "G_trusted_background" or role == "hard_negative":
            if label != 0:
                errors.append(f"{cid}: trusted background has positive label")
            if intent not in {"", "benign"}:
                errors.append(f"{cid}: trusted background label_intent={intent!r}")
            if mapping:
                errors.append(f"{cid}: trusted background has attack_mapping={mapping!r}")
            if stage != "G_trusted_background":
                errors.append(f"{cid}: trusted background stage={stage!r}")
            if role != "hard_negative":
                errors.append(f"{cid}: trusted background dataset_role={role!r}")

        if stage == "D_mixed" and label == 1:
            sid = str(row.get("scenario_id") or "")
            scenario = BY_ID.get(sid)
            if scenario is not None and scenario.family == "lots":
                errors.append(f"{cid}: positive D_mixed sample uses LOTS scenario {sid}")

    event_counts: Counter[str] = Counter()
    for event in events:
        cid = str(event.get("campaign_id") or "")
        event_counts[cid] += 1
        campaign = by_id.get(cid)
        if campaign is None:
            errors.append(f"event references unknown campaign_id: {cid}")
            continue
        if "label_binary" in event and int(event.get("label_binary") or 0) != int(campaign.get("label_binary") or 0):
            errors.append(
                f"{cid}: event label {event.get('label_binary')} != campaign label {campaign.get('label_binary')}"
            )

    for cid, row in by_id.items():
        expected = row.get("expected_events")
        if expected is not None and event_counts[cid] != int(expected):
            warnings.append(f"{cid}: event_count={event_counts[cid]} expected_events={expected}")

    report = {
        "passed": not errors,
        "campaigns": len(campaigns),
        "events": len(events),
        "errors": errors[:200],
        "error_count": len(errors),
        "warnings": warnings[:200],
        "warning_count": len(warnings),
        "contract_revision": 2,
    }
    return report


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--stage-dir", required=True)
    ap.add_argument("--out")
    args = ap.parse_args()
    report = validate(Path(args.stage_dir))
    text = json.dumps(report, indent=2, sort_keys=True)
    if args.out:
        Path(args.out).parent.mkdir(parents=True, exist_ok=True)
        Path(args.out).write_text(text + "\n")
    print(text)
    if not report["passed"]:
        raise SystemExit("dataset ground-truth contract failed")


if __name__ == "__main__":
    main()
