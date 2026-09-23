from __future__ import annotations

import argparse
import json
from collections import Counter
from pathlib import Path


def _read_jsonl(path: Path) -> list[dict]:
    if not path.exists():
        return []
    return [json.loads(x) for x in path.read_text(errors="replace").splitlines() if x.strip()]


def build_report(stage_dir: Path) -> dict:
    campaigns = _read_jsonl(stage_dir / "manifests" / "campaigns.jsonl")
    events = _read_jsonl(stage_dir / "manifests" / "events.jsonl")
    errors: list[str] = []
    ids = {str(x.get("campaign_id", "")) for x in campaigns}

    if not campaigns:
        errors.append("empty campaign manifest")
    if any(int(x.get("label_binary", 0)) != 1 for x in campaigns):
        errors.append("Stage M contains non-positive labels")
    if any(x.get("positive_only") is not True for x in campaigns):
        errors.append("Stage M contains rows without positive_only=true")
    if any(str(x.get("status", "")) != "success" for x in campaigns):
        bad = [str(x.get("campaign_id")) for x in campaigns if str(x.get("status", "")) != "success"]
        errors.append("failed campaigns: " + ",".join(bad[:25]))
    if any(str(x.get("dataset_role", "")) not in {"train_candidate", "implementation_holdout"} for x in campaigns):
        errors.append("invalid dataset_role")
    if any(not str(x.get("implementation_id", "")) for x in campaigns):
        errors.append("missing implementation_id")
    if any(not str(x.get("network_profile", "")) for x in campaigns):
        errors.append("missing network_profile")
    if any(float(x.get("nominal_interval_seconds", 0)) < 0 for x in campaigns):
        errors.append("negative nominal interval")
    unknown_events = sorted({str(e.get("campaign_id", "")) for e in events} - ids)
    if unknown_events:
        errors.append("events reference unknown campaigns: " + ",".join(unknown_events[:25]))
    if any(e.get("timestamp_retimed") is not True for e in events):
        errors.append("events are not fully timestamp-retimed")
    if any(c.get("timestamp_retimed") is not True for c in campaigns):
        errors.append("campaigns are not fully timestamp-retimed")

    retime_path = stage_dir / "manifests" / "retime_report.json"
    retime = json.loads(retime_path.read_text()) if retime_path.exists() else {}
    if not retime.get("passed"):
        errors.append("retime report missing or failed")
    if float(retime.get("mapping_fraction", 0.0)) < 0.90:
        errors.append("retime mapping fraction below 0.90")

    role_counts = Counter(str(x.get("dataset_role")) for x in campaigns)
    family_counts = Counter(str(x.get("scenario_id")) for x in campaigns)
    implementation_counts = Counter(str(x.get("implementation_id")) for x in campaigns)
    event_counts = Counter(str(x.get("campaign_id")) for x in events)
    zero_event = sorted(cid for cid in ids if event_counts[cid] == 0)
    if zero_event:
        errors.append("campaigns without manifest events: " + ",".join(zero_event[:25]))

    return {
        "schema_version": 1,
        "positive_only": True,
        "passed": not errors,
        "errors": errors,
        "campaign_count": len(campaigns),
        "event_count": len(events),
        "unique_campaign_ids": len(ids) == len(campaigns),
        "role_counts": dict(sorted(role_counts.items())),
        "family_counts": dict(sorted(family_counts.items())),
        "implementation_counts": dict(sorted(implementation_counts.items())),
        "retime": retime,
        "all_campaigns_have_events": not zero_event,
    }


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--stage-dir", required=True)
    ap.add_argument("--out", required=True)
    args = ap.parse_args()
    report = build_report(Path(args.stage_dir))
    out = Path(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")
    print(json.dumps(report, sort_keys=True))
    if not report["passed"]:
        raise SystemExit("Stage M shard quality failed")


if __name__ == "__main__":
    main()
