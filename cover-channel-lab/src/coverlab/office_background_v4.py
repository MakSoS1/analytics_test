from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path


def sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def validate(root: Path) -> dict:
    manifest = root / "office_background.jsonl"
    if not manifest.exists():
        return {"validated": False, "records": 0, "reason": "office_background.jsonl missing"}
    rows = [json.loads(x) for x in manifest.read_text().splitlines() if x.strip()]
    errors = []
    total_sessions = 0
    total_duration = 0.0
    for i, r in enumerate(rows):
        if r.get("benign_verified") is not True:
            errors.append(f"row {i}: benign_verified=true required")
        if r.get("privacy_scrubbed") is not True:
            errors.append(f"row {i}: privacy_scrubbed=true required")
        if r.get("training_eligible") is not False:
            errors.append(f"row {i}: office holdout must be training-ineligible")
        if r.get("dataset_role") != "office_external_holdout":
            errors.append(f"row {i}: invalid dataset_role")
        sessions = int(r.get("session_count", 0) or 0)
        duration = float(r.get("duration_seconds", 0) or 0)
        if sessions <= 0 or duration <= 0:
            errors.append(f"row {i}: positive session_count/duration_seconds required")
        total_sessions += max(0, sessions)
        total_duration += max(0.0, duration)
        rel = str(r.get("pcap_file", ""))
        p = root / rel
        if not rel or not p.is_file():
            errors.append(f"row {i}: pcap missing")
        elif sha256(p) != r.get("pcap_sha256"):
            errors.append(f"row {i}: pcap sha mismatch")
    return {
        "validated": bool(rows) and not errors,
        "records": len(rows),
        "errors": errors,
        "total_sessions": total_sessions,
        "total_duration_seconds": total_duration,
        "dataset_role": "office_external_holdout",
        "training_eligible": False,
    }


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--root", required=True)
    ap.add_argument("--out", required=True)
    a = ap.parse_args()
    report = validate(Path(a.root))
    p = Path(a.out)
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")
    print(json.dumps(report, sort_keys=True))


if __name__ == "__main__":
    main()
