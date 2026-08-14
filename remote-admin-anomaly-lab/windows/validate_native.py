#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import math
from pathlib import Path


PROTOCOLS = ("openssh", "smb", "winrm", "dcom", "rdp")


def validate(report: dict) -> dict:
    if report.get("environment_id") != "windows_native":
        raise ValueError("Windows fidelity report has wrong environment_id")
    if report.get("capture_source") != "pktmon":
        raise ValueError("Windows fidelity report must retain pktmon provenance")
    protocols = report.get("protocols")
    if not isinstance(protocols, dict):
        raise ValueError("Windows fidelity report missing protocols mapping")

    validated: list[str] = []
    failures: list[str] = []
    for name in PROTOCOLS:
        item = protocols.get(name)
        if not isinstance(item, dict):
            failures.append(f"missing_protocol:{name}")
            continue
        required = ("tool_present", "wire_observed", "session_completed", "fidelity_status")
        if any(key not in item for key in required):
            failures.append(f"incomplete_protocol:{name}")
            continue
        triple = bool(item["tool_present"]) and bool(item["wire_observed"]) and bool(item["session_completed"])
        status = str(item["fidelity_status"])
        if status == "native_windows_validated":
            if not triple:
                failures.append(f"invalid_native_claim:{name}")
            else:
                validated.append(name)
        elif triple:
            failures.append(f"validated_evidence_without_status:{name}")

    return {
        "schema_version": 2,
        "status": "ok" if not failures else "failed",
        "protocols_reported": len([p for p in PROTOCOLS if p in protocols]),
        "validated_protocols": validated,
        "validated_protocol_count": len(validated),
        "failures": failures,
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("report", type=Path)
    parser.add_argument("--out", type=Path)
    args = parser.parse_args()

    report = json.loads(args.report.read_text(encoding="utf-8-sig"))
    result = validate(report)
    target = args.out or args.report.with_name("windows_fidelity_validation.json")
    target.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps(result, indent=2, sort_keys=True))
    if result["status"] != "ok":
        raise SystemExit("Windows fidelity validation failed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
