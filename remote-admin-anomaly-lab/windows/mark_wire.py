#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import re
from pathlib import Path


PORTS = {
    "openssh": (22,),
    "smb": (445,),
    "winrm": (5985, 5986),
    "dcom": (135,),
    "rdp": (3389,),
}


def read_pktmon_text(path: Path) -> str:
    raw = path.read_bytes()
    if raw.startswith((b"\xff\xfe", b"\xfe\xff")):
        return raw.decode("utf-16", errors="replace")
    return raw.decode("utf-8-sig", errors="replace")


def endpoint_port_count(text: str, port: int) -> int:
    # pktmon format renders TCP endpoints as IPv4/IPv6 `.PORT` tokens, e.g.
    # `127.0.0.1.52152 > 127.0.0.1.22`. Some builds may use colon notation.
    return len(re.findall(rf"(?:\.|:){port}\b", text, flags=re.IGNORECASE))


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("report", type=Path)
    parser.add_argument("capture_text", type=Path)
    args = parser.parse_args()

    report = json.loads(args.report.read_text(encoding="utf-8-sig"))
    text = read_pktmon_text(args.capture_text)
    protocols = report["protocols"]
    validated: list[str] = []
    evidence_counts: dict[str, dict[str, int]] = {}
    for name, ports in PORTS.items():
        item = protocols[name]
        counts = {str(port): endpoint_port_count(text, port) for port in ports}
        evidence_counts[name] = counts
        item["wire_observed"] = any(count > 0 for count in counts.values())
        triple = bool(item.get("tool_present")) and bool(item.get("wire_observed")) and bool(item.get("session_completed"))
        if triple:
            item["fidelity_status"] = "native_windows_validated"
            item["failure_reason"] = ""
            validated.append(name)
        elif name == "rdp" and not bool(item.get("session_completed")):
            item["fidelity_status"] = "unavailable_hosted_runner"
        else:
            item["fidelity_status"] = "attempted_unverified"
    report["validated_protocols"] = validated
    report["wire_evidence_counts"] = evidence_counts
    args.report.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps({"validated_protocols": validated, "wire_evidence_counts": evidence_counts}, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
