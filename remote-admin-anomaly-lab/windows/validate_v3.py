#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from adminlab.windows_v3 import validate_v3_windows_report


def read_text(path: Path) -> str:
    raw = path.read_bytes()
    if raw.startswith((b"\xff\xfe", b"\xfe\xff")):
        return raw.decode("utf-16", errors="replace")
    return raw.decode("utf-8-sig", errors="replace")


def port_count(text: str, port: int) -> int:
    return len(re.findall(rf"(?:\.|:){port}\b", text, flags=re.IGNORECASE))


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--base-report", type=Path, required=True)
    parser.add_argument("--extra-report", type=Path, required=True)
    parser.add_argument("--extra-capture", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()

    base = json.loads(args.base_report.read_text(encoding="utf-8-sig"))
    extra = json.loads(args.extra_report.read_text(encoding="utf-8-sig"))
    text = read_text(args.extra_capture)
    counts = {"135": port_count(text, 135), "3389": port_count(text, 3389)}
    report = validate_v3_windows_report(
        base,
        extra_port_counts=counts,
        extra_dcom_completed=bool(extra.get("dcom", {}).get("session_completed")),
    )
    report["v3_extra_probe"] = extra
    report["v3_extra_capture"] = str(args.extra_capture)
    args.out.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps(report, indent=2, sort_keys=True))

    # Technical workflow needs at least the proven V2-family native protocols.
    required_any = {"openssh", "smb", "winrm"}
    if not required_any.intersection(report.get("validated_protocols", [])):
        raise SystemExit("no Windows native protocol validated in V3")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
