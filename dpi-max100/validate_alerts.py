#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import shutil
import subprocess
import sys
from collections import Counter
from pathlib import Path


def run_checked(cmd: list[str], *, cwd: Path | None = None) -> subprocess.CompletedProcess[str]:
    proc = subprocess.run(cmd, cwd=cwd, text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    if proc.returncode != 0:
        print("command failed:", " ".join(cmd), file=sys.stderr)
        print(proc.stdout, file=sys.stderr)
        raise SystemExit(proc.returncode)
    return proc


def detector_from_signature(signature: str) -> str | None:
    if not signature.startswith("DPI|"):
        return None
    parts = signature.split("|")
    if len(parts) != 3 or parts[0] != "DPI":
        return None
    if parts[2] not in {"protocol", "service"}:
        return None
    return parts[1]


def parse_eve_alerts(eve_path: Path) -> tuple[set[str], Counter[str], list[dict]]:
    detectors: set[str] = set()
    counts: Counter[str] = Counter()
    raw_alerts: list[dict] = []
    if not eve_path.exists():
        return detectors, counts, raw_alerts

    with eve_path.open("r", encoding="utf-8", errors="replace") as handle:
        for line in handle:
            try:
                event = json.loads(line)
            except json.JSONDecodeError:
                continue
            if event.get("event_type") != "alert":
                continue
            alert = event.get("alert") or {}
            signature = str(alert.get("signature") or "")
            detector = detector_from_signature(signature)
            if detector is None:
                continue
            detectors.add(detector)
            counts[detector] += 1
            raw_alerts.append(
                {
                    "timestamp": event.get("timestamp"),
                    "src_ip": event.get("src_ip"),
                    "src_port": event.get("src_port"),
                    "dest_ip": event.get("dest_ip"),
                    "dest_port": event.get("dest_port"),
                    "proto": event.get("proto"),
                    "app_proto": event.get("app_proto"),
                    "signature": signature,
                    "signature_id": alert.get("signature_id"),
                }
            )
    return detectors, counts, raw_alerts


def markdown_report(report: dict) -> str:
    summary = report["summary"]
    lines = [
        "# DPI max100 Suricata validation report",
        "",
        f"- Suricata: `{report['suricata_version']}`",
        f"- Rules: **{report['active_rule_count']}**",
        f"- PCAP cases: **{summary['case_count']}**",
        f"- Passed cases: **{summary['passed_cases']} / {summary['case_count']}**",
        f"- Required detector assertions: **{summary['required_assertions_passed']} / {summary['required_assertions']}**",
        f"- Unexpected detector/case pairs (FP in this matrix): **{summary['unexpected_detector_case_pairs']}**",
        "",
        "> Zero FP here means zero cross-detector false positives on this committed regression matrix. It is not a universal zero-false-positive guarantee for arbitrary production traffic.",
        "",
        "| Case | Required | Observed DPI detectors | Missing | Unexpected | Result |",
        "|---|---|---|---|---|---|",
    ]
    for case in report["cases"]:
        required = ", ".join(case["required"]) or "—"
        observed = ", ".join(case["observed"]) or "—"
        missing = ", ".join(case["missing"]) or "—"
        unexpected = ", ".join(case["unexpected"]) or "—"
        result = "PASS" if case["passed"] else "FAIL"
        lines.append(f"| {case['name']} | {required} | {observed} | {missing} | {unexpected} | {result} |")
    lines.append("")
    return "\n".join(lines)


def count_active_rules(path: Path) -> int:
    count = 0
    for raw in path.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if line and not line.startswith("#") and line.startswith(("alert ", "pass ", "drop ", "reject ")):
            count += 1
    return count


def main() -> None:
    parser = argparse.ArgumentParser(description="Replay generated PCAPs through Suricata and validate DPI TP/FP matrix")
    parser.add_argument("--suricata", required=True)
    parser.add_argument("--config", required=True, type=Path)
    parser.add_argument("--rules", required=True, type=Path)
    parser.add_argument("--cases", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()

    args.rules = args.rules.resolve()
    args.config = args.config.resolve()
    args.cases = args.cases.resolve()
    args.output = args.output.resolve()

    if not args.rules.exists():
        raise SystemExit(f"rules file not found: {args.rules}")
    if not args.config.exists():
        raise SystemExit(f"Suricata config not found: {args.config}")
    if not args.cases.exists():
        raise SystemExit(f"cases manifest not found: {args.cases}")

    version = run_checked([args.suricata, "-V"]).stdout.strip()
    syntax = run_checked([args.suricata, "-T", "-c", str(args.config), "-S", str(args.rules)])

    manifest = json.loads(args.cases.read_text(encoding="utf-8"))
    cases = manifest["cases"]
    case_root = args.cases.parent
    eve_root = args.output / "eve"
    if eve_root.exists():
        shutil.rmtree(eve_root)
    eve_root.mkdir(parents=True, exist_ok=True)

    results = []
    required_assertions = 0
    required_assertions_passed = 0
    unexpected_pairs = 0
    all_observed: Counter[str] = Counter()

    for case in cases:
        name = case["name"]
        pcap = (case_root / case["pcap"]).resolve()
        required = set(case.get("required", []))
        allowed = set(case.get("allowed", []))
        if not required <= allowed:
            raise SystemExit(f"case {name}: required detectors must be a subset of allowed detectors")
        if not pcap.exists():
            raise SystemExit(f"case {name}: PCAP not found: {pcap}")

        log_dir = eve_root / name
        log_dir.mkdir(parents=True, exist_ok=True)
        cmd = [
            args.suricata,
            "--runmode",
            "single",
            "-c",
            str(args.config),
            "-S",
            str(args.rules),
            "-r",
            str(pcap),
            "-l",
            str(log_dir),
            "-k",
            "none",
        ]
        proc = run_checked(cmd)
        (log_dir / "suricata-stdout.log").write_text(proc.stdout, encoding="utf-8")

        observed, counts, raw_alerts = parse_eve_alerts(log_dir / "eve.json")
        all_observed.update(counts)
        missing = sorted(required - observed)
        unexpected = sorted(observed - allowed)
        passed = not missing and not unexpected
        required_assertions += len(required)
        required_assertions_passed += len(required - set(missing))
        unexpected_pairs += len(unexpected)

        results.append(
            {
                "name": name,
                "pcap": str(pcap),
                "required": sorted(required),
                "allowed": sorted(allowed),
                "observed": sorted(observed),
                "alert_counts": dict(sorted(counts.items())),
                "missing": missing,
                "unexpected": unexpected,
                "passed": passed,
                "dpi_alerts": raw_alerts,
            }
        )

    passed_cases = sum(1 for item in results if item["passed"])
    report = {
        "version": manifest.get("version"),
        "suricata_version": version,
        "syntax_check_output": syntax.stdout.strip(),
        "active_rule_count": count_active_rules(args.rules),
        "summary": {
            "case_count": len(results),
            "passed_cases": passed_cases,
            "failed_cases": len(results) - passed_cases,
            "required_assertions": required_assertions,
            "required_assertions_passed": required_assertions_passed,
            "unexpected_detector_case_pairs": unexpected_pairs,
            "total_dpi_alerts_by_detector": dict(sorted(all_observed.items())),
        },
        "cases": results,
    }

    args.output.mkdir(parents=True, exist_ok=True)
    (args.output / "report.json").write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    report_md = markdown_report(report)
    (args.output / "report.md").write_text(report_md, encoding="utf-8")
    print(report_md)

    if passed_cases != len(results):
        print(f"validation failed: {len(results) - passed_cases} case(s) failed", file=sys.stderr)
        raise SystemExit(1)


if __name__ == "__main__":
    main()
