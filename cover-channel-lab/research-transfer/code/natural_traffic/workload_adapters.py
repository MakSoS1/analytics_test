"""Allowlisted, legitimate local application tasks with semantic receipts.

No entrypoint, shell command or import path is ever taken from a manifest.
External applications require explicit Python registration by trusted code.
"""

from __future__ import annotations

import json
from pathlib import Path
import re
from typing import Callable

from .office_workload import run_benign_office_workload


_NAME = re.compile(r"[a-z][a-z0-9_]{0,63}\Z")
_RUNNERS: dict[str, Callable[..., dict]] = {
    "verified_local_https": run_benign_office_workload,
}


def register_benign_adapter(name: str, runner: Callable[..., dict]) -> None:
    """Register a function supplied by trusted local Python code, never JSON."""
    if not isinstance(name, str) or not _NAME.fullmatch(name):
        raise ValueError("invalid benign adapter name")
    if not callable(runner):
        raise ValueError("benign adapter must be a callable")
    if name in _RUNNERS:
        raise ValueError("benign adapter already registered")
    _RUNNERS[name] = runner


def run_benign_adapter(name: str, out: Path, *, sessions: int, seed: int) -> dict:
    """Run an explicitly known local task and persist its measured capability."""
    if not isinstance(name, str) or not _NAME.fullmatch(name) or name not in _RUNNERS:
        raise ValueError("unknown or disallowed benign adapter")
    if type(sessions) is not int or not 1 <= sessions <= 10000:
        raise ValueError("sessions must be between 1 and 10000")
    if type(seed) is not int:
        raise ValueError("seed must be an integer")
    out = Path(out)
    if out.exists():
        raise FileExistsError(out)
    result = _RUNNERS[name](out, sessions=sessions, seed=seed)
    if not isinstance(result, dict) or not isinstance(result.get("tasks_completed"), int) or (
        result["tasks_completed"] < 1
    ):
        raise ValueError("benign adapter returned no verifiable task receipt")
    for must_match in (
        ("source", "isolated_disposable_local_fixture"),
        ("naturalness_status", "not_passed"),
        ("training_eligible", False),
        ("production_ready", False),
    ):
        field, expected = must_match
        if result.get(field) != expected:
            raise ValueError(f"benign adapter invalid safety receipt field {field}")
    built_in = name == "verified_local_https"
    if built_in and not all(bool(result.get(key)) for key in (
        "tls_peer_verified", "document_versions_verified", "download_integrity_verified",
    )):
        raise ValueError("HTTPS fixture semantic evidence is incomplete")
    report = {
        **result,
        "adapter_name": name,
        "capabilities": {
            "verified_document_read_edit": built_in and bool(result.get("document_versions_verified")),
            "verified_local_file_upload_download": built_in and bool(result.get("download_integrity_verified")),
            "verified_https_navigation": built_in and bool(result.get("tls_peer_verified")),
            "verified_local_messages": built_in and bool(result.get("tasks_completed")),
            "real_browser_verified": False,  # stdlib HTTPSConnection is not a browser.
            "cloud_sync_verified": False,
        },
        "office_application_mix_verified": False,
        "naturalness_status": "not_passed",
        "training_eligible": False,
        "production_ready": False,
    }
    (out / "adapter_receipt.json").write_text(json.dumps(report, sort_keys=True, indent=2) + "\n")
    return report
