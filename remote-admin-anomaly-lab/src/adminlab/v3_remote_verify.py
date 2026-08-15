from __future__ import annotations

import hashlib
from pathlib import Path
from typing import Any, Iterable


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def verify_downloaded_remote_tree(root: Path | str, expected: Iterable[dict[str, Any]]) -> dict[str, Any]:
    """Verify a downloaded Hub prefix byte-for-byte against expected objects."""
    base = Path(root)
    failures: list[dict[str, Any]] = []
    verified_files = 0
    verified_bytes = 0
    seen: set[str] = set()
    for row in expected:
        remote = str(row.get("remote_path", "")).strip("/")
        sha = str(row.get("remote_sha256", ""))
        size = int(row.get("remote_bytes", -1))
        if not remote or remote in seen:
            failures.append({"remote_path": remote, "reason": "empty_or_duplicate_expected_path"})
            continue
        seen.add(remote)
        path = base / remote
        if not path.is_file():
            failures.append({"remote_path": remote, "reason": "missing"})
            continue
        observed_size = int(path.stat().st_size)
        if observed_size != size:
            failures.append({"remote_path": remote, "reason": "size", "expected": size, "observed": observed_size})
            continue
        observed_sha = sha256_file(path)
        if observed_sha != sha:
            failures.append({"remote_path": remote, "reason": "sha256", "expected": sha, "observed": observed_sha})
            continue
        verified_files += 1
        verified_bytes += observed_size

    report = {
        "ok": not failures and verified_files == len(seen),
        "expected_files": len(seen),
        "verified_files": verified_files,
        "verified_bytes": verified_bytes,
        "failures": failures[:50],
        "verification": "full_download_sha256_all_expected_objects",
    }
    if not report["ok"]:
        raise RuntimeError("remote verification failed: " + repr(report["failures"][:10]))
    return report
