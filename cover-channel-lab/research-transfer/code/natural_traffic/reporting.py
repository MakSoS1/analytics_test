from __future__ import annotations

import hashlib
import json
from pathlib import Path
import shutil
from typing import Any, Iterable

REPORT_VERSION = "natural-report-v2"

def write_report(
    path: Path,
    *,
    kind: str,
    status: str,
    support: dict[str, int] | None = None,
    payload: dict[str, Any] | None = None,
) -> dict[str, Any]:
    body = {
        "version": REPORT_VERSION,
        "kind": str(kind),
        "status": str(status),
        "support": dict(sorted((support or {}).items())),
        "payload": payload or {},
    }
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(json.dumps(body, sort_keys=True, separators=(",", ":"), ensure_ascii=False) + "\n")
    return body

def _sha256(path: Path) -> str:
    h = hashlib.sha256()
    with Path(path).open("rb") as fh:
        for block in iter(lambda: fh.read(1 << 20), b""):
            h.update(block)
    return h.hexdigest()

def _sensitive(path: Path) -> bool:
    name = path.name.lower()
    parts = {p.lower() for p in path.parts}
    if name in {"private-key.asc", "private_key.asc", "dictionary.json"}:
        return True
    if "decrypted" in parts or "private" in parts:
        return True
    if "hmac" in name and "key" in name:
        return True
    if name.endswith(".key"):
        return True
    if name.endswith(".pem") and "public" not in name:
        return True
    return False

def package_release(inputs: Iterable[Path], out_dir: Path) -> dict[str, Any]:
    out = Path(out_dir)
    if out.exists():
        raise FileExistsError(out)
    out.mkdir(parents=True)
    files: list[str] = []
    hashes: dict[str, str] = {}
    for source in sorted({Path(p).resolve() for p in inputs}, key=lambda p: str(p)):
        if not source.is_file() or _sensitive(source):
            continue
        name = source.name
        target = out / name
        if target.exists():
            raise ValueError(f"duplicate release basename: {name}")
        shutil.copy2(source, target)
        files.append(name)
        hashes[name] = _sha256(target)
    report = {
        "version": "natural-release-v2",
        "status": "packaged",
        "files": sorted(files),
        "sha256": dict(sorted(hashes.items())),
        "production_ready": False,
    }
    (out / "release_manifest.json").write_text(
        json.dumps(report, sort_keys=True, separators=(",", ":")) + "\n"
    )
    return report
