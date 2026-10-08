#!/usr/bin/env python3
"""Re-stamp the MLflow wrapper's runtime code hash after a pipeline edit.

`training_code_sha256` is history and is never touched. `runtime_code_sha256`
names the package that currently loads the frozen run2 bytes, so it legitimately
changes whenever this package does — and the test that pins it is what makes
that change deliberate instead of silent.
"""
from __future__ import annotations

import json
from pathlib import Path

from lab_pipeline.train_fastv1 import code_sha256


RUN_JSON = Path(__file__).resolve().parent.parent / "models" / "fastv1" / "mlflow" / "run.json"


def refresh(path: Path = RUN_JSON) -> tuple[str, str]:
    payload = json.loads(path.read_text())
    if payload.get("training_code_sha256") != payload.get("code_sha256"):
        raise ValueError("training hash and code hash disagree; refusing to rewrite provenance")
    previous = payload["runtime_code_sha256"]
    payload["runtime_code_sha256"] = code_sha256()
    path.write_text(json.dumps(payload, indent=2, ensure_ascii=False) + "\n")
    return previous, payload["runtime_code_sha256"]


if __name__ == "__main__":
    was, now = refresh()
    print(json.dumps({"runtime_code_sha256": {"was": was, "now": now}}))
