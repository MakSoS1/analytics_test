#!/usr/bin/env python3

from __future__ import annotations

import base64
import hashlib
import json
import socket
import time
from pathlib import Path
from typing import Any
from urllib.parse import urljoin

import requests
from bs4 import BeautifulSoup, Comment


BASE_URL = "http://34.40.133.67:8080"
OUTPUT_DIR = Path("old-web-raw")
OUTPUT_FILE = OUTPUT_DIR / "result.json"
MAX_BODY_BYTES = 256 * 1024
USER_AGENT = "Mozilla/5.0 (compatible; BushBash-CTF-bounded-probe/1.0)"

PATHS = [
    "/",
    "/robots.txt",
    "/sitemap.xml",
    "/favicon.ico",
    "/.well-known/security.txt",
    "/admin",
    "/admin/",
    "/login",
    "/login.php",
    "/index.php",
    "/api",
    "/api/",
    "/old",
    "/old/",
    "/backup",
    "/backup/",
    "/.git/HEAD",
    "/.env",
    "/server-status",
    "/phpinfo.php",
    "/backup.zip",
    "/site.zip",
    "/www.zip",
    "/index.php~",
    "/index.php.bak",
    "/index.html~",
    "/index.html.bak",
]


def encode_bytes(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


def parse_html(body: bytes, content_type: str) -> dict[str, Any] | None:
    if "html" not in content_type.lower() and not body.lstrip().startswith((b"<!DOCTYPE", b"<html", b"<HTML")):
        return None

    text = body.decode("utf-8", errors="replace")
    soup = BeautifulSoup(text, "html.parser")

    forms = []
    for form in soup.find_all("form"):
        forms.append(
            {
                "action": form.get("action"),
                "method": form.get("method", "GET"),
                "enctype": form.get("enctype"),
                "inputs": [
                    {
                        "name": element.get("name"),
                        "type": element.get("type"),
                        "value": element.get("value"),
                    }
                    for element in form.find_all(["input", "button", "textarea", "select"])
                ],
            }
        )

    return {
        "title": soup.title.string.strip() if soup.title and soup.title.string else None,
        "links": sorted({str(tag.get("href")) for tag in soup.find_all("a", href=True)}),
        "scripts": sorted({str(tag.get("src")) for tag in soup.find_all("script", src=True)}),
        "stylesheets": sorted({str(tag.get("href")) for tag in soup.find_all("link", href=True)}),
        "forms": forms,
        "comments": [str(comment) for comment in soup.find_all(string=lambda value: isinstance(value, Comment))],
        "visible_text": "\n".join(soup.stripped_strings)[:65536],
    }


def request_once(method: str, path: str, extra_headers: dict[str, str] | None = None) -> dict[str, Any]:
    url = urljoin(BASE_URL + "/", path.lstrip("/"))
    headers = {
        "User-Agent": USER_AGENT,
        "Accept": "*/*",
        "Connection": "close",
    }
    if extra_headers:
        headers.update(extra_headers)

    started = time.monotonic()
    result: dict[str, Any] = {
        "method": method,
        "path": path,
        "url": url,
        "request_headers": headers,
    }

    try:
        response = requests.request(
            method,
            url,
            headers=headers,
            timeout=(5, 12),
            allow_redirects=False,
        )
        complete_body = response.content
        body = complete_body[:MAX_BODY_BYTES]
        content_type = response.headers.get("Content-Type", "")
        result.update(
            {
                "elapsed_ms": round((time.monotonic() - started) * 1000, 2),
                "status": response.status_code,
                "reason": response.reason,
                "headers": dict(response.headers),
                "cookies": response.cookies.get_dict(),
                "body_length": len(complete_body),
                "body_truncated": len(complete_body) > len(body),
                "body_sha256": hashlib.sha256(complete_body).hexdigest(),
                "body_b64": encode_bytes(body),
                "html": parse_html(body, content_type),
            }
        )
    except Exception as error:
        result.update(
            {
                "elapsed_ms": round((time.monotonic() - started) * 1000, 2),
                "error": f"{type(error).__name__}: {error}",
            }
        )

    return result


def main() -> None:
    results: dict[str, Any] = {
        "target": BASE_URL,
        "reverse_dns": None,
        "requests": [],
    }

    try:
        results["reverse_dns"] = socket.gethostbyaddr("34.40.133.67")
    except Exception as error:
        results["reverse_dns"] = f"{type(error).__name__}: {error}"

    results["requests"].append(request_once("OPTIONS", "/"))
    results["requests"].append(request_once("HEAD", "/"))

    for path in PATHS:
        results["requests"].append(request_once("GET", path))

    # Small, explicit virtual-host comparison only. No host fuzzing.
    for host in ("34.40.133.67", "localhost", "127.0.0.1"):
        results["requests"].append(request_once("GET", "/", {"Host": host}))

    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    OUTPUT_FILE.write_text(
        json.dumps(results, ensure_ascii=False, indent=2, default=str),
        encoding="utf-8",
    )


if __name__ == "__main__":
    main()
