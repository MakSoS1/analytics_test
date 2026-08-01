#!/usr/bin/env python3

from __future__ import annotations

import base64
import json
import os
import random
import socket
import ssl
import string
import subprocess
import tempfile
import time
from pathlib import Path
from typing import Any

import dns.flags
import dns.message
import dns.query
import dns.rcode
import dns.rdatatype
import requests
import urllib3


urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

TARGET = "secret-hidden-website.bushbash.cssa.club"
PARENT = "bushbash.cssa.club"
ROOT = "cssa.club"
OUTPUT_DIR = Path("secret-web-raw")
OUTPUT_FILE = OUTPUT_DIR / "result.json"
MAX_BODY_BYTES = 256 * 1024
DNS_SERVERS = ["1.1.1.1", "8.8.8.8", "9.9.9.9"]
QTYPE_NAMES = [
    "A",
    "AAAA",
    "CNAME",
    "TXT",
    "NS",
    "SOA",
    "MX",
    "CAA",
    "HTTPS",
    "SVCB",
    "SRV",
]
HTTP_PATHS = [
    "/",
    "/robots.txt",
    "/sitemap.xml",
    "/.well-known/security.txt",
    "/favicon.ico",
    "/admin",
    "/secret",
    "/flag",
    "/next",
]
USER_AGENT = "Mozilla/5.0 (compatible; BushBash-CTF-passive-probe/1.0)"


def serialise_dns_section(section: Any) -> list[str]:
    records: list[str] = []
    for rrset in section:
        records.append(rrset.to_text())
    return records


def query_dns(name: str, qtype_name: str, server: str) -> dict[str, Any]:
    qtype = dns.rdatatype.from_text(qtype_name)
    query = dns.message.make_query(name, qtype, want_dnssec=True)
    query.flags |= dns.flags.RD

    started = time.monotonic()
    result: dict[str, Any] = {
        "name": name,
        "qtype": qtype_name,
        "server": server,
    }

    try:
        response = dns.query.udp(query, server, timeout=4)
        if response.flags & dns.flags.TC:
            response = dns.query.tcp(query, server, timeout=6)

        result.update(
            {
                "elapsed_ms": round((time.monotonic() - started) * 1000, 2),
                "rcode": dns.rcode.to_text(response.rcode()),
                "flags": dns.flags.to_text(response.flags),
                "answer": serialise_dns_section(response.answer),
                "authority": serialise_dns_section(response.authority),
                "additional": serialise_dns_section(response.additional),
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


def parse_ip_records(dns_results: list[dict[str, Any]], name: str) -> list[str]:
    found: set[str] = set()
    for item in dns_results:
        if item.get("name") != name or item.get("qtype") not in {"A", "AAAA"}:
            continue
        for rrset_text in item.get("answer", []):
            for line in rrset_text.splitlines():
                fields = line.split()
                if fields and fields[-1] not in {"A", "AAAA"}:
                    candidate = fields[-1]
                    try:
                        socket.inet_pton(socket.AF_INET, candidate)
                        found.add(candidate)
                        continue
                    except OSError:
                        pass
                    try:
                        socket.inet_pton(socket.AF_INET6, candidate)
                        found.add(candidate)
                    except OSError:
                        pass
    return sorted(found)


def fetch_ct_hosts() -> dict[str, Any]:
    url = f"https://crt.sh/?q=%25.{PARENT}&output=json"
    result: dict[str, Any] = {"url": url}
    try:
        response = requests.get(
            url,
            headers={"User-Agent": USER_AGENT},
            timeout=15,
        )
        result["status"] = response.status_code
        result["headers"] = dict(response.headers)
        body = response.content[:MAX_BODY_BYTES]
        result["body_b64"] = base64.b64encode(body).decode("ascii")
        result["body_truncated"] = len(response.content) > len(body)

        hosts: set[str] = set()
        if response.ok:
            for row in response.json():
                for field in ("name_value", "common_name"):
                    value = row.get(field)
                    if not isinstance(value, str):
                        continue
                    for hostname in value.splitlines():
                        hostname = hostname.strip().lower().rstrip(".")
                        if hostname.startswith("*."):
                            hostname = hostname[2:]
                        if hostname == PARENT or hostname.endswith("." + PARENT):
                            hosts.add(hostname)
        result["hosts"] = sorted(hosts)[:200]
    except Exception as error:
        result["error"] = f"{type(error).__name__}: {error}"
    return result


def fetch_url(url: str, *, headers: dict[str, str] | None = None) -> dict[str, Any]:
    result: dict[str, Any] = {"url": url}
    merged_headers = {"User-Agent": USER_AGENT, "Accept": "*/*"}
    if headers:
        merged_headers.update(headers)

    started = time.monotonic()
    try:
        response = requests.get(
            url,
            headers=merged_headers,
            timeout=(5, 10),
            allow_redirects=False,
            verify=False,
        )
        body = response.content[:MAX_BODY_BYTES]
        result.update(
            {
                "elapsed_ms": round((time.monotonic() - started) * 1000, 2),
                "status": response.status_code,
                "reason": response.reason,
                "headers": dict(response.headers),
                "body_b64": base64.b64encode(body).decode("ascii"),
                "body_length": len(response.content),
                "body_truncated": len(response.content) > len(body),
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


def curl_resolve(hostname: str, ip: str, path: str, scheme: str) -> dict[str, Any]:
    port = 443 if scheme == "https" else 80
    url = f"{scheme}://{hostname}{path}"
    result: dict[str, Any] = {
        "url": url,
        "resolve_ip": ip,
    }

    with tempfile.TemporaryDirectory(prefix="secret-web-curl-") as directory:
        directory_path = Path(directory)
        headers_path = directory_path / "headers.bin"
        body_path = directory_path / "body.bin"
        stderr_path = directory_path / "stderr.bin"

        command = [
            "curl",
            "--silent",
            "--show-error",
            "--insecure",
            "--connect-timeout",
            "5",
            "--max-time",
            "12",
            "--max-filesize",
            str(MAX_BODY_BYTES),
            "--resolve",
            f"{hostname}:{port}:{ip}",
            "--user-agent",
            USER_AGENT,
            "--dump-header",
            str(headers_path),
            "--output",
            str(body_path),
            "--write-out",
            "%{http_code}\n%{remote_ip}\n%{remote_port}\n%{url_effective}\n",
            url,
        ]

        started = time.monotonic()
        with stderr_path.open("wb") as stderr_file:
            process = subprocess.run(
                command,
                stdout=subprocess.PIPE,
                stderr=stderr_file,
                timeout=20,
                check=False,
            )

        result["elapsed_ms"] = round((time.monotonic() - started) * 1000, 2)
        result["exit_code"] = process.returncode
        result["meta"] = process.stdout.decode("utf-8", errors="replace")
        result["stderr_b64"] = base64.b64encode(stderr_path.read_bytes()[:65536]).decode("ascii")
        result["headers_b64"] = base64.b64encode(headers_path.read_bytes()[:65536]).decode("ascii")
        result["body_b64"] = base64.b64encode(body_path.read_bytes()[:MAX_BODY_BYTES]).decode("ascii")

    return result


def tls_certificate(hostname: str, ip: str | None = None) -> dict[str, Any]:
    result: dict[str, Any] = {"hostname": hostname, "ip": ip}
    context = ssl.create_default_context()
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE

    try:
        address = ip or hostname
        with socket.create_connection((address, 443), timeout=6) as raw_socket:
            with context.wrap_socket(raw_socket, server_hostname=hostname) as tls_socket:
                der = tls_socket.getpeercert(binary_form=True)
                result["cipher"] = tls_socket.cipher()
                result["version"] = tls_socket.version()
                result["peer"] = tls_socket.getpeername()
                result["certificate_der_b64"] = base64.b64encode(der).decode("ascii")
    except Exception as error:
        result["error"] = f"{type(error).__name__}: {error}"

    return result


def main() -> None:
    random_label = "probe-" + "".join(random.choice(string.ascii_lowercase) for _ in range(12))
    names = [
        TARGET,
        PARENT,
        ROOT,
        f"www.{PARENT}",
        f"{random_label}.{PARENT}",
        f"_acme-challenge.{TARGET}",
        f"_http._tcp.{TARGET}",
        f"_https._tcp.{TARGET}",
    ]

    dns_results: list[dict[str, Any]] = []
    for name in names:
        for qtype in QTYPE_NAMES:
            for server in DNS_SERVERS:
                dns_results.append(query_dns(name, qtype, server))

    ct_result = fetch_ct_hosts()
    ct_hosts = ct_result.get("hosts", [])

    # Resolve CT-discovered siblings so their ingress addresses can be tested
    # as virtual-host candidates for the otherwise hidden hostname.
    for hostname in ct_hosts[:80]:
        for qtype in ("A", "AAAA", "CNAME"):
            for server in DNS_SERVERS[:2]:
                dns_results.append(query_dns(hostname, qtype, server))

    direct_http: list[dict[str, Any]] = []
    for scheme in ("https", "http"):
        for path in HTTP_PATHS:
            direct_http.append(fetch_url(f"{scheme}://{TARGET}{path}"))

    candidate_names = sorted(set([TARGET, PARENT, f"www.{PARENT}"] + list(ct_hosts[:80])))
    candidate_ips: set[str] = set()
    for name in candidate_names:
        candidate_ips.update(parse_ip_records(dns_results, name))

    resolved_http: list[dict[str, Any]] = []
    for ip in sorted(candidate_ips)[:30]:
        for scheme in ("https", "http"):
            for path in HTTP_PATHS:
                resolved_http.append(curl_resolve(TARGET, ip, path, scheme))

    certificates = [tls_certificate(TARGET)]
    for ip in sorted(candidate_ips)[:30]:
        certificates.append(tls_certificate(TARGET, ip))

    system_resolution: dict[str, Any] = {}
    for hostname in candidate_names:
        try:
            system_resolution[hostname] = socket.getaddrinfo(hostname, None)
        except Exception as error:
            system_resolution[hostname] = f"{type(error).__name__}: {error}"

    output = {
        "target": TARGET,
        "random_wildcard_label": random_label,
        "dns": dns_results,
        "certificate_transparency": ct_result,
        "system_resolution": system_resolution,
        "candidate_ips": sorted(candidate_ips),
        "direct_http": direct_http,
        "resolved_http": resolved_http,
        "tls": certificates,
    }

    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    OUTPUT_FILE.write_text(json.dumps(output, ensure_ascii=False, indent=2, default=str), encoding="utf-8")


if __name__ == "__main__":
    main()
