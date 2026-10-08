"""Isolated benign office-workflow fixture with real, verified HTTPS sessions.

This is an application-task correctness fixture, NOT a PCAP camouflage or
naturalness optimizer. It never contacts a corporate or public endpoint.
"""
from __future__ import annotations

import argparse
from contextlib import closing, contextmanager
import hashlib
from http.client import HTTPSConnection
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import os
from pathlib import Path
import random
import select
import shutil
import signal
import ssl
import subprocess
import tempfile
from threading import Lock, Thread
import time
from typing import Iterator


MAX_BODY = 128 * 1024
MAX_SESSIONS = 1000


def audit_client_handshakes(pcap: Path, *, server_port: int) -> dict[str, int]:
    """Count independent TCP handshakes from bytes, not action receipts.

    This checks session start coverage, not completeness of every TLS record
    or office-domain representativeness. Only aggregate counts are exported.
    """
    from office_injection.source import read_pcap, transport

    syn: set[tuple] = set()
    synack: set[tuple] = set()
    for _, frame in read_pcap(pcap, max_regression=0.00005):
        packet = transport(frame)
        if packet is None or packet["proto"] != 6:
            continue
        if all(endpoint[1] != server_port for endpoint in packet["key"][:2]):
            continue
        flags = packet["flags"]
        if flags & 0x12 == 0x02:  # Client SYN without ACK.
            syn.add(packet["key"])
        elif flags & 0x12 == 0x12:  # Server SYN-ACK.
            synack.add(packet["key"])
    return {
        "client_syn_flows": len(syn),
        "server_synack_flows": len(synack),
        "completed_tcp_handshakes": len(syn & synack),
    }


def _wait_for_capture_ready(proc: subprocess.Popen, path: Path,
                            *, timeout_seconds: float = 5.0) -> None:
    """Wait for tcpdump to attach its interface/filter before connecting.

    A header alone may remain buffered by the dumper until its first packet,
    so prefer tcpdump's immediate 'listening on' startup acknowledgement.
    """
    deadline = time.monotonic() + timeout_seconds
    stderr = getattr(proc, "stderr", None)
    startup_message = bytearray()
    while True:
        if proc.poll() is not None:
            raise RuntimeError("native capture exited before workload execution")
        if stderr is not None:
            ready, _, _ = select.select([stderr], [], [], 0)
            if ready:
                chunk = os.read(stderr.fileno(), 4096)
                startup_message.extend(chunk)
                if b"listening on " in startup_message.lower():
                    return
                if len(startup_message) > 8192:
                    raise RuntimeError("native capture produced excessive startup diagnostics")
        else:
            # Injected/alternate capture processes without stderr can expose
            # an initialized global header as their readiness signal.
            try:
                with path.open("rb") as stream:
                    header = stream.read(24)
                if len(header) == 24 and header[:4] in (
                    b"\xd4\xc3\xb2\xa1", b"\xa1\xb2\xc3\xd4",
                    b"\x4d\x3c\xb2\xa1", b"\xa1\xb2\x3c\x4d",
                ):
                    return
            except FileNotFoundError:
                pass
        if time.monotonic() >= deadline:
            raise RuntimeError("native capture not ready before timeout")
        time.sleep(0.05)


class _OfficeState:
    def __init__(self, sessions: int):
        self.lock = Lock()
        self.documents = {
            f"doc-{i}": {"revision": 1, "text": f"Disposable draft {i}"}
            for i in range(sessions)
        }
        self.files: dict[str, bytes] = {}
        self.messages: list[dict[str, str]] = []


def _handler_type(state: _OfficeState) -> type[BaseHTTPRequestHandler]:
    class Handler(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def log_message(self, *args: object) -> None:
            # No user content, URL, or access credentials enter CI logs.
            pass

        def _send(self, status: int, payload: bytes, content_type: str) -> None:
            self.send_response(status)
            self.send_header("Content-Type", content_type)
            self.send_header("Content-Length", str(len(payload)))
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
            self.wfile.write(payload)

        def _json(self, status: int, data: object) -> None:
            self._send(status, json.dumps(data, sort_keys=True).encode(), "application/json")

        def _read(self) -> bytes | None:
            try:
                length = int(self.headers.get("Content-Length", "-1"))
            except ValueError:
                length = -1
            if not 0 <= length <= MAX_BODY:
                self._json(413, {"error": "invalid body size"})
                self.close_connection = True
                return None
            return self.rfile.read(length)

        def do_GET(self) -> None:
            with state.lock:
                if self.path == "/docs":
                    return self._json(200, {"ids": sorted(state.documents)})
                if self.path.startswith("/docs/"):
                    doc = state.documents.get(self.path[len("/docs/"):])
                    return self._json(200, doc) if doc else self._json(404, {"error": "missing"})
                if self.path.startswith("/uploads/"):
                    blob = state.files.get(self.path[len("/uploads/"):])
                    return self._send(200, blob, "application/octet-stream") if blob is not None else self._json(404, {"error": "missing"})
                if self.path == "/messages":
                    return self._json(200, {"messages": state.messages})
            self._json(404, {"error": "unknown fixture route"})

        def do_PUT(self) -> None:
            raw = self._read()
            if raw is None:
                return
            if not self.path.startswith("/docs/"):
                return self._json(404, {"error": "unknown fixture route"})
            try:
                data = json.loads(raw)
                revision, text = data["revision"], data["text"]
                if not isinstance(revision, int) or not isinstance(text, str) or len(text) > 10000:
                    raise ValueError("invalid edit")
            except (ValueError, KeyError, TypeError):
                return self._json(400, {"error": "invalid edit"})
            with state.lock:
                doc = state.documents.get(self.path[len("/docs/"):])
                if doc is None:
                    return self._json(404, {"error": "missing"})
                if doc["revision"] != revision:
                    return self._json(409, {"error": "revision conflict"})
                doc["revision"] += 1
                doc["text"] = text
                self._json(200, {"revision": doc["revision"]})

        def do_POST(self) -> None:
            raw = self._read()
            if raw is None:
                return
            if self.path.startswith("/uploads/"):
                file_id = self.path[len("/uploads/"):]
                if not file_id or "/" in file_id:
                    return self._json(400, {"error": "invalid fixture file"})
                with state.lock:
                    state.files[file_id] = raw
                return self._json(200, {"sha256": hashlib.sha256(raw).hexdigest()})
            if self.path == "/messages":
                try:
                    data = json.loads(raw)
                    if not isinstance(data["text"], str) or len(data["text"]) > 5000:
                        raise ValueError("invalid message")
                except (ValueError, KeyError, TypeError):
                    return self._json(400, {"error": "invalid message"})
                with state.lock:
                    state.messages.append({"text": data["text"]})
                    index = len(state.messages)
                return self._json(200, {"message_count": index})
            self._json(404, {"error": "unknown fixture route"})

    return Handler


@contextmanager
def _fixture_server(sessions: int, directory: Path) -> Iterator[tuple[int, Path]]:
    cert = directory / "fixture.crt"
    key = directory / "fixture.key"
    subprocess.run([
        "openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes",
        "-keyout", str(key), "-out", str(cert), "-days", "1",
        "-subj", "/CN=localhost", "-addext", "subjectAltName=IP:127.0.0.1",
    ], check=True, capture_output=True)
    state = _OfficeState(sessions)
    server = ThreadingHTTPServer(("127.0.0.1", 0), _handler_type(state))
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.load_cert_chain(certfile=cert, keyfile=key)
    server.socket = context.wrap_socket(server.socket, server_side=True)
    thread = Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield int(server.server_address[1]), cert
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)


def _call(conn: HTTPSConnection, method: str, path: str, payload: bytes | None = None,
          *, mime: str = "application/json") -> bytes:
    headers = {"Accept": "application/json"}
    if payload is not None:
        headers["Content-Type"] = mime
    conn.request(method, path, body=payload, headers=headers)
    response = conn.getresponse()
    data = response.read()
    if response.status != 200:
        raise RuntimeError(f"fixture HTTP {response.status} for declared {method} task")
    return data


def _tasks(port: int, cert: Path, *, sessions: int, seed: int,
           action_pause_seconds: float) -> dict[str, object]:
    rng = random.Random(seed)
    actions = 0
    completed = 0
    for i in range(sessions):
        context = ssl.create_default_context(cafile=str(cert))
        with closing(HTTPSConnection("127.0.0.1", port, timeout=10, context=context)) as conn:
            def action(method: str, path: str, data: bytes | None = None,
                       mime: str = "application/json") -> bytes:
                nonlocal actions
                result = _call(conn, method, path, data, mime=mime)
                actions += 1
                if action_pause_seconds:
                    time.sleep(action_pause_seconds)
                return result

            doc_id = f"doc-{i}"
            listing = json.loads(action("GET", "/docs"))
            if doc_id not in listing["ids"]:
                raise RuntimeError("document list lacks session fixture")
            original = json.loads(action("GET", "/docs/" + doc_id))
            completed += 1  # Navigate and read a document.

            edit = "Disposable note " + str(rng.randrange(10**12))
            saved = json.loads(action("PUT", "/docs/" + doc_id, json.dumps({
                "revision": original["revision"], "text": edit,
            }).encode()))
            reread = json.loads(action("GET", "/docs/" + doc_id))
            if reread["text"] != edit or saved["revision"] != original["revision"] + 1 or reread["revision"] != saved["revision"]:
                raise RuntimeError("document save/readback mismatch")
            completed += 1  # Edit then verify committed revision.

            blob = rng.randbytes(128 + rng.randrange(1024))
            file_id = f"dummy-{i}"
            upload = json.loads(action("POST", "/uploads/" + file_id, blob,
                                       mime="application/octet-stream"))
            downloaded = action("GET", "/uploads/" + file_id)
            if upload["sha256"] != hashlib.sha256(blob).hexdigest() or downloaded != blob:
                raise RuntimeError("file synchronization integrity mismatch")
            completed += 1  # Upload and download the same disposable file.

            note = "Disposable team update " + str(i)
            action("POST", "/messages", json.dumps({"text": note}).encode())
            messages = json.loads(action("GET", "/messages"))
            if {"text": note} not in messages["messages"]:
                raise RuntimeError("collaboration message not committed")
            completed += 1  # Post and verify a collaboration message.
    return {"sessions_completed": sessions, "tasks_completed": completed,
            "actions_completed": actions}


@contextmanager
def _capture(port: int, path: Path, enabled: bool) -> Iterator[None]:
    if not enabled:
        yield
        return
    if os.name != "posix" or not shutil.which("tcpdump"):
        raise RuntimeError("native tcpdump capture capability unavailable")
    command = ([] if os.geteuid() == 0 else ["sudo", "-n"]) + [
        "tcpdump", "-i", "lo", "-s", "0", "-U", "-w", str(path),
        "tcp", "port", str(port),
    ]
    proc = subprocess.Popen(command, stdout=subprocess.DEVNULL,
                            stderr=subprocess.PIPE)
    try:
        _wait_for_capture_ready(proc, path)
        yield
    finally:
        if proc.poll() is None:
            proc.send_signal(signal.SIGINT)
        try:
            proc.wait(timeout=10)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.wait(timeout=5)
        if proc.stderr is not None:
            proc.stderr.close()
        if proc.returncode not in (0, 130, -signal.SIGINT):
            raise RuntimeError(f"native capture terminated abnormally: rc={proc.returncode}")


def run_benign_office_workload(
    out: Path, *, sessions: int = 3, seed: int = 20261008,
    action_pause_seconds: float = 0.03, capture: bool = False,
) -> dict[str, object]:
    """Execute and attest synthetic work tasks; never assert office equivalence."""
    if isinstance(sessions, bool) or not isinstance(sessions, int) or not 1 <= sessions <= MAX_SESSIONS:
        raise ValueError(f"sessions must be an integer in [1, {MAX_SESSIONS}]")
    if not 0 <= action_pause_seconds <= 10:
        raise ValueError("action pause must be between 0 and 10 seconds")
    out = Path(out)
    if out.exists():
        raise FileExistsError(out)
    out.mkdir(mode=0o700, parents=True)
    pcap_path = out / "benign_workload.pcap"
    with tempfile.TemporaryDirectory(prefix="disposable-office-fixture-") as tmp:
        with _fixture_server(sessions, Path(tmp)) as (port, cert):
            with _capture(port, pcap_path, capture):
                result = _tasks(
                    port, cert, sessions=sessions, seed=seed,
                    action_pause_seconds=action_pause_seconds,
                )
            if capture:
                handshakes = audit_client_handshakes(pcap_path, server_port=port)
                if any(handshakes[k] != sessions for k in (
                    "client_syn_flows", "server_synack_flows", "completed_tcp_handshakes",
                )):
                    raise RuntimeError(
                        f"captured TCP handshake coverage incomplete: "
                        f"expected {sessions}, observed {handshakes}"
                    )
    capture_info: dict[str, object] = {"capture_status": "not_requested"}
    if capture:
        from .pcap_quality import audit_pcap
        quality = audit_pcap(pcap_path)
        if not quality.accepted:
            raise RuntimeError(f"captured PCAP quality failure: {quality.reasons}")
        capture_info = {
            "capture_status": "quality_accepted",
            "pcap_sha256": hashlib.sha256(pcap_path.read_bytes()).hexdigest(),
            "physical_frames": quality.packet_count,
            "handshake_coverage_validated": True,
            **handshakes,
        }
    report: dict[str, object] = {
        "version": "verified-benign-application-workload-v1",
        "source": "isolated_disposable_local_fixture",
        "client_stack": "python_stdlib_https",
        "tls_peer_verified": True,
        "document_versions_verified": True,
        "download_integrity_verified": True,
        "seed": seed,
        "source_label": "verified_benign_fixture_only",
        "source_pcap_rewritten": False,
        "office_application_mix_verified": False,
        "naturalness_status": "not_passed",
        "training_eligible": False,
        "production_ready": False,
        **result,
        **capture_info,
    }
    (out / "workload_receipt.json").write_text(
        json.dumps(report, sort_keys=True, indent=2) + "\n"
    )
    return report


def main() -> None:
    parser = argparse.ArgumentParser(description="Generate disposable benign office HTTPS tasks")
    parser.add_argument("--out", required=True, type=Path)
    parser.add_argument("--sessions", type=int, default=3)
    parser.add_argument("--seed", type=int, default=20261008)
    parser.add_argument("--action-pause-seconds", type=float, default=0.03)
    parser.add_argument("--capture", action="store_true")
    args = parser.parse_args()
    report = run_benign_office_workload(
        args.out, sessions=args.sessions, seed=args.seed,
        action_pause_seconds=args.action_pause_seconds, capture=args.capture,
    )
    print(json.dumps(report, sort_keys=True))


if __name__ == "__main__":
    main()
