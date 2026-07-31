#!/usr/bin/env python3
import base64
import json
import socket
import time
from typing import List, Tuple

HOST = "34.40.133.67"
PORT = 6768

TESTS: List[Tuple[str, List[bytes]]] = [
    ("banner_only", []),
    ("standard_lf", [b"admin\n", b"password\n"]),
    ("standard_crlf", [b"admin\r\n", b"password\r\n"]),
    ("reversed", [b"password\n", b"admin\n"]),
    ("colon_inline", [b"admin:password\n"]),
    ("space_inline", [b"admin password\n"]),
    ("nul_username", [b"admin\x00\n", b"password\n"]),
    ("nul_password", [b"admin\n", b"password\x00\n"]),
    ("both_nul", [b"admin\x00\n", b"password\x00\n"]),
    ("double_password", [b"admin\n", b"passwordpassword\n"]),
]


def recv_available(sock: socket.socket, total_timeout: float = 2.0) -> bytes:
    chunks = []
    deadline = time.monotonic() + total_timeout
    sock.settimeout(0.25)
    while time.monotonic() < deadline:
        try:
            data = sock.recv(4096)
            if not data:
                break
            chunks.append(data)
            deadline = time.monotonic() + 0.45
        except socket.timeout:
            continue
        except OSError:
            break
    return b"".join(chunks)


def run_case(label: str, sends: List[bytes]) -> dict:
    record = {"label": label, "sent": [], "received_chunks": [], "error": None}
    try:
        with socket.create_connection((HOST, PORT), timeout=5.0) as sock:
            initial = recv_available(sock, 1.5)
            record["received_chunks"].append(initial)
            for payload in sends:
                record["sent"].append(payload)
                sock.sendall(payload)
                time.sleep(0.25)
                record["received_chunks"].append(recv_available(sock, 1.5))
            try:
                sock.shutdown(socket.SHUT_WR)
            except OSError:
                pass
            record["received_chunks"].append(recv_available(sock, 1.0))
    except Exception as exc:
        record["error"] = f"{type(exc).__name__}: {exc}"

    def encode(blob: bytes) -> dict:
        return {
            "len": len(blob),
            "hex": blob.hex(),
            "b64": base64.b64encode(blob).decode("ascii"),
            "repr": repr(blob),
        }

    return {
        "label": record["label"],
        "sent": [encode(x) for x in record["sent"]],
        "received_chunks": [encode(x) for x in record["received_chunks"]],
        "error": record["error"],
    }


def main() -> None:
    results = []
    for label, sends in TESTS:
        results.append(run_case(label, sends))
        time.sleep(0.15)
    with open("ctf_password/transcript.json", "w", encoding="utf-8") as fh:
        json.dump({"host": HOST, "port": PORT, "results": results}, fh, indent=2)


if __name__ == "__main__":
    main()
