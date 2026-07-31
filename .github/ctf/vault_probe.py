#!/usr/bin/env python3
import re
import socket
from pathlib import Path

HOST = "34.40.133.67"
PORT = 7776
PASSWORD = b"th3M0ssM4ni5h3re,y0uc4ntcatchm3\n"
OUT = Path("vault-result.txt")


def recv_all(sock: socket.socket) -> bytes:
    chunks: list[bytes] = []
    while True:
        try:
            chunk = sock.recv(4096)
        except socket.timeout:
            break
        if not chunk:
            break
        chunks.append(chunk)
    return b"".join(chunks)


def main() -> int:
    try:
        with socket.create_connection((HOST, PORT), timeout=12) as sock:
            sock.settimeout(3)
            try:
                sock.recv(8192)
            except socket.timeout:
                pass
            sock.sendall(PASSWORD)
            response = recv_all(sock)
    except Exception as exc:
        OUT.write_text(f"connection_error: {type(exc).__name__}: {exc}\n", encoding="utf-8")
        print("Probe completed; remote output was not printed.")
        return 1

    match = re.search(rb"bushbash\{[^\r\n}]+\}", response)
    if match is None:
        OUT.write_text("flag_not_found\n", encoding="utf-8")
        print("Probe completed; remote output was not printed.")
        return 2

    OUT.write_bytes(match.group(0) + b"\n")
    print("Result prepared for encryption without printing it.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
