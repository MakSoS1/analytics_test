#!/usr/bin/env python3
import base64
import json
import socket
import time

HOST = "34.40.133.67"
PORT = 6768


def cobs_encode(data: bytes) -> bytes:
    out = bytearray()
    code_index = 0
    out.append(0)
    code = 1
    for byte in data:
        if byte == 0:
            out[code_index] = code
            code_index = len(out)
            out.append(0)
            code = 1
        else:
            out.append(byte)
            code += 1
            if code == 0xFF:
                out[code_index] = code
                code_index = len(out)
                out.append(0)
                code = 1
    out[code_index] = code
    out.append(0)
    return bytes(out)


def cobs_decode(frame: bytes) -> bytes:
    if frame.endswith(b"\x00"):
        frame = frame[:-1]
    out = bytearray()
    i = 0
    while i < len(frame):
        code = frame[i]
        if code == 0:
            raise ValueError("zero code inside frame")
        i += 1
        end = i + code - 1
        if end > len(frame):
            raise ValueError("length code exceeds frame")
        out.extend(frame[i:end])
        i = end
        if code != 0xFF and i < len(frame):
            out.append(0)
    return bytes(out)


def recv_available(sock: socket.socket, total_timeout: float) -> bytes:
    chunks = []
    deadline = time.monotonic() + total_timeout
    sock.settimeout(0.25)
    while time.monotonic() < deadline:
        try:
            data = sock.recv(4096)
            if not data:
                break
            chunks.append(data)
            deadline = time.monotonic() + 0.5
        except socket.timeout:
            continue
        except OSError:
            break
    return b"".join(chunks)


def split_and_decode(stream: bytes) -> list[dict]:
    frames = []
    for raw in stream.split(b"\x00"):
        if not raw:
            continue
        encoded = raw + b"\x00"
        try:
            decoded = cobs_decode(encoded)
            frames.append({
                "encoded_hex": encoded.hex(),
                "decoded_hex": decoded.hex(),
                "decoded_b64": base64.b64encode(decoded).decode("ascii"),
                "decoded_text": decoded.decode("utf-8", errors="replace"),
                "error": None,
            })
        except Exception as exc:
            frames.append({
                "encoded_hex": encoded.hex(),
                "decoded_hex": None,
                "decoded_b64": None,
                "decoded_text": None,
                "error": f"{type(exc).__name__}: {exc}",
            })
    return frames


def main() -> None:
    username_packet = cobs_encode(b"admin")
    password_packet = cobs_encode(b"password")
    record = {
        "host": HOST,
        "port": PORT,
        "username_packet_hex": username_packet.hex(),
        "password_packet_hex": password_packet.hex(),
        "chunks": [],
        "error": None,
    }
    try:
        with socket.create_connection((HOST, PORT), timeout=5.0) as sock:
            record["chunks"].append(recv_available(sock, 2.0))
            sock.sendall(username_packet)
            record["chunks"].append(recv_available(sock, 2.0))
            sock.sendall(password_packet)
            record["chunks"].append(recv_available(sock, 3.0))
            try:
                sock.shutdown(socket.SHUT_WR)
            except OSError:
                pass
            record["chunks"].append(recv_available(sock, 1.0))
    except Exception as exc:
        record["error"] = f"{type(exc).__name__}: {exc}"

    combined = b"".join(record["chunks"])
    output = {
        "host": record["host"],
        "port": record["port"],
        "username_packet_hex": record["username_packet_hex"],
        "password_packet_hex": record["password_packet_hex"],
        "error": record["error"],
        "raw_chunks": [
            {
                "len": len(chunk),
                "hex": chunk.hex(),
                "b64": base64.b64encode(chunk).decode("ascii"),
            }
            for chunk in record["chunks"]
        ],
        "decoded_frames": split_and_decode(combined),
    }
    with open("ctf_password/transcript.json", "w", encoding="utf-8") as fh:
        json.dump(output, fh, indent=2)


if __name__ == "__main__":
    main()
