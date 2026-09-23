from __future__ import annotations

import argparse
import asyncio
import json
import struct
import time
from pathlib import Path

TRACE = Path("/tmp/coverlab_stage_m_tunnel_trace.jsonl")
ALLOWED_FRAMING = {"len16", "len32", "newline", "fixed64"}
ALLOWED_DIRECTION = {"symmetric", "upload_80_20", "download_20_80", "burst_idle", "steady_duplex"}


def _trace(record: dict) -> None:
    with TRACE.open("a", encoding="utf-8") as f:
        f.write(json.dumps(record, separators=(",", ":"), default=str) + "\n")


async def _read_frame(reader: asyncio.StreamReader, framing: str) -> bytes:
    if framing == "len16":
        n = struct.unpack("!H", await reader.readexactly(2))[0]
        return await reader.readexactly(n)
    if framing == "len32":
        n = struct.unpack("!I", await reader.readexactly(4))[0]
        return await reader.readexactly(n)
    if framing == "newline":
        return (await reader.readline()).rstrip(b"\n")
    return await reader.readexactly(64)


async def _write_frame(writer: asyncio.StreamWriter, framing: str, data: bytes) -> None:
    if framing == "len16": writer.write(struct.pack("!H", len(data)) + data)
    elif framing == "len32": writer.write(struct.pack("!I", len(data)) + data)
    elif framing == "newline": writer.write(data.replace(b"\n", b".") + b"\n")
    else: writer.write(data[:64].ljust(64, b"."))
    await writer.drain()


def _reply(data: bytes, direction: str) -> bytes:
    if direction == "upload_80_20": return b"A" * max(16, len(data) // 4)
    if direction == "download_20_80": return (data[:64] or b"D") * 4
    if direction == "burst_idle": return data[: max(16, min(len(data), 256))]
    if direction == "steady_duplex": return data[:512].ljust(min(512, max(64, len(data))), b"S")
    return data[:512]


async def handler(reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
    peer = writer.get_extra_info("peername") or ("", 0)
    try:
        hello = json.loads((await asyncio.wait_for(reader.readline(), timeout=5)).decode())
        framing = str(hello.get("framing", "len16"))
        direction = str(hello.get("direction", "symmetric"))
        campaign = str(hello.get("campaign_id", ""))
        if framing not in ALLOWED_FRAMING or direction not in ALLOWED_DIRECTION:
            writer.write(b"ERR\n"); await writer.drain(); return
        writer.write(b"OK\n"); await writer.drain()
        frames = 0; in_bytes = 0; out_bytes = 0
        while True:
            try:
                data = await asyncio.wait_for(_read_frame(reader, framing), timeout=10)
            except (asyncio.IncompleteReadError, asyncio.TimeoutError):
                break
            if not data: break
            frames += 1; in_bytes += len(data)
            reply = _reply(data, direction)
            out_bytes += len(reply)
            await _write_frame(writer, framing, reply)
        _trace({"ts": time.time(), "client": peer[0], "campaign_id": campaign, "framing": framing, "direction": direction, "frames": frames, "in_bytes": in_bytes, "out_bytes": out_bytes})
    finally:
        writer.close(); await writer.wait_closed()


async def main_async(host: str, port: int):
    server = await asyncio.start_server(handler, host, port)
    async with server:
        await server.serve_forever()


def main():
    ap=argparse.ArgumentParser(); ap.add_argument("--host",default="10.20.0.20"); ap.add_argument("--port",type=int,default=9090); a=ap.parse_args()
    asyncio.run(main_async(a.host,a.port))


if __name__ == "__main__": main()
