from __future__ import annotations

"""Bounded in-lab duplex TCP fixture for Stage M.

The protocol never accepts a destination and never opens onward connections.
It only exchanges capped synthetic frames with the connected client.
"""

import argparse
import asyncio
import struct

MAX_FRAME = 65536


async def _read_frame(reader: asyncio.StreamReader, framing: str) -> bytes:
    if framing == "fixed":
        head = await reader.readexactly(2)
        n = struct.unpack("!H", head)[0]
        if n > MAX_FRAME: raise ValueError("frame too large")
        return await reader.readexactly(n)
    if framing == "length_prefixed":
        head = await reader.readexactly(4)
        n = struct.unpack("!I", head)[0]
        if n > MAX_FRAME: raise ValueError("frame too large")
        return await reader.readexactly(n)
    if framing == "line":
        line = await reader.readline()
        if len(line) > MAX_FRAME + 1: raise ValueError("line too large")
        return line.rstrip(b"\n")
    raise ValueError("unsupported framing")


async def _write_frame(writer: asyncio.StreamWriter, framing: str, data: bytes) -> None:
    data = data[:MAX_FRAME]
    if framing == "fixed": writer.write(struct.pack("!H", len(data)) + data)
    elif framing == "length_prefixed": writer.write(struct.pack("!I", len(data)) + data)
    elif framing == "line": writer.write(data.replace(b"\n", b".") + b"\n")
    else: raise ValueError("unsupported framing")
    await writer.drain()


async def handle(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
    try:
        line = await asyncio.wait_for(reader.readline(), timeout=5)
        parts = line.decode(errors="replace").strip().split()
        if len(parts) != 3 or parts[0] != "STAGEM1": return
        framing = parts[1]
        response_size = min(MAX_FRAME, max(1, int(parts[2])))
        if framing not in {"fixed", "length_prefixed", "line"}: return
        writer.write(b"OK\n"); await writer.drain()
        while True:
            try:
                payload = await asyncio.wait_for(_read_frame(reader, framing), timeout=30)
            except (asyncio.IncompleteReadError, TimeoutError):
                break
            marker = payload[0] if payload else 82
            response = bytes([marker ^ 0x5A]) + b"R" * max(0, response_size - 1)
            await _write_frame(writer, framing, response)
    except Exception:
        pass
    finally:
        writer.close()
        try: await writer.wait_closed()
        except Exception: pass


async def main_async(host: str, port: int) -> None:
    server = await asyncio.start_server(handle, host, port, backlog=1024)
    async with server:
        await server.serve_forever()


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--host", default="10.20.0.20")
    ap.add_argument("--port", type=int, default=9090)
    args = ap.parse_args()
    asyncio.run(main_async(args.host, args.port))


if __name__ == "__main__":
    main()
