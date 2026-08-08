from __future__ import annotations

import argparse
import asyncio

ALLOWED = {"synthetic-api.test:8081", "echo.test:8080", "cover-api.test:8080"}


async def handle(reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
    try:
        head = await asyncio.wait_for(reader.readuntil(b"\r\n\r\n"), timeout=5)
        first = head.split(b"\r\n", 1)[0].decode(errors="replace")
        parts = first.split()
        allowed = len(parts) >= 3 and parts[0] == "CONNECT" and parts[1] in ALLOWED
        if not allowed:
            writer.write(b"HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"); await writer.drain(); return
        writer.write(b"HTTP/1.1 200 Connection Established\r\nProxy-Agent: coverlab-safe\r\n\r\n"); await writer.drain()
        # Deliberately do not connect to the requested target. The post-CONNECT
        # phase is a bounded local echo channel solely for tunnel-shaped traffic.
        for _ in range(8):
            data = await asyncio.wait_for(reader.read(4096), timeout=2)
            if not data: break
            writer.write(data[:4096]); await writer.drain()
    except (asyncio.IncompleteReadError, asyncio.LimitOverrunError, asyncio.TimeoutError):
        pass
    finally:
        writer.close(); await writer.wait_closed()


async def amain(host: str, port: int):
    server = await asyncio.start_server(handle, host, port)
    async with server: await server.serve_forever()


def main():
    p = argparse.ArgumentParser(); p.add_argument("--host", default="10.20.0.20"); p.add_argument("--port", type=int, default=8082); a = p.parse_args()
    asyncio.run(amain(a.host, a.port))


if __name__ == "__main__": main()
