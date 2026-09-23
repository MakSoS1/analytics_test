from __future__ import annotations

"""Very small local HTTP/1.1 fixture used for plaintext-on-443 Stage M traffic."""

import argparse
import asyncio

MAX_BODY = 65536


async def handle(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
    try:
        head = await asyncio.wait_for(reader.readuntil(b"\r\n\r\n"), timeout=5)
        lines = head.decode(errors="replace").split("\r\n")
        headers = {}
        for line in lines[1:]:
            if ":" in line:
                k, v = line.split(":", 1); headers[k.strip().lower()] = v.strip()
        n = min(MAX_BODY, max(0, int(headers.get("content-length", "0") or 0)))
        if n: await reader.readexactly(n)
        response_size = min(MAX_BODY, max(1, int(headers.get("x-stage-m-response-bytes", "96") or 96)))
        body = b"R" * response_size
        writer.write(
            b"HTTP/1.1 200 OK\r\n"
            + f"Content-Length: {len(body)}\r\nConnection: close\r\nContent-Type: application/octet-stream\r\n\r\n".encode()
            + body
        )
        await writer.drain()
    except Exception:
        pass
    finally:
        writer.close()
        try: await writer.wait_closed()
        except Exception: pass


async def main_async(host: str, ports: list[int]) -> None:
    servers = [await asyncio.start_server(handle, host, p, backlog=1024) for p in ports]
    async with servers[0], servers[1]:
        await asyncio.gather(*(s.serve_forever() for s in servers))


def main() -> None:
    ap = argparse.ArgumentParser(); ap.add_argument("--host", required=True); ap.add_argument("--ports", default="80,443")
    args = ap.parse_args(); ports = [int(x) for x in args.ports.split(",") if x]
    if len(ports) != 2: raise SystemExit("exactly two ports are required")
    asyncio.run(main_async(args.host, ports))


if __name__ == "__main__": main()
