from __future__ import annotations

import argparse
import asyncio
import json
import ssl

from websockets.asyncio.server import serve
from websockets.exceptions import ConnectionClosed

MAX_REPLY = 8192


async def handler(ws) -> None:
    try:
        async for msg in ws:
            if isinstance(msg, bytes):
                await ws.send(msg[:MAX_REPLY] or b"R")
                continue
            try: obj = json.loads(msg)
            except Exception: obj = {}
            n = min(MAX_REPLY, max(1, int(obj.get("response_bytes", 64))))
            await ws.send("R" * n)
    except (ConnectionClosed, RuntimeError, ValueError):
        return


async def main_async(host: str, port: int, cert: str, key: str) -> None:
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(certfile=cert, keyfile=key)
    async with serve(handler, host, port, ssl=ctx, compression=None, ping_interval=None, max_size=1 << 20):
        await asyncio.Future()


def main() -> None:
    ap=argparse.ArgumentParser(); ap.add_argument('--host',default='10.20.0.21'); ap.add_argument('--port',type=int,default=9550); ap.add_argument('--cert',required=True); ap.add_argument('--key',required=True); a=ap.parse_args()
    asyncio.run(main_async(a.host,a.port,a.cert,a.key))


if __name__=='__main__': main()
