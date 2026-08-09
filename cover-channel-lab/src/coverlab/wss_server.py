from __future__ import annotations

import argparse
import asyncio
import base64
import json
import ssl

from websockets.asyncio.server import serve
from websockets.exceptions import ConnectionClosed

from .server import append_trace, body_record, read_state, token


def _client_ip(ws) -> str | None:
    peer = ws.remote_address
    if isinstance(peer, tuple) and peer:
        return str(peer[0])
    return None


async def handler(ws) -> None:
    client_ip = _client_ip(ws)
    st = read_state(client_ip)
    seed = int(st.get("seed", 1))
    try:
        async for msg in ws:
            if isinstance(msg, str):
                append_trace({
                    "kind": "websocket",
                    "client_ip": client_ip,
                    "scenario_id": st.get("scenario_id"),
                    "direction": "to_server",
                    "text": msg[:16384],
                    "truncated": len(msg) > 16384,
                })
                try:
                    obj = json.loads(msg)
                except Exception:
                    obj = {"type": "echo", "data": msg}
                mtype = obj.get("type") or obj.get("action") or "ack"
                if mtype in {"socks_connect", "connect"}:
                    target = obj.get("target_host", "synthetic-api.test")
                    port = int(obj.get("target_port", 8081))
                    allowed = target in {"synthetic-api.test", "echo.test", "cover-api.test"} and port in {8081, 8080, 8443, 8445}
                    await ws.send(json.dumps({"type": "connect_ack", "allowed": allowed, "conn_id": obj.get("conn_id", "0")}))
                elif mtype in {"socks_data", "data"}:
                    await ws.send(json.dumps({"type": "data_ack", "conn_id": obj.get("conn_id", "0"), "n": len(str(obj.get("data", "")))}))
                else:
                    await ws.send(json.dumps({"type": "ack", "for": mtype, "value": token(seed, 12)}))
            else:
                data = bytes(msg)
                append_trace({
                    "kind": "websocket",
                    "client_ip": client_ip,
                    "scenario_id": st.get("scenario_id"),
                    "direction": "to_server",
                    **body_record(data),
                })
                await ws.send(data[:64])
    except ConnectionClosed:
        return


async def main_async(host: str, port: int, cert: str, key: str) -> None:
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(certfile=cert, keyfile=key)
    async with serve(handler, host, port, ssl=ctx, compression=None, max_size=1 << 20):
        await asyncio.Future()


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--host", default="10.20.0.20")
    ap.add_argument("--port", type=int, default=8445)
    ap.add_argument("--cert", required=True)
    ap.add_argument("--key", required=True)
    args = ap.parse_args()
    asyncio.run(main_async(args.host, args.port, args.cert, args.key))


if __name__ == "__main__":
    main()
