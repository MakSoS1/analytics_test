from __future__ import annotations

import argparse
import asyncio
import base64
import json
import os
import ssl
from pathlib import Path

from websockets.asyncio.server import serve
from websockets.exceptions import ConnectionClosed

from .server import body_record, read_state, token

# WSS used to share the HTTP fixture's cross-process trace file. Under sustained
# multi-persona workloads, hundreds of short-lived WSS handlers could queue on
# the same flock as the HTTP server and remain alive long enough to exhaust the
# listener backlog. Keep WSS ground truth in a dedicated local file and merge it
# into the release after capture. This preserves all ground truth without making
# protocol availability depend on logging contention.
WSS_TRACE = Path(os.environ.get("COVERLAB_WSS_TRACE", "/tmp/coverlab_wss_trace.jsonl"))
_TRACE_LOCK: asyncio.Lock | None = None


def _client_ip(ws) -> str | None:
    peer = ws.remote_address
    if isinstance(peer, tuple) and peer:
        return str(peer[0])
    return None


def _write_trace(record: dict) -> None:
    WSS_TRACE.parent.mkdir(parents=True, exist_ok=True)
    with WSS_TRACE.open("a", encoding="utf-8") as out:
        out.write(json.dumps(record, separators=(",", ":"), default=str) + "\n")


async def _append_trace(record: dict) -> None:
    global _TRACE_LOCK
    if _TRACE_LOCK is None:
        _TRACE_LOCK = asyncio.Lock()
    # One WSS process owns this file, so an asyncio lock is sufficient. File I/O
    # is moved off-loop to keep accept/TLS/RFC6455 handshakes responsive.
    async with _TRACE_LOCK:
        await asyncio.to_thread(_write_trace, record)


async def handler(ws) -> None:
    client_ip = _client_ip(ws)
    st = await asyncio.to_thread(read_state, client_ip)
    seed = int(st.get("seed", 1))
    try:
        async for msg in ws:
            if isinstance(msg, str):
                await _append_trace({
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
                await _append_trace({
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
    # The corpus intentionally creates many short connections from four personas.
    # Disable idle keepalive work and use a large accept backlog so the fixture is
    # stable under this synthetic churn rather than silently changing the corpus.
    async with serve(
        handler,
        host,
        port,
        ssl=ctx,
        compression=None,
        max_size=1 << 20,
        max_queue=128,
        ping_interval=None,
        close_timeout=1,
        backlog=2048,
    ):
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
