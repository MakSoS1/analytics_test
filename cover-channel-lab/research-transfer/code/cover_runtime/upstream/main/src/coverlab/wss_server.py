from __future__ import annotations

import argparse
import asyncio
import json
import os
import ssl
from pathlib import Path

from websockets.asyncio.server import serve
from websockets.exceptions import ConnectionClosed

from .server import body_record, read_state, token

WSS_TRACE = Path(os.environ.get("COVERLAB_WSS_TRACE", "/tmp/coverlab_wss_trace.jsonl"))
_TRACE_QUEUE: asyncio.Queue[dict | None] | None = None


def _client_ip(ws) -> str | None:
    peer = ws.remote_address
    if isinstance(peer, tuple) and peer:
        return str(peer[0])
    return None


def _write_batch(records: list[dict]) -> None:
    if not records:
        return
    WSS_TRACE.parent.mkdir(parents=True, exist_ok=True)
    with WSS_TRACE.open("a", encoding="utf-8") as out:
        for record in records:
            out.write(json.dumps(record, separators=(",", ":"), default=str) + "\n")


async def _trace_writer(queue: asyncio.Queue[dict | None]) -> None:
    """Single buffered writer so connection handlers never block on disk I/O."""
    batch: list[dict] = []
    while True:
        item = await queue.get()
        if item is None:
            queue.task_done()
            if batch:
                await asyncio.to_thread(_write_batch, batch)
            return

        batch.append(item)
        queue.task_done()

        while len(batch) < 64:
            try:
                extra = queue.get_nowait()
            except asyncio.QueueEmpty:
                break
            if extra is None:
                queue.task_done()
                if batch:
                    await asyncio.to_thread(_write_batch, batch)
                return
            batch.append(extra)
            queue.task_done()

        if len(batch) >= 64:
            to_write, batch = batch, []
            await asyncio.to_thread(_write_batch, to_write)
        else:
            # Flush small batches quickly enough that ground truth is durable,
            # while still keeping the hot WebSocket path free of file I/O.
            await asyncio.sleep(0)
            if batch:
                to_write, batch = batch, []
                await asyncio.to_thread(_write_batch, to_write)


async def _append_trace(record: dict) -> None:
    if _TRACE_QUEUE is None:
        raise RuntimeError("WSS trace queue is not initialized")
    await _TRACE_QUEUE.put(record)


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
    global _TRACE_QUEUE
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(certfile=cert, keyfile=key)
    _TRACE_QUEUE = asyncio.Queue(maxsize=32768)
    writer = asyncio.create_task(_trace_writer(_TRACE_QUEUE))
    try:
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
            open_timeout=10,
            backlog=4096,
            write_limit=1 << 16,
        ):
            await asyncio.Future()
    finally:
        await _TRACE_QUEUE.join()
        await _TRACE_QUEUE.put(None)
        await writer


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
