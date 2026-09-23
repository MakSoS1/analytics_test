from __future__ import annotations

import argparse
import asyncio
import json
import ssl
import time
from pathlib import Path

TRACE = Path("/tmp/coverlab_stage_m_http_trace.jsonl")


def _trace(record: dict) -> None:
    with TRACE.open("a", encoding="utf-8") as f:
        f.write(json.dumps(record, separators=(",", ":"), default=str) + "\n")


async def _read_request(reader: asyncio.StreamReader) -> tuple[str, str, str, dict[str, str], bytes] | None:
    try:
        line = await asyncio.wait_for(reader.readline(), timeout=15)
    except asyncio.TimeoutError:
        return None
    if not line:
        return None
    parts = line.decode("latin1", errors="replace").strip().split()
    if len(parts) != 3:
        return None
    method, target, version = parts
    headers: dict[str, str] = {}
    while True:
        h = await reader.readline()
        if h in {b"\r\n", b"\n", b""}:
            break
        text = h.decode("latin1", errors="replace").rstrip("\r\n")
        if ":" in text:
            k, v = text.split(":", 1)
            headers[k.strip().lower()] = v.strip()
    body = b""
    length = int(headers.get("content-length", "0") or 0)
    if length:
        body = await reader.readexactly(min(length, 1 << 20))
        if length > len(body):
            await reader.readexactly(length - len(body))
    return method, target, version, headers, body


async def _send(writer: asyncio.StreamWriter, status: int, body: bytes, headers: dict[str, str], chunked: bool) -> None:
    reason = "OK" if status == 200 else "No Content"
    base = {
        "Server": "stage-m-asyncio/1",
        "Content-Type": "application/octet-stream",
        "Connection": headers.get("connection", "keep-alive"),
    }
    if chunked:
        base["Transfer-Encoding"] = "chunked"
    else:
        base["Content-Length"] = str(len(body))
    writer.write((f"HTTP/1.1 {status} {reason}\r\n" + "".join(f"{k}: {v}\r\n" for k, v in base.items()) + "\r\n").encode())
    if chunked:
        for part in (body[:32], body[32:96], body[96:]):
            if not part:
                continue
            writer.write(f"{len(part):X}\r\n".encode() + part + b"\r\n")
        writer.write(b"0\r\n\r\n")
    else:
        writer.write(body)
    await writer.drain()


async def handler(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
    peer = writer.get_extra_info("peername") or ("", 0)
    ssl_obj = writer.get_extra_info("ssl_object")
    requests = 0
    try:
        while requests < 128:
            req = await _read_request(reader)
            if req is None:
                break
            method, target, version, headers, body = req
            requests += 1
            response_mode = headers.get("x-stage-m-response", "small")
            transfer = headers.get("x-stage-m-transfer", "content-length")
            if target.startswith("/healthz"):
                out = b'{"ok":true}'
            elif target.startswith("/dns-query"):
                out = body or b"\x00\x00\x81\x80\x00\x00\x00\x00\x00\x00\x00\x00"
            elif response_mode == "large":
                out = (b"STAGE_M_RESPONSE_" * 256)[:4096]
            else:
                out = b'{"ok":true,"stage":"m"}'
            _trace({
                "ts": time.time(), "client": peer[0], "method": method, "target": target,
                "request_bytes": len(body), "response_bytes": len(out), "transfer": transfer,
                "tls_version": ssl_obj.version() if ssl_obj else None,
                "session_reused": bool(getattr(ssl_obj, "session_reused", False)) if ssl_obj else False,
            })
            await _send(writer, 200, out, headers, transfer == "chunked")
            if headers.get("connection", "").lower() == "close":
                break
    except (asyncio.IncompleteReadError, ConnectionError, ValueError):
        pass
    finally:
        writer.close()
        try:
            await writer.wait_closed()
        except Exception:
            pass


def ssl_context(cert: str, key: str, profile: str) -> ssl.SSLContext:
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(certfile=cert, keyfile=key)
    if profile == "tls12":
        ctx.minimum_version = ssl.TLSVersion.TLSv1_2
        ctx.maximum_version = ssl.TLSVersion.TLSv1_2
    elif profile == "tls13":
        ctx.minimum_version = ssl.TLSVersion.TLSv1_3
        ctx.maximum_version = ssl.TLSVersion.TLSv1_3
    return ctx


async def main_async(host: str, port: int, cert: str | None, key: str | None, tls_profile: str) -> None:
    ctx = ssl_context(cert, key, tls_profile) if cert and key else None
    server = await asyncio.start_server(handler, host, port, ssl=ctx)
    async with server:
        await server.serve_forever()


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--host", default="10.20.0.20")
    ap.add_argument("--port", type=int, required=True)
    ap.add_argument("--cert")
    ap.add_argument("--key")
    ap.add_argument("--tls-profile", choices=["default", "tls12", "tls13"], default="default")
    args = ap.parse_args()
    asyncio.run(main_async(args.host, args.port, args.cert, args.key, args.tls_profile))


if __name__ == "__main__":
    main()
