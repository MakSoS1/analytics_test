from __future__ import annotations

"""Dedicated safe ASGI endpoint for Stage M.

It exists separately from the legacy CoverLab fixture so Stage M can vary server
implementations without changing the semantics of retained V5 traffic.
"""

import base64
from urllib.parse import urlparse

from fastapi import FastAPI, Request, WebSocket, WebSocketDisconnect
from fastapi.responses import HTMLResponse, Response

app = FastAPI(title="coverlab-stage-m-safe-asgi")
MAX_BYTES = 65536
LOCAL_HOST_SUFFIX = ".test"


def _response_size(path: str) -> int:
    if path.startswith("/api/detail"): return 4096
    if path.startswith("/api/upload"): return 96
    if path.startswith("/public/"): return 192
    return 512


@app.get("/healthz")
async def healthz():
    return {"ok": True}


@app.api_route("/dns-query", methods=["GET", "POST"])
async def dns_query(request: Request):
    if request.method == "GET":
        token = request.query_params.get("dns", "")
        token += "=" * ((4 - len(token) % 4) % 4)
        try: body = base64.urlsafe_b64decode(token.encode())
        except Exception: body = b""
    else:
        body = (await request.body())[:MAX_BYTES]
    if not body:
        body = b"\x00\x00\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00"
    return Response(body, media_type="application/dns-message")


@app.get("/stage-m/browser-http")
async def browser_http(request: Request):
    target = request.query_params.get("target", "")
    parsed = urlparse(target)
    if parsed.scheme != "https" or not parsed.hostname or not parsed.hostname.endswith(LOCAL_HOST_SUFFIX):
        return Response("local .test HTTPS target required", status_code=400)
    events = min(100, max(1, int(request.query_params.get("events", "1"))))
    payload = min(4096, max(0, int(request.query_params.get("payload", "0"))))
    delay_ms = min(1000, max(0, int(request.query_params.get("delay_ms", "0"))))
    method = "GET" if request.query_params.get("method") == "GET" else "POST"
    js = f"""
    const target={target!r}, n={events}, payload='A'.repeat({payload}), delay={delay_ms}, method={method!r};
    (async()=>{{for(let i=0;i<n;i++){{let o={{method,mode:'no-cors',cache:'no-store'}};if(method==='POST')o.body=payload;try{{await fetch(target,o)}}catch(e){{}}if(i+1<n&&delay)await new Promise(r=>setTimeout(r,delay));}}document.body.textContent='done';}})();
    """
    return HTMLResponse(f"<html><body>running<script>{js}</script></body></html>")


@app.get("/stage-m/browser-wss")
async def browser_wss(request: Request):
    target = request.query_params.get("target", "custom")
    url = "wss://stage-m-ws.test:9550/ws" if target == "custom" else "wss://stage-m-asgi.test:9543/ws"
    events = min(100, max(1, int(request.query_params.get("events", "1"))))
    payload = min(8192, max(1, int(request.query_params.get("payload", "64"))))
    response = min(8192, max(1, int(request.query_params.get("response", "64"))))
    delay_ms = min(1000, max(0, int(request.query_params.get("delay_ms", "0"))))
    js=f"""
    const n={events}, payload='A'.repeat({payload}), response={response}, delay={delay_ms};
    const w=new WebSocket({url!r}); let sent=0;
    w.onopen=()=>w.send(JSON.stringify({{type:'data',data:payload,response_bytes:response}}));
    w.onmessage=async()=>{{sent++;if(sent>=n){{w.close();document.body.textContent='done';return;}}if(delay)await new Promise(r=>setTimeout(r,delay));w.send(JSON.stringify({{type:'data',data:payload,response_bytes:response}}));}};
    """
    return HTMLResponse(f"<html><body>running<script>{js}</script></body></html>")


@app.websocket("/ws")
async def ws(ws: WebSocket):
    await ws.accept()
    try:
        while True:
            obj = await ws.receive_json()
            n = min(8192, max(1, int(obj.get("response_bytes", 64))))
            await ws.send_text("R" * n)
    except (WebSocketDisconnect, RuntimeError, ValueError):
        return


@app.api_route("/{path:path}", methods=["GET", "POST", "PUT", "PATCH", "DELETE", "HEAD"])
async def generic(path: str, request: Request):
    if request.url.path == "/api/unavailable":
        return Response(b"temporarily unavailable", status_code=503)
    _ = (await request.body())[:MAX_BYTES]
    n = _response_size(request.url.path)
    return Response(b"R" * n, media_type="application/octet-stream")
