from __future__ import annotations

import asyncio
import base64
import fcntl
import json
import os
import random
import time
from pathlib import Path

from fastapi import FastAPI, Request, Response, WebSocket, WebSocketDisconnect
from fastapi.responses import HTMLResponse, JSONResponse, PlainTextResponse, StreamingResponse

STATE = Path(os.environ.get("COVERLAB_STATE", "/tmp/coverlab_server_state.json"))
TRACE = Path(os.environ.get("COVERLAB_SERVER_TRACE", "/tmp/coverlab_server_trace.jsonl"))
app = FastAPI(title="coverlab-safe-fixture")


def read_state(client_ip: str | None = None) -> dict:
    try:
        raw=json.loads(STATE.read_text())
        if client_ip and isinstance(raw, dict) and "clients" in raw:
            return raw.get("clients", {}).get(client_ip, raw.get("default", {}))
        return raw.get("default", raw) if isinstance(raw, dict) else {}
    except Exception:
        return {"scenario_id": "BENIGN", "suspicious": False, "seed": 1}


def token(seed: int, n: int = 32) -> str:
    r = random.Random(seed)
    alphabet = "0123456789abcdef"
    return "".join(r.choice(alphabet) for _ in range(n))



def append_trace(record: dict) -> None:
    TRACE.parent.mkdir(parents=True,exist_ok=True)
    lock_path=TRACE.with_suffix(TRACE.suffix+".lock")
    with lock_path.open("w") as lock:
        fcntl.flock(lock,fcntl.LOCK_EX)
        with TRACE.open("a",encoding="utf-8") as out:
            out.write(json.dumps(record,separators=(",",":"),default=str)+"\n")
        fcntl.flock(lock,fcntl.LOCK_UN)


def body_record(data: bytes, limit: int = 16384) -> dict:
    clipped=data[:limit]
    return {"body_b64":base64.b64encode(clipped).decode(),"body_length":len(data),"body_truncated":len(data)>limit}


def response_for(sid: str, suspicious: bool, seed: int) -> Response:
    # Suspicious and benign responses deliberately use comparable protocol shapes.
    marker = token(seed, 32) if suspicious else token(seed + 1000003, 32)
    if sid == "CC_RESP_01":
        return PlainTextResponse("ECHO_ALPHA" if suspicious else "STATUS_OK")
    if sid == "CC_RESP_02":
        return JSONResponse({"status":"ok","data":marker,"build":"2026.08","count":3})
    if sid == "CC_RESP_03":
        chunks = [marker[i:i+8] for i in range(0,32,8)]
        xml = "<manifest>" + "".join(f'<item id="{c}-0000-4000-8000-{c}{c}" />' for c in chunks) + "</manifest>"
        return Response(xml, media_type="application/xml")
    if sid == "CC_RESP_04":
        return HTMLResponse(f"<html><body data-build='{marker[:12]}'><!--{marker[12:]}--><h1>Status</h1></body></html>")
    if sid == "CC_RESP_05":
        return Response(f".v-{marker[:8]}{{margin:{int(marker[0],16)%8}px}} /* {marker[8:]} */", media_type="text/css")
    if sid == "CC_RESP_06":
        # Synthetic image-like bytes, not a real user image.
        return Response(b"\x89PNG\r\n\x1a\n" + marker.encode() + b"\x00" * 64, media_type="image/png")
    if sid == "CC_RESP_07":
        resp = PlainTextResponse("ok")
        resp.set_cookie("session", marker, httponly=True, secure=True)
        return resp
    if sid == "CC_RESP_08":
        return Response(status_code=304, headers={"ETag": f'"{marker}"'})
    if sid == "CC_RESP_09":
        return Response(status_code=(204 if int(marker[0],16)%2 else 200))
    if sid == "CC_RESP_10":
        return Response(status_code=302, headers={"Location": f"/static/{marker[:16]}.js"})
    if sid == "CC_RESP_11":
        size = 1024 + (int(marker[:2], 16) % 4) * 256
        return Response(b"A" * size, media_type="application/octet-stream")
    if sid == "CC_RESP_12":
        async def chunks():
            for i, n in enumerate((64,128,96,160)):
                yield (marker[i*8:(i+1)*8] or "x").encode().ljust(n,b".")
                await asyncio.sleep(0.002)
        return StreamingResponse(chunks(), media_type="application/octet-stream")
    return JSONResponse({"ok": True, "ts": int(time.time()), "value": marker[:16]})


@app.get("/healthz")
async def healthz():
    return {"ok": True}


@app.api_route("/dns-query", methods=["GET", "POST"])
async def dns_query(request: Request):
    # Returns a tiny synthetic DNS response body; semantics are never forwarded to a resolver.
    body = await request.body()
    if not body:
        body = b"\x00\x00\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00"
    # Echoing the query is sufficient for wire-format traffic generation and stays local.
    append_trace({"ts":time.time(),"kind":"http","client_ip":request.client.host if request.client else None,"scenario_id":"CC_DOH_01","method":request.method,"path":"/dns-query","request_headers":dict(request.headers),"request":body_record(body),"response_status":200,"response_content_type":"application/dns-message"})
    return Response(body, media_type="application/dns-message")


@app.get("/events")
async def events(request: Request):
    st = read_state(request.client.host if request.client else None)
    sid = st.get("scenario_id", "BENIGN")
    suspicious = bool(st.get("suspicious", False))
    seed = int(st.get("seed", 1))
    value = token(seed if suspicious else seed+7, 24)
    async def gen():
        for i in range(4):
            yield f"id: {i}\nevent: update\ndata: {{\"value\":\"{value[i*4:(i+1)*4]}\",\"status\":\"ok\"}}\n\n"
            await asyncio.sleep(0.01)
    return StreamingResponse(gen(), media_type="text/event-stream")



@app.get("/browser-fixture/{sid}")
async def browser_fixture(sid: str):
    # Genuine browser network primitives against LOCAL .test endpoints only.
    if sid == "CC_BROWSER_09":
        js = "navigator.sendBeacon('/collect', JSON.stringify({event:'pagehide',value:'SYNTHETIC_BROWSER_BEACON'}));"
        body = f"<html><body><script>{js}</script>browser fixture</body></html>"
        return HTMLResponse(body)
    if sid == "CC_BROWSER_10":
        body = "<html><body><img src='https://blocked.synthetic.invalid/x'>CSP fixture</body></html>"
        return HTMLResponse(body, headers={"Content-Security-Policy":"default-src 'self'; img-src 'none'; report-uri /csp-report"})
    if sid == "CC_BROWSER_11":
        body = "<html><head><link rel='prefetch' href='/prefetch/a1b2c3d4.js'><link rel='preconnect' href='https://cover-api.test:8443'></head><body>prefetch fixture</body></html>"
        return HTMLResponse(body)
    if sid == "CC_BROWSER_06":
        body = """<html><body><script>let w=new WebSocket('wss://cover-ws.test:8443/ws');w.onopen=()=>w.send(JSON.stringify({action:'recv',container:'SYNTHETIC'}));</script>WSS fixture</body></html>"""
        return HTMLResponse(body)
    body = "<html><body><script>fetch('/browser/background?id=synthetic');setTimeout(()=>fetch('/browser/heartbeat'),300);</script>browser fixture</body></html>"
    return HTMLResponse(body)

@app.websocket("/ws")
async def ws_endpoint(ws: WebSocket):
    await ws.accept()
    st = read_state(ws.client.host if ws.client else None)
    seed = int(st.get("seed", 1))
    try:
        while True:
            msg = await ws.receive()
            if msg.get("text") is not None:
                text = msg["text"]
                append_trace({"ts":time.time(),"kind":"websocket","client_ip":ws.client.host if ws.client else None,"scenario_id":st.get("scenario_id"),"direction":"to_server","text":text[:16384],"truncated":len(text)>16384})
                try:
                    obj = json.loads(text)
                except Exception:
                    obj = {"type":"echo","data":text}
                mtype = obj.get("type") or obj.get("action") or "ack"
                # Safe SOCKS-like grammar is acknowledged but never connected/forwarded.
                if mtype in {"socks_connect","connect"}:
                    target = obj.get("target_host", "synthetic-api.test")
                    port = int(obj.get("target_port", 8081))
                    allowed = target in {"synthetic-api.test","echo.test","cover-api.test"} and port in {8081,8080,8443}
                    await ws.send_text(json.dumps({"type":"connect_ack","allowed":allowed,"conn_id":obj.get("conn_id","0")}))
                elif mtype in {"socks_data","data"}:
                    await ws.send_text(json.dumps({"type":"data_ack","conn_id":obj.get("conn_id","0"),"n":len(str(obj.get("data","")))}))
                else:
                    await ws.send_text(json.dumps({"type":"ack","for":mtype,"value":token(seed,12)}))
            elif msg.get("bytes") is not None:
                data = msg["bytes"]
                append_trace({"ts":time.time(),"kind":"websocket","client_ip":ws.client.host if ws.client else None,"scenario_id":st.get("scenario_id"),"direction":"to_server",**body_record(data)})
                await ws.send_bytes(data[:64])
    except (WebSocketDisconnect, RuntimeError):
        return


@app.api_route("/{path:path}", methods=["GET","POST","PUT","PATCH","DELETE","HEAD"])
async def catch_all(path: str, request: Request):
    st = read_state(request.client.host if request.client else None)
    sid = st.get("scenario_id", "BENIGN")
    suspicious = bool(st.get("suspicious", False))
    seed = int(st.get("seed", 1))
    req_body = await request.body()  # synthetic input only; never execute it
    resp=response_for(sid, suspicious, seed)
    response_body=getattr(resp,"body",b"") or b""
    append_trace({"ts":time.time(),"kind":"http","client_ip":request.client.host if request.client else None,"scenario_id":sid,"suspicious":suspicious,"method":request.method,"path":request.url.path,"query":request.url.query,"request_headers":dict(request.headers),"request":body_record(req_body),"response_status":resp.status_code,"response_headers":dict(resp.headers),"response":body_record(response_body)})
    return resp
