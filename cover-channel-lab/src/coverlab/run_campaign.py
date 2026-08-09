from __future__ import annotations

import argparse
import base64
import gzip
import fcntl
import hashlib
import json
import os
import random
import subprocess
import ssl
import urllib.request
import urllib.error
import socket
import struct
import time
import urllib.parse
import uuid
from datetime import datetime, timezone
from pathlib import Path

import dns.message
import dns.name
import dns.rdatatype
import httpx
from websockets.sync.client import connect as ws_connect

from .scenarios import BY_ID, Scenario


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00","Z")


def entropy_blob(r: random.Random, n: int) -> bytes:
    return bytes(r.randrange(0,256) for _ in range(n))


def encoded_value(r: random.Random, suspicious: bool, size: int = 48) -> str:
    raw = entropy_blob(r, size)
    if suspicious:
        return base64.urlsafe_b64encode(gzip.compress(raw)).decode().rstrip("=")
    # Hard-negative high-entropy token of roughly comparable length.
    return base64.urlsafe_b64encode(entropy_blob(r, size + 6)).decode().rstrip("=")


def base_host(s: Scenario) -> str:
    if s.family == "lots":
        if s.scenario_id in {"CC_LOTS_01","CC_LOTS_02","CC_LOTS_03","CC_LOTS_04"}:
            return "lots-chatops.test"
        if s.scenario_id == "CC_LOTS_08":
            return "lots-bucket.test"
        if s.scenario_id == "CC_LOTS_07":
            return "dyndns-relay.test"
        return "lots-tunnel.test"
    if s.family == "mqtt_ws": return "mqtt-broker.test"
    if s.family == "doh": return "doh-relay.test"
    if s.family in {"websocket","tunnel"} or s.transport == "wss": return "cover-ws.test"
    if s.transport == "h2" or s.family in {"http2","grpc"}: return "cover-h2.test"
    if s.family == "response": return "cover-static.test"
    return "cover-api.test"


def make_http(s: Scenario, suspicious: bool, r: random.Random, i: int) -> tuple[str, dict, bytes|None, str]:
    value = encoded_value(r, suspicious, 24 + (i % 3) * 8)
    headers = {
        "User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 Chrome/136.0 Safari/537.36" if s.family in {"browser"} else "coverlab-client/1.0",
        "Accept": "*/*",
        "X-Request-Id": str(uuid.UUID(bytes=hashlib.md5(f"{value}-{i}".encode()).digest())),
    }
    path = "/api/status"
    body: bytes|None = None
    method = "GET"
    c = s.carrier
    if c in {"query_value","query_values","multi_request_query"}:
        path = "/api/search?" + urllib.parse.urlencode({"q":"status","id":value})
    elif c == "path_segment": path = f"/assets/{value[:24]}/status.json"
    elif c == "filename": path = f"/assets/{value[:24]}.gif"
    elif c == "matrix_path": path = f"/api;id={value[:20]};v=2/status"
    elif c == "query_key": path = f"/api/search?{urllib.parse.quote(value[:10])}=1&page=2"
    elif c == "uri_length": path = "/api/search?q=" + ("a" * (32 if suspicious and i%2 else 64))
    elif c == "cookie": headers["Cookie"] = f"session={value}; pref=en-US"
    elif c == "authorization": headers["Authorization"] = f"Bearer {value}"
    elif c == "user_agent": headers["User-Agent"] += f" rv/{value[:12]}"
    elif c == "referer": headers["Referer"] = f"https://benign-api.test/dashboard?ref={value}"
    elif c == "origin": headers["Origin"] = f"https://{value[:8]}.cover-api.test"
    elif c == "accept_language": headers["Accept-Language"] = "en-US,en;q=0.9,ru;q=0.8" if i%2 else "ru-RU,ru;q=0.9,en;q=0.8"
    elif c == "accept_encoding": headers["Accept-Encoding"] = "gzip, br, deflate" if i%2 else "br, gzip, deflate"
    elif c == "if_none_match": headers["If-None-Match"] = f'"{value}"'
    elif c == "if_modified_since": headers["If-Modified-Since"] = "Sat, 08 Aug 2026 20:%02d:00 GMT" % (i*3)
    elif c == "range": headers["Range"] = f"bytes={1024+i*256}-{2047+i*256}"
    elif c == "content_type_param":
        method="POST"; headers["Content-Type"] = f"multipart/form-data; boundary=----{value[:20]}"; body=b"synthetic"
    elif c.startswith("x_"):
        name = {"x_session_id":"X-Session-Id","x_request_id":"X-Request-Id","x_correlation_id":"X-Correlation-Id","x_telemetry":"X-Telemetry"}[c]
        headers[name] = value
    elif c in {"json","json_junk","graphql_variables"}:
        method="POST"; headers["Content-Type"]="application/json"
        obj = {"status":"ok","device":value[:12],"metrics":{"cpu":31+i,"memory":52}}
        if c == "json_junk": obj.update({f"field{j}": hashlib.sha1(f"{value}{j}".encode()).hexdigest()[:12] for j in range(8)})
        if c == "graphql_variables": obj={"query":"query Status($id:String!){status(id:$id){ok}}","variables":{"id":value}}
        body=json.dumps(obj,separators=(",",":")).encode()
    elif c == "form":
        method="POST"; headers["Content-Type"]="application/x-www-form-urlencoded"; body=urllib.parse.urlencode({"name":"telemetry","value":value}).encode()
    elif c in {"multipart","multipart_filename"}:
        method="POST"; boundary="----coverlab"+value[:8]; headers["Content-Type"]=f"multipart/form-data; boundary={boundary}"
        filename=(value[:16]+".bin") if c=="multipart_filename" else "synthetic.log"
        body=(f"--{boundary}\r\nContent-Disposition: form-data; name=\"file\"; filename=\"{filename}\"\r\nContent-Type: application/octet-stream\r\n\r\n".encode()+entropy_blob(r,512)+f"\r\n--{boundary}--\r\n".encode())
    elif c == "octet_stream": method="POST"; headers["Content-Type"]="application/octet-stream"; body=entropy_blob(r,1024)
    elif c == "protobuf_like": method="POST"; headers["Content-Type"]="application/x-protobuf"; body=struct.pack("!I",len(value))+value.encode()
    elif c == "xml_attributes": method="POST"; headers["Content-Type"]="application/xml"; body=f'<status id="{value}" cpu="{31+i}" />'.encode()
    elif c == "chunked": method="POST"; headers["Content-Type"]="application/octet-stream"; body=(value*8).encode()
    elif c in {"sse_command","sse_encoded","sse_comment_timing","last_event_id","sse_sparse"}:
        path="/events"; headers["Accept"]="text/event-stream";
        if c=="last_event_id": headers["Last-Event-ID"]=value[:16]
    elif c in {"long_poll_recv","rotating_poll","poll_upload"}:
        path=f"/api/poll?cursor={value[:12]}" if c=="rotating_poll" else "/api/poll"
        if c=="poll_upload" and i%2: method="POST"; body=json.dumps({"result":value}).encode(); headers["Content-Type"]="application/json"
    elif c.startswith("grpc_"):
        method="POST"; path="/coverlab.Control/Exchange"; headers["Content-Type"]="application/grpc"; headers["TE"]="trailers"
        msg=value.encode(); body=b"\x00"+len(msg).to_bytes(4,"big")+msg
    elif c == "extension_registration": path="/extension/register?build=136.0"
    elif c in {"service_worker_alarm","push_wakeup","keepalive_tab","native_echo","headless"}: path=f"/browser/{c}?id={value[:12]}"
    elif c == "fetch_stream": method="POST"; path="/browser/upload"; body=entropy_blob(r,2048); headers["Content-Type"]="application/octet-stream"
    elif c == "send_beacon": method="POST"; path="/collect"; body=json.dumps({"event":"pagehide","v":value}).encode(); headers["Content-Type"]="text/plain;charset=UTF-8"
    elif c == "csp_report": method="POST"; path="/csp-report"; body=json.dumps({"csp-report":{"document-uri":"https://app.test/","blocked-uri":f"https://{value[:16]}.asset.test/x","violated-directive":"img-src"}}).encode(); headers["Content-Type"]="application/csp-report"
    elif c == "prefetch": path=f"/prefetch/{value[:16]}.js"
    elif c in {"chatops_poll","chatops_push","chatops_document","webhook"}:
        if c=="chatops_poll": path=f"/botLAB/getUpdates?offset={i}&timeout=2"
        elif c=="chatops_push": method="POST"; path="/botLAB/sendMessage"; headers["Content-Type"]="application/json"; body=json.dumps({"chat_id":"LAB","text":value}).encode()
        elif c=="chatops_document": method="POST"; path="/botLAB/sendDocument"; headers["Content-Type"]="application/octet-stream"; body=entropy_blob(r,4096)
        else: method="POST"; path="/api/webhooks/100000000000/LABTOKEN"; headers["Content-Type"]="application/json"; body=json.dumps({"content":value}).encode()
    elif c == "bucket_dead_drop": path=f"/cloudfront-{(i+17):03d}/slot-{value[:16]}.json"
    elif c in {"script_default","browser_like","clienthello_variation","resumption","zero_rtt_marker","sni_loss_fixture","fallback","shared_edge","cert_rotation","inspection_bypass"}:
        path=f"/tls/{c}/status"
    elif c in {"response_body","response_json","response_xml","response_html","response_css","response_image_meta","set_cookie","etag","status_code","redirect","response_size","response_chunks"}:
        path="/assets/status.xml"
    elif c in {"fixed_beacon","low_jitter","medium_jitter","high_jitter","burst","work_hours","backoff","binary_timing","low_slow","event_driven"}:
        path="/telemetry/heartbeat"
    return method, headers, body, path



def execute_http(client_impl: str, method: str, url: str, headers: dict, body: bytes|None, use_h2: bool) -> tuple[int, str]:
    """Execute one request with a real independent client stack where requested."""
    if client_impl == "curl_linux":
        cmd=["curl","--noproxy","*","-ksS","-o","/dev/null","-w","%{http_code}","-X",method]
        if use_h2: cmd.append("--http2")
        for k,v in headers.items(): cmd += ["-H",f"{k}: {v}"]
        if body is not None: cmd += ["--data-binary","@-"]
        cmd.append(url)
        cp=subprocess.run(cmd,input=body,stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=15)
        if cp.returncode==0:
            try: return int(cp.stdout.decode().strip()[-3:]), "curl_linux"
            except Exception: pass
    elif client_impl == "node_fetch" and not use_h2:
        helper=Path(os.environ.get("COVERLAB_NODE_CLIENT","clients/node_client.mjs"))
        q={"url":url,"method":method,"headers":headers,"body_b64":base64.b64encode(body or b"").decode()}
        cp=subprocess.run(["node",str(helper)],input=json.dumps(q).encode(),stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=15)
        if cp.returncode==0:
            try: return int(cp.stdout.decode().strip().splitlines()[-1]), "node_fetch"
            except Exception: pass
    elif client_impl == "go_nethttp":
        helper=os.environ.get("COVERLAB_GO_CLIENT","/tmp/coverlab-go-client")
        q={"url":url,"method":method,"headers":headers,"body_b64":base64.b64encode(body or b"").decode()}
        cp=subprocess.run([helper],input=json.dumps(q).encode(),stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=15)
        if cp.returncode==0:
            try: return int(cp.stdout.decode().strip().splitlines()[-1]), "go_nethttp"
            except Exception: pass
    elif client_impl == "python_stdlib" and not use_h2:
        req=urllib.request.Request(url,data=body,headers=headers,method=method)
        ctx=ssl.create_default_context(); ctx.check_hostname=False; ctx.verify_mode=ssl.CERT_NONE
        opener=urllib.request.build_opener(urllib.request.HTTPSHandler(context=ctx), urllib.request.HTTPHandler())
        try:
            with opener.open(req,timeout=10) as resp: resp.read(); return int(resp.status), "python_stdlib"
        except urllib.error.HTTPError as e:
            e.read(); return int(e.code), "python_stdlib"
    # httpx provides both an H1/OpenSSL and an H2-capable implementation.
    with httpx.Client(verify=False,http2=use_h2,timeout=10,follow_redirects=False,trust_env=False) as client:
        resp=client.request(method,url,headers=headers,content=body)
        _=resp.content
        return resp.status_code, "python_httpx_h2" if use_h2 else "python_httpx"


def browser_run(host: str, scenario_id: str) -> int:
    chrome=os.environ.get("COVERLAB_CHROME") or next((x for x in ["google-chrome","google-chrome-stable","chromium","chromium-browser"] if subprocess.run(["bash","-lc",f"command -v {x}"],stdout=subprocess.DEVNULL).returncode==0), "")
    if not chrome:
        raise RuntimeError("Chrome/Chromium not available for browser-native challenge")
    url=f"https://{host}:8443/browser-fixture/{scenario_id}"
    cp=subprocess.run([chrome,"--headless","--no-sandbox","--disable-gpu","--ignore-certificate-errors","--disable-background-networking","--disable-component-update","--disable-sync","--metrics-recording-only","--no-first-run","--virtual-time-budget=2500","--dump-dom",url],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,timeout=20)
    if cp.returncode!=0: raise RuntimeError(f"browser returned {cp.returncode}")
    return 200


def raw_syntax_request(host: str, port: int, s: Scenario, suspicious: bool, i: int) -> int:
    # Valid HTTP/1.1 only. Difference is syntax/order, not malformed protocol evasion.
    value="1" if suspicious else "0"
    headers=[("Host",host),("Accept","*/*"),("X-Request-Id",f"trace-{i:04d}"),("User-Agent","coverlab-raw/1.0")]
    if s.carrier == "header_order" and suspicious: headers=[headers[0],headers[3],headers[2],headers[1]]
    if s.carrier == "header_case" and suspicious: headers[2]=(headers[2][0].lower(),headers[2][1])
    if s.carrier == "duplicate_headers": headers.append(("X-Trace",value)); headers.append(("X-Trace",str(i)))
    method = "HEAD" if s.carrier == "method" and suspicious and i%2 else "GET"
    if s.carrier == "content_length_parity":
        body=(b"A"*(17 if suspicious else 18)); method="POST"; headers.append(("Content-Length",str(len(body))))
    else: body=b""
    headers.append(("Connection","close" if s.carrier=="connection_reuse" and suspicious and i%2 else "keep-alive"))
    req=f"{method} /syntax/status HTTP/1.1\r\n"+"".join(f"{k}: {v}\r\n" for k,v in headers)+"\r\n"
    with socket.create_connection((host,port),timeout=5) as sock:
        sock.sendall(req.encode()+body)
        data=sock.recv(4096)
    try: return int(data.split(b" ",2)[1])
    except Exception: return 0


def ws_run(url: str, s: Scenario, suspicious: bool, r: random.Random, count: int) -> list[dict]:
    out=[]
    ctx=ssl.create_default_context(); ctx.check_hostname=False; ctx.verify_mode=ssl.CERT_NONE
    # websockets 15 auto-discovers HTTP(S) proxies unless proxy=None. All WSS
    # fixtures are local .test hosts in the isolated lab, so force a direct path.
    with ws_connect(url, ssl=ctx, open_timeout=10, proxy=None) as ws:
        for i in range(count):
            value=encoded_value(r,suspicious,32)
            if s.family == "mqtt_ws":
                # Harmless MQTT-like binary fixture; not connected to an external broker.
                payload=(b"\x30"+bytes([min(125,len(value)+12)])+b"\x00\x08lab/test"+value.encode()[:100])
                ws.send(payload); reply=ws.recv()
            elif s.family in {"tunnel"} or s.scenario_id in {"CC_LOTS_05","CC_LOTS_06","CC_LOTS_07"}:
                conn=f"c{i%3}"
                messages=[
                    {"type":"auth","login":"lab","password":"synthetic","uuid":str(uuid.uuid4())},
                    {"type":"socks_connect","conn_id":conn,"target_host":"synthetic-api.test","target_port":8081},
                    {"type":"socks_data","conn_id":conn,"data":base64.b64encode(("HELLO_SYNTHETIC_"+value[:24]).encode()).decode()},
                    {"type":"socks_close","conn_id":conn},
                ]
                for m in messages:
                    ws.send(json.dumps(m,separators=(",",":"))); reply=ws.recv()
            else:
                obj={"action":"recv" if i%2==0 else "send","container":value,"target":"LAB","sender":"fixture","message":"STATUS"}
                ws.send(json.dumps(obj,separators=(",",":"))); reply=ws.recv()
            out.append({"index":i,"reply_len":len(reply) if hasattr(reply,"__len__") else 0})
    return out


def run(args) -> dict:
    s=BY_ID[args.scenario]
    r=random.Random(args.seed)
    host=base_host(s)
    suspicious=args.variant=="suspicious"
    count=args.events
    scheme="https" if s.transport in {"https","h2"} or s.family in {"browser","lots","doh"} else "http"
    if s.transport=="wss": scheme="wss"
    port=8443 if scheme in {"https","wss"} else 8080
    started=now_iso(); events=[]
    state={"scenario_id":s.scenario_id,"suspicious":suspicious,"seed":args.seed,"campaign_id":args.campaign_id}
    state_path=Path(args.state); state_path.parent.mkdir(parents=True,exist_ok=True)
    lock_path=state_path.with_suffix(state_path.suffix+".lock")
    with lock_path.open("w") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        try:
            raw=json.loads(state_path.read_text()) if state_path.exists() else {"clients":{},"default":{}}
        except Exception:
            raw={"clients":{},"default":{}}
        raw.setdefault("clients",{})[args.source_ip]=state
        raw["default"]=state
        tmp=state_path.with_suffix(state_path.suffix+".tmp")
        tmp.write_text(json.dumps(raw)); os.replace(tmp,state_path)
        fcntl.flock(lock, fcntl.LOCK_UN)
    time.sleep(0.005)
    if args.client_impl == "browser_chromium" and s.family == "browser":
        for i in range(count):
            evt_start=now_iso(); status=browser_run(host,s.scenario_id)
            events.append({"event_id":f"{args.campaign_id}-e{i:03d}","event_type":"browser_native_exchange","sent_at":evt_start,"completed_at":now_iso(),"http_method":"BROWSER","http_path":f"/browser-fixture/{s.scenario_id}","response_status":status,"encoded_length":0})
    elif scheme=="wss":
        details=ws_run(f"wss://{host}:8443/ws",s,suspicious,r,count)
        for d in details:
            events.append({"event_id":f"{args.campaign_id}-e{d['index']:03d}","sent_at":now_iso(),"transport":"wss","reply_len":d["reply_len"]})
    else:
        for i in range(count):
            evt_start=now_iso()
            if s.family=="syntax":
                status=raw_syntax_request(host,8080,s,suspicious,i); method="RAW"; path="/syntax/status"; encoded_len=0
            elif s.family=="doh":
                q=dns.message.make_query(dns.name.from_text(f"lab-{i}.synthetic.test."),dns.rdatatype.TXT).to_wire()
                with httpx.Client(verify=False,http2=True,timeout=10,trust_env=False) as client:
                    resp=client.post(f"https://{host}:8443/dns-query",content=q,headers={"Content-Type":"application/dns-message","Accept":"application/dns-message"})
                status=resp.status_code; method="POST"; path="/dns-query"; encoded_len=len(q)
            else:
                method,headers,body,path=make_http(s,suspicious,r,i)
                status,effective_client=execute_http(args.client_impl,method,f"{scheme}://{host}:{port}{path}",headers,body,(s.transport=="h2" or s.family=="grpc"))
                encoded_len=len(body or b"")+sum(len(k)+len(v) for k,v in headers.items())
            events.append({"event_id":f"{args.campaign_id}-e{i:03d}","event_type":"synthetic_exchange","sent_at":evt_start,"completed_at":now_iso(),"http_method":method,"http_path":path,"response_status":status,"encoded_length":encoded_len})
            # Accelerated equivalents of timing profiles. Original profile is retained in manifest.
            if s.family=="timing":
                delay={"fixed_beacon":.03,"low_jitter":.04,"medium_jitter":r.uniform(.03,.07),"high_jitter":r.uniform(.02,.12),"burst":.005,"work_hours":.025,"backoff":.01*(2**min(i,4)),"binary_timing":.01 if i%2 else .03,"low_slow":.08,"event_driven":r.uniform(.005,.04)}.get(s.carrier,.02)
                time.sleep(delay)
    ended=now_iso()
    raw_semantic=("SYNTHETIC_C2:"+s.scenario_id+":"+str(args.seed)).encode() if suspicious else ("BENIGN:"+s.benign_semantic_type+":"+str(args.seed)).encode()
    record={
        "campaign_id":args.campaign_id,"run_id":args.run_id,"scenario_id":s.scenario_id,
        "label_binary":1 if suspicious else 0,"label_family":s.label_family if suspicious else "benign",
        "label_intent":s.label_intent if suspicious else "benign","benign_semantic_type":None if suspicious else s.benign_semantic_type,
        "protocol":s.transport,"carrier":s.carrier,"attack_mapping":list(s.attack_mapping) if suspicious else [],
        "visibility_mode":"opaque_and_ground_truth" if s.transport in {"https","h2","wss"} else "content",
        "inspection_policy":"bypass" if s.transport in {"https","h2","wss"} else "not_applicable",
        "inspection_outcome":"encrypted" if s.transport in {"https","h2","wss"} else "plaintext",
        "sni_visibility":"clear","feature_availability_bitmap":"runtime",
        "persona":args.persona,"source_ip":args.source_ip,"destination_ip":"10.20.0.20","destination_host":host,
        "seed":args.seed,"started_at":started,"ended_at":ended,"expected_events":len(events),
        "capture_file":args.capture_file,"status":"success","generator_name":"coverlab_safe_python",
        "generator_version":"1.0.0","generator_commit":os.environ.get("GITHUB_SHA",os.environ.get("COVERLAB_GIT_COMMIT","local")),
        "server_impl":"fastapi_hypercorn","client_impl":args.client_impl,"client_tls_impl":args.client_impl,"external_dependency":False,
        "policy_authorized":False if suspicious else True,
        "infra_category":"synthetic_local_fixture","plaintext_sha256":hashlib.sha256(raw_semantic).hexdigest(),
        "timing_acceleration":1000 if s.family=="timing" else 1,
    }
    with open(args.manifest,"a",encoding="utf-8") as f: f.write(json.dumps(record,separators=(",",":"))+"\n")
    with open(args.events_out,"a",encoding="utf-8") as f:
        for e in events:
            e.update({"campaign_id":args.campaign_id,"run_id":args.run_id,"scenario_id":s.scenario_id,"label_binary":record["label_binary"]})
            f.write(json.dumps(e,separators=(",",":"))+"\n")
    return record


def main():
    p=argparse.ArgumentParser()
    p.add_argument("--scenario",required=True,choices=sorted(BY_ID))
    p.add_argument("--variant",required=True,choices=["suspicious","benign"])
    p.add_argument("--seed",type=int,required=True)
    p.add_argument("--campaign-id",required=True)
    p.add_argument("--run-id",required=True)
    p.add_argument("--persona",default="Victim-2-Dev")
    p.add_argument("--source-ip",default="10.20.0.11")
    p.add_argument("--events",type=int,default=3)
    p.add_argument("--client-impl",default="python_httpx",choices=["python_httpx","python_httpx_h2","curl_linux","node_fetch","go_nethttp","python_stdlib","browser_chromium"])
    p.add_argument("--state",default="/tmp/coverlab_server_state.json")
    p.add_argument("--manifest",required=True)
    p.add_argument("--events-out",required=True)
    p.add_argument("--capture-file",required=True)
    args=p.parse_args(); run(args)

if __name__=="__main__": main()