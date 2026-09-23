from __future__ import annotations

import argparse
import asyncio
import base64
import fcntl
import hashlib
import json
import os
import random
import socket
import ssl
import struct
import subprocess
import time
import urllib.parse
import uuid
from datetime import datetime, timezone
from pathlib import Path

import dns.message
import dns.query
import dns.rdatatype
from websockets.sync.client import connect as ws_connect

from .client_runtime_v3 import install as install_client_runtime
from . import run_campaign as rc
from .stage_m_catalog import BY_FAMILY, CampaignPlan, iter_campaigns, validate_plan

install_client_runtime()

PERSONAS=(("office","10.20.0.10"),("developer","10.20.0.11"),("devops","10.20.0.30"),("soc","10.20.0.31"))
STATE=Path("/tmp/coverlab_server_state.json")
LOCK=STATE.with_suffix(".json.lock")
DNS_DIRECT="10.20.0.20"; DNS_RECURSIVE="10.20.0.40"; TUNNEL_HOST="10.20.0.20"; TUNNEL_PORT=9090


def now_iso():
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00","Z")


def append_jsonl(path:Path,row:dict):
    path.parent.mkdir(parents=True,exist_ok=True)
    with path.open("a",encoding="utf-8") as f:f.write(json.dumps(row,separators=(",",":"),default=str)+"\n")


def set_state(source_ip:str,scenario_id:str,campaign_id:str,seed:int):
    STATE.parent.mkdir(parents=True,exist_ok=True)
    with LOCK.open("w") as lk:
        fcntl.flock(lk,fcntl.LOCK_EX)
        try: raw=json.loads(STATE.read_text()) if STATE.exists() else {"clients":{},"default":{}}
        except Exception: raw={"clients":{},"default":{}}
        st={"scenario_id":scenario_id,"suspicious":True,"seed":seed,"campaign_id":campaign_id}
        raw.setdefault("clients",{})[source_ip]=st; raw["default"]=st
        tmp=STATE.with_suffix(".tmp");tmp.write_text(json.dumps(raw));os.replace(tmp,STATE)


def payload(plan:CampaignPlan,i:int,r:random.Random)->str:
    style=plan.payload_style
    if style=="high_entropy_fixed":return base64.urlsafe_b64encode(bytes(r.randrange(256) for _ in range(32))).decode().rstrip("=")
    if style=="low_entropy_code":return ("ok","go","id","up","do","cfg","ack","sync")[(i+plan.index_in_family)%8]+str(i%10)
    if style=="guid":return str(uuid.UUID(bytes=hashlib.md5(f"{plan.seed}:{i}".encode()).digest()))
    if style=="hex_fixed":return hashlib.sha256(f"{plan.seed}:{i}".encode()).hexdigest()[:32]
    if style=="fragment_2_6":
        n=2+(plan.seed+i)%5; alphabet="abcxyz0123456789";return "".join(r.choice(alphabet) for _ in range(n))
    if style=="base32":return base64.b32encode(bytes(r.randrange(256) for _ in range(20))).decode().rstrip("=").lower()
    return hashlib.sha256(f"{plan.seed}:{i}".encode()).hexdigest()[:16]


def offsets(plan:CampaignPlan)->list[float]:
    r=random.Random(plan.seed^0x5A17);out=[0.0]
    for i in range(1,plan.event_count_target):
        gap=max(.001,plan.nominal_interval_seconds*(1+r.uniform(-plan.jitter_fraction,plan.jitter_fraction)))
        if plan.family_id=="M-RMM-SHAPE" and i>=max(1,int(plan.event_count_target*.7)):gap=max(.01,min(1.0,gap*.005))
        out.append(out[-1]+gap)
    return out


def pause(plan):return min(.02,max(.001,plan.nominal_interval_seconds*.00005))


def http_impl(impl):
    return {
        "python_httpx_h1":("python_httpx",False),"python_httpx_h2":("python_httpx",True),
        "curl_h1":("curl_linux",False),"curl_h2":("curl_linux",True),
        "go_nethttp":("go_nethttp",False),"node_fetch":("node_fetch",False),"python_stdlib":("python_stdlib",False),
    }.get(impl,("python_httpx",False))


def browser(url):
    chrome=os.environ.get("COVERLAB_CHROME","")
    if not chrome:
        for x in ("google-chrome","google-chrome-stable","chromium","chromium-browser"):
            if subprocess.run(["bash","-lc",f"command -v {x}"],stdout=subprocess.DEVNULL).returncode==0:chrome=x;break
    if not chrome:raise RuntimeError("Chromium not available")
    cp=subprocess.run([chrome,"--headless","--no-sandbox","--disable-gpu","--ignore-certificate-errors","--disable-background-networking","--disable-component-update","--disable-sync","--metrics-recording-only","--no-first-run","--virtual-time-budget=5000","--dump-dom",url],stdout=subprocess.DEVNULL,stderr=subprocess.PIPE,timeout=30)
    if cp.returncode:raise RuntimeError("chromium failed: "+cp.stderr.decode(errors="replace")[-500:])


def response_scenario(plan,i):
    if plan.direction_profile in {"small_large","download_20_80"} or (plan.direction_profile=="alternating" and i%2):return "CC_RESP_11"
    return "CC_RESP_01"


def http_parts(plan,value,i):
    method="POST";path=f"/stage-m/{plan.family_id[2:].lower()}/{plan.campaign_id}/{i}"
    headers={"User-Agent":"coverlab-stage-m/1.0","Accept":"application/json","X-Stage-M-Campaign":plan.campaign_id};body=None
    if plan.family_id=="M-HTTPS-FRAG":method="GET";path+="?"+urllib.parse.urlencode({"v":value})
    elif plan.family_id=="M-HTTPS-LOWENT" and i%2:method="GET";path+="?"+urllib.parse.urlencode({"id":value,"mode":"status"})
    elif plan.family_id=="M-HTTPS-LOWENT":headers["Content-Type"]="application/json";body=json.dumps({"id":value,"status":"ok"},separators=(",",":")).encode()
    elif plan.family_id=="M-HTTP-443":headers["Content-Type"]="application/octet-stream";body=value.encode().ljust(48,b".")
    elif plan.direction_profile in {"large_small","upload_80_20"}:headers["Content-Type"]="application/octet-stream";body=(value.encode()*32)[:4096]
    else:headers["Content-Type"]="application/json";body=json.dumps({"id":value,"seq":i},separators=(",",":")).encode()
    return method,path,headers,body


def add_event(out,plan,i,phase,start,end,off,**extra):
    append_jsonl(out,{"campaign_id":plan.campaign_id,"event_id":f"{plan.campaign_id}-e{i:03d}","event_index":i,"label_binary":1,"transport_phase":phase,"sent_at":start,"completed_at":end,"nominal_offset_seconds":off,**extra})


def run_http(plan,source_ip,out):
    r=random.Random(plan.seed);off=offsets(plan)
    host=plan.front_host if plan.family_id=="M-HTTPS-FRONT" else "beacon.stage-m.test"
    scheme,port=("http",443 if plan.index_in_family%2==0 else 80) if plan.family_id=="M-HTTP-443" else ("https",8443)
    if plan.implementation_id=="chromium_fetch":
        set_state(source_ip,response_scenario(plan,0),plan.campaign_id,plan.seed)
        q=urllib.parse.urlencode({"campaign":plan.campaign_id,"events":plan.event_count_target,"payload":plan.payload_style,"family":plan.family_id,"mode":"fetch"})
        start=now_iso();browser(f"https://{host}:8443/stage-m/browser?{q}");end=now_iso()
        add_event(out,plan,0,"https",start,end,0.0,wire_exchanges_target=plan.event_count_target,implementation_id="chromium_boringssl")
        return host,"chromium_boringssl"
    client,h2=http_impl(plan.implementation_id)
    for i in range(plan.event_count_target):
        value=payload(plan,i,r);set_state(source_ip,response_scenario(plan,i),plan.campaign_id,plan.seed+i)
        method,path,headers,body=http_parts(plan,value,i);start=now_iso()
        status,effective=rc.execute_http(client,method,f"{scheme}://{host}:{port}{path}",headers,body,h2);end=now_iso()
        add_event(out,plan,i,scheme,start,end,off[i],http_method=method,http_path=path,response_status=status,encoded_length=len(body or b""),implementation_id=effective)
        if i+1<plan.event_count_target:time.sleep(pause(plan))
    return host,plan.implementation_id


def qname(plan,i,r):
    v=payload(plan,i,r).replace("_","a").replace("-","b").lower();v="".join(c for c in v if c.isalnum())[:58] or "x"
    prefix="nx-" if plan.family_id=="M-DNS-BULK" and (i+plan.seed)%5==0 else ""
    return f"{prefix}{v}.{i%97}.{plan.campaign_id}.stage-m.test."


def dns_wire(name,qtype):return dns.message.make_query(name,dns.rdatatype.from_text(qtype)).to_wire()


def raw_dns(server,wire,tcp=False):
    if tcp:
        with socket.create_connection((server,53),timeout=4) as s:
            s.sendall(struct.pack("!H",len(wire))+wire);head=s.recv(2)
            if len(head)!=2:return 0
            n=struct.unpack("!H",head)[0];data=b""
            while len(data)<n:
                x=s.recv(n-len(data))
                if not x:break
                data+=x
            return len(data)
    with socket.socket(socket.AF_INET,socket.SOCK_DGRAM) as s:
        s.settimeout(4);s.sendto(wire,(server,53));data,_=s.recvfrom(65535);return len(data)


def node_helper(obj):
    helper=os.environ.get("COVERLAB_STAGE_M_NODE_CLIENT","clients/stage_m_node_client.mjs")
    cp=subprocess.run(["node",helper],input=json.dumps(obj).encode(),stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=40)
    if cp.returncode:raise RuntimeError(cp.stderr.decode(errors="replace")[-500:])
    return cp.stdout


def run_dns(plan,out):
    r=random.Random(plan.seed);off=offsets(plan);server=DNS_RECURSIVE if plan.dns_topology=="recursive_local" else DNS_DIRECT
    for i in range(plan.event_count_target):
        name=qname(plan,i,r);qt=plan.qtype or ("TXT","A","AAAA")[i%3];wire=dns_wire(name,qt);start=now_iso()
        if plan.implementation_id=="dnspython_udp":rb=len(dns.query.udp(dns.message.from_wire(wire),server,port=53,timeout=4).to_wire())
        elif plan.implementation_id=="node_dns":rb=len(node_helper({"mode":"dns","server":server,"qname":name,"qtype":qt}))
        else:rb=raw_dns(server,wire,plan.implementation_id=="raw_tcp")
        end=now_iso();add_event(out,plan,i,"dns",start,end,off[i],dns_qname=name,dns_qtype=qt,dns_server=server,dns_topology=plan.dns_topology,dns_transport="tcp" if plan.implementation_id=="raw_tcp" else "udp",query_bytes=len(wire),response_bytes=rb,implementation_id=plan.implementation_id)
        if i+1<plan.event_count_target:time.sleep(pause(plan))
    return server,plan.implementation_id


def run_doh(plan,source_ip,out):
    r=random.Random(plan.seed);off=offsets(plan);host="doh.stage-m.test"
    if plan.implementation_id=="chromium_doh":
        set_state(source_ip,"CC_DOH_01",plan.campaign_id,plan.seed);q=urllib.parse.urlencode({"campaign":plan.campaign_id,"events":plan.event_count_target,"family":plan.family_id,"mode":"doh"})
        s=now_iso();browser(f"https://{host}:8443/stage-m/browser?{q}");e=now_iso();add_event(out,plan,0,"doh",s,e,0.0,wire_exchanges_target=plan.event_count_target,implementation_id="chromium_boringssl");return host,"chromium_boringssl"
    client,h2=http_impl(plan.implementation_id)
    for i in range(plan.event_count_target):
        name=qname(plan,i,r);qt=("TXT","A","AAAA")[i%3];body=dns_wire(name,qt);set_state(source_ip,"CC_DOH_01",plan.campaign_id,plan.seed+i);s=now_iso()
        status,effective=rc.execute_http(client,"POST",f"https://{host}:8443/dns-query",{"Content-Type":"application/dns-message","Accept":"application/dns-message","X-Stage-M-Campaign":plan.campaign_id},body,h2);e=now_iso()
        add_event(out,plan,i,"doh",s,e,off[i],dns_qname=name,dns_qtype=qt,response_status=status,encoded_length=len(body),implementation_id=effective)
        if i+1<plan.event_count_target:time.sleep(pause(plan))
    return host,plan.implementation_id


def ws_messages(plan):
    r=random.Random(plan.seed);rows=[]
    for i in range(plan.event_count_target):
        v=payload(plan,i,r)
        if plan.direction_profile in {"large_small","upload_80_20"}:v=(v*64)[:4096]
        rows.append(json.dumps({"type":"stage_m","campaign_id":plan.campaign_id,"seq":i,"value":v},separators=(",",":")))
    return rows


def raw_ws(host,messages,delay):
    key=base64.b64encode(os.urandom(16)).decode();ctx=ssl.create_default_context();ctx.check_hostname=False;ctx.verify_mode=ssl.CERT_NONE
    sock=ctx.wrap_socket(socket.create_connection((host,8443),timeout=5),server_hostname=host)
    sock.sendall(f"GET /ws HTTP/1.1\r\nHost: {host}:8443\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: {key}\r\nSec-WebSocket-Version: 13\r\n\r\n".encode())
    head=b""
    while b"\r\n\r\n" not in head:head+=sock.recv(4096)
    if b" 101 " not in head:raise RuntimeError("raw websocket handshake failed")
    times=[]
    for msg in messages:
        s=now_iso();data=msg.encode();mask=os.urandom(4);n=len(data)
        hdr=bytes([0x81,0x80|n]) if n<126 else bytes([0x81,0x80|126])+struct.pack("!H",n)
        sock.sendall(hdr+mask+bytes(b^mask[i%4] for i,b in enumerate(data)));sock.recv(4096);times.append((s,now_iso()));time.sleep(delay)
    sock.close();return times


def run_wss(plan,source_ip,out):
    host="ws.stage-m.test";msgs=ws_messages(plan);off=offsets(plan);set_state(source_ip,"CC_WS_09",plan.campaign_id,plan.seed)
    if plan.implementation_id=="chromium_websocket":
        q=urllib.parse.urlencode({"campaign":plan.campaign_id,"events":plan.event_count_target,"family":plan.family_id,"mode":"wss"})
        s=now_iso();browser(f"https://beacon.stage-m.test:8443/stage-m/browser?{q}");e=now_iso();add_event(out,plan,0,"wss",s,e,0.0,wire_exchanges_target=plan.event_count_target,implementation_id="chromium_websocket");return host,"chromium_websocket"
    if plan.implementation_id=="node_websocket":
        raw=node_helper({"mode":"ws","url":f"wss://{host}:8443/ws","messages":msgs,"delay_ms":max(1,int(pause(plan)*1000))})
        data=json.loads(raw.decode().strip().splitlines()[-1]);evs=data.get("events",[])
        base=evs[0]["ms"] if evs else 0
        for i,m in enumerate(msgs):
            ms=evs[i]["ms"] if i<len(evs) else base;s=datetime.fromtimestamp(ms/1000,tz=timezone.utc).isoformat(timespec="milliseconds").replace("+00:00","Z")
            add_event(out,plan,i,"wss",s,s,off[i],encoded_length=len(m),implementation_id=plan.implementation_id)
        return host,plan.implementation_id
    if plan.implementation_id=="python_raw_ws":times=raw_ws(host,msgs,pause(plan))
    else:
        ctx=ssl.create_default_context();ctx.check_hostname=False;ctx.verify_mode=ssl.CERT_NONE;times=[]
        with ws_connect(f"wss://{host}:8443/ws",ssl=ctx,open_timeout=10,proxy=None) as ws:
            for m in msgs:
                s=now_iso();ws.send(m);ws.recv();times.append((s,now_iso()));time.sleep(pause(plan))
    for i,(s,e) in enumerate(times):add_event(out,plan,i,"wss",s,e,off[i],encoded_length=len(msgs[i]),implementation_id=plan.implementation_id)
    return host,plan.implementation_id


def frame(data,kind):
    b=data.encode()
    if kind=="len16":return struct.pack("!H",len(b))+b
    if kind=="len32":return struct.pack("!I",len(b))+b
    if kind=="newline":return b.replace(b"\n",b".")+b"\n"
    return b[:64].ljust(64,b".")


def python_tunnel(plan,payloads):
    with socket.create_connection((TUNNEL_HOST,TUNNEL_PORT),timeout=5) as s:
        s.sendall((json.dumps({"campaign_id":plan.campaign_id,"framing":plan.behavior_profile or "len16","direction":plan.direction_profile})+"\n").encode())
        if b"OK" not in s.recv(32):raise RuntimeError("tunnel handshake failed")
        for p in payloads:s.sendall(frame(p,plan.behavior_profile or "len16"));s.recv(8192);time.sleep(pause(plan))


def run_tunnel(plan,out):
    r=random.Random(plan.seed);off=offsets(plan);payloads=[payload(plan,i,r) for i in range(plan.event_count_target)];s=now_iso()
    if plan.implementation_id in {"python_socket","python_asyncio"}:python_tunnel(plan,payloads)
    elif plan.implementation_id=="node_net":node_helper({"mode":"tunnel","host":TUNNEL_HOST,"port":TUNNEL_PORT,"campaign_id":plan.campaign_id,"framing":plan.behavior_profile or "len16","direction":plan.direction_profile,"payloads":payloads,"delay_ms":max(1,int(pause(plan)*1000))})
    else:
        exe=os.environ.get("COVERLAB_STAGE_M_GO_TUNNEL","/tmp/coverlab-stage-m-go-tunnel");cp=subprocess.run([exe],input=json.dumps({"host":TUNNEL_HOST,"port":TUNNEL_PORT,"campaign_id":plan.campaign_id,"framing":plan.behavior_profile or "len16","direction":plan.direction_profile,"payloads":payloads,"delay_ms":max(1,int(pause(plan)*1000))}).encode(),stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=40)
        if cp.returncode:raise RuntimeError(cp.stderr.decode(errors="replace")[-500:])
    e=now_iso()
    for i,p in enumerate(payloads):add_event(out,plan,i,"tcp",s,e,off[i],encoded_length=len(p),implementation_id=plan.implementation_id)
    return TUNNEL_HOST,plan.implementation_id


def run_dead_drop(plan,source_ip,out):
    off=offsets(plan);r=random.Random(plan.seed)
    if plan.implementation_id=="chromium_fetch":
        set_state(source_ip,"CC_RESP_01",plan.campaign_id,plan.seed);q=urllib.parse.urlencode({"campaign":plan.campaign_id,"events":plan.event_count_target,"payload":plan.payload_style,"family":plan.family_id,"mode":"dead_drop"})
        s=now_iso();browser(f"https://graph.stage-m.test:8443/stage-m/browser?{q}");e=now_iso();add_event(out,plan,0,"dead_drop_then_beacon",s,e,0.0,wire_exchanges_target=plan.event_count_target,implementation_id="chromium_boringssl");return "graph.stage-m.test->beacon.stage-m.test","chromium_boringssl"
    client,h2=http_impl(plan.implementation_id)
    for i in range(plan.event_count_target):
        phase="dead_drop" if i==0 else "beacon";host="graph.stage-m.test" if i==0 else "beacon.stage-m.test";v=payload(plan,i,r);set_state(source_ip,"CC_RESP_01",plan.campaign_id,plan.seed+i);s=now_iso()
        status,effective=rc.execute_http(client,"GET",f"https://{host}:8443/stage-m/{phase}/{plan.campaign_id}/{i}?id={urllib.parse.quote(v)}",{"X-Stage-M-Campaign":plan.campaign_id},None,h2);e=now_iso()
        add_event(out,plan,i,phase,s,e,off[i],response_status=status,destination_host=host,implementation_id=effective)
        if i+1<plan.event_count_target:time.sleep(pause(plan))
    return "graph.stage-m.test->beacon.stage-m.test",plan.implementation_id


def run_fallback(plan,source_ip,out):
    first_https=(plan.behavior_profile or "https_to_dns")=="https_to_dns";split=max(1,plan.event_count_target//2);off=offsets(plan);r=random.Random(plan.seed);http_i,dns_i=plan.implementation_id.split("+",1)
    for i in range(plan.event_count_target):
        use_https=(i<split)==first_https
        if use_https:
            client,h2=http_impl(http_i);v=payload(plan,i,r);set_state(source_ip,"CC_RESP_01",plan.campaign_id,plan.seed+i);s=now_iso();status,effective=rc.execute_http(client,"POST",f"https://beacon.stage-m.test:8443/stage-m/fallback/{plan.campaign_id}/{i}",{"Content-Type":"text/plain","X-Stage-M-Campaign":plan.campaign_id},v.encode(),h2);e=now_iso();extra={"response_status":status,"implementation_id":effective,"destination_host":"beacon.stage-m.test"};phase="https"
        else:
            name=qname(plan,i,r);qt=plan.qtype or ("A","AAAA","TXT")[i%3];wire=dns_wire(name,qt);server=DNS_RECURSIVE if plan.dns_topology=="recursive_local" else DNS_DIRECT;s=now_iso()
            rb=len(node_helper({"mode":"dns","server":server,"qname":name,"qtype":qt})) if dns_i=="node_dns" else raw_dns(server,wire,dns_i=="raw_tcp")
            e=now_iso();extra={"dns_qname":name,"dns_qtype":qt,"dns_server":server,"response_bytes":rb,"implementation_id":dns_i};phase="dns"
        add_event(out,plan,i,phase,s,e,off[i],**extra)
        if i+1<plan.event_count_target:time.sleep(pause(plan))
    return "beacon.stage-m.test+dns",plan.implementation_id


def run_one(plan,persona,source_ip,capture_file,manifest,out):
    spec=BY_FAMILY[plan.family_id];started=now_iso();destination="";effective=plan.implementation_id;err="";status="success"
    try:
        if plan.family_id in {"M-HTTPS-BEACON","M-HTTPS-FRONT","M-HTTPS-LOWENT","M-HTTPS-FRAG","M-HTTP-443","M-RMM-SHAPE"}:destination,effective=run_http(plan,source_ip,out)
        elif plan.family_id in {"M-DNS-BEACON","M-DNS-BULK"}:destination,effective=run_dns(plan,out)
        elif plan.family_id=="M-DOH":destination,effective=run_doh(plan,source_ip,out)
        elif plan.family_id=="M-DEAD-DROP":destination,effective=run_dead_drop(plan,source_ip,out)
        elif plan.family_id=="M-WSS-LONG":destination,effective=run_wss(plan,source_ip,out)
        elif plan.family_id=="M-TUNNEL":destination,effective=run_tunnel(plan,out)
        elif plan.family_id=="M-FALLBACK":destination,effective=run_fallback(plan,source_ip,out)
        else:raise RuntimeError("unsupported family")
    except Exception as exc:status="failed";err=f"{type(exc).__name__}: {exc}"
    encrypted=spec.protocol in {"https","https+https","https+dns","wss","http+https"}
    expected=1 if plan.implementation_id.startswith("chromium_") else plan.event_count_target
    record={"campaign_id":plan.campaign_id,"run_id":"stage-m","scenario_id":plan.family_id,"experiment_stage":"M_positive_diversity","dataset_role":plan.primary_split,"label_binary":1,"label_family":"cover_channel","label_intent":spec.label_intent,"attack_mapping":list(spec.attack_mapping),"positive_only":True,"protocol":spec.protocol,"carrier":spec.carrier,"persona":persona,"source_ip":source_ip,"destination_ip":DNS_RECURSIVE if plan.dns_topology=="recursive_local" and spec.protocol=="dns" else "10.20.0.20","destination_host":destination,"seed":plan.seed,"client_impl":plan.implementation_id,"visibility_mode":"opaque_and_ground_truth" if encrypted else "content","inspection_policy":"bypass" if encrypted else "not_applicable","inspection_outcome":"encrypted" if encrypted else "plaintext","sni_visibility":"clear" if encrypted else "not_applicable","started_at":started,"ended_at":now_iso(),"expected_events":expected,"event_count_target":plan.event_count_target,"capture_file":capture_file,"status":status,"error":err,"generator_name":"coverlab_stage_m","generator_version":"1.0.0","generator_commit":os.environ.get("GITHUB_SHA","local"),"implementation_id":plan.implementation_id,"effective_client_impl":effective,"primary_split":plan.primary_split,"training_eligible":plan.primary_split=="train_candidate","implementation_holdout":plan.primary_split=="implementation_holdout","network_profile":plan.network_profile,"nominal_interval_seconds":plan.nominal_interval_seconds,"jitter_fraction":plan.jitter_fraction,"payload_style":plan.payload_style,"direction_profile":plan.direction_profile,"connection_policy":plan.connection_policy,"front_host":plan.front_host,"dns_topology":plan.dns_topology,"qtype":plan.qtype,"behavior_profile":plan.behavior_profile,"runtime_timing":"compressed_for_capture_then_pcap_retimed","timestamp_retime_required":True,"external_dependency":False,"infra_category":"synthetic_local_fixture","plaintext_sha256":hashlib.sha256((plan.campaign_id+":"+plan.payload_style).encode()).hexdigest(),"safety_boundary":{"no_command_execution":True,"no_arbitrary_forwarding":True,"no_internet_route":True,"synthetic_test_domains_only":True}}
    append_jsonl(manifest,record)
    if status!="success":raise RuntimeError(f"{plan.campaign_id} failed: {err}")


def main():
    ap=argparse.ArgumentParser();ap.add_argument("--out",required=True);ap.add_argument("--capture-file",required=True);ap.add_argument("--network-profile",required=True);ap.add_argument("--shard",type=int,default=0);ap.add_argument("--shards",type=int,default=1);ap.add_argument("--persona-index",type=int,choices=range(4),required=True);ap.add_argument("--limit",type=int,default=0);ap.add_argument("--limit-per-family",type=int,default=0);ap.add_argument("--family",action="append",default=[]);a=ap.parse_args()
    out=Path(a.out);out.mkdir(parents=True,exist_ok=True);manifest=out/"campaigns.jsonl";events=out/"events.jsonl";manifest.touch();events.touch()
    plans=list(iter_campaigns());check=validate_plan(plans)
    if not check["passed"]:raise SystemExit(json.dumps(check))
    selected=[];local=0;wanted=set(a.family)
    for gi,p in enumerate(plans):
        if p.network_profile!=a.network_profile or (wanted and p.family_id not in wanted):continue
        if gi%4!=a.persona_index:continue
        if local%a.shards==a.shard:selected.append(p)
        local+=1
    if a.limit_per_family>0:
        kept=[];seen={}
        for p in selected:
            n=seen.get(p.family_id,0)
            if n<a.limit_per_family:
                kept.append(p);seen[p.family_id]=n+1
        selected=kept
    if a.limit>0:selected=selected[:a.limit]
    persona,source_ip=PERSONAS[a.persona_index]
    for p in selected:run_one(p,persona,source_ip,a.capture_file,manifest,events)
    print(json.dumps({"stage":"M_positive_diversity","network_profile":a.network_profile,"shard":a.shard,"persona":persona,"campaigns":len(selected),"events":sum(1 for _ in events.open()),"positive_only":True}))


if __name__=="__main__":main()
