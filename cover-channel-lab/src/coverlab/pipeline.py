from __future__ import annotations

import argparse
import base64
import bisect
import hashlib
import json
import math
import statistics
from collections import defaultdict
from pathlib import Path

import pandas as pd
from scapy.all import PcapReader, IP, IPv6, TCP, UDP


def read_jsonl(path: Path) -> list[dict]:
    if not path.exists():
        return []
    out=[]
    with path.open(errors="replace") as f:
        for line in f:
            line=line.strip()
            if not line:
                continue
            try:
                out.append(json.loads(line))
            except json.JSONDecodeError:
                continue
    return out


def sha256(path: Path) -> str:
    h=hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda:f.read(1024*1024),b""):
            h.update(chunk)
    return h.hexdigest()


def shannon_entropy(data: bytes) -> float:
    if not data:
        return 0.0
    counts=defaultdict(int)
    for b in data:
        counts[b]+=1
    n=len(data)
    return -sum((c/n)*math.log2(c/n) for c in counts.values())


def campaign_intervals(df: pd.DataFrame) -> dict[str, tuple[list[float], list[tuple[float,float,str]]]]:
    """Build a per-source-IP interval index for packet/trace -> campaign mapping."""
    by_src: dict[str,list[tuple[float,float,str]]]=defaultdict(list)
    for r in df.itertuples(index=False):
        try:
            start=pd.Timestamp(r.started_at).timestamp()
            end=pd.Timestamp(r.ended_at).timestamp()
            by_src[str(r.source_ip)].append((start,end,str(r.campaign_id)))
        except Exception:
            continue
    out={}
    for src,rows in by_src.items():
        rows.sort(key=lambda x:x[0])
        out[src]=([x[0] for x in rows],rows)
    return out


def lookup_campaign(index: dict, src_ip: str, ts: float) -> str | None:
    item=index.get(src_ip)
    if not item:
        return None
    starts,rows=item
    pos=bisect.bisect_right(starts,ts)-1
    if pos>=0:
        start,end,cid=rows[pos]
        if start-0.050 <= ts <= end+0.050:
            return cid
    # Rare adjacent-boundary case: check next interval as well.
    pos+=1
    if 0 <= pos < len(rows):
        start,end,cid=rows[pos]
        if start-0.050 <= ts <= end+0.050:
            return cid
    return None


def normalize(stage_dir: Path, silver: Path):
    silver.mkdir(parents=True,exist_ok=True)
    campaigns=read_jsonl(stage_dir/"campaigns.jsonl")
    events=read_jsonl(stage_dir/"events.jsonl")
    if campaigns:
        pd.DataFrame(campaigns).to_parquet(silver/"campaigns.parquet",index=False)
    if events:
        pd.DataFrame(events).to_parquet(silver/"events.parquet",index=False)
    decrypted=read_jsonl(stage_dir/"manifests"/"decrypted_transactions.jsonl")
    if decrypted:
        pd.json_normalize(decrypted,sep=".").to_parquet(silver/"decrypted_transactions.parquet",index=False)
    eve=[]
    for p in stage_dir.rglob("eve.json"):
        eve.extend(read_jsonl(p))
    if eve:
        pd.json_normalize(eve,sep=".").to_parquet(silver/"suricata_eve.parquet",index=False)
    for name in ["conn","http","ssl","websocket","quic","dns"]:
        rows=[]
        for p in stage_dir.rglob(f"{name}.log"):
            rows.extend(read_jsonl(p))
        if rows:
            pd.DataFrame(rows).to_parquet(silver/f"zeek_{name}.parquet",index=False)
    return campaigns


def campaign_packet_features(pcap: Path, df: pd.DataFrame) -> pd.DataFrame:
    """Compute network-only features per campaign, never capture-global duplicates.

    A campaign is mapped with (source IP, campaign start/end). The namespace topology
    keeps each persona IP stable and campaigns for one persona non-overlapping.
    """
    index=campaign_intervals(df)
    acc: dict[str,dict]=defaultdict(lambda:{
        "sizes":[],"times":[],"up_bytes":0,"down_bytes":0,"up_packets":0,"down_packets":0,
        "tcp_packets":0,"udp_packets":0,
    })
    if pcap.exists():
        with PcapReader(str(pcap)) as rd:
            for pkt in rd:
                try:
                    ts=float(pkt.time); n=len(pkt)
                    if IP in pkt:
                        src,dst=pkt[IP].src,pkt[IP].dst
                    elif IPv6 in pkt:
                        src,dst=pkt[IPv6].src,pkt[IPv6].dst
                    else:
                        continue
                    persona_ip=src if src in index else dst if dst in index else None
                    if not persona_ip:
                        continue
                    cid=lookup_campaign(index,persona_ip,ts)
                    if not cid:
                        continue
                    a=acc[cid]; a["sizes"].append(n); a["times"].append(ts)
                    if src==persona_ip:
                        a["up_bytes"]+=n; a["up_packets"]+=1
                    else:
                        a["down_bytes"]+=n; a["down_packets"]+=1
                    if TCP in pkt: a["tcp_packets"]+=1
                    if UDP in pkt: a["udp_packets"]+=1
                except Exception:
                    continue
    rows=[]
    for cid in df.campaign_id.astype(str):
        a=acc.get(cid,{"sizes":[],"times":[],"up_bytes":0,"down_bytes":0,"up_packets":0,"down_packets":0,"tcp_packets":0,"udp_packets":0})
        sizes=a["sizes"]; times=sorted(a["times"])
        inter=[b-a0 for a0,b in zip(times,times[1:])]
        rows.append({
            "campaign_id":cid,
            "packet_count":len(sizes),
            "byte_count":sum(sizes),
            "wire_duration_s":(times[-1]-times[0]) if len(times)>1 else 0.0,
            "packet_size_mean":statistics.fmean(sizes) if sizes else 0.0,
            "packet_size_std":statistics.pstdev(sizes) if len(sizes)>1 else 0.0,
            "packet_size_p95":sorted(sizes)[max(0,math.ceil(.95*len(sizes))-1)] if sizes else 0,
            "interarrival_mean":statistics.fmean(inter) if inter else 0.0,
            "interarrival_std":statistics.pstdev(inter) if len(inter)>1 else 0.0,
            "up_bytes":a["up_bytes"],"down_bytes":a["down_bytes"],
            "up_packets":a["up_packets"],"down_packets":a["down_packets"],
            "up_down_byte_ratio":a["up_bytes"]/max(1,a["down_bytes"]),
            "tcp_packets":a["tcp_packets"],"udp_packets":a["udp_packets"],
        })
    return pd.DataFrame(rows)


def transaction_features(stage_dir: Path, df: pd.DataFrame, gold: Path) -> None:
    """Create content-visible transaction features from LAB decrypted ground truth only."""
    traces=read_jsonl(stage_dir/"manifests"/"decrypted_transactions.jsonl")
    if not traces:
        return
    index=campaign_intervals(df)
    rows=[]
    for t in traces:
        src=str(t.get("client_ip") or "")
        try:
            ts=float(t.get("ts"))
        except Exception:
            continue
        cid=lookup_campaign(index,src,ts)
        if not cid:
            continue
        headers=t.get("request_headers") or {}
        req=t.get("request") or {}
        resp=t.get("response") or {}
        body=b""
        try:
            body=base64.b64decode(req.get("body_b64") or "",validate=False)
        except Exception:
            pass
        header_blob="\n".join(f"{k}:{v}" for k,v in headers.items()).encode(errors="replace")
        path=str(t.get("path") or "")
        query=str(t.get("query") or "")
        rows.append({
            "campaign_id":cid,"ts":ts,"kind":t.get("kind"),"method":t.get("method"),
            "path_length":len(path),"query_length":len(query),"header_count":len(headers),
            "header_bytes":len(header_blob),"header_entropy":shannon_entropy(header_blob),
            "request_body_length":int(req.get("body_length") or 0),"request_body_entropy":shannon_entropy(body),
            "request_body_truncated":bool(req.get("body_truncated") or False),
            "response_status":t.get("response_status"),"response_body_length":int(resp.get("body_length") or 0),
        })
    if rows:
        pd.DataFrame(rows).to_parquet(gold/"transaction_features.parquet",index=False)


def build_gold(stage_dir: Path, silver: Path, gold: Path, pcap: Path) -> float:
    gold.mkdir(parents=True,exist_ok=True)
    cpath=silver/"campaigns.parquet"
    if not cpath.exists():
        return 0.0
    df=pd.read_parquet(cpath)
    feat=pd.DataFrame({
        "campaign_id":df.campaign_id,
        "label_binary":df.label_binary,
        "label_family":df.label_family,
        "protocol":df.protocol,
        "carrier":df.carrier,
        "persona":df.persona,
        "client_impl":df.get("client_impl",pd.Series(["unknown"]*len(df))),
        "visibility_mode":df.visibility_mode,
        "expected_events":df.expected_events,
        "infra_category":df.infra_category,
        "inspection_policy":df.inspection_policy,
        "sni_visibility":df.sni_visibility,
    })
    net=campaign_packet_features(pcap,df)
    feat=feat.merge(net,on="campaign_id",how="left")
    feat.to_parquet(gold/"session_features.parquet",index=False)
    transaction_features(stage_dir,df,gold)
    mapping_coverage=float((feat.packet_count.fillna(0)>0).mean()) if len(feat) else 0.0

    splits={"train":[],"validation":[],"test":[],"challenge":[]}
    stage_series=df.get("experiment_stage",pd.Series([""]*len(df))).astype(str)
    for cid,stage_name in zip(df.campaign_id.astype(str),stage_series):
        if "challenge" in stage_name.lower() or "commodity" in stage_name.lower():
            bucket="challenge"
        else:
            x=int(hashlib.sha256(cid.encode()).hexdigest()[:8],16)%100
            bucket="train" if x<70 else "validation" if x<80 else "test"
        splits[bucket].append(cid)
    for name,ids in splits.items():
        (gold/f"{name}_campaigns.txt").write_text("\n".join(ids)+("\n" if ids else ""))
    return mapping_coverage


def quality(stage_dir: Path, pcap: Path, out: Path, mapping_coverage: float):
    out.mkdir(parents=True,exist_ok=True)
    campaigns=read_jsonl(stage_dir/"campaigns.jsonl"); events=read_jsonl(stage_dir/"events.jsonl")
    checks={
        "pcap_exists":pcap.exists(),"pcap_nonempty":pcap.exists() and pcap.stat().st_size>24,
        "campaign_count":len(campaigns),"event_count":len(events),
        "unique_campaign_ids":len({c.get('campaign_id') for c in campaigns})==len(campaigns),
        "all_success":all(c.get("status")=="success" for c in campaigns),
        "external_dependencies_false":all(c.get("external_dependency") is False for c in campaigns),
        "event_to_packet_mapping_coverage":round(mapping_coverage,6),
        "mapping_coverage_ge_0_95":mapping_coverage>=0.95 if campaigns else False,
    }
    checks["passed"]=all(v for k,v in checks.items() if isinstance(v,bool))
    (out/"capture_health.json").write_text(json.dumps(checks,indent=2))
    checksum={}
    for p in stage_dir.rglob("*"):
        if p.is_file(): checksum[str(p.relative_to(stage_dir))]=sha256(p)
    if pcap.exists(): checksum[str(pcap.name)]=sha256(pcap)
    (out/"checksums.json").write_text(json.dumps(checksum,indent=2,sort_keys=True))
    leak={
        "duplicate_campaign_ids":not checks["unique_campaign_ids"],
        "label_in_capture_filename":any(x in pcap.name.lower() for x in ["malicious","suspicious","benign"]),
        "capture_global_features_repeated_per_campaign":False,
    }
    leak["passed"]=checks["unique_campaign_ids"] and not leak["label_in_capture_filename"]
    (out/"leakage_checks.json").write_text(json.dumps(leak,indent=2))
    return checks


def main():
    p=argparse.ArgumentParser()
    p.add_argument("--stage-dir",required=True); p.add_argument("--pcap",required=True)
    p.add_argument("--silver",required=True); p.add_argument("--gold",required=True); p.add_argument("--quality",required=True)
    a=p.parse_args(); stage=Path(a.stage_dir); silver=Path(a.silver); gold=Path(a.gold); pcap=Path(a.pcap)
    normalize(stage,silver)
    mapping=build_gold(stage,silver,gold,pcap)
    result=quality(stage,pcap,Path(a.quality),mapping)
    print(json.dumps(result))


if __name__=="__main__":
    main()
