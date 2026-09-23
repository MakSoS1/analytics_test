from __future__ import annotations

import argparse
import bisect
import json
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path

from scapy.all import IP, IPv6, PcapReader, PcapWriter


def _read(path: Path) -> list[dict]:
    return [json.loads(x) for x in path.read_text(errors="replace").splitlines() if x.strip()]


def _write(path: Path, rows: list[dict]) -> None:
    path.write_text("".join(json.dumps(x, separators=(",", ":"), default=str) + "\n" for x in rows))


def _ts(value: str) -> float:
    return datetime.fromisoformat(value.replace("Z", "+00:00")).timestamp()


def _iso(value: float) -> str:
    return datetime.fromtimestamp(value, tz=timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")


def _packet_ips(pkt) -> tuple[str, str]:
    if IP in pkt: return str(pkt[IP].src), str(pkt[IP].dst)
    if IPv6 in pkt: return str(pkt[IPv6].src), str(pkt[IPv6].dst)
    return "", ""


def retime(pcap_in: Path, pcap_out: Path, campaigns_path: Path, events_path: Path, report_path: Path) -> dict:
    campaigns = _read(campaigns_path); events = _read(events_path)
    by_campaign_events: dict[str, list[dict]] = defaultdict(list)
    for e in events: by_campaign_events[str(e["campaign_id"])].append(e)
    for rows in by_campaign_events.values(): rows.sort(key=lambda x: int(x.get("event_index", 0)))

    packets=[]
    with PcapReader(str(pcap_in)) as rd:
        for pkt in rd: packets.append(pkt)
    if not packets: raise ValueError("empty input pcap")
    base=float(packets[0].time)

    by_source: dict[str, list[dict]] = defaultdict(list)
    for c in campaigns: by_source[str(c.get("source_ip", ""))].append(c)
    for rows in by_source.values(): rows.sort(key=lambda c: _ts(c["started_at"]))

    campaign_maps={}; source_slot={ip:i for i,ip in enumerate(sorted(k for k in by_source if k))}
    for source, rows in by_source.items():
        cursor=0.0
        for c in rows:
            cid=str(c["campaign_id"]); evs=by_campaign_events.get(cid,[])
            new_base=base + source_slot[source]*0.25 + cursor
            actual_start=_ts(c["started_at"]); actual_end=_ts(c["ended_at"])
            event_maps=[]; max_target=0.0
            for e in evs:
                es=_ts(e["sent_at"]); ee=_ts(e["completed_at"]); off=float(e.get("nominal_offset_seconds",0.0)); duration=max(0.001,ee-es)
                event_maps.append({"actual_start":es,"actual_end":ee,"target_start":new_base+off,"duration":duration,"event":e})
                max_target=max(max_target,off+duration)
            span=max(max_target, max(0.01,actual_end-actual_start))
            campaign_maps[cid]={"source":source,"actual_start":actual_start,"actual_end":actual_end,"target_start":new_base,"target_end":new_base+span,"events":event_maps,"campaign":c}
            cursor += span + 0.5

    intervals_by_source=defaultdict(list)
    for cid,m in campaign_maps.items(): intervals_by_source[m["source"]].append((m["actual_start"]-0.05,m["actual_end"]+0.25,cid))
    for source in intervals_by_source: intervals_by_source[source].sort()

    mapped_packets=0; event_mapped=0; campaign_mapped=0
    for pkt in packets:
        old=float(pkt.time); src,dst=_packet_ips(pkt); source=src if src in intervals_by_source else dst if dst in intervals_by_source else ""
        if not source: continue
        candidates=intervals_by_source[source]; starts=[x[0] for x in candidates]; pos=bisect.bisect_right(starts,old)-1
        cid=None
        for j in (pos,pos-1,pos+1):
            if 0<=j<len(candidates) and candidates[j][0] <= old <= candidates[j][1]: cid=candidates[j][2];break
        if cid is None: continue
        m=campaign_maps[cid]; chosen=None; best=1e9
        for em in m["events"]:
            if em["actual_start"]-0.02 <= old <= em["actual_end"]+0.08:
                d=abs(old-em["actual_start"])
                if d<best: chosen=em;best=d
        if chosen:
            pkt.time=chosen["target_start"]+(old-chosen["actual_start"]);event_mapped+=1
        else:
            pkt.time=m["target_start"]+max(0.0,old-m["actual_start"]);campaign_mapped+=1
        mapped_packets+=1

    packets.sort(key=lambda p: float(p.time))
    with PcapWriter(str(pcap_out),sync=True) as wr:
        for pkt in packets: wr.write(pkt)

    for cid,m in campaign_maps.items():
        c=m["campaign"]; c["raw_started_at"]=c["started_at"];c["raw_ended_at"]=c["ended_at"];c["started_at"]=_iso(m["target_start"]);c["ended_at"]=_iso(m["target_end"]);c["timestamp_retimed"]=True;c["timing_fidelity"]="pcap_timestamp_retimed_from_nominal_schedule"
        for em in m["events"]:
            e=em["event"];e["raw_sent_at"]=e["sent_at"];e["raw_completed_at"]=e["completed_at"];e["sent_at"]=_iso(em["target_start"]);e["completed_at"]=_iso(em["target_start"]+em["duration"]);e["timestamp_retimed"]=True
    _write(campaigns_path,campaigns);_write(events_path,events)
    report={"schema_version":1,"input_packets":len(packets),"mapped_packets":mapped_packets,"event_mapped_packets":event_mapped,"campaign_mapped_packets":campaign_mapped,"mapping_fraction":mapped_packets/max(1,len(packets)),"campaigns":len(campaigns),"events":len(events),"passed":mapped_packets/max(1,len(packets))>=0.90}
    report_path.parent.mkdir(parents=True,exist_ok=True);report_path.write_text(json.dumps(report,indent=2,sort_keys=True)+"\n")
    if not report["passed"]: raise SystemExit(f"Stage M retiming mapped only {report['mapping_fraction']:.3f} of packets")
    return report


def main():
    ap=argparse.ArgumentParser();ap.add_argument("--input",required=True);ap.add_argument("--output",required=True);ap.add_argument("--campaigns",required=True);ap.add_argument("--events",required=True);ap.add_argument("--report",required=True);a=ap.parse_args()
    print(json.dumps(retime(Path(a.input),Path(a.output),Path(a.campaigns),Path(a.events),Path(a.report)),sort_keys=True))

if __name__=="__main__":main()
