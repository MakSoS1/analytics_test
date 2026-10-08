"""Fail-closed packet evidence audit for synthetic Windows native client."""
import argparse
import json
from pathlib import Path
from scapy.all import PcapNgReader, TCP, IP, IPv6

def inspect(path: Path, port: int = 18443) -> dict:
    total = matches = syn = 0
    stamps = []
    with PcapNgReader(str(path)) as reader:
        for packet in reader:
            total += 1
            if TCP not in packet:
                continue
            tcp = packet[TCP]
            if int(tcp.sport) != port and int(tcp.dport) != port:
                continue
            if IP not in packet and IPv6 not in packet:
                continue
            matches += 1
            stamps.append(float(packet.time))
            if int(tcp.flags) & 0x02:
                syn += 1
    return {
        "version":"windows-benign-pktmon-probe-v1",
        "captured_frames":total,
        "tls_fixture_tcp_frames":matches,
        "syn_flag_frames":syn,
        "capture_span_seconds":round(max(stamps)-min(stamps), 3) if stamps else 0,
        "supported": matches >= 8 and syn >= 1 and (max(stamps)-min(stamps) >= 1 if stamps else False),
        "scope":"local_only_synthetic_tls_httpclient",
        "authorizes_windows_backend":False,
        "office_naturalness_proven":False,
        "production_ready":False,
    }

if __name__ == "__main__":
    p=argparse.ArgumentParser()
    p.add_argument("--pcapng",type=Path,required=True)
    p.add_argument("--report",type=Path,required=True)
    a=p.parse_args()
    out=inspect(a.pcapng)
    a.report.write_text(json.dumps(out,indent=2,sort_keys=True)+"\n")
    print(json.dumps(out,sort_keys=True))
    if not out["supported"]:
        raise SystemExit("Windows pktmon packet evidence insufficient")
