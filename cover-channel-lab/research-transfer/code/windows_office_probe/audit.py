"""Fail-closed packet evidence audit for synthetic Windows native client."""
import argparse
import json
from pathlib import Path
from scapy.all import PcapNgReader, TCP, IP, IPv6

def inspect(path: Path, port: int = 443) -> dict:
    total = matches = syn = fin = data = handshakes = 0
    stamps = []
    pairs: set[tuple] = set()
    with PcapNgReader(str(path)) as reader:
        for packet in reader:
            total += 1
            if TCP not in packet:
                continue
            tcp = packet[TCP]
            if int(tcp.sport) != port and int(tcp.dport) != port:
                continue
            ip = packet[IP] if IP in packet else (packet[IPv6] if IPv6 in packet else None)
            if ip is None:
                continue
            src=(str(ip.src),int(tcp.sport))
            dst=(str(ip.dst),int(tcp.dport))
            pairs.add(tuple(sorted((src,dst))))
            matches += 1
            stamps.append(float(packet.time))
            flags=int(tcp.flags)
            if flags & 0x02 and not flags & 0x10:
                syn += 1
            if flags & 0x01:
                fin += 1
            payload=bytes(tcp.payload)
            if payload:
                data += 1
                if payload[0] == 0x16 and len(payload) > 5 and payload[1] == 0x03:
                    handshakes += 1
    span=round(max(stamps)-min(stamps),3) if stamps else 0
    passed=(matches >= 8 and syn >= 1 and handshakes >= 1 and span >= 8)
    return {
        "version":"windows-benign-pktmon-probe-v2",
        "captured_frames":total,
        "public_https_tcp_frames":matches,
        "tcp_client_syn_frames":syn,
        "tcp_fin_frames":fin,
        "tcp_payload_frames":data,
        "tls_handshake_record_frames":handshakes,
        "unique_undirected_tcp_connections":len(pairs),
        "capture_span_seconds":span,
        "supported":bool(passed),
        "capture_component_scope":"nics_only",
        "scope":"public_example_com_native_windows_https_probe_no_user_data",
        "authorizes_windows_backend":False,
        "office_naturalness_proven":False,
        "production_ready":False,
    }

if __name__ == "__main__":
    p=argparse.ArgumentParser()
    p.add_argument("--pcapng",type=Path,required=True)
    p.add_argument("--report",type=Path,required=True)
    p.add_argument("--port",type=int,default=443)
    a=p.parse_args()
    out=inspect(a.pcapng,port=a.port)
    a.report.write_text(json.dumps(out,indent=2,sort_keys=True)+"\n")
    print(json.dumps(out,sort_keys=True))
    if not out["supported"]:
        raise SystemExit("Windows pktmon packet evidence insufficient")