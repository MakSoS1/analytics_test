"""Fail-closed packet evidence audit for synthetic Windows native client."""
import argparse
import json
import ipaddress
import hashlib
from pathlib import Path
from scapy.all import PcapNgReader, TCP, IP, IPv6

def inspect(path: Path, allowed_ips: set[str], port: int = 443) -> dict:
    if not allowed_ips:
        raise ValueError("a pinned target IP allowlist is required")
    target_addresses = {ipaddress.ip_address(ip) for ip in allowed_ips}
    total = matches = syn = fin = data = handshakes = duplicate_frames = 0
    stamps = []
    pairs: dict[tuple, list[float]] = {}
    seen: set[tuple] = set()
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
            src_ip = ipaddress.ip_address(str(ip.src))
            dst_ip = ipaddress.ip_address(str(ip.dst))
            if not (src_ip in target_addresses or dst_ip in target_addresses):
                continue
            src=(str(src_ip),int(tcp.sport))
            dst=(str(dst_ip),int(tcp.dport))
            key=tuple(sorted((src,dst)))
            pairs.setdefault(key,[]).append(float(packet.time))
            matches += 1
            stamps.append(float(packet.time))
            fingerprint=(
                round(float(packet.time),6),
                hashlib.sha256(bytes(packet)).hexdigest(),
            )
            if fingerprint in seen:
                duplicate_frames += 1
            else:
                seen.add(fingerprint)
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
    flow_spans=sorted(
        [round(max(v)-min(v),3) for v in pairs.values()],
        reverse=True
    )
    longest=flow_spans[0] if flow_spans else 0
    passed=(matches >= 8 and syn >= 1 and handshakes >= 1 and span >= 8)
    return {
        "version":"windows-benign-pktmon-probe-v3",
        "captured_frames":total,
        "target_https_tcp_frames":matches,
        "tcp_client_syn_frames":syn,
        "tcp_fin_frames":fin,
        "tcp_payload_frames":data,
        "tls_handshake_record_frames":handshakes,
        "unique_undirected_tcp_connections":len(pairs),
        "exact_timestamp_and_packet_duplicate_frames":duplicate_frames,
        "capture_span_seconds":span,
        "longest_single_tcp_connection_seconds":longest,
        "single_connection_dwell_at_least_8_seconds":bool(longest >= 8),
        "supported":bool(passed),
        "target_ip_whitelisted":True,
        "target_ip_count":len(target_addresses),
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
    p.add_argument("--allowed-ips",type=Path,required=True)
    a=p.parse_args()
    ip_values=json.loads(a.allowed_ips.read_text())
    if not isinstance(ip_values,list) or not all(isinstance(x,str) for x in ip_values):
        raise SystemExit("target allowlist must be a JSON array of IP strings")
    out=inspect(a.pcapng,allowed_ips=set(ip_values),port=a.port)
    a.report.write_text(json.dumps(out,indent=2,sort_keys=True)+"\n")
    print(json.dumps(out,sort_keys=True))
    if not out["supported"]:
        raise SystemExit("Windows pktmon packet evidence insufficient")