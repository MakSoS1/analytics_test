"""Verify native NIC packet bytes during PCAPNG -> PCAP rewrapping.

This converter only selects a previously declared public fixture target. It
does not modify packet bytes, change packet timing, or claim office fidelity.
"""
from __future__ import annotations
import argparse
import hashlib
import ipaddress
import json
from pathlib import Path

from scapy.all import Ether, IP, IPv6, TCP, PcapNgReader, PcapReader, PcapWriter


def convert(pcapng: Path, pcap: Path, allowed_ips: set[str]) -> dict:
    target = {ipaddress.ip_address(x) for x in allowed_ips}
    if not target:
        raise ValueError("missing allowed public target addresses")
    original: list[tuple[str, float]] = []
    if pcap.exists():
        raise FileExistsError(pcap)
    with PcapNgReader(str(pcapng)) as reader, PcapWriter(
        str(pcap), linktype=1, sync=True
    ) as writer:
        for pkt in reader:
            if Ether not in pkt or TCP not in pkt:
                continue
            ip = pkt[IP] if IP in pkt else (pkt[IPv6] if IPv6 in pkt else None)
            if ip is None:
                continue
            if (
                ipaddress.ip_address(str(ip.src)) not in target
                and ipaddress.ip_address(str(ip.dst)) not in target
            ):
                continue
            tcp=pkt[TCP]
            if int(tcp.sport) != 443 and int(tcp.dport) != 443:
                continue
            wire=bytes(pkt)
            original.append((hashlib.sha256(wire).hexdigest(), float(pkt.time)))
            writer.write(pkt)
    if len(original) < 8:
        raise ValueError("native packet source has fewer than eight TCP frames")
    actual: list[tuple[str, float]] = []
    with PcapReader(str(pcap)) as reader:
        for pkt in reader:
            actual.append((hashlib.sha256(bytes(pkt)).hexdigest(), float(pkt.time)))
    if len(actual) != len(original):
        raise ValueError("rewrap packet count changed")
    if any(a[0] != b[0] for a,b in zip(original,actual)):
        raise ValueError("rewrap changed captured packet bytes")
    max_error=max(abs(a[1]-b[1]) for a,b in zip(original,actual))
    if max_error > 5e-6:
        raise ValueError("rewrap changed timestamps by >5 microseconds")
    return {
        "version":"windows-pcapng-to-pcap-readonly-v1",
        "packets_verified":len(original),
        "all_packet_bytes_equal":True,
        "max_timestamp_delta_seconds":max_error,
        "output_sha256":hashlib.sha256(pcap.read_bytes()).hexdigest(),
        "profile":"real_windows_public_https_only",
        "production_ready":False,
    }


def extract_smoke(pcap: Path, directory: Path) -> dict:
    import sys
    sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
    import pandas as pd
    from natural_traffic.contracts import CaptureBundle
    from natural_traffic.composition import extract_pipeline_capture

    directory.mkdir(exist_ok=False,parents=True)
    manifest=directory / "runtime.json"
    manifest.write_text(json.dumps({
        "version":"windows-observational-probe-v1",
        "privacy":"public_fixture_only",
        "naturalness_status":"not_evaluated",
    })+"\n")
    sha=hashlib.sha256(pcap.read_bytes()).hexdigest()
    metadata_sha=hashlib.sha256(manifest.read_bytes()).hexdigest()
    bundle=CaptureBundle(
        pair_id="windows-public-httpclient",
        role="control",
        profile_id="windows-native-http",
        fidelity="native-win-httpclient-real-wire",
        pcap_path=pcap,
        pcap_sha256=sha,
        evidence=(),
        runtime_metadata_path=manifest,
        runtime_metadata_sha256=metadata_sha,
    )
    result=extract_pipeline_capture(
        bundle,directory/"processed",run_id="windows-public-probe",min_free_gib=1
    )
    frame=pd.read_parquet(result.parquet_path)
    durations=pd.to_numeric(frame["flow_duration"],errors="coerce").dropna()
    return {
        "version":"windows-real-stack-production-extractor-smoke-v1",
        "extracted_session_rows":len(frame),
        "positive_duration_rows":int((durations>0).sum()),
        "flow_duration_median_seconds":float(durations.median()) if len(durations) else None,
        "flow_duration_max_seconds":float(durations.max()) if len(durations) else None,
        "tcp_packet_count_sum":int(pd.to_numeric(frame["pkt_count"],errors="coerce").sum()),
        "measured_nonnull_tls_version_rows":int(frame["tls_version"].notna().sum()),
        "extractor_source_pcap_sha256":result.source_pcap_sha256,
        "same_original_feature_schema":all(c in frame for c in
            ("seq_signed_len","seq_iat_us","seq_flags","flow_duration","tls_version")),
        "office_naturalness_proven":False,
        "production_ready":False,
    }


def main():
    p=argparse.ArgumentParser()
    p.add_argument("--pcapng",type=Path,required=True)
    p.add_argument("--pcap",type=Path,required=True)
    p.add_argument("--allowed-ips",type=Path,required=True)
    p.add_argument("--report",type=Path,required=True)
    p.add_argument("--work",type=Path,required=True)
    a=p.parse_args()
    ips=json.loads(a.allowed_ips.read_text())
    if not isinstance(ips,list) or not all(isinstance(x,str) for x in ips):
        raise SystemExit("invalid target IP whitelist")
    copy=convert(a.pcapng,a.pcap,set(ips))
    result=extract_smoke(a.pcap,a.work)
    report={"conversion":copy,"pipeline":result}
    a.report.write_text(json.dumps(report,sort_keys=True,indent=2)+"\n")
    print("WINDOWS_PRODUCTION_EXTRACTOR",json.dumps(report,sort_keys=True))
    if not result["positive_duration_rows"] or not result["same_original_feature_schema"]:
        raise SystemExit("native Windows feature extraction lacked flow support")


if __name__=="__main__":
    main()
