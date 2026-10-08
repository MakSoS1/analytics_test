#!/usr/bin/env python3
"""Extract NGFW-plausible packet-level features from lab pcaps (plan v3 §34–36).

Runs next to the pcaps (WSL /opt/tunnel_lab). Does not copy captures to the Mac.
Uses tcpdump -tt -nn -e (no payload). Skips DNS. Snaplen-limited pcaps still
work: tcpdump's `length N` is the on-wire origlen, not the truncated caplen. Does not emit leakage columns
as model features (ports/IPs may be kept on the row for QC only, then dropped
at train time).
"""
from __future__ import annotations

import argparse
import csv
import json
import math
import re
import subprocess
import sys
from collections import Counter
from pathlib import Path
from typing import Any

_PKG_ROOT = Path(__file__).resolve().parent.parent
if str(_PKG_ROOT) not in sys.path:
    sys.path.insert(0, str(_PKG_ROOT))
from lab_pipeline.online_schema import in_scope  # noqa: E402
from lab_pipeline.schema import MODEL_FEATURE_NAMES, SEQ_N  # noqa: E402

DEFAULT_SOURCES = "wsl_tunnel_lab_v3,wsl_tunnel_lab"

# tcpdump >= 4.99 with -e drops the redundant "IP " token after the ethertype,
# older builds keep it. Accept both: without this the -e branch never matches and
# read_pcap_packets silently falls back to the no-ethernet output, where the frame
# length is reconstructed from the payload instead of read off the wire.
# One line of `tcpdump -e -tt -nn`, in every layout the link actually carries.
#
# `frame` is the OUTER length, which is what the contract's `l2_frame_no_fcs`
# means; the non-greedy prefix stops at the first `length N:` so a VLAN preamble
# cannot shift it. `IP ` is optional because tcpdump 4.99 omits it with -e —
# requiring it once cost months of lengths reconstructed as payload+42.
#
# The address alternation covers IPv6, which never matched before, so every IPv6
# flow was missing from every corpus while the Suricata exporter scored IPv6
# without complaint. The optional VLAN preamble covers tagged frames; a SPAN
# port carries tags routinely and the old pattern would have emptied the corpus
# without a single error.
#
# Ports are required on both sides, which is what keeps ARP and ICMP out: a
# wrong match invents a flow, and that is worse than a missing one.
_ADDR = r"(?:\d+\.\d+\.\d+\.\d+|[0-9a-fA-F:]*:[0-9a-fA-F:.]+)"
_VLAN = r"(?:vlan \d+, p \d+, ethertype [^,]+, )*"

LINE_RE = re.compile(
    r"^(?P<ts>\d+\.\d+)\s+.*?length (?P<frame>\d+): "
    + _VLAN
    + r"(?:IP6? )?(?P<src>" + _ADDR + r")\.(?P<sport>\d+) > "
    r"(?P<dst>" + _ADDR + r")\.(?P<dport>\d+): (?P<rest>.*)$"
)
LINE_RE_NO_ETH = re.compile(
    r"^(?P<ts>\d+\.\d+) IP (?P<src>\d+\.\d+\.\d+\.\d+)\.(?P<sport>\d+) > "
    r"(?P<dst>\d+\.\d+\.\d+\.\d+)\.(?P<dport>\d+): (?P<rest>.*)$"
)
UDP_LEN_RE = re.compile(r"UDP, length (\d+)")
TCP_LEN_RE = re.compile(r"length (\d+)\s*$")


def _shannon(values: list[int]) -> float:
    if not values:
        return 0.0
    counts = Counter(values)
    n = float(len(values))
    ent = 0.0
    for c in counts.values():
        p = c / n
        ent -= p * math.log2(p)
    return ent


def _pct(sorted_vals: list[float], q: float) -> float:
    if not sorted_vals:
        return 0.0
    idx = min(len(sorted_vals) - 1, max(0, int(round((q / 100.0) * (len(sorted_vals) - 1)))))
    return float(sorted_vals[idx])


def parse_tcpdump_line(line: str) -> dict[str, Any] | None:
    m = LINE_RE.search(line) or LINE_RE_NO_ETH.search(line)
    if not m:
        return None
    sport, dport = int(m.group("sport")), int(m.group("dport"))
    # The scope lives in online_schema and nowhere else. It used to be a private
    # DNS_PORTS set here, a second one in the office collector and nothing at all
    # in the Suricata exporter, so the three components disagreed about what the
    # detector was even being asked about.
    if not in_scope(sport, dport):
        return None
    rest = m.group("rest")
    length = 0
    if "frame" in m.groupdict() and m.groupdict().get("frame"):
        try:
            length = int(m.group("frame"))
        except (TypeError, ValueError):
            length = 0
    um = UDP_LEN_RE.search(rest)
    tm = TCP_LEN_RE.search(rest)
    if um:
        length = max(length, int(um.group(1)) + 42)
    elif tm and length == 0:
        length = int(tm.group(1)) + 54
    proto = "udp" if "UDP" in rest else ("tcp" if "Flags" in rest or "tcp" in rest.lower() else "other")
    flags = ""
    fm = re.search(r"Flags \[([^\]]+)\]", rest)
    if fm:
        flags = fm.group(1)
    return {
        "ts": float(m.group("ts")),
        "src": m.group("src"),
        "dst": m.group("dst"),
        "sport": sport,
        "dport": dport,
        "length": max(length, 1),
        "proto": proto,
        "flags": flags,
    }


def packets_from_tcpdump(text: str) -> list[dict[str, Any]]:
    out = []
    for line in text.splitlines():
        rec = parse_tcpdump_line(line)
        if rec:
            out.append(rec)
    return out


MAX_ETHERNET_FRAME = 1514


def split_coalesced_frames(pkts: list[dict[str, Any]], mtu: int = MAX_ETHERNET_FRAME) -> list[dict[str, Any]]:
    """Undo receive-side coalescing so captures from different NICs compare.

    Generic receive offload hands the capture one frame of up to 64 KB in place
    of the segments that were actually on the wire. How much of that happens
    depends on the NIC and its offload settings, not on the traffic: the WSL lab
    captures show ~24% coalesced frames, the office SPAN (with `rx-gro-hw off`)
    shows none. Training tunnels from one and background from the other would
    let a model separate the classes on the capture path alone — the same defect
    that made the March 2026 corpus worthless.

    So every oversized frame is expanded back into MTU-sized segments plus the
    remainder. Sub-segment timings are genuinely lost — the capture never had
    them — so the pieces share the coalesced frame's timestamp. Both sides get
    the identical treatment, which is what makes them comparable.
    """
    if not pkts:
        return pkts
    out: list[dict[str, Any]] = []
    for p in pkts:
        length = int(p.get("length") or 0)
        if length <= mtu:
            out.append(p)
            continue
        whole, rest = divmod(length, mtu)
        for _ in range(whole):
            seg = dict(p)
            seg["length"] = mtu
            seg["coalesced_split"] = True
            out.append(seg)
        if rest > 0:
            seg = dict(p)
            seg["length"] = rest
            seg["coalesced_split"] = True
            out.append(seg)
    return out


def iter_pcap_packets(pcap: Path):
    """Stream packets instead of materialising them.

    `read_pcap_packets` captures the whole tcpdump output and builds one list.
    A 60-second office window is ~2.4M frames, and a 300-second one killed the
    collector outright: the sensor has 15 GB and the packet list alone wanted
    more. Streaming keeps memory flat regardless of window length, which is what
    makes long capture windows — and therefore a usable FPR denominator —
    possible at all.

    De-coalescing still applies, per frame, so the output matches
    `read_pcap_packets` element for element.
    """
    for args in (["-tt", "-nn", "-e"], ["-tt", "-nn"]):
        proc = subprocess.Popen(
            ["tcpdump", *args, "-r", str(pcap)],
            stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True, bufsize=1 << 20,
        )
        produced = False
        assert proc.stdout is not None
        for line in proc.stdout:
            rec = parse_tcpdump_line(line)
            if rec is None:
                continue
            produced = True
            length = int(rec.get("length") or 0)
            if length <= MAX_ETHERNET_FRAME:
                yield rec
                continue
            whole, rest = divmod(length, MAX_ETHERNET_FRAME)
            for _ in range(whole):
                seg = dict(rec); seg["length"] = MAX_ETHERNET_FRAME; seg["coalesced_split"] = True
                yield seg
            if rest > 0:
                seg = dict(rec); seg["length"] = rest; seg["coalesced_split"] = True
                yield seg
        proc.stdout.close()
        proc.wait()
        if produced:
            return


def read_pcap_packets(pcap: Path) -> list[dict[str, Any]]:
    proc = subprocess.run(
        ["tcpdump", "-tt", "-nn", "-e", "-r", str(pcap)],
        capture_output=True,
        text=True,
        check=False,
    )
    text = proc.stdout or ""
    pkts = packets_from_tcpdump(text)
    if pkts:
        return split_coalesced_frames(pkts)
    proc2 = subprocess.run(
        ["tcpdump", "-tt", "-nn", "-r", str(pcap)],
        capture_output=True,
        text=True,
        check=False,
    )
    return split_coalesced_frames(packets_from_tcpdump(proc2.stdout or ""))


def infer_client(pkts: list[dict[str, Any]], meta: dict[str, Any]) -> str:
    hinted = str(meta.get("outer_src") or "")
    if hinted and not hinted.endswith(".53"):
        return hinted
    counts: Counter[str] = Counter()
    for p in pkts:
        if p["src"].startswith("10.3") and p["src"].endswith(".10"):
            return p["src"]
        counts[p["src"]] += 1
    return counts.most_common(1)[0][0] if counts else ""


def features_from_packets(pkts: list[dict[str, Any]], meta: dict[str, Any] | None = None) -> dict[str, Any]:
    meta = meta or {}
    if not pkts:
        row = {name: 0.0 for name in MODEL_FEATURE_NAMES}
        row["pkt_count"] = 0
        return row
    client = infer_client(pkts, meta)
    t0 = pkts[0]["ts"]
    t1 = pkts[-1]["ts"]
    duration = max(t1 - t0, 1e-6)
    lens: list[int] = []
    iats: list[float] = []
    dirs: list[int] = []
    up_pkts = down_pkts = 0
    up_bytes = down_bytes = 0
    syn = fin = rst = 0
    udp = tcp = 0
    bursts = 0
    in_burst = False
    prev_ts = None
    prev_dir = None
    dir_changes = 0
    idle = 0.0
    for p in pkts:
        direction = 1 if p["src"] == client else -1
        if prev_dir is not None and direction != prev_dir:
            dir_changes += 1
        prev_dir = direction
        iat = 0.0 if prev_ts is None else max(p["ts"] - prev_ts, 0.0)
        if prev_ts is not None and iat > 1.0:
            idle += iat
        if prev_ts is not None and iat < 0.05:
            if not in_burst:
                bursts += 1
                in_burst = True
        else:
            in_burst = False
        prev_ts = p["ts"]
        ln = int(p["length"])
        lens.append(ln)
        iats.append(iat)
        dirs.append(direction)
        if direction > 0:
            up_pkts += 1
            up_bytes += ln
        else:
            down_pkts += 1
            down_bytes += ln
        if p["proto"] == "udp":
            udp += 1
        elif p["proto"] == "tcp":
            tcp += 1
        flags = p.get("flags") or ""
        if "S" in flags and "." not in flags:
            syn += 1
        if "F" in flags:
            fin += 1
        if "R" in flags:
            rst += 1
    n = len(pkts)
    slens = sorted(float(x) for x in lens)
    mean_len = sum(lens) / n
    var_len = sum((x - mean_len) ** 2 for x in lens) / n
    nonempty_iat = iats[1:] if len(iats) > 1 else [0.0]
    mean_iat = sum(nonempty_iat) / len(nonempty_iat)
    var_iat = sum((x - mean_iat) ** 2 for x in nonempty_iat) / len(nonempty_iat)
    total_bytes = up_bytes + down_bytes
    row: dict[str, Any] = {
        "pkt_count": n,
        "up_pkt_count": up_pkts,
        "down_pkt_count": down_pkts,
        "total_bytes": total_bytes,
        "up_bytes": up_bytes,
        "down_bytes": down_bytes,
        "flow_duration": duration,
        "up_down_pkt_ratio": up_pkts / max(down_pkts, 1),
        "up_down_bytes_ratio": up_bytes / max(down_bytes, 1),
        "pkt_rate": n / duration,
        "byte_rate": total_bytes / duration,
        "pkt_len_mean": mean_len,
        "pkt_len_std": math.sqrt(var_len),
        "pkt_len_min": min(lens),
        "pkt_len_max": max(lens),
        "pkt_len_median": _pct(slens, 50),
        "pkt_len_p10": _pct(slens, 10),
        "pkt_len_p90": _pct(slens, 90),
        "pkt_len_entropy": _shannon(lens),
        "iat_mean": mean_iat,
        "iat_std": math.sqrt(var_iat),
        "iat_min": min(nonempty_iat),
        "iat_max": max(nonempty_iat),
        "iat_p90": _pct(sorted(nonempty_iat), 90),
        "burst_count": bursts,
        "idle_ratio": idle / duration,
        "direction_changes": dir_changes,
        "udp_share": udp / n,
        "tcp_share": tcp / n,
        "syn_count": syn,
        "fin_count": fin,
        "rst_count": rst,
    }
    for i in range(SEQ_N):
        if i < n:
            row[f"signed_len_{i}"] = dirs[i] * lens[i]
            row[f"dir_{i}"] = dirs[i]
            row[f"iat_{i}"] = iats[i]
            row[f"mask_{i}"] = 1
        else:
            row[f"signed_len_{i}"] = 0
            row[f"dir_{i}"] = 0
            row[f"iat_{i}"] = 0.0
            row[f"mask_{i}"] = 0
    return row


def load_lab_metadata(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text())


def extract_session(meta: dict[str, Any], pcap: Path | None) -> dict[str, Any]:
    pkts: list[dict[str, Any]] = []
    if pcap and pcap.is_file():
        pkts = read_pcap_packets(pcap)
    feats = features_from_packets(pkts, meta)
    row = dict(feats)
    row["session_id"] = str(meta.get("session_id") or (pcap.stem if pcap else ""))
    row["label_binary"] = meta.get("label_binary") or ""
    row["label_family"] = meta.get("label_family") or ""
    row["campaign_id"] = meta.get("campaign_id") or ""
    row["workload"] = meta.get("workload") or ""
    row["netem_profile"] = meta.get("netem_profile") or ""
    row["capture_source"] = meta.get("capture_source") or ""
    row["stack_variant"] = meta.get("stack_variant") or ""
    row["server_endpoint"] = meta.get("server_endpoint") or ""
    row["server_baseline_delay_ms"] = meta.get("server_baseline_delay_ms") or 0
    row["pcap"] = str(pcap or meta.get("pcap") or "")
    row["y"] = 1 if row["label_binary"] == "tunnel" else 0
    return row


def source_allowed(capture_source: str, filter_spec: str) -> bool:
    src = capture_source or ""
    if src == "wsl_tunnel_lab_v2":
        return False
    if not filter_spec or filter_spec == "all":
        return src != "wsl_tunnel_lab_v2"
    allowed = {part.strip() for part in filter_spec.split(",") if part.strip()}
    return src in allowed


def iter_lab_sessions(metadata_dir: Path, source_filter: str = DEFAULT_SOURCES) -> list[dict[str, Any]]:
    rows = []
    for fp in sorted(metadata_dir.glob("*.json")):
        try:
            meta = load_lab_metadata(fp)
        except json.JSONDecodeError:
            continue
        if not source_allowed(str(meta.get("capture_source") or ""), source_filter):
            continue
        pcap = Path(str(meta.get("pcap") or ""))
        if not pcap.is_file():
            alt = metadata_dir.parent / "pcaps" / (fp.stem + ".pcap")
            pcap = alt if alt.is_file() else pcap
        if not pcap.is_file():
            continue
        rows.append(extract_session(meta, pcap))
    return rows


def write_csv(path: Path, rows: list[dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fields = (
        [
            "session_id",
            "label_binary",
            "y",
            "label_family",
            "campaign_id",
            "workload",
            "netem_profile",
            "capture_source",
            "stack_variant",
            "server_endpoint",
            "server_baseline_delay_ms",
            "pcap",
        ]
        + MODEL_FEATURE_NAMES
    )
    with path.open("w", newline="", encoding="utf-8") as fh:
        writer = csv.DictWriter(fh, fieldnames=fields, extrasaction="ignore")
        writer.writeheader()
        for row in rows:
            writer.writerow(row)


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--metadata-dir", default="/opt/tunnel_lab/metadata")
    p.add_argument("--out-csv", default="/opt/tunnel_lab/features/lab_v3_features.csv")
    p.add_argument("--source-filter", default=DEFAULT_SOURCES)
    args = p.parse_args()
    rows = iter_lab_sessions(Path(args.metadata_dir), args.source_filter)
    write_csv(Path(args.out_csv), rows)
    n_t = sum(1 for r in rows if r.get("y") == 1)
    n_b = sum(1 for r in rows if r.get("y") == 0)
    print(json.dumps({"rows": len(rows), "tunnel": n_t, "benign": n_b, "csv": args.out_csv}))
    return 0 if rows else 2


if __name__ == "__main__":
    raise SystemExit(main())
