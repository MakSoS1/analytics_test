#!/usr/bin/env python3
"""Minute pcaps to flow segments, then a SQL-shaped stitch.

A segment is the part of one session that sits inside a single minute file.
The file edge does not end the session: the segment is written with
ends_instance=0 and the next file continues it, as long as the gap stays
inside the Suricata idle timeout (TCP 60/600/10 s, UDP 30/300 s, the same
numbers as detector/lab_pipeline/online_schema.py).

stitch_segments() is the reference grouping. The Spark job runs the same
rules in SQL. Addresses are hashed with the office salt before they are
written; the segment file contains no IPs.
"""
from __future__ import annotations

import argparse
import csv
import gzip
import hashlib
import hmac
import ipaddress
import json
import subprocess
import sys
from pathlib import Path

_TCP_NEW, _TCP_EST, _TCP_CLOSED = 60.0, 600.0, 10.0
_UDP_NEW, _UDP_EST = 30.0, 300.0

FIELDS = [
    "flow_key", "proto", "file_idx", "t_first", "t_last",
    "pkts_a", "pkts_b", "bytes_a", "bytes_b",
    "opens_with_syn", "fin_count", "rst", "closed", "established",
    "ends_instance", "truncated", "a_priv", "b_priv",
]


def timeout_of(proto: str, established: bool, closed: bool) -> float:
    if closed and proto == "tcp":
        return _TCP_CLOSED
    if proto == "tcp":
        return _TCP_EST if established else _TCP_NEW
    return _UDP_EST if established else _UDP_NEW


def _private(ip: str) -> int:
    try:
        return int(ipaddress.ip_address(ip).is_private)
    except ValueError:
        return 0


def _bare_syn(flags: str) -> bool:
    return "S" in (flags or "") and "." not in (flags or "")


class _Seg:
    __slots__ = (
        "key", "proto", "established", "closed", "fin_seen", "rst_seen",
        "last_seen", "file_idx", "t_first", "pkts_a", "pkts_b", "bytes_a",
        "bytes_b", "opens_with_syn", "a_priv", "b_priv", "seg_fins",
        "last_segment_idx",
    )

    def __init__(self, key, proto, file_idx, ts, from_a, syn, length, a_priv, b_priv, flags):
        self.key = key
        self.proto = proto
        self.established = False
        self.closed = False
        self.fin_seen = 0
        self.rst_seen = 0
        self.last_seen = ts
        self.file_idx = file_idx
        self.t_first = ts
        self.pkts_a = 0
        self.pkts_b = 0
        self.bytes_a = 0
        self.bytes_b = 0
        self.opens_with_syn = int(syn)
        self.a_priv = a_priv
        self.b_priv = b_priv
        self.seg_fins = 0
        self.last_segment_idx = -1
        self.add(from_a, length, flags, ts)

    def add(self, from_a: bool, length: int, flags: str, ts: float) -> None:
        if from_a:
            self.pkts_a += 1
            self.bytes_a += length
        else:
            self.pkts_b += 1
            self.bytes_b += length
        self.last_seen = ts
        if self.pkts_a and self.pkts_b:
            self.established = True
        if "R" in flags:
            self.rst_seen += 1
            self.closed = True
        if "F" in flags:
            self.fin_seen += 1
            self.seg_fins += 1
            if self.fin_seen >= 2:
                self.closed = True

    def row(self, ends: int, truncated: int = 0) -> dict:
        return {
            "flow_key": self.key,
            "proto": self.proto,
            "file_idx": self.file_idx,
            "t_first": self.t_first,
            "t_last": self.last_seen,
            "pkts_a": self.pkts_a,
            "pkts_b": self.pkts_b,
            "bytes_a": self.bytes_a,
            "bytes_b": self.bytes_b,
            "opens_with_syn": self.opens_with_syn,
            "fin_count": self.seg_fins,
            "rst": int(self.rst_seen > 0),
            "closed": int(self.closed),
            "established": int(self.established),
            "ends_instance": ends,
            "truncated": truncated,
            "a_priv": self.a_priv,
            "b_priv": self.b_priv,
        }

    def begin_segment(self, file_idx: int, ts: float, from_a: bool, syn: bool, length: int, flags: str) -> None:
        self.file_idx = file_idx
        self.t_first = ts
        self.pkts_a = 0
        self.pkts_b = 0
        self.bytes_a = 0
        self.bytes_b = 0
        self.opens_with_syn = int(syn)
        self.seg_fins = 0
        self.add(from_a, length, flags, ts)


class Segmenter:
    def __init__(self, salt: bytes):
        self.salt = salt
        self.live: dict[str, _Seg] = {}
        self.segments: list[dict] = []
        self.packets = 0
        self.closed_timeout = 0
        self.closed_reopen = 0
        self.open_at_end = 0
        self._swept_at = 0.0

    def _hkey(self, ip_a, port_a, ip_b, port_b, proto) -> str:
        raw = f"{ip_a}\t{port_a}\t{ip_b}\t{port_b}\t{proto}"
        return hmac.new(self.salt, raw.encode(), hashlib.sha256).hexdigest()[:16]

    def _expire(self, now: float) -> None:
        dead = [
            k for k, s in self.live.items()
            if now - s.last_seen > timeout_of(s.proto, s.established, s.closed)
        ]
        for k in dead:
            sess = self.live.pop(k)
            if sess.pkts_a + sess.pkts_b > 0:
                self.segments.append(sess.row(1))
            elif sess.last_segment_idx >= 0:
                self.segments[sess.last_segment_idx]["ends_instance"] = 1
            self.closed_timeout += 1

    def packet(self, p: dict) -> None:
        now = float(p["ts"])
        self.packets += 1
        a = (p["src"], int(p["sport"]))
        b = (p["dst"], int(p["dport"]))
        ordered = (a, b, p["proto"]) if a <= b else (b, a, p["proto"])
        from_a = a == ordered[0]
        key = self._hkey(ordered[0][0], ordered[0][1], ordered[1][0], ordered[1][1], ordered[2])
        flags = p.get("flags") or ""
        syn = _bare_syn(flags)
        length = int(p["length"])
        file_idx = int(p["_file"])
        sess = self.live.get(key)
        if sess is not None and sess.pkts_a + sess.pkts_b > 0:
            gap = now - sess.last_seen
            limit = timeout_of(sess.proto, sess.established, sess.closed)
            if gap > limit or (syn and sess.closed):
                self.segments.append(sess.row(1))
                if gap > limit:
                    self.closed_timeout += 1
                else:
                    self.closed_reopen += 1
                del self.live[key]
                sess = None
        if sess is not None and sess.pkts_a + sess.pkts_b == 0:
            # Flushed at the previous file edge. Continue only inside the timeout.
            gap = now - sess.last_seen
            limit = timeout_of(sess.proto, sess.established, sess.closed)
            if gap > limit or (syn and sess.closed):
                if sess.last_segment_idx >= 0:
                    self.segments[sess.last_segment_idx]["ends_instance"] = 1
                if gap > limit:
                    self.closed_timeout += 1
                else:
                    self.closed_reopen += 1
                del self.live[key]
                sess = None
            else:
                sess.begin_segment(file_idx, now, from_a, syn, length, flags)
                self._expire(now)
                return
        if sess is None:
            self.live[key] = _Seg(
                key, p["proto"], file_idx, now, from_a, syn, length,
                _private(ordered[0][0]), _private(ordered[1][0]), flags,
            )
        else:
            sess.add(from_a, length, flags, now)
        if now - self._swept_at >= 1.0:
            self._swept_at = now
            self._expire(now)

    def end_file(self, now: float) -> None:
        self._expire(now)
        for sess in self.live.values():
            if sess.pkts_a + sess.pkts_b == 0:
                continue
            self.segments.append(sess.row(0))
            sess.last_segment_idx = len(self.segments) - 1
            sess.pkts_a = sess.pkts_b = 0
            sess.bytes_a = sess.bytes_b = 0
            sess.seg_fins = 0

    def finish(self) -> None:
        for sess in self.live.values():
            if sess.pkts_a + sess.pkts_b == 0:
                if sess.last_segment_idx >= 0:
                    self.segments[sess.last_segment_idx]["truncated"] = 1
                    self.open_at_end += 1
                continue
            row = sess.row(0, truncated=1)
            self.segments.append(row)
            self.open_at_end += 1
        self.live.clear()


def stitch_segments(segments: list[dict]) -> list[dict]:
    rows = sorted(segments, key=lambda r: (r["flow_key"], float(r["t_first"]), int(r["file_idx"])))
    out: list[dict] = []
    cur: dict | None = None

    def splits(prev: dict, nxt: dict) -> bool:
        if int(prev["ends_instance"]) == 1:
            return True
        gap = float(nxt["t_first"]) - float(prev["t_last"])
        limit = timeout_of(prev["proto"], bool(int(prev["established"])), bool(int(prev["closed"])))
        if gap > limit:
            return True
        return int(nxt["opens_with_syn"]) == 1 and int(prev["closed"]) == 1

    for row in rows:
        if cur is None or cur["flow_key"] != row["flow_key"] or splits(cur, row):
            if cur is not None:
                out.append(cur)
            cur = {
                "flow_key": row["flow_key"],
                "proto": row["proto"],
                "file_min": int(row["file_idx"]),
                "file_max": int(row["file_idx"]),
                "t_first": float(row["t_first"]),
                "t_last": float(row["t_last"]),
                "pkts_a": int(row["pkts_a"]),
                "pkts_b": int(row["pkts_b"]),
                "established": int(row["established"]),
                "closed": int(row["closed"]),
                "ends_instance": int(row["ends_instance"]),
                "truncated": int(row.get("truncated") or 0),
                "segments": 1,
            }
            continue
        cur["file_max"] = int(row["file_idx"])
        cur["t_last"] = float(row["t_last"])
        cur["pkts_a"] += int(row["pkts_a"])
        cur["pkts_b"] += int(row["pkts_b"])
        cur["established"] = int(int(row["established"]) or (cur["pkts_a"] > 0 and cur["pkts_b"] > 0))
        cur["closed"] = int(row["closed"])
        cur["ends_instance"] = int(row["ends_instance"])
        cur["truncated"] = int(row.get("truncated") or 0)
        cur["segments"] += 1
    if cur is not None:
        out.append(cur)
    return out


def summarise(segments: list[dict], sessions: list[dict], packets: int) -> dict:
    def bidi(row) -> bool:
        return int(row["pkts_a"]) > 0 and int(row["pkts_b"]) > 0

    tcp = [s for s in sessions if s["proto"] == "tcp"]
    tcp_long = [s for s in tcp if int(s["pkts_a"]) + int(s["pkts_b"]) >= 20]
    by_flow: dict[str, list] = {}
    for seg in segments:
        by_flow.setdefault(seg["flow_key"], []).append(seg)
    split_fixed = 0
    for sess in sessions:
        if not bidi(sess):
            continue
        parts = [
            p for p in by_flow.get(sess["flow_key"], [])
            if int(sess["file_min"]) <= int(p["file_idx"]) <= int(sess["file_max"])
            and float(sess["t_first"]) - 1e-6 <= float(p["t_first"]) <= float(sess["t_last"]) + 1e-6
        ]
        if len(parts) >= 2 and all(int(p["pkts_a"]) == 0 or int(p["pkts_b"]) == 0 for p in parts):
            split_fixed += 1
    durations = [float(s["t_last"]) - float(s["t_first"]) for s in sessions]
    crossing = [s for s in sessions if int(s["file_max"]) > int(s["file_min"])]
    return {
        "packets": packets,
        "segments": len(segments),
        "sessions": len(sessions),
        "sessions_tcp": len(tcp),
        "sessions_spanning_files": len(crossing),
        "max_files_in_session": max((int(s["file_max"]) - int(s["file_min"]) + 1 for s in sessions), default=0),
        "max_duration_s": round(max(durations, default=0.0), 3),
        "sessions_longer_than_60s": sum(d > 60 for d in durations),
        "sessions_longer_than_300s": sum(d > 300 for d in durations),
        "open_at_end": sum(int(s.get("truncated") or 0) == 1 for s in sessions),
        "bidirectional_tcp": sum(bidi(s) for s in tcp),
        "one_way_tcp": sum(not bidi(s) for s in tcp),
        "tcp_ge20": len(tcp_long),
        "tcp_ge20_one_way": sum(not bidi(s) for s in tcp_long),
        "tcp_ge20_bidirectional": sum(bidi(s) for s in tcp_long),
        "one_way_fixed_by_merging_files": split_fixed,
    }


def _self_test() -> None:
    salt = b"test-salt"
    eng = Segmenter(salt)
    eng.packet({"_file": 0, "ts": 0.0, "src": "10.0.0.1", "sport": 40000, "dst": "1.2.3.4",
                "dport": 443, "proto": "tcp", "length": 60, "flags": "S"})
    eng.packet({"_file": 0, "ts": 0.1, "src": "10.0.0.1", "sport": 40000, "dst": "1.2.3.4",
                "dport": 443, "proto": "tcp", "length": 100, "flags": "."})
    eng.end_file(0.1)
    eng.packet({"_file": 1, "ts": 30.0, "src": "1.2.3.4", "sport": 443, "dst": "10.0.0.1",
                "dport": 40000, "proto": "tcp", "length": 60, "flags": "S."})
    eng.end_file(30.0)
    eng.finish()
    sessions = stitch_segments(eng.segments)
    assert len(sessions) == 1, sessions
    assert sessions[0]["file_min"] == 0 and sessions[0]["file_max"] == 1, sessions
    assert sessions[0]["pkts_a"] > 0 and sessions[0]["pkts_b"] > 0

    quiet = Segmenter(salt)
    quiet.packet({"_file": 0, "ts": 0.0, "src": "10.0.0.2", "sport": 9, "dst": "8.8.8.8",
                  "dport": 443, "proto": "tcp", "length": 60, "flags": "S"})
    quiet.end_file(0.0)
    quiet.packet({"_file": 1, "ts": 120.0, "src": "10.0.0.2", "sport": 9, "dst": "8.8.8.8",
                  "dport": 443, "proto": "tcp", "length": 60, "flags": "."})
    quiet.end_file(120.0)
    quiet.finish()
    assert len(stitch_segments(quiet.segments)) == 2

    held = Segmenter(salt)
    held.packet({"_file": 0, "ts": 0.0, "src": "10.1.0.3", "sport": 111, "dst": "9.9.9.9",
                 "dport": 443, "proto": "tcp", "length": 60, "flags": "S"})
    held.packet({"_file": 0, "ts": 0.2, "src": "9.9.9.9", "sport": 443, "dst": "10.1.0.3",
                 "dport": 111, "proto": "tcp", "length": 60, "flags": "S."})
    held.end_file(0.2)
    held.packet({"_file": 1, "ts": 400.0, "src": "10.1.0.3", "sport": 111, "dst": "9.9.9.9",
                 "dport": 443, "proto": "tcp", "length": 80, "flags": "."})
    held.end_file(400.0)
    held.finish()
    both = stitch_segments(held.segments)
    assert len(both) == 1 and both[0]["file_max"] == 1, both
    summary = summarise(eng.segments, sessions, eng.packets)
    assert summary["one_way_fixed_by_merging_files"] == 1, summary
    print("self-test ok")


def _parse_pcap(path: Path, file_idx: int, eng: Segmenter) -> float:
    from lab_pipeline.extract_lab_features import parse_tcpdump_line
    import lab_pipeline.extract_lab_features as elf
    elf.in_scope = lambda _sport, _dport: True
    proc = subprocess.Popen(
        ["tcpdump", "-tt", "-nn", "-e", "-r", str(path)],
        stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True, bufsize=1 << 20,
    )
    last_ts = 0.0
    assert proc.stdout is not None
    try:
        for line in proc.stdout:
            rec = parse_tcpdump_line(line)
            if rec is None:
                continue
            rec["_file"] = file_idx
            last_ts = float(rec["ts"])
            eng.packet(rec)
            if eng.packets % 2_000_000 == 0:
                print(json.dumps({"packets": eng.packets, "live": len(eng.live), "file": file_idx}), flush=True)
    finally:
        proc.stdout.close()
        return_code = proc.wait()
    if return_code != 0:
        raise RuntimeError(f"tcpdump failed for {path} (exit {return_code})")
    return last_ts


def main() -> int:
    if "--self-test" in sys.argv:
        _self_test()
        return 0
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--pcap", nargs="+", type=Path, required=True)
    ap.add_argument("--salt-file", type=Path, required=True)
    ap.add_argument("--out-dir", type=Path, required=True)
    args = ap.parse_args()
    salt = args.salt_file.read_bytes().strip()
    if not salt:
        raise SystemExit("salt file is empty")
    args.out_dir.mkdir(parents=True, exist_ok=True)
    eng = Segmenter(salt)
    names = []
    for idx, pcap in enumerate(args.pcap):
        names.append(pcap.name)
        last = _parse_pcap(pcap, idx, eng)
        eng.end_file(last)
        print(json.dumps({"file_done": pcap.name, "packets": eng.packets, "live": len(eng.live)}), flush=True)
    eng.finish()
    seg_path = args.out_dir / "segments.csv.gz"
    with gzip.open(seg_path, "wt", newline="") as raw:
        writer = csv.DictWriter(raw, fieldnames=FIELDS)
        writer.writeheader()
        writer.writerows(eng.segments)
    sessions = stitch_segments(eng.segments)
    summary = summarise(eng.segments, sessions, eng.packets)
    summary["pcap_files"] = names
    summary["closed_timeout"] = eng.closed_timeout
    summary["closed_reopen"] = eng.closed_reopen
    cut = 4  # files 0..4 and 5..9, the stand-in for an hour boundary
    early = [s for s in sessions if int(s["file_max"]) <= cut]
    late_only = [s for s in sessions if int(s["file_min"]) > cut]
    crossing = [s for s in sessions if int(s["file_min"]) <= cut < int(s["file_max"])]
    summary["hour_cut_file"] = cut
    summary["sessions_ending_before_cut"] = len(early)
    summary["sessions_starting_after_cut"] = len(late_only)
    summary["sessions_crossing_cut"] = len(crossing)
    summary["sessions_check"] = len(early) + len(late_only) + len(crossing)
    (args.out_dir / "summary.json").write_text(json.dumps(summary, indent=2) + "\n")
    print(json.dumps(summary, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
