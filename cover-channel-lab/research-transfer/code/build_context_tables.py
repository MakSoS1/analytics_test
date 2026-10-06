#!/usr/bin/env python3
"""Tables around the sessions: host windows, pair history, SSH fingerprints, capture quality.

The sessions table answers "what did this connection look like". These answer
the questions one connection cannot:

  office_host_windows      one row per client host per window (5 min, 1 h, 24 h):
                           remote-access activity, how its TCP connections ended,
                           direction, payload, fan-out, and what was NEW for it
  office_pairs             one row per client-server-port-protocol pair: first and
                           last seen, sessions, volume, failures. It is also the
                           history the novelty columns are measured against, and
                           it accumulates: pass the previous one with --pairs-in
  office_ssh_fingerprints  one row per client host and SSH software fingerprint
  office_capture_quality   one row per capture interval: frames, packets, what was
                           not a flow, what was truncated or lost

Windows are tumbling and aligned: 5 min and 1 h on the clock, 24 h on Moscow
midnight. A session belongs to the window its first packet falls in. Counts
are over sessions (a long session written in parts counts once, with its final
connection state); volumes add up all parts. A window the capture only partly
covered says how much (`coverage_share`), because 10 minutes of a 24-hour
window is not a quiet day.

Novelty is "not seen before this window": from --pairs-in (earlier runs) and
from earlier windows of this run. With no history, the first window of every
host is all new -- which is true, and is why novelty needs days of data before
it means much.

  build_context_tables.py --sessions sessions.parquet --out-dir DIR \\
      [--pairs-in previous/office_pairs.parquet] [--journal consumed.jsonl ...]
"""
from __future__ import annotations

import argparse
import json
import re
from datetime import datetime, timezone
from pathlib import Path

import numpy as np
import pandas as pd

WINDOWS = (300, 3600, 86400)
MOSCOW_OFFSET = 3 * 3600          # 24 h windows start at Moscow midnight
FAILED = {"S0", "REJ", "RSTOS0", "SH"}
# Набор 1 null policy: a share or mean over no events is 0.0; NaN only where the
# value is undefined even with events (payload of a session that carried none).
RESET = {"RSTO", "RSTR", "RSTOS0", "RSTRH"}
UNCLOSED = {"S1", "OTH"}
HIGH_ENTROPY = 7.5


def window_start(t: pd.Series, seconds: int) -> pd.Series:
    offset = MOSCOW_OFFSET if seconds == 86400 else 0
    return ((t + offset) // seconds) * seconds - offset


def sessions_view(df: pd.DataFrame) -> pd.DataFrame:
    """One row per session: first part's start, the last part's state, sums."""
    df = df.sort_values(["session_uid", "segment_index"])
    g = df.groupby("session_uid", sort=False)
    first = g.head(1).set_index("session_uid")
    last = g.tail(1).set_index("session_uid")
    sums = g[["pkt_count", "up_bytes", "down_bytes", "direction_changes",
              "ra_small_up_count", "data_pkt_up", "small_data_up_bytes",
              "tcp_retx_pkts_up", "tcp_retx_pkts_down"]].sum(min_count=1)
    s = first[["host_key", "server_key", "dest_port", "proto", "session_start_epoch",
               "admin_service_by_port", "ra_off_hours", "pay_entropy_up",
               "pay_printable_up", "pay_b64_share_up", "pay_bytes_sampled_up",
               "ssh_client_fp_key"]].copy()
    s["conn_state"] = last["conn_state"]
    s = s.join(sums)
    if "seq_signed_len" in df.columns:
        # Segment-local counters omit the direction switch at a row boundary.
        def edge_sign(value, first_edge):
            if value is None or (isinstance(value, (float, np.floating)) and np.isnan(value)):
                return 0
            parts = value if isinstance(value, (list, tuple, np.ndarray)) else str(value or "").split()
            if len(parts) == 0:
                return 0
            value = int(parts[0] if first_edge else parts[-1])
            return (value > 0) - (value < 0)

        boundary = {}
        for uid, parts in g:
            prev = 0
            changes = 0
            for seq in parts.seq_signed_len:
                first_sign = edge_sign(seq, True)
                last_sign = edge_sign(seq, False)
                if prev and first_sign and prev != first_sign:
                    changes += 1
                if last_sign:
                    prev = last_sign
            boundary[uid] = changes
        s["direction_changes"] += pd.Series(boundary)
    return s.reset_index()


def volume_windows(hm: pd.DataFrame) -> pd.DataFrame:
    """G. volume per host window from the per-minute host table (host_minutes.py).

    Time-true: a minute's bytes land in the window of that minute. Rows of one
    (host, minute) split between batches are added first.
    """
    m = (hm.groupby(["host_key", "minute_epoch"], as_index=False)
         .agg(bo=("bytes_out", "sum"), bi=("bytes_in", "sum"), tp=("top_peer_bytes", "max")))
    out = []
    for seconds in WINDOWS:
        v = m.assign(window_seconds=seconds,
                     window_start_epoch=window_start(m.minute_epoch.astype(float), seconds).astype(float),
                     both=m.bo + m.bi)
        g = v.groupby(["host_key", "window_seconds", "window_start_epoch"], as_index=False).agg(
            up_bytes_total=("bo", "sum"), down_bytes_total=("bi", "sum"),
            peak_minute_bytes=("both", "max"), tp=("tp", "sum"))
        total = g.up_bytes_total + g.down_bytes_total
        g["top_peer_share"] = np.where(total > 0, g.tp / total.where(total > 0, 1), 0.0)
        out.append(g.drop(columns="tp"))
    return pd.concat(out, ignore_index=True)


def host_windows(s: pd.DataFrame, seen_pairs: dict, seen_ports: dict, seen_fp: dict,
                 t_min: float, t_max: float,
                 capture_intervals: pd.DataFrame | None = None,
                 volume: pd.DataFrame | None = None) -> pd.DataFrame:
    rows = []
    coverage_by_window = {}
    if capture_intervals is not None:
        # Preaggregate once: a week has ~30k capture intervals and potentially
        # millions of host windows. Scanning all intervals for each host would
        # turn this into a prohibitive cross product.
        for r in capture_intervals[capture_intervals.status == "ok"].itertuples():
            start, end = r.interval_start_epoch, r.interval_start_epoch + r.interval_seconds
            for span in WINDOWS:
                offset = MOSCOW_OFFSET if span == 86400 else 0
                w0 = ((start + offset) // span) * span - offset
                while w0 < end:
                    key = (span, w0)
                    coverage_by_window[key] = coverage_by_window.get(key, 0.0) + max(
                        0.0, min(w0 + span, end) - max(w0, start))
                    w0 += span
    s = s.sort_values("session_start_epoch")
    for seconds in WINDOWS:
        s = s.assign(w=window_start(s.session_start_epoch, seconds))
        for (host, w), g in s.groupby(["host_key", "w"], sort=True):
            if capture_intervals is None:
                covered = max(0.0, min(w + seconds, t_max) - max(w, t_min))
            else:
                covered = coverage_by_window.get((seconds, w), 0.0)
            tcp = g[g.proto == "tcp"]
            admin = g[g.admin_service_by_port.fillna("") != ""]
            with_pay = g[g.pay_bytes_sampled_up.fillna(0) > 0]
            n, n_tcp = len(g), len(tcp)
            pairs = set(zip(g.server_key))
            ports = set(zip(g.server_key, g.dest_port, g.proto))
            new_pairs = {p for p in pairs if seen_pairs.get((host,) + p, np.inf) >= w}
            new_ports = {p for p in ports if seen_ports.get((host,) + p, np.inf) >= w}
            fps = set(g.ssh_client_fp_key.dropna()) - {""}
            new_fp = {f for f in fps if seen_fp.get((host, f), np.inf) >= w}
            data_up = tcp.data_pkt_up.sum()
            rows.append({
                "host_key": host, "window_seconds": seconds,
                "window_start_epoch": float(w), "window_end_epoch": float(w + seconds),
                "coverage_share": round(covered / seconds, 4),
                "sessions": n, "tcp_sessions": n_tcp, "udp_sessions": int((g.proto == "udp").sum()),
                "unique_servers": g.server_key.nunique(),
                "unique_server_ports": len(ports),
                # A. remote access
                "admin_sessions": len(admin),
                "admin_keystrokes": int(admin.ra_small_up_count.sum()),
                "admin_keystroke_share": (admin.ra_small_up_count.sum() / admin.data_pkt_up.sum()
                                          if len(admin) and admin.data_pkt_up.sum() > 0 else 0.0),
                "admin_keystroke_bytes": int(admin.small_data_up_bytes.sum()),
                "admin_unique_servers": admin.server_key.nunique(),
                "admin_unique_ports": admin.dest_port.nunique(),
                "admin_off_hours_share": admin.ra_off_hours.mean() if len(admin) else 0.0,
                "admin_up_bytes_mean": admin.up_bytes.mean() if len(admin) else 0.0,
                # B. how TCP connections ended
                **{f"{name}_share": (tcp.conn_state.isin(states).mean() if n_tcp else 0.0)
                   for name, states in (("syn_no_answer", {"S0"}), ("rejected", {"REJ"}),
                                        ("reset", RESET), ("clean_close", {"SF"}),
                                        ("unclosed", UNCLOSED))},
                "failed_connections": int(tcp.conn_state.isin(FAILED).sum()),
                # C. direction
                "direction_changes_mean": g.direction_changes.mean(),
                "direction_changes_max": int(g.direction_changes.max()),
                "multi_direction_share": (g.direction_changes > 0).mean(),
                # D. payload of the client's first bytes
                "pay_entropy_up_mean": with_pay.pay_entropy_up.mean() if len(with_pay) else np.nan,
                "pay_entropy_up_max": with_pay.pay_entropy_up.max() if len(with_pay) else np.nan,
                "high_entropy_share": ((with_pay.pay_entropy_up > HIGH_ENTROPY).mean()
                                       if len(with_pay) else 0.0),
                "pay_printable_up_mean": with_pay.pay_printable_up.mean() if len(with_pay) else np.nan,
                "pay_b64_up_mean": with_pay.pay_b64_share_up.mean() if len(with_pay) else np.nan,
                # E. fan-out and scanning
                "ports_per_server": g.dest_port.nunique() / max(g.server_key.nunique(), 1),
                "short_session_share": (g.pkt_count <= 3).mean(),
                "sessions_per_second": n / covered if covered > 0 else np.nan,
                # F. novelty
                "new_servers": len(new_pairs),
                "new_server_share": len(new_pairs) / max(len(pairs), 1),
                "new_server_ports": len(new_ports),
                "new_server_port_share": len(new_ports) / max(len(ports), 1),
                "new_ssh_fingerprints": len(new_fp),
                # retransmissions
                "tcp_retx_share": (tcp.tcp_retx_pkts_up.sum() / data_up
                                   if n_tcp and data_up > 0 else np.nan),
                "_covered": covered,
            })
    win = pd.DataFrame(rows)
    # G. volume: a burst is itself something to model, not something to filter
    # out -- counted per minute from the packets, not per session.
    if volume is not None and len(volume):
        win = win.merge(volume, on=["host_key", "window_seconds", "window_start_epoch"], how="left")
    else:
        for c in ("up_bytes_total", "down_bytes_total", "peak_minute_bytes", "top_peer_share"):
            win[c] = np.nan
    total = win.up_bytes_total + win.down_bytes_total
    win["bytes_per_second"] = np.where(win._covered > 0, total / win._covered.where(win._covered > 0, 1), np.nan)
    return win.drop(columns="_covered")


def pairs_table(s: pd.DataFrame, previous: pd.DataFrame | None) -> pd.DataFrame:
    key = ["host_key", "server_key", "dest_port", "proto"]
    cur = s.groupby(key, dropna=False).agg(
        first_seen_epoch=("session_start_epoch", "min"),
        last_seen_epoch=("session_start_epoch", "max"),
        sessions=("session_uid", "count"),
        up_bytes=("up_bytes", "sum"), down_bytes=("down_bytes", "sum"),
        failed_sessions=("conn_state", lambda x: int(x.isin(FAILED).sum())),
        admin_service_by_port=("admin_service_by_port", "first"),
    ).reset_index()
    if previous is None or previous.empty:
        return cur
    overlap = cur.merge(previous[key + ["last_seen_epoch"]], on=key, how="inner",
                        suffixes=("", "_previous"))
    if (overlap.first_seen_epoch <= overlap.last_seen_epoch_previous).any():
        raise ValueError("pair history overlap: input includes sessions already summarized in --pairs-in")
    both = pd.concat([previous[cur.columns], cur])
    return both.groupby(key, dropna=False).agg(
        first_seen_epoch=("first_seen_epoch", "min"), last_seen_epoch=("last_seen_epoch", "max"),
        sessions=("sessions", "sum"), up_bytes=("up_bytes", "sum"), down_bytes=("down_bytes", "sum"),
        failed_sessions=("failed_sessions", "sum"),
        admin_service_by_port=("admin_service_by_port", "first")).reset_index()


def capture_quality(journals: list[Path], rotate: int,
                    expected_start: float | None = None,
                    expected_end: float | None = None,
                    reference_journals: list[Path] | None = None) -> pd.DataFrame:
    rows = []
    for j in journals:
        for line in j.read_text().splitlines():
            if not line.strip():
                continue
            e = json.loads(line)
            m = re.search(r"(\d{8}T\d{6})Z", e.get("pcap", "") or e.get("rows_file", ""))
            t = datetime.strptime(m.group(1), "%Y%m%dT%H%M%S").replace(tzinfo=timezone.utc).timestamp()
            nonflow = e.get("nonflow", {}) or {}
            rows.append({"interval_start_epoch": t, "status": e.get("status", ""),
                         "error": e.get("error", "") or "",
                         "frames": e.get("frames"), "flow_packets": e.get("packets"),
                         "truncated_frames": e.get("truncated"),
                         "non_ip_frames": nonflow.get("non_ip"), "ip_fragments": nonflow.get("ip_fragment"),
                         "other_l4_frames": nonflow.get("other_l4"),
                         "bad_header_frames": (nonflow.get("short_header") or 0) + (nonflow.get("bad_tcp_header") or 0),
                         "pcap_bytes": e.get("pcap_bytes"), "convert_seconds": e.get("seconds")})
    q = pd.DataFrame(rows)
    if q.empty:
        q = pd.DataFrame(columns=["interval_start_epoch", "status"])
    else:
        # An interval converted again after a failure appears twice: keep the success.
        q = (q.assign(_ok=(q.status == "ok").astype(int))
             .sort_values(["interval_start_epoch", "_ok"], ascending=[True, False], kind="stable")
             .drop_duplicates("interval_start_epoch").drop(columns="_ok"))
    # Intervals the series skips were never captured or converted: named rows.
    if len(q) or (expected_start is not None and expected_end is not None):
        start = expected_start if expected_start is not None else q.interval_start_epoch.min()
        end = expected_end if expected_end is not None else q.interval_start_epoch.max() + rotate
        full = np.arange(start, end, rotate)
        missing = sorted(set(full) - set(q.interval_start_epoch))
        if missing:
            preserved_elsewhere = set()
            if reference_journals:
                for ref in reference_journals:
                    for line in ref.read_text().splitlines():
                        if not line.strip():
                            continue
                        e = json.loads(line)
                        if e.get("status") == "ok":
                            m = re.search(r"(\d{8}T\d{6})Z", e.get("pcap", "") or e.get("rows_file", ""))
                            if m:
                                preserved_elsewhere.add(datetime.strptime(m.group(1), "%Y%m%dT%H%M%S")
                                                        .replace(tzinfo=timezone.utc).timestamp())
            q = pd.concat([q, pd.DataFrame({"interval_start_epoch": missing,
                                            "status": ["not_preserved" if t in preserved_elsewhere
                                                       else "missing" for t in missing]})])
    q["interval_seconds"] = rotate
    return q.sort_values("interval_start_epoch").reset_index(drop=True)


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--sessions", required=True, type=Path)
    ap.add_argument("--out-dir", required=True, type=Path)
    ap.add_argument("--pairs-in", type=Path)
    ap.add_argument("--fingerprints-in", type=Path)
    ap.add_argument("--journal", type=Path, nargs="*", default=[])
    ap.add_argument("--host-minutes", type=Path, nargs="*", default=[],
                    help="host_minutes.py CSV/parquet files: time-true volume per window")
    ap.add_argument("--rotate-seconds", type=int, default=20)
    ap.add_argument("--expected-start", type=float, help="first expected interval epoch")
    ap.add_argument("--expected-end", type=float, help="exclusive end of expected intervals")
    ap.add_argument("--reference-journal", type=Path, nargs="*", default=[],
                    help="full capture journal; labels converted intervals whose pcap was not preserved")
    args = ap.parse_args()
    args.out_dir.mkdir(parents=True, exist_ok=True)

    df = pd.read_parquet(args.sessions)
    s = sessions_view(df)
    t_min = df.session_start_epoch.min()
    t_max = (df.session_start_epoch + df.flow_duration).max()

    prev_pairs = pd.read_parquet(args.pairs_in) if args.pairs_in and args.pairs_in.exists() else None
    prev_fp = (pd.read_parquet(args.fingerprints_in)
               if args.fingerprints_in and args.fingerprints_in.exists() else None)
    pairs = pairs_table(s, prev_pairs)
    q = (capture_quality(args.journal, args.rotate_seconds, args.expected_start, args.expected_end,
                         args.reference_journal)
         if args.journal else None)
    # "Seen before" = first seen in earlier runs or earlier in this one.
    seen_pairs = {}
    for r in pairs.itertuples(index=False):
        k = (r.host_key, r.server_key)
        seen_pairs[k] = min(seen_pairs.get(k, np.inf), r.first_seen_epoch)
    seen_ports = {(r.host_key, r.server_key, r.dest_port, r.proto): r.first_seen_epoch
                  for r in pairs.itertuples(index=False)}
    fp = (s[s.ssh_client_fp_key.fillna("") != ""]
          .groupby(["host_key", "ssh_client_fp_key"])
          .agg(first_seen_epoch=("session_start_epoch", "min"), sessions=("session_uid", "count"))
          .reset_index())
    if prev_fp is not None and not prev_fp.empty:
        fp = (pd.concat([prev_fp[fp.columns], fp]).groupby(["host_key", "ssh_client_fp_key"])
              .agg(first_seen_epoch=("first_seen_epoch", "min"), sessions=("sessions", "sum")).reset_index())
    seen_fp = {(r.host_key, r.ssh_client_fp_key): r.first_seen_epoch for r in fp.itertuples(index=False)}

    volume = None
    if args.host_minutes:
        hm = pd.concat([pd.read_parquet(f) if f.suffix == ".parquet" else pd.read_csv(f)
                        for f in args.host_minutes], ignore_index=True)
        volume = volume_windows(hm)
    win = host_windows(s, seen_pairs, seen_ports, seen_fp, t_min, t_max, q, volume)
    report = {"sessions": len(s), "rows": len(df)}
    for name, table in (("office_host_windows", win), ("office_pairs", pairs),
                        ("office_ssh_fingerprints", fp)):
        table.to_parquet(args.out_dir / f"{name}.parquet", compression="zstd", index=False)
        report[name] = len(table)
    if q is not None:
        q.to_parquet(args.out_dir / "office_capture_quality.parquet", compression="zstd", index=False)
        report["office_capture_quality"] = len(q)
    print(json.dumps(report))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
