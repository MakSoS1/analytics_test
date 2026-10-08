#!/usr/bin/env python3
"""Join the two passes and emit the tables that leave this host.

  sessions        one row per session SEGMENT (`segment_uid` unique,
                  `session_uid` shared by the segments of one instance): the 112 corpus features over the
                  whole session, the sequence block to --seq-ext, `cc_*`/`ra_*`
                  behavioural features and the payload block.
  lots_conns      one row per connection in the canonical shape
                  `lots_ngfw/features.py` reads (ts, duration, bytes_up,
                  bytes_down, host, service, dst, ja3, ja4, has_sni), so the
                  1200/600 window grid and the 12 contract features are computed
                  by the LoTS code itself rather than reimplemented here.

`service` follows the LoTS rule `sni or dest_ip`, with both sides hashed.
ja3/ja4 are written empty on purpose: the contract excludes them, and records
that office logs cannot supply were shown there to hand a tree a fake, perfect
separation.

A connection whose segments fall into different batches is written once, by
the batch its last segment is in: the batch that sees an unfinished one hands it
on through `--conns-carry-out`, and the next takes it in with `--conns-carry-in`.

Bytes in lots_conns are IP bytes, header-inclusive, as the contract requires --
NOT the L2 frame bytes the session table carries in `total_bytes`.
"""
from __future__ import annotations

import argparse
import csv
import json
import sys
from pathlib import Path

csv.field_size_limit(1 << 24)


# Facts about a whole session, seen once in its first packets: they belong to
# every row of it. A long session is written in several rows, and without this
# only the first would say it was TLS to a named site; the rest would read as
# sessions that never shook hands.
NOT_IN_SESSIONS = {"bytes_up_ip", "bytes_down_ip", "tls_has_sni", "tls_ja4_present"}
SESSION_FACTS = ["service_key", "tls_has_sni", "tls_sni_len", "tls_ja4_present",
                 "tls_ja4s_present", "tls_ja4_unique", "tls_version", "tls_cipher_count",
                 "tls_ext_count", "tls_group_count", "tls_sigalg_count", "tls_alpn_h2",
                 "tls_alpn_h3", "tls_alpn_http11", "tls_alpn_other", "tls_resumed",
                 "tls_early_data", "ssh_client_software", "ssh_server_software",
                 "ssh_client_fp_key", "ssh_server_fp_key"]


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--sessions", required=True, nargs="+",
                    help="one file, or one per shard of the session pass")
    ap.add_argument("--payload", required=True)
    ap.add_argument("--lots-conns-in", required=True, nargs="+")
    ap.add_argument("--out-sessions", required=True)
    ap.add_argument("--out-lots-conns", required=True)
    ap.add_argument("--stats-json", default="")
    ap.add_argument("--facts-carry-in", help="session facts of long sessions still open")
    ap.add_argument("--facts-carry-out", help="where to write them for the next batch")
    ap.add_argument("--conns-carry-in", help="unfinished connections of earlier batches")
    ap.add_argument("--conns-carry-out",
                    help="write connections still open at the end of this batch here "
                         "instead of into lots_conns")
    args = ap.parse_args()

    pay: dict[str, dict] = {}
    with open(args.payload) as fh:
        reader = csv.DictReader(fh)
        pay_cols = [c for c in reader.fieldnames if c != "segment_uid"]
        # Read, but not written to the sessions: IP bytes are the frame bytes
        # the session already has minus link headers (the LoTS connections
        # still take them), and the two flags are `> 0` of a count beside them.
        out_pay_cols = [c for c in pay_cols if c not in NOT_IN_SESSIONS]
        for r in reader:
            pay[r["segment_uid"]] = r

    # A session no payload record reached was not measured, not measured as
    # zero: "0 TLS handshakes, 0 DNS queries" would be a claim about it. The
    # columns stay empty and `payload_matched` says why.
    zero = {c: "" for c in pay_cols}

    # Session facts from each session's first row, here or carried in.
    facts: dict[str, dict] = {}
    if args.facts_carry_in and Path(args.facts_carry_in).exists():
        facts.update(json.loads(Path(args.facts_carry_in).read_text()))
    carried_facts = set(facts)
    fact_cols = [c for c in SESSION_FACTS if c in pay_cols]
    for uid, r in pay.items():
        session, _, index = uid.rpartition(".")
        if index == "0" and (r.get("tls_version") not in ("", "0", None)
                             or r.get("service_key") or r.get("ssh_client_software")
                             or r.get("ssh_server_software")):
            facts[session] = {c: r[c] for c in fact_cols}
    continuing: set[str] = set()
    filled = 0
    matched = missing = 0

    def session_rows():
        header = None
        for path in args.sessions:
            with open(path) as sfh:
                sr = csv.DictReader(sfh)
                if header is None:
                    header = sr.fieldnames
                    yield header
                elif sr.fieldnames != header:
                    raise SystemExit(f"{path}: columns differ from {args.sessions[0]}")
                yield from sr

    rows_in = session_rows()
    with open(args.out_sessions, "w", newline="", encoding="utf-8") as ofh:
        cols = list(next(rows_in)) + out_pay_cols + ["payload_matched"]
        w = csv.DictWriter(ofh, fieldnames=cols, extrasaction="ignore")
        w.writeheader()
        svc = {}
        finished: set[str] = set()
        for row in rows_in:
            if row.get("session_continues") == "1":
                continuing.add(row["session_uid"])
            # The last segment of a session says it does not continue; without
            # the column (older tables) every segment is taken as the last.
            if row.get("session_continues", "0") in ("0", ""):
                finished.add(row["session_uid"])
            p = pay.get(row["segment_uid"])
            if p is None:
                missing += 1
                row.update(zero)
                row["payload_matched"] = 0
            else:
                matched += 1
                for c in pay_cols:
                    row[c] = p[c]
                row["payload_matched"] = 1
                if row.get("segment_index", "0") != "0" and row["session_uid"] in facts:
                    row.update(facts[row["session_uid"]])
                    filled += 1
                svc[row["segment_uid"]] = (p["service_key"], p["bytes_up_ip"], p["bytes_down_ip"])
            w.writerow(row)

    lots_cols = ["ts", "duration", "bytes_up", "bytes_down", "host", "service",
                 "dst", "ja3", "ja4", "has_sni"]
    # The LoTS contract counts CONNECTIONS, so the segments a long session was
    # cut into have to be put back together first. Writing them straight through
    # would make one long connection look like several in the 1200/600 grid and
    # inflate every count feature it feeds.
    merged: dict[str, dict] = {}
    order: list[str] = []
    dropped = segments_read = 0
    carried_in = 0
    if args.conns_carry_in:
        for conn in json.loads(Path(args.conns_carry_in).read_text()):
            uid = conn.pop("session_uid")
            merged[uid] = conn
            order.append(uid)
            carried_in += 1
    def lots_rows():
        for path in args.lots_conns_in:
            with open(path) as lfh:
                yield from csv.DictReader(lfh)

    for r in lots_rows():
        s = svc.get(r["segment_uid"])
        if s is None:
            dropped += 1
            continue
        service_key, up_ip, down_ip = s
        segments_read += 1
        uid = r["session_uid"]
        ts, dur = float(r["ts"]), float(r["duration"] or 0.0)
        conn = merged.get(uid)
        if conn is None:
            order.append(uid)
            merged[uid] = {
                "ts": ts, "end": ts + dur,
                "bytes_up": int(up_ip), "bytes_down": int(down_ip),
                "host": r["host"], "dst": r["dst"], "service": service_key,
            }
            continue
        conn["ts"] = min(conn["ts"], ts)
        conn["end"] = max(conn["end"], ts + dur)
        conn["bytes_up"] += int(up_ip)
        conn["bytes_down"] += int(down_ip)
        # The SNI is in the handshake, so only the first segment can carry
        # it; a later segment must not blank it.
        conn["service"] = conn["service"] or service_key

    kept = 0
    still_open = []
    with open(args.out_lots_conns, "w", newline="", encoding="utf-8") as ofh:
        w = csv.DictWriter(ofh, fieldnames=lots_cols)
        w.writeheader()
        for uid in order:
            conn = merged[uid]
            if args.conns_carry_out and uid not in finished:
                still_open.append({"session_uid": uid, **conn})
                continue
            w.writerow({
                "ts": round(conn["ts"], 6),
                "duration": round(conn["end"] - conn["ts"], 6),
                "bytes_up": conn["bytes_up"],
                "bytes_down": conn["bytes_down"],
                "host": conn["host"],
                # LoTS rule: the service is the SNI, or the destination when
                # there is none.  Both are already salted hashes here.
                "service": conn["service"] or conn["dst"],
                "dst": conn["dst"],
                "ja3": "",
                "ja4": "",
                "has_sni": int(bool(conn["service"])),
            })
            kept += 1
    if args.conns_carry_out:
        Path(args.conns_carry_out).write_text(json.dumps(still_open))
    if args.facts_carry_out:
        # Kept while the session is open: it continued in this batch, or it
        # came in open and wrote no row here at all.
        keep = (continuing | carried_facts) - finished
        Path(args.facts_carry_out).write_text(json.dumps(
            {s: facts[s] for s in keep if s in facts}))

    report = {
        "status": "ok",
        "sessions_out": args.out_sessions,
        "lots_conns_out": args.out_lots_conns,
        "sessions_with_payload": matched,
        "sessions_without_payload": missing,
        "payload_join_rate": round(matched / max(matched + missing, 1), 4),
        "lots_conns_written": kept,
        "lots_conns_segments_merged": segments_read + carried_in - kept - len(still_open),
        "lots_conns_carried_in": carried_in,
        "continuation_rows_given_session_facts": filled,
        "lots_conns_carried_out": len(still_open) if args.conns_carry_out else None,
        "lots_conns_dropped_no_payload": dropped,
        "note": "lots_conns bytes are IP bytes per the LoTS contract; sessions.total_bytes stays L2",
    }
    print(json.dumps(report))
    if args.stats_json:
        Path(args.stats_json).write_text(json.dumps(report, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
