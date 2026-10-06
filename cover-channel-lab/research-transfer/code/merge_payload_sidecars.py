#!/usr/bin/env python3
"""Join the minute payload sidecars onto the sessions the packet rows built.

This is the second half of what used to be `extract_payload_features.py`. That
one re-read the pcap; there is no pcap once the capture is long enough to need
this path, so the payload facts were already collected on the sensor, per flow
per minute, and this step only has to put them on the right session.

It does NOT re-derive session identity. The session pass wrote a private index
of (flow, time span, segment_uid, client endpoint), and every sidecar record is
matched against it. Two rules, because a flow can appear in several minutes and
a 4-tuple can be reused:

* **Byte counts add up across every overlapping minute.** They are sums, and a
  session that ran for an hour has a record in each of its sixty minutes.
* **Payload shape comes from the earliest overlapping minute only.** The
  feature is "the first packets of this session", so later minutes must not
  dilute it -- and the session's first packets are in the minute it started.

Where a minute overlaps more than one instance of the same flow, the record
goes to the earliest of them (see below why not the one it overlaps most), and
`ambiguous_minutes` counts it rather than leaving the choice invisible.

**Records of sessions still open are carried, not their files.** A session
carried across a batch boundary on the checkpoint can close in the next batch
without a single packet in it -- it simply idles out -- and every payload
record it has belongs to the batch before. Pointing the merge at one hour's
sidecars left 7036 such sessions of 530277 with no payload at all. Keeping all
earlier sidecars instead is no answer for a month: one tunnel open since the
first hour would pin every file since. So in batch mode (`--pending-out`) a
record that no written row can take yet, but whose flow is still open
(`--live`, from the session pass) at or before its end, is handed to the next
batch; one whose flow is closed can never be taken and is let go. Every record
is then read exactly once, and the batch's sidecar files can be deleted.

**A record goes to the EARLIEST span of its flow it touches.** Spans of one flow
are written in time order and never overlap -- a segment is cut before the next
one opens, a new instance only after the old one was emitted -- so the earliest
span a record touches is already written when the record is first read, and
the answer is the same however the capture is cut into batches. The span it
overlaps most is not: that one may not be written yet.

The output is the same table `finalize_tables.py` already reads, so nothing
downstream can tell which of the two paths produced it -- which is the point.
"""
from __future__ import annotations

import argparse
import csv
from datetime import datetime, timezone
import json
import os
import pickle
import re
import sys
import time
from collections import Counter
from pathlib import Path

# Одна ячейка держит всю последовательность пакетов сессии, поэтому
# стандартный лимит поля в 128 КиБ пробивается на первой же длинной сессии.
csv.field_size_limit(1 << 24)

sys.path.insert(0, str(Path(__file__).resolve().parent))
import payload_sidecar as ps  # noqa: E402
from payload_sidecar import (  # noqa: E402
    _B64, _PRINT, entropy_from_hist, label_entropy, read_sidecar, share_from_hist,
)

PAY_NAMES = [
    "bytes_up_ip", "bytes_down_ip",
    "pay_entropy_up", "pay_entropy_down", "pay_printable_up",
    "pay_printable_down", "pay_null_share_up", "pay_b64_share_up",
    "pay_bytes_sampled_up", "pay_bytes_sampled_down",
    "dns_qname_len_mean", "dns_qname_len_max", "dns_label_entropy",
    "dns_query_count", "tls_has_sni", "tls_sni_len",
    # TLS handshake shape. The fingerprints themselves never appear: only
    # whether one was seen and how many distinct ones. `ja4_hash_int` is on the
    # repository's leakage list because the value names the client software,
    # and naming the software is one step from naming the label.
    "tls_ja4_present", "tls_ja4s_present", "tls_ja4_unique",
    "tls_version", "tls_cipher_count", "tls_ext_count",
    "tls_group_count", "tls_sigalg_count",
    "tls_alpn_h2", "tls_alpn_h3", "tls_alpn_http11", "tls_alpn_other",
    "tls_resumed", "tls_early_data",
    # QUIC. Connection-ID churn is what connection migration looks like from
    # outside, and a tunnel hiding in QUIC does a lot of it.
    "quic_datagrams", "quic_datagram_bytes", "quic_cid_changes",
    # DNS question types. TXT is the classic carrier for a DNS tunnel.
    "dns_qtype_a", "dns_qtype_aaaa", "dns_qtype_txt",
    "dns_qtype_null", "dns_qtype_other",
    # Какой версией сайдкара снята строка. У версии 1 полей TLS/QUIC/типов DNS
    # не было: там они пустые, а не нулевые. Ноль означал бы «рукопожатия не
    # было», и модель научилась бы отличать один захват от другого.
    "payload_schema_version",
    # CAPWAP: туннель Wi-Fi между точкой доступа и контроллером. С версии 3
    # помечается по самому заголовку CAPWAP; для старых — по портам 5246/5247
    # (на проверочном захвате порты совпали с tshark на все 256 074 пакета).
    "is_capwap_tunnel", "capwap_packets",
    # v4. TCP segments that repeated bytes already sent, and those bytes, by
    # direction (keep-alive probes excluded). Counted per 20-s capture file, so
    # the first segment of a flow in each file is never judged a repeat.
    "tcp_retx_pkts_up", "tcp_retx_pkts_down", "tcp_retx_bytes_up", "tcp_retx_bytes_down",
    # v4. SSH: software family from each side's identification string, and a
    # salted fingerprint of each side's KEXINIT (the HASSH idea). They name the
    # software -- fine for remote-access work, off-limits for the VPN model.
    "ssh_client_software", "ssh_server_software", "ssh_client_fp_key", "ssh_server_fp_key",
]
_V4_ONLY = PAY_NAMES[PAY_NAMES.index("tcp_retx_pkts_up"):]

CAPWAP_PORTS = {5246, 5247}
# До версии 3 QUIC не расшифровывался: у UDP-сессий TLS-полей тогда просто не
# измеряли, и ноль в них означал бы «рукопожатия не было».
_TLS_COLUMNS = [c for c in PAY_NAMES if c.startswith("tls_")]

# Колонки, которых в сайдкаре версии 1 не существовало.
_V2_ONLY = [
    "tls_ja4_present", "tls_ja4s_present", "tls_ja4_unique",
    "tls_version", "tls_cipher_count", "tls_ext_count",
    "tls_group_count", "tls_sigalg_count",
    "tls_alpn_h2", "tls_alpn_h3", "tls_alpn_http11", "tls_alpn_other",
    "tls_resumed", "tls_early_data",
    "quic_datagrams", "quic_datagram_bytes", "quic_cid_changes",
    "dns_qtype_a", "dns_qtype_aaaa", "dns_qtype_txt",
    "dns_qtype_null", "dns_qtype_other",
]

# Версия 2 хранила только первую и последнюю букву ALPN (код JA4): «h2», «h3»,
# «h1» для http/1.1. Это неоднозначно («h3-alias-02» тоже даёт «h2»), поэтому с
# версии 3 категорию считает сайдкар по полному имени, а эта таблица осталась
# только для старых файлов.
_ALPN_KNOWN = {"h2": "tls_alpn_h2", "h3": "tls_alpn_h3", "h1": "tls_alpn_http11"}
_ALPN_BY_CATEGORY = {1: "tls_alpn_h2", 2: "tls_alpn_h3", 3: "tls_alpn_http11",
                     4: "tls_alpn_other"}
_QTYPE_COLUMN = {1: "dns_qtype_a", 28: "dns_qtype_aaaa",
                 16: "dns_qtype_txt", 10: "dns_qtype_null"}


class Acc:
    # The byte histograms of the shape record are reduced to the numbers the
    # table needs as soon as they are taken, and the per-session containers
    # are created only when something goes into them: at a million sessions
    # per batch, holding the raw histograms cost ~6 KB a session and ran a
    # 15 GB host out of memory.
    __slots__ = ("ip_up", "ip_down", "shape", "n_up", "n_down",
                 "shape_ts", "service_key", "sni_len", "dns_q", "dns_len_sum",
                 "dns_len_max", "dns_labels", "dns_qtypes", "ja4_keys",
                 "ja4s_keys", "tls_flags", "tls_version", "cipher_count",
                 "ext_count", "group_count", "sigalg_count", "alpn",
                 "quic_datagrams", "quic_datagram_bytes", "quic_cids",
                 "schema_version", "pkts", "capwap_pkts", "proto", "capwap_port",
                 "alpn_category", "retx", "ssh_sw", "ssh_fp")

    def __init__(self):
        self.ip_up = self.ip_down = 0
        self.shape = _EMPTY_SHAPE
        self.n_up = self.n_down = 0
        self.shape_ts = None
        self.service_key = ""
        self.sni_len = 0
        self.dns_q = self.dns_len_sum = self.dns_len_max = 0
        self.dns_labels: Counter | None = None
        self.dns_qtypes: Counter | None = None
        self.ja4_keys: set | None = None
        self.ja4s_keys: set | None = None
        self.tls_flags = 0
        self.tls_version = 0
        self.cipher_count = self.ext_count = 0
        self.group_count = self.sigalg_count = 0
        self.alpn = ""
        self.quic_datagrams = self.quic_datagram_bytes = self.quic_cids = 0
        self.schema_version = 0
        self.pkts = self.capwap_pkts = 0
        self.proto = 0
        self.capwap_port = False
        self.alpn_category = None
        self.retx = [0, 0, 0, 0]          # pkts up, pkts down, bytes up, bytes down
        self.ssh_sw = [0, 0]              # client, server
        self.ssh_fp = ["", ""]


def shape_of(up, down) -> tuple:
    """What the table says about the first payload bytes, from their histograms."""
    return (round(entropy_from_hist(up), 6), round(entropy_from_hist(down), 6),
            round(share_from_hist(up, _PRINT), 6), round(share_from_hist(down, _PRINT), 6),
            round(share_from_hist(up, {0}), 6), round(share_from_hist(up, _B64), 6),
            sum(up.values()), sum(down.values()))


_EMPTY_SHAPE = shape_of(Counter(), Counter())


# What a record counts rather than describes, and so what can be shared out
# between two rows of one long session when a row boundary falls inside it.
_ADDITIVE = ("ip_a2b", "ip_b2a", "bytes_a2b", "bytes_b2a", "quic_datagrams",
             "quic_datagram_bytes", "pkts", "capwap_pkts",
             "retx_pkts_a2b", "retx_pkts_b2a", "retx_bytes_a2b", "retx_bytes_b2a")


def split_record(rec: dict, cut: float) -> tuple[dict, dict]:
    """The part of a record up to `cut` and the part after it.

    A long session is written in numbered rows (segments) so that it never has
    to be held whole, and a sidecar record covers one capture interval, so a
    row boundary can fall inside a record. Giving the whole record to the
    earlier row credited it with bytes it never carried and left a short later
    row with none at all. The counts are shared by time instead -- in whole
    numbers, so the two parts always add up to the record. What the record
    describes once (the handshake, the first payload bytes, DNS names) stays
    with the earlier part, where it happened.
    """
    dur = rec["last_ts"] - rec["first_ts"]
    share = min(max((cut - rec["first_ts"]) / dur, 0.0), 1.0) if dur > 0 else 1.0
    head, tail = dict(rec), dict(rec)
    for k in _ADDITIVE:
        v = rec.get(k)
        if v is None:
            continue
        head[k] = int(round(v * share))
        tail[k] = v - head[k]
    head["last_ts"] = min(rec["last_ts"], cut)
    tail["first_ts"] = cut + 1e-6
    empty = Counter()
    tail.update(hist_a2b=empty, hist_b2a=empty, n_a2b=0, n_b2a=0, dns_q=0, dns_len_sum=0,
                dns_len_max=0, dns_labels=Counter(), dns_qtypes=Counter(), ja4_key="",
                ja4s_key="", tls_flags=0, tls_version=0, sni_len=0, service_key="",
                quic_cids=0)
    if rec.get("ssh_sw_a2b") is not None:
        tail.update(ssh_sw_a2b=0, ssh_sw_b2a=0, hassh_a2b="", hassh_b2a="")
    return head, tail


def _stamp_epoch(name: str) -> float | None:
    """Epoch of `chunk-YYYYmmddTHHMMSSZ.pay`, or None if it is named otherwise."""
    match = re.search(r"(\d{8}T\d{6})Z", name)
    if not match:
        return None
    return datetime.strptime(match.group(1), "%Y%m%dT%H%M%S").replace(
        tzinfo=timezone.utc).timestamp()


_PROTO_NUMBER = {"tcp": 6, "udp": 17}
def load_index(path: Path):
    """flow -> sorted [(t_start, t_end, segment_uid, client endpoint)]."""
    index: dict[tuple, list] = {}
    with path.open(newline="") as fh:
        for r in csv.DictReader(fh):
            # The protocol is part of the flow: TCP and UDP on the same four
            # numbers are two sessions that may well run at the same time.
            key = (r["ip_a"], int(r["port_a"]), r["ip_b"], int(r["port_b"]),
                   _PROTO_NUMBER.get(r.get("proto", ""), 0))
            index.setdefault(key, []).append((
                float(r["t_start"]), float(r["t_end"]), r["segment_uid"],
                (r["client_ip"], int(r["client_port"])),
            ))
    for spans in index.values():
        spans.sort(key=lambda sp: (sp[0], sp[1]))
    return index


def read_pending(path: Path):
    """Records an earlier batch handed on, one at a time.

    The file is a stream of pickled records. A long-lived flow (a CAPWAP
    tunnel) never closes, so its records wait batch after batch: 978444 of them
    took 10.7 GB as one list and the next batch's merge was killed for memory.
    A file written as one list by the old code is still read, and released
    record by record as it goes."""
    # A private file this program wrote, never a network input.
    with path.open("rb") as fh:
        while True:
            try:
                obj = pickle.load(fh)
            except EOFError:
                return
            if isinstance(obj, list):
                obj.reverse()
                while obj:
                    yield obj.pop()
            else:
                yield obj


def pick_span(spans, first_ts, last_ts):
    """The earliest span this record touches, and how many spans it touched."""
    best, contested = None, 0
    for span in spans:
        # A zero-length overlap is still a real touch: a one-packet session has
        # t_start == t_end, and refusing it would drop the session's payload.
        if min(last_ts, span[1]) - max(first_ts, span[0]) < 0:
            continue
        contested += 1
        if best is None:
            best = span
    return best, contested


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--sidecar-dir", type=Path, required=True,
                    help="every sidecar of the capture, not just this batch's")
    ap.add_argument("--glob", default="*.pay")
    ap.add_argument("--interval-seconds", type=float, default=60.0,
                    help="the capture's rotation period, used to skip whole files")
    ap.add_argument("--session-index", type=Path, required=True, nargs="+",
                    help="one file, or one per shard of the session pass")
    ap.add_argument("--out-csv", type=Path, required=True)
    ap.add_argument("--stats-json", default="")
    ap.add_argument("--pending-in", type=Path,
                    help="records an earlier batch could not place yet")
    ap.add_argument("--pending-out", type=Path,
                    help="batch mode: write the records still waiting for an open flow here")
    ap.add_argument("--live", type=Path, nargs="+",
                    help="flows still open after this batch (extract_office_sessions --live-out)")
    args = ap.parse_args()
    batch_mode = args.pending_out is not None
    if batch_mode and args.live is None:
        ap.error("--pending-out needs --live")

    index: dict[tuple, list] = {}
    for path in args.session_index:
        for key, spans in load_index(path).items():
            index.setdefault(key, []).extend(spans)
    for spans in index.values():
        spans.sort(key=lambda sp: (sp[0], sp[1]))
    live: dict[tuple, float] = {}
    for path in args.live or []:
        with path.open(newline="") as fh:
            for r in csv.DictReader(fh):
                live[(r["ip_a"], int(r["port_a"]), r["ip_b"], int(r["port_b"]),
                      _PROTO_NUMBER.get(r["proto"], 0))] = float(r["seg_start"])
    acc: dict[str, Acc] = {}
    matched = unmatched = ambiguous = records = starved = 0
    # Waiting records go straight to disk: holding them in a list (and the
    # pickler's memo over it) is what ran the machine out of memory.
    pending = 0
    pending_tmp = pending_fh = None
    if batch_mode:
        pending_tmp = args.pending_out.with_name(args.pending_out.name + ".tmp")
        pending_fh = pending_tmp.open("wb")
        os.chmod(pending_tmp, 0o600)
    split_records = 0
    t0 = time.time()
    files = sorted(args.sidecar_dir.glob(args.glob))
    if not files and not batch_mode:
        print(json.dumps({"status": "error", "reason": f"no {args.glob} sidecars"}))
        return 1

    spans_all = [sp for spans in index.values() for sp in spans]
    if not spans_all and not batch_mode:
        print(json.dumps({"status": "error", "reason": "empty session index"}))
        return 1
    skipped = 0
    if not batch_mode:
        # The sessions span a known stretch of time. A sidecar file covers one
        # rotation interval starting at the stamp in its name, so one outside
        # that stretch cannot hold a record for any of them. (In batch mode
        # every file is read: its records may belong to flows still open.)
        earliest = min(sp[0] for sp in spans_all)
        latest = max(sp[1] for sp in spans_all)
        kept = []
        for path in files:
            stamp = _stamp_epoch(path.name)
            if stamp is not None and (stamp > latest or stamp + args.interval_seconds < earliest):
                skipped += 1
                continue
            kept.append(path)
        files = kept

    def all_records():
        if args.pending_in is not None and args.pending_in.exists():
            yield from read_pending(args.pending_in)
        for path in files:
            yield from read_sidecar(path)

    def apply(rec, span):
        a, b = rec["a"], rec["b"]
        uid, client = span[2], span[3]
        ac = acc.get(uid)
        if ac is None:
            ac = acc[uid] = Acc()
        # `a2b` is canonical, `up` is client-to-server; only the session
        # pass knows which endpoint opened the connection.
        client_is_a = client == a
        ac.ip_up += rec["ip_a2b"] if client_is_a else rec["ip_b2a"]
        ac.ip_down += rec["ip_b2a"] if client_is_a else rec["ip_a2b"]
        ac.dns_q += rec["dns_q"]
        ac.dns_len_sum += rec["dns_len_sum"]
        ac.dns_len_max = max(ac.dns_len_max, rec["dns_len_max"])
        if rec["dns_labels"]:
            if ac.dns_labels is None:
                ac.dns_labels = Counter()
            ac.dns_labels.update(rec["dns_labels"])
        if rec["dns_qtypes"]:
            if ac.dns_qtypes is None:
                ac.dns_qtypes = Counter()
            ac.dns_qtypes.update(rec["dns_qtypes"])
        ac.quic_datagrams += rec["quic_datagrams"]
        ac.quic_datagram_bytes += rec["quic_datagram_bytes"]
        ac.quic_cids = max(ac.quic_cids, rec["quic_cids"])
        if rec["ja4_key"]:
            if ac.ja4_keys is None:
                ac.ja4_keys = set()
            ac.ja4_keys.add(rec["ja4_key"])
        if rec["ja4s_key"]:
            if ac.ja4s_keys is None:
                ac.ja4s_keys = set()
            ac.ja4s_keys.add(rec["ja4s_key"])
        ac.tls_flags |= rec["tls_flags"]
        ac.proto = rec["proto"]
        ac.capwap_port = ac.capwap_port or bool({a[1], b[1]} & CAPWAP_PORTS)
        if rec.get("pkts") is not None:
            ac.pkts += rec["pkts"]
            ac.capwap_pkts += rec["capwap_pkts"]
        # Худшая из версий: если хоть одна минута снята старым сайдкаром,
        # новые поля у этой сессии неполны и заявлять их нельзя.
        v = rec.get("schema_version", 2)
        ac.schema_version = v if not ac.schema_version else min(ac.schema_version, v)
        # The handshake happens once, at the start; a later minute of the
        # same session must not overwrite what it said.
        if rec["tls_version"] and not ac.tls_version:
            ac.tls_version = rec["tls_version"]
            ac.cipher_count = rec["cipher_count"]
            ac.ext_count = rec["ext_count"]
            ac.group_count = rec["group_count"]
            ac.sigalg_count = rec["sigalg_count"]
            ac.alpn = rec["alpn"]
            ac.alpn_category = rec.get("alpn_category")
        if rec.get("retx_pkts_a2b") is not None:
            up, down = ("a2b", "b2a") if client_is_a else ("b2a", "a2b")
            ac.retx[0] += rec[f"retx_pkts_{up}"]
            ac.retx[1] += rec[f"retx_pkts_{down}"]
            ac.retx[2] += rec[f"retx_bytes_{up}"]
            ac.retx[3] += rec[f"retx_bytes_{down}"]
            for i, side in enumerate((up, down)):
                if rec[f"ssh_sw_{side}"] and not ac.ssh_sw[i]:
                    ac.ssh_sw[i] = rec[f"ssh_sw_{side}"]
                if rec[f"hassh_{side}"] and not ac.ssh_fp[i]:
                    ac.ssh_fp[i] = rec[f"hassh_{side}"]
        if rec["sni_len"] and not ac.sni_len:
            ac.service_key, ac.sni_len = rec["service_key"], rec["sni_len"]
        if ac.shape_ts is None or rec["first_ts"] < ac.shape_ts:
            ac.shape_ts = rec["first_ts"]
            ac.shape = (shape_of(rec["hist_a2b"], rec["hist_b2a"]) if client_is_a
                        else shape_of(rec["hist_b2a"], rec["hist_a2b"]))
            ac.n_up = rec["n_a2b"] if client_is_a else rec["n_b2a"]
            ac.n_down = rec["n_b2a"] if client_is_a else rec["n_a2b"]

    def continues_after(spans, span, key, rec) -> bool:
        """Does the flow go on past this span within the record's interval --
        into a later row already written, or into one still open?"""
        # "Not before", not "after": a row cut inside a burst of coalesced
        # frames starts at the very timestamp the previous one ended on.
        later = any(sp is not span and sp[0] >= span[1] and sp[0] <= rec["last_ts"]
                    for sp in spans)
        seg_start = live.get(key)
        return later or (seg_start is not None and span[1] <= seg_start <= rec["last_ts"])

    queue: list = []
    for original in all_records():
        records += 1
        first_piece = True
        queue.append(original)
        while queue:
            rec = queue.pop()
            a, b = rec["a"], rec["b"]
            key = (a[0], a[1], b[0], b[1], rec["proto"])
            spans = index.get(key)
            span, touched = pick_span(spans, rec["first_ts"], rec["last_ts"]) if spans else (None, 0)
            if span is None:
                # Not yet placeable. It waits only if the flow is still open
                # and its next row can still reach back to this record.
                seg_start = live.get(key)
                if batch_mode and seg_start is not None and rec["last_ts"] >= seg_start:
                    pickle.dump(rec, pending_fh, protocol=pickle.HIGHEST_PROTOCOL)
                    pending += 1
                elif first_piece:
                    unmatched += 1
                first_piece = False
                continue
            if first_piece:
                matched += 1
                # The flow's still-open instance is a span too, just not
                # written yet: one process would have seen the record touch
                # both. Counting it here keeps the starvation ceiling the same
                # however the capture is cut.
                seg_start = live.get(key)
                if seg_start is not None and rec["last_ts"] >= seg_start:
                    touched += 1
                ambiguous += touched > 1
                # One record spread over N sessions can leave all N-1 others
                # without payload -- not one. Sidecars written before records
                # were cut at session boundaries do this.
                starved += max(0, touched - 1)
            first_piece = False
            if continues_after(spans or [], span, key, rec):
                head, tail = split_record(rec, span[1])
                apply(head, span)
                queue.append(tail)
                split_records += 1
            else:
                apply(rec, span)

    cols = ["segment_uid", "service_key"] + PAY_NAMES
    args.out_csv.parent.mkdir(parents=True, exist_ok=True)
    with args.out_csv.open("w", newline="", encoding="utf-8") as fh:
        w = csv.DictWriter(fh, fieldnames=cols)
        w.writeheader()
        for uid, ac in acc.items():
            (ent_up, ent_down, prn_up, prn_down, null_up, b64_up,
             up_n, down_n) = ac.shape
            alpn_cols = {c: 0 for c in ("tls_alpn_h2", "tls_alpn_h3",
                                        "tls_alpn_http11", "tls_alpn_other")}
            if ac.alpn_category:
                alpn_cols[_ALPN_BY_CATEGORY[ac.alpn_category]] = 1
            elif ac.alpn:
                alpn_cols[_ALPN_KNOWN.get(ac.alpn, "tls_alpn_other")] = 1
            qtype_cols = {c: 0 for c in ("dns_qtype_a", "dns_qtype_aaaa",
                                         "dns_qtype_txt", "dns_qtype_null",
                                         "dns_qtype_other")}
            for qtype, count in (ac.dns_qtypes or {}).items():
                qtype_cols[_QTYPE_COLUMN.get(qtype, "dns_qtype_other")] += count
            row = {
                **alpn_cols, **qtype_cols,
                "payload_schema_version": ac.schema_version,
                "tls_ja4_present": int(bool(ac.ja4_keys)),
                "tls_ja4s_present": int(bool(ac.ja4s_keys)),
                "tls_ja4_unique": len(ac.ja4_keys or ()),
                "tls_version": ac.tls_version,
                "tls_cipher_count": ac.cipher_count,
                "tls_ext_count": ac.ext_count,
                "tls_group_count": ac.group_count,
                "tls_sigalg_count": ac.sigalg_count,
                "tls_resumed": int(bool(ac.tls_flags & ps.TLS_PSK)),
                "tls_early_data": int(bool(ac.tls_flags & ps.TLS_EARLY_DATA)),
                "quic_datagrams": ac.quic_datagrams,
                "quic_datagram_bytes": ac.quic_datagram_bytes,
                "quic_cid_changes": max(0, ac.quic_cids - 1),
                "segment_uid": uid,
                "service_key": ac.service_key,
                "bytes_up_ip": ac.ip_up,
                "bytes_down_ip": ac.ip_down,
                "pay_entropy_up": ent_up,
                "pay_entropy_down": ent_down,
                "pay_printable_up": prn_up,
                "pay_printable_down": prn_down,
                "pay_null_share_up": null_up,
                "pay_b64_share_up": b64_up,
                "pay_bytes_sampled_up": up_n,
                "pay_bytes_sampled_down": down_n,
                "dns_qname_len_mean": round(ac.dns_len_sum / ac.dns_q, 3) if ac.dns_q else 0.0,
                "dns_qname_len_max": ac.dns_len_max,
                "dns_label_entropy": round(label_entropy(ac.dns_labels or Counter()), 6),
                "dns_query_count": ac.dns_q,
                "tls_has_sni": int(bool(ac.sni_len)),
                "tls_sni_len": ac.sni_len,
            }
            if ac.schema_version >= 3:
                row["capwap_packets"] = ac.capwap_pkts
                row["is_capwap_tunnel"] = int(ac.capwap_pkts > 0
                                              and ac.capwap_pkts * 2 >= ac.pkts)
            else:
                row["capwap_packets"] = ""
                row["is_capwap_tunnel"] = int(ac.capwap_port)
            if ac.schema_version < 3 and ac.proto == 17:
                for name in _TLS_COLUMNS:
                    row[name] = ""
            if ac.schema_version < 2:
                # Пусто, а не ноль: этих полей в том сайдкаре не существовало.
                for name in _V2_ONLY:
                    row[name] = ""
            if ac.schema_version >= 4 and ac.proto == 6:
                row.update({
                    "tcp_retx_pkts_up": ac.retx[0], "tcp_retx_pkts_down": ac.retx[1],
                    "tcp_retx_bytes_up": ac.retx[2], "tcp_retx_bytes_down": ac.retx[3],
                    "ssh_client_software": ps.SSH_SOFTWARE[ac.ssh_sw[0]],
                    "ssh_server_software": ps.SSH_SOFTWARE[ac.ssh_sw[1]],
                    "ssh_client_fp_key": ac.ssh_fp[0], "ssh_server_fp_key": ac.ssh_fp[1]})
            else:
                # Older sidecars did not count these; UDP has none of them.
                row.update({name: "" for name in _V4_ONLY})
            w.writerow(row)

    if batch_mode:
        pending_fh.close()
        os.replace(pending_tmp, args.pending_out)

    report = {
        "status": "ok", "sidecar_files": len(files),
        "records_pending_out": pending if batch_mode else None,
        "records_split_between_rows": split_records,
        "sidecar_files_skipped_by_time": skipped, "records": records,
        "sessions_with_payload": len(acc),
        "records_matched": matched, "records_unmatched": unmatched,
        "ambiguous_minutes": ambiguous,
        "sessions_possibly_starved": starved,
        "match_rate": round(matched / max(records, 1), 4),
        "sni_found": sum(1 for a in acc.values() if a.sni_len),
        "seconds": round(time.time() - t0, 1),
        "note": "a record goes to the earliest span it touches, each record read "
                "once across all batches; byte counts summed over the records; payload shape "
                "taken from the earliest one",
    }
    print(json.dumps(report))
    if args.stats_json:
        Path(args.stats_json).write_text(json.dumps(report, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
