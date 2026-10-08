#!/usr/bin/env python3
"""Whole-session features across a capture, plus the LoTS window table.

The problem this exists to fix: features were being computed one 5-minute file
at a time, so no session could be longer than 300 s.  Measured on the first two
files of the 20260920 hour, p99 duration was 293 s and the maximum 297 s -- a
ceiling imposed by the file edge, not by traffic -- while 3670 of 10103 flows
per file were discarded as `skipped_midflow`, which is what a continuation of a
session from the previous file looks like.  A behavioural model cannot be built
on that.

So the files are consumed as ONE ordered stream and a session is emitted when it
really ends.

Session identity is NOT the 5-tuple.  It follows `lab_pipeline.flow_observation`:
a 4-tuple plus an instance counter, where a reused 4-tuple opens a NEW instance
rather than continuing the old one, using `online_schema.idle_timeout`
(TCP 60/600/10 s, UDP 30/300 s) and the rule that a bare SYN reopens the tuple
only once the current instance has finished -- otherwise a retransmitted
handshake would split a session in half.

Two tables come out of one pass:

  sessions     one row per session instance: the 112 corpus features over the
               WHOLE session, the sequence block extended to --seq-ext packets,
               and `cc_*` / `ra_*` blocks for covert-channel and remote-admin
               work.  The `cc_*` names are deliberately outside
               MODEL_FEATURE_NAMES: several of them are in the repository's
               FORBIDDEN_SHORTCUTS list, and the VPN model must not be able to
               reach them by accident.

  lots_conns   one row per connection in the shape `lots_ngfw/features.py`
               consumes (ts, duration, bytes_up, bytes_down, host, service, dst,
               has_sni), from which the 1200/600 window grid is tiled.  The
               window table is built by a separate step so the LoTS contract
               stays the one definition of its own features.

Parsing is the repository's `parse_tcpdump_line`, applied to a streamed tcpdump,
so lengths and protocol labels keep every quirk the corpus was built with.
Loading a 5-minute file through `read_pcap_packets` instead needs 11.5 GiB on a
15 GiB host; streaming needs a few hundred MB, and only sessions still open are
held.

Privacy: addresses and SNI are salted-hashed into `host_key` / `service_key` and
never written in the clear.  The mapping is written separately, only when
--emit-name-map is given, so it can stay behind.
"""
from __future__ import annotations

import argparse
import csv
import hashlib
import hmac
import ipaddress
import json
import math
import os
import pickle
import re as _re
import struct
import subprocess
import sys
import tempfile
import time
from array import array
from collections import Counter
from pathlib import Path
from typing import Any, Iterator

# `lab_pipeline` lives in `detector/` in the repository and flat beside this
# file once the ops scripts are copied to the sensor. Both layouts have to work:
# checking only the flat one meant this module could not be imported on a
# developer machine at all, so its own test never ran there.
_HERE = Path(__file__).resolve().parent
_CANDIDATES = [_HERE, _HERE / "detector", _HERE.parent, _HERE.parent / "detector"]
_CANDIDATES += [parent / "detector" for parent in _HERE.parents]
for cand in _CANDIDATES:
    if (cand / "lab_pipeline").is_dir():
        if str(cand) not in sys.path:
            sys.path.insert(0, str(cand))
        break
else:
    raise ImportError(
        f"lab_pipeline not found next to {_HERE} nor in any parent's detector/"
    )

from lab_pipeline.extract_lab_features import (  # noqa: E402
    features_from_packets,
    parse_tcpdump_line,
    split_coalesced_frames,
)
from lab_pipeline import extract_lab_features as _elf  # noqa: E402
from lab_pipeline.online_schema import idle_timeout  # noqa: E402
from lab_pipeline.schema import MODEL_FEATURE_NAMES, SEQ_N  # noqa: E402

# Корпусные признаки без раскрытой последовательности. Сама последовательность
# уходит массивами (`seq_*`), по одному столбцу на величину, и раскрывать её
# под конкретную модель — дело того, кто модель обучает: у разных моделей
# разная длина входа, а таблица не должна выбирать за них.
SCALAR_FEATURE_NAMES = [
    c for c in MODEL_FEATURE_NAMES
    if not _re.fullmatch(r"(signed_len|dir|iat|mask)_\d+", c)
]

# `parse_tcpdump_line` drops ports 53 and 5353 outright, because
# OUT_OF_SCOPE_PORTS says the VPN detector is not trained to judge DNS.  DNS
# tunnelling is the classic covert channel, so the rows are kept here and marked
# `out_of_scope_vpn=1` instead: the VPN corpus drops them with one condition and
# its contract is untouched, while covert-channel work gets the traffic it needs.
# The override is narrow on purpose -- nothing else about the parse changes.
_elf.in_scope = lambda _sport, _dport: True

DNS_PORTS = {53, 5353}
CLOSED_TIMEOUT = 10.0          # online_schema FLOW_TIMEOUTS["tcp"]["closed"]
# An open session holds every one of its packets so whole-session percentiles
# stay exact.  That is fine for an hour and fatal for a month: a tunnel is by
# definition a long-lived session, and its arrays -- and the checkpoint they are
# pickled into -- would grow without limit for as long as it stays open.  So a
# session that reaches this many held packets emits what it has as a numbered
# SEGMENT and keeps accumulating under the same identity.  Nothing is dropped:
# every packet still leaves in exactly one row, `session_uid` still names the
# session instance, and downstream work regroups the segments by it.  The cap is
# high enough that ordinary sessions never reach it -- only the long ones are
# segmented, and those are the ones a window model reads anyway.
MAX_HELD_PACKETS = 262144
# Session.tcp_bits: each flag has an A-side bit and, one to the left, a B-side bit.
TCP_SYN, TCP_SYNACK, TCP_RST, TCP_ANY, TCP_DATA = 1, 4, 16, 64, 256
SMALL_PACKET = 100             # bytes on the wire; `small_pkt_share`
# Remote administration (`ra_*`). A keystroke is a SHORT PIECE OF DATA from the
# client -- not a short frame: an empty TCP ACK is a short frame too, and on the
# office capture 98% of the client's short frames were exactly that, which made
# every download look like someone typing. So these count data packets only.
KEYSTROKE_PAYLOAD = 128        # bytes of transport payload: one keystroke or a small command
ECHO_WINDOW = 1.0              # s: a server reply this soon after a keystroke is its echo
INTERACTIVE_ECHO = 0.2         # s: the median echo a person at a terminal sees
MIN_KEYSTROKES = 10            # fewer is a query and its answer (DNS), not someone typing
OFFICE_TZ = "Europe/Moscow"    # office hours are the office's, not the processing host's
OFFICE_HOURS = (8, 20)


def _hkey(salt: bytes, value: str) -> str:
    return hmac.new(salt, value.encode(), hashlib.sha256).hexdigest()[:16]


def _entropy(values) -> float:
    if not values:
        return 0.0
    counts = Counter(values)
    n = len(values)
    return -sum((c / n) * math.log2(c / n) for c in counts.values())


def _pct(sorted_vals: list[float], q: float) -> float:
    """Nearest-rank percentile -- the method the corpus features use.

    `pkt_len_median`, `pkt_len_p10`, `pkt_len_p90` come from the lab code and
    take the nearest element of the sorted values; the percentiles added here
    used to interpolate, so the same word meant two things in one table. Now
    every percentile in it is an actual observed value (the median of 60 and 66
    is 60, not 63).
    """
    return _elf._pct(sorted_vals, q)


class Session:
    __slots__ = ("ts", "length", "payload", "side", "flag_id", "ip_a", "port_a", "ip_b",
                 "port_b", "proto", "instance", "start_observed", "closed",
                 "fin_seen", "fin_a", "fin_b", "rst_seen", "tcp_bits", "bidirectional", "first_dir",
                 "last_seen", "first_dport", "segment_index", "client_is_a",
                 "a_private", "b_private")

    def __init__(self, ip_a, port_a, ip_b, port_b, proto, instance,
                 start_observed, first_dir, first_dport,
                 a_private=None, b_private=None):
        self.ts = array("d")
        self.length = array("i")
        # Transport payload bytes, -1 where the source did not say (tcpdump
        # text). An empty ACK and a keystroke are both short frames; only this
        # tells them apart.
        self.payload = array("i")
        self.side = bytearray()
        self.flag_id = array("H")
        self.ip_a, self.port_a = ip_a, port_a
        self.ip_b, self.port_b = ip_b, port_b
        self.proto = proto
        self.instance = instance
        self.start_observed = start_observed
        self.closed = False
        self.fin_seen = 0
        # A FIN from each side, not two FINs: a retransmitted FIN is still
        # one side saying it is done, and the other may go on sending.
        self.fin_a = self.fin_b = False
        # Which side sent a bare SYN, a SYN/ACK, a RST -- what the connection
        # state (`conn_state`) is read from. Bits: TCP_BITS below.
        self.tcp_bits = 0
        self.rst_seen = 0
        self.bidirectional = False
        self.first_dir = first_dir
        self.last_seen = 0.0
        self.first_dport = first_dport
        self.segment_index = 0
        # From the packet row when it says so, since a hashed address cannot be
        # asked later; from the address itself on the tcpdump text path.
        self.a_private = _is_private(ip_a) if a_private is None else bool(a_private)
        self.b_private = _is_private(ip_b) if b_private is None else bool(b_private)
        # Decided once, on the first row this session emits, and reused by every
        # later segment. Re-deriving it per segment would flip up/down halfway
        # through a session, because only the first segment contains the SYN.
        self.client_is_a = None

    def reset_packets(self) -> None:
        """Drop the held packets and open the next segment of the same session."""
        self.ts = array("d")
        self.length = array("i")
        self.payload = array("i")
        self.side = bytearray()
        self.flag_id = array("H")
        self.segment_index += 1

    def idle_limit(self) -> float:
        if self.closed and self.proto == "tcp":
            return CLOSED_TIMEOUT
        return idle_timeout("udp" if self.proto == "udp" else "tcp", self.bidirectional)


# `export_full_packets.py` writes this; see its docstring for the field order.
_PKT_REC = struct.Struct("<d8s8sHHHHBBB")
# tcpdump's own order for `Flags [...]`, so a row from a packet file and a row
# from tcpdump text produce the same string and the same session decisions.
_FLAG_CHARS = ((0x01, "F"), (0x02, "S"), (0x04, "R"), (0x08, "P"),
               (0x10, "."), (0x20, "U"), (0x40, "E"), (0x80, "W"))


def _flag_string(bits: int) -> str:
    return "".join(ch for mask, ch in _FLAG_CHARS if bits & mask)


_FLAG_STRINGS = [_flag_string(bits) for bits in range(256)]


def shard_rows(buf: bytes, shard: tuple[int, int]) -> bytes:
    """The rows of `buf` whose flow belongs to shard k of N.

    The shard is a function of the flow alone, and the same whichever way a
    packet travels: the XOR of the two address keys and the two ports does not
    change when source and destination swap. So every packet of a session
    reaches the same worker, and the workers never need to talk. Selected with
    numpy before any row becomes a Python object -- a worker pays for its own
    rows, not for everybody's.
    """
    k, n = shard
    size = _PKT_REC.size
    try:
        import numpy as np
    except ImportError:                 # same rows, slowly
        out = bytearray()
        for off in range(0, len(buf), size):
            h = (int.from_bytes(buf[off + 8:off + 12], "little")
                 ^ int.from_bytes(buf[off + 16:off + 20], "little")
                 ^ int.from_bytes(buf[off + 26:off + 28], "little")
                 ^ int.from_bytes(buf[off + 28:off + 30], "little"))
            if h % n == k:
                out += buf[off:off + size]
        return bytes(out)
    m = np.frombuffer(buf, dtype=np.uint8).reshape(-1, size)
    h = (m[:, 8:12].copy().view("<u4")[:, 0] ^ m[:, 16:20].copy().view("<u4")[:, 0]
         ^ m[:, 26:28].copy().view("<u2")[:, 0].astype(np.uint32)
         ^ m[:, 28:30].copy().view("<u2")[:, 0].astype(np.uint32))
    return m[h % n == k].tobytes()


# The time of the last row read from the files, whatever its shard. A shard
# ends its batch at its own last packet, which is not when the capture stopped.
CLOCK = {"last_ts": 0.0}


def iter_packed(path: Path, shard: tuple[int, int] | None = None) -> Iterator[dict[str, Any]]:
    """Packet rows in place of the pcap, for a capture too big to keep.

    The fields are the same ones ``parse_tcpdump_line`` returns, with the
    addresses already replaced by their keyed hashes -- the pcap they came from
    is deleted on the sensor, so this is the last form the packet level exists
    in. `src_private` / `dst_private` travel alongside because a hash cannot be
    asked afterwards which side of the office the address was on.
    """
    size = _PKT_REC.size
    unpack = _PKT_REC.unpack_from
    with path.open("rb") as fh:
        while True:
            buf = fh.read(size * 65536)
            if not buf:
                return
            if len(buf) % size:
                raise ValueError(
                    f"{path}: {len(buf) % size} trailing bytes, not a whole row")
            # Exactly what `now` is after the last row in one process.
            CLOCK["last_ts"] = _PKT_REC.unpack_from(buf, len(buf) - size)[0]
            if shard is not None and shard[1] > 1:
                buf = shard_rows(buf, shard)
            for off in range(0, len(buf), size):
                (ts, src, dst, origlen, sport, dport, paylen,
                 proto_n, flags, meta) = unpack(buf, off)
                yield {
                    "ts": ts,
                    "src": src.hex(),
                    "dst": dst.hex(),
                    "sport": sport,
                    "dport": dport,
                    "length": max(origlen, 1),
                    "payload": paylen,
                    "proto": "tcp" if proto_n == 6 else ("udp" if proto_n == 17 else "other"),
                    "flags": _FLAG_STRINGS[flags] if proto_n == 6 else "",
                    "src_private": meta & 1,
                    "dst_private": (meta >> 1) & 1,
                }


def _parse_line_with_real_proto(line: str) -> dict[str, Any] | None:
    """`parse_tcpdump_line`, with tcpdump's protocol guess corrected to UDP.

    tcpdump prints `UDP, length N` only for traffic it has no dissector for. It
    dissects DNS, so a DNS packet has neither the `UDP` token nor `Flags`, and
    the repository parser ends up calling it `other`. That is not cosmetic:
    `proto` is part of the session key and picks the idle timeouts, so every
    dissected UDP session was being held to TCP's 60/600/10 s instead of UDP's
    30/300 s. Measured on a 25-minute synthetic capture, 25 of 201 sessions were
    labelled `other`, and five of them stayed open to the end of the capture
    that should have closed by timeout.

    The correction is sound rather than a guess about ports: the parser's own
    regex requires `address.port > address.port`, which only TCP and UDP print,
    and TCP always prints `Flags`. So a row that reached here as `other` is UDP.

    This is deliberately local to the office pipeline. `extract_lab_features`
    still labels the lab corpus the way tcpdump does, so `udp_share` is not
    comparable between the two for dissected UDP until that side is settled.
    """
    parsed = parse_tcpdump_line(line)
    if parsed is not None and parsed["proto"] == "other":
        parsed["proto"] = "udp"
    return parsed


def iter_parsed(pcaps: list[Path], shard: tuple[int, int] | None = None) -> Iterator[dict[str, Any]]:
    """One ordered packet stream across every file, via the repository parser.

    ``.txt`` files are already ``tcpdump -tt -nn -e`` text, and ``.pkts`` files
    are the packed packet rows. Both exist because a month-long capture cannot
    keep its pcap: it is larger than the fast paths off this sensor.
    """
    parse = _parse_line_with_real_proto
    for pcap in pcaps:
        if pcap.suffix == ".pkts":
            yield from iter_packed(pcap, shard)
            continue
        if shard is not None and shard[1] > 1:
            raise ValueError("sharding is only implemented for packet rows (.pkts)")
        if pcap.suffix == ".txt":
            with pcap.open(encoding="utf-8", errors="replace") as fh:
                for line in fh:
                    parsed = parse(line)
                    if parsed is not None:
                        yield parsed
            continue
        with tempfile.TemporaryFile(mode="w+") as errors:
            proc = subprocess.Popen(
                ["tcpdump", "-tt", "-nn", "-e", "-r", str(pcap)],
                stdout=subprocess.PIPE, stderr=errors,
                text=True, bufsize=1 << 20,
            )
            try:
                assert proc.stdout is not None
                for line in proc.stdout:
                    p = parse(line)
                    if p is not None:
                        yield p
            finally:
                if proc.stdout:
                    proc.stdout.close()
                rc = proc.wait()
            if rc != 0:
                errors.seek(0)
                raise RuntimeError(f"tcpdump failed for {pcap}: rc={rc}: {errors.read()[-1000:]}")


def _save_state(path: Path, state: dict) -> None:
    """Write a private checkpoint atomically so a failed hour can be rerun."""
    path.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile(dir=path.parent, prefix=path.name + ".",
                                     delete=False) as fh:
        temp = Path(fh.name)
        os.chmod(temp, 0o600)
        try:
            pickle.dump(state, fh, protocol=pickle.HIGHEST_PROTOCOL)
            fh.flush()
            os.fsync(fh.fileno())
        except BaseException:
            temp.unlink(missing_ok=True)
            raise
    os.replace(temp, path)


def session_rows(pcaps: list[Path], salt: bytes, seq_ext: int, min_packets: int,
                 stats: Counter, name_map: dict[str, str] | None,
                 state_in: Path | None = None, state_out: Path | None = None,
                 finalize: bool = True, max_held: int = MAX_HELD_PACKETS,
                 live_out: Path | None = None, shard: tuple[int, int] = (0, 1)):
    """Yield (session_row, lots_conn, index) as sessions close or segment."""
    live: dict[tuple, Session] = {}
    flag_ids: dict[str, int] = {}
    flag_list: list[str] = []
    next_instance = 0
    last_sweep = 0.0
    t_first = None
    now = 0.0
    if state_in is not None:
        # State is a private file produced by this program, never a network input.
        with Path(state_in).open("rb") as fh:
            saved = pickle.load(fh)
        if saved.get("version") != 5:
            raise ValueError(
                "unsupported office session checkpoint version "
                f"{saved.get('version')!r}; version 5 keeps the TCP flags each side "
                "sent, and a checkpoint from before it cannot be resumed"
            )
        if saved.get("salt_sha256") != hashlib.sha256(salt).hexdigest():
            raise ValueError("office session checkpoint salt differs")
        if tuple(saved.get("shard", (0, 1))) != tuple(shard):
            # A flow's sessions live in exactly one shard's checkpoint; a
            # different split would hand them to a worker that never saw them.
            raise ValueError(f"checkpoint is shard {saved.get('shard', (0, 1))}, "
                             f"this run is shard {shard}")
        live = saved["live"]
        flag_ids = saved["flag_ids"]
        flag_list = saved["flag_list"]
        next_instance = saved["next_instance"]
        last_sweep = saved["last_sweep"]
        t_first = saved["t_first"]
        now = saved["last_ts"]
    previous_end = now if state_in is not None else None
    CLOCK["last_ts"] = now

    def emit(sess: Session, truncated: bool, continues: bool = False):
        nonlocal stats
        # A continuation segment is emitted whatever its size: dropping a short
        # remainder as "too short" would silently lose packets from a session
        # whose earlier segments were already written.
        floor = min_packets if sess.segment_index == 0 else 1
        out = _build_row(sess, flag_list, salt, seq_ext, floor, truncated,
                         t_first, stats, name_map, continues)
        return out

    for p in iter_parsed(pcaps, shard):
        now = p["ts"]
        if previous_end is not None:
            if now < previous_end:
                raise ValueError("new pcap batch predates the session checkpoint")
            previous_end = None
        if t_first is None:
            t_first = now
        stats["packets"] += 1
        a = (p["src"], p["sport"])
        b = (p["dst"], p["dport"])
        key = (a, b, p["proto"]) if a <= b else (b, a, p["proto"])
        from_a = (a == key[0])
        fl = p["flags"] or ""
        syn = "S" in fl and "." not in fl

        sess = live.get(key)
        if sess is not None:
            if sess.first_dir != from_a:
                sess.bidirectional = True
            gap = now - sess.last_seen
            # No idle limit is below CLOSED_TIMEOUT, so the common case -- a
            # packet a moment after the last one -- skips the lookup.
            if (gap > CLOSED_TIMEOUT and gap > sess.idle_limit()) or (syn and sess.closed):
                stats["closed_timeout" if gap > sess.idle_limit() else "closed_reopen"] += 1
                row = emit(sess, truncated=False)
                if row:
                    yield row
                del live[key]
                sess = None
        if sess is None:
            next_instance += 1
            priv = None
            if "src_private" in p:
                priv = ((p["src_private"], p["dst_private"]) if from_a
                        else (p["dst_private"], p["src_private"]))
            sess = Session(key[0][0], key[0][1], key[1][0], key[1][1], p["proto"],
                           # Unique across shards: worker k of N numbers k, N+k, 2N+k...
                           next_instance * shard[1] + shard[0], start_observed=syn or p["proto"] != "tcp",
                           first_dir=from_a, first_dport=p["dport"],
                           a_private=None if priv is None else priv[0],
                           b_private=None if priv is None else priv[1])
            live[key] = sess

        # Bound what one open session can hold. See MAX_HELD_PACKETS. The cut
        # is made when the packet AFTER a full segment arrives, not when the
        # segment fills: only then is it certain the session goes on, and a
        # segment marked "continues" is never the last one the session writes.
        # Cutting on fill left a session that ended exactly there with a final
        # row claiming a continuation that never came.
        if len(sess.ts) >= max_held:
            stats["segments_emitted"] += 1
            row = emit(sess, truncated=False, continues=True)
            if row:
                yield row
            sess.reset_packets()

        fid = flag_ids.get(fl)
        if fid is None:
            fid = len(flag_list)
            flag_ids[fl] = fid
            flag_list.append(fl)
        sess.ts.append(now)
        sess.length.append(p["length"])
        sess.payload.append(p.get("payload", -1))
        sess.side.append(0 if from_a else 1)
        sess.flag_id.append(fid)
        sess.last_seen = now
        side = 0 if from_a else 1
        sess.tcp_bits |= TCP_ANY << side
        if p.get("payload", 0) > 0:
            sess.tcp_bits |= TCP_DATA << side
        if fl:
            if "S" in fl:
                sess.tcp_bits |= (TCP_SYNACK if "." in fl else TCP_SYN) << side
            # A reset after this side's own FIN does not undo the close -- the
            # connection already ended cleanly on its side (Zeek does the same).
            if "R" in fl and not (sess.fin_a if from_a else sess.fin_b):
                sess.tcp_bits |= TCP_RST << side
        if "R" in fl:
            sess.rst_seen += 1
            sess.closed = True
        if "F" in fl:
            sess.fin_seen += 1
            if from_a:
                sess.fin_a = True
            else:
                sess.fin_b = True
            if sess.fin_a and sess.fin_b:
                sess.closed = True

        # Retiring expired sessions keeps memory to what is actually open.
        if now - last_sweep > 10.0:
            last_sweep = now
            for k in [k for k, s in live.items() if now - s.last_seen > s.idle_limit()]:
                s = live.pop(k)
                stats["closed_sweep"] += 1
                row = emit(s, truncated=False)
                if row:
                    yield row

    if not finalize:
        if state_out is None:
            raise ValueError("state_out is required when finalize=False")
        stats["pending_at_end"] = len(live)
        stats["pending_packets_held"] = sum(len(s.ts) for s in live.values())
        # Раньше этого момента не начнётся ни один будущий сегмент: у открытой
        # сессии следующий сегмент стартует с её первого удержанного пакета, а
        # новые сессии — не раньше конца пакета.
        stats["pending_earliest_ts"] = min(
            [s.ts[0] if len(s.ts) else s.last_seen for s in live.values()] + [now])
        stats["batch_last_ts"] = now
        if live_out is not None:
            # Which flows are still open, and from when their next row starts.
            # The payload pass keeps a record for a later batch only if it can
            # still land on one of these; everything else it can let go.
            with Path(live_out).open("w", newline="", encoding="utf-8") as fh:
                w = csv.writer(fh)
                w.writerow(["ip_a", "port_a", "ip_b", "port_b", "proto", "seg_start"])
                for sess in live.values():
                    w.writerow([sess.ip_a, sess.port_a, sess.ip_b, sess.port_b, sess.proto,
                                repr(sess.ts[0] if len(sess.ts) else sess.last_seen)])
            os.chmod(live_out, 0o600)
        _save_state(Path(state_out), {
            "version": 5,
            "salt_sha256": hashlib.sha256(salt).hexdigest(),
            "live": live,
            "flag_ids": flag_ids,
            "flag_list": flag_list,
            "next_instance": next_instance,
            "last_sweep": last_sweep,
            "t_first": t_first,
            "last_ts": now,
            "shard": list(shard),
        })
    else:
        # When the capture stopped: the last packet of any shard.
        now = max(now, CLOCK["last_ts"])
        for k in list(live.keys()):
            s = live.pop(k)
            # Already past its idle limit: it ended, the sweep just had not
            # come round yet. Truncated means "still open when the capture
            # stopped", and whether a sweep happened to run in the last ten
            # seconds must not decide that.
            ended = now - s.last_seen > s.idle_limit()
            stats["closed_timeout_at_end" if ended else "closed_at_capture_end"] += 1
            row = emit(s, truncated=not ended)
            if row:
                yield row


def _build_row(sess: Session, flag_list, salt, seq_ext, min_packets, truncated,
               t_first, stats: Counter, name_map, continues: bool = False):
    pkts = []
    ts, ln, pl, sd, fid = sess.ts, sess.length, sess.payload, sess.side, sess.flag_id
    for i in range(len(ts)):
        s = sd[i]
        pkts.append({"ts": ts[i], "src": "A" if s == 0 else "B",
                     "dst": "B" if s == 0 else "A", "sport": 0, "dport": 0,
                     "length": ln[i], "payload": pl[i], "proto": sess.proto,
                     "flags": flag_list[fid[i]]})
    pkts = split_coalesced_frames(pkts)
    stats["sessions_seen"] += 1
    if len(pkts) < min_packets:
        stats["skipped_short"] += 1
        return None

    if sess.client_is_a is None:
        sess.client_is_a = _client_is_a(sess, pkts)
    client_is_a = sess.client_is_a
    client = "A" if client_is_a else "B"
    row = features_from_packets(pkts, {"outer_src": client})
    # Скалярные агрегаты корпуса берём, раскрытый seq-блок — нет: он у нас в
    # массивах целиком, а как колонка на пакет он ещё и обрывался на двадцатом.
    row = {k: row.get(k, 0.0) for k in SCALAR_FEATURE_NAMES}
    if seq_ext > SEQ_N:
        row.update(_ext_sequence(pkts, client, SEQ_N, seq_ext))
    row.update(_behaviour_features(pkts, client, sess))
    row.update(_sequence_arrays(pkts, client))

    client_ip = sess.ip_a if client_is_a else sess.ip_b
    server_ip = sess.ip_b if client_is_a else sess.ip_a
    dport = _server_port(sess, client_is_a)
    row.update(_session_context(pkts, client, sess, client_is_a))
    row["proto"] = sess.proto
    row["dest_port"] = dport
    row["host_key"] = _hkey(salt, client_ip)
    row["server_key"] = _hkey(salt, server_ip)
    row["session_uid"] = f"{_hkey(salt, f'{sess.ip_a}:{sess.port_a}-{sess.ip_b}:{sess.port_b}')}#{sess.instance}"
    # `session_uid` names the session INSTANCE and repeats across its segments.
    # `segment_uid` is what is unique per row, and what every join downstream
    # keys on. Regroup by `session_uid` to get the whole session back.
    row["segment_uid"] = f"{row['session_uid']}.{sess.segment_index}"
    row["segment_index"] = sess.segment_index
    row["session_continues"] = int(continues)
    row["time_bucket"] = time.strftime("%Y-%m-%dT%H", time.gmtime(pkts[0]["ts"]))
    row["session_start_epoch"] = round(pkts[0]["ts"], 6)
    # Only the first segment can have seen the session open.
    row["start_observed"] = int(sess.start_observed and sess.segment_index == 0)
    row["truncated_at_capture_end"] = int(truncated)
    # Clean means both sides said goodbye and nobody reset. A reset closes
    # the session too, but it is an abort, and `rst_seen` says so.
    row["closed_cleanly"] = int(sess.fin_a and sess.fin_b and not sess.rst_seen)
    # DNS stays in the table for covert-channel work, flagged so the VPN model
    # can drop it with one condition and its OUT_OF_SCOPE_PORTS contract holds.
    row["out_of_scope_vpn"] = int(dport in DNS_PORTS or sess.port_a in DNS_PORTS
                                  or sess.port_b in DNS_PORTS)
    row["y_presumed"] = 0
    row["label_source"] = "office_unlabeled"
    row["label_family"] = "office_benign"
    if name_map is not None:
        name_map[row["host_key"]] = client_ip
        name_map[row["server_key"]] = server_ip
    stats["rows_written"] += 1

    up = sum(p["length"] for p in pkts if p["src"] == client)
    down = sum(p["length"] for p in pkts if p["src"] != client)
    lots = {
        "ts": round(pkts[0]["ts"], 6),
        "duration": round(pkts[-1]["ts"] - pkts[0]["ts"], 6),
        "bytes_up": up,
        "bytes_down": down,
        "host": row["host_key"],
        "dst": row["server_key"],
        "dest_port": dport,
        "proto": sess.proto,
        "session_uid": row["session_uid"],
        "segment_uid": row["segment_uid"],
    }
    # The payload pass must not re-derive which side is the client: on a
    # continuation segment its first packet can be the server's. The session
    # pass already decided, so it says so here.
    index = (sess.ip_a, sess.port_a, sess.ip_b, sess.port_b, sess.proto,
             repr(pkts[0]["ts"]), repr(pkts[-1]["ts"]), row["segment_uid"],
             client_ip, sess.port_a if client_is_a else sess.port_b)
    return row, lots, index


def _client_is_a(sess: Session, pkts) -> bool:
    for p in pkts:
        fl = p["flags"] or ""
        if "S" in fl and "." not in fl:
            return p["src"] == "A"
    a_priv, b_priv = sess.a_private, sess.b_private
    if a_priv and not b_priv:
        return True
    if b_priv and not a_priv:
        return False
    return pkts[0]["src"] == "A"


# The same definition the packet rows use (export_full_packets._is_private):
# RFC 1918, loopback, link-local, unique-local. Not `ipaddress.is_private`,
# which also counts documentation and reserved ranges, so the two paths would
# disagree on whether a server is inside.
_INTERNAL = [ipaddress.ip_network(n) for n in (
    "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "127.0.0.0/8", "169.254.0.0/16",
    "::1/128", "fc00::/7", "fe80::/10")]


def _is_private(ip: str) -> bool:
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return any(addr.version == n.version and addr in n for n in _INTERNAL)


def _ext_sequence(pkts, client, n_from, n_to) -> dict:
    row = {}
    prev = None
    for i in range(n_to):
        if i < len(pkts):
            p = pkts[i]
            d = 1 if p["src"] == client else -1
            iat = 0.0 if prev is None else max(p["ts"] - prev, 0.0)
            prev = p["ts"]
            if i >= n_from:
                row[f"ext_signed_len_{i}"] = d * p["length"]
                row[f"ext_dir_{i}"] = d
                row[f"ext_iat_{i}"] = iat
                row[f"ext_mask_{i}"] = 1
        elif i >= n_from:
            row[f"ext_signed_len_{i}"] = 0
            row[f"ext_dir_{i}"] = 0
            row[f"ext_iat_{i}"] = 0.0
            row[f"ext_mask_{i}"] = 0
    return row


def ext_names(n_from: int, n_to: int) -> list[str]:
    names = []
    for i in range(n_from, n_to):
        names += [f"ext_signed_len_{i}", f"ext_dir_{i}", f"ext_iat_{i}", f"ext_mask_{i}"]
    return names


CC_NAMES = [
    "iat_entropy", "iat_cv", "iat_p50", "iat_p99", "iat_regularity",
    "len_entropy_up", "len_entropy_down", "len_unique_up", "len_unique_down",
    "small_pkt_share", "low_rate_long", "dir_entropy",
    "idle_gt60_count", "up_bytes_per_pkt", "down_bytes_per_pkt",
    "const_len_share_up",
    "pkt_len_p95", "psh_count", "ack_count", "urg_count",
    "flow_boundary_count",
    "burst_len_mean", "burst_len_max",
    "dir_burst_count", "dir_burst_len_mean", "dir_burst_len_max",
]
SEQ_FLAG_BITS = {"F": 1, "S": 2, "R": 4, "P": 8, ".": 16, "U": 32}

# The per-packet sequence travels as THREE array columns, not as one column per
# packet. Measured on the 2026-09-22 capture: only 4.8% of sessions run past
# 100 packets, but those sessions carry 97.0% of all packets -- so a sequence
# block that stops at 100 throws away almost all of the traffic, and throws it
# away from exactly the long sessions a behavioural model is built for.
#
# Space-separated text, because Spark splits a string into an array in plain
# SQL. The executors there have no python interpreter, so anything needing a
# UDF to be read would not be readable at all.
#
# Direction is the SIGN of the length, so there is no separate direction array;
# gaps are whole microseconds, which is the resolution the capture has.
#
# `transport_tcp` / `transport_udp` from the catalog are still not added: the
# table already carries `tcp_share` and `udp_share`, and a third encoding of one
# fact is how a model splits its weight across copies of the same signal.
# `seq_packets` is gone: the arrays are the whole session, so their length is
# `pkt_count` and a second column for it was an exact copy.
SEQ_ARRAY_NAMES = ["seq_signed_len", "seq_iat_us", "seq_flags"]


def _flag_bits(flags: str) -> int:
    bits = 0
    for ch in flags or "":
        bits |= SEQ_FLAG_BITS.get(ch, 0)
    return bits


def _sequence_arrays(pkts, client) -> dict:
    """The whole session's packet sequence, nothing dropped."""
    lens = []
    gaps = []
    flags = []
    prev = None
    for pkt in pkts:
        sign = 1 if pkt["src"] == client else -1
        lens.append(str(sign * int(pkt["length"])))
        gaps.append("0" if prev is None
                    else str(max(0, int(round((pkt["ts"] - prev) * 1_000_000)))))
        prev = pkt["ts"]
        flags.append(str(_flag_bits(pkt["flags"])))
    return {"seq_signed_len": " ".join(lens),
            "seq_iat_us": " ".join(gaps),
            "seq_flags": " ".join(flags)}


RA_NAMES = [
    "ra_small_up_count", "ra_small_up_share", "ra_keystroke_iat_p50",
    "ra_echo_ratio", "ra_echo_latency_p50", "ra_interactive_score",
    "ra_burst_after_idle", "ra_off_hours",
]

# What the session is, around the traffic itself: where its ends sit, which
# remote-access service its server port names, how its TCP handshake went and
# when it started. `admin_service_by_port` replaces the old yes/no
# `ra_known_admin_port`, which was fully derivable from it.
CONTEXT_NAMES = [
    "client_internal", "server_internal", "internal_pair", "admin_service_by_port",
    "conn_state", "tcp_handshake_rtt_ms",
    "data_pkt_up", "data_pkt_down", "small_data_up_bytes",
    "start_hour_sin", "start_hour_cos", "start_dow_sin", "start_dow_cos",
]
ADMIN_SERVICE_PORTS = {22: "ssh", 23: "telnet", 3389: "rdp", 5900: "vnc", 5901: "vnc",
                       5985: "winrm", 5986: "winrm", 445: "smb", 139: "smb", 135: "rpc",
                       4899: "radmin", 5938: "teamviewer"}


def _server_port(sess: Session, client_is_a: bool) -> int:
    """The port of the side that did not open the session. `first_dport` is
    the destination of whichever packet came first -- the client's random port
    when the capture joined a session already under way."""
    return sess.port_b if client_is_a else sess.port_a


def conn_state(sess: Session, client_is_a: bool) -> str:
    """Zeek's `conn_state`, from what each side sent over the whole session.

    Follows Zeek's own order (base/protocols/conn): a reset by the server is
    looked at first, then by the client, then the FINs, then the handshake.
    REJ SYN answered by RST · RSTRH server reset, the client never sent a SYN ·
    RSTR server reset · RSTOS0 client sent SYN then reset, the server never answered · RSTO
    client reset · SF both sides closed (FIN), whether or not the capture saw
    the start · SH / S2 only the client closed (server silent / not) · SHR / S3
    only the server closed (client silent / not) · S0 SYN, no answer · S1
    established, still open · OTH joined mid-way and not closed. A reset after
    a side's own FIN does not count. UDP: S0 one side only, SF both. For a row
    that is a part of a long session, the state at the end of that part.

    One-sided mirroring matters here: a SYN whose SYN/ACK the mirror did not see
    reads S0 exactly as one nobody answered. Zeek on the same capture says the
    same, and `down_pkt_count == 0` shows which rows are affected.
    """
    c, s = (0, 1) if client_is_a else (1, 0)
    bit = lambda flag, side: bool(sess.tcp_bits & (flag << side))
    fin_c, fin_s = (sess.fin_a, sess.fin_b) if client_is_a else (sess.fin_b, sess.fin_a)
    if sess.proto != "tcp":
        return "SF" if sess.bidirectional else "S0"
    syn, synack = bit(TCP_SYN, c), bit(TCP_SYNACK, s)
    rst_c, rst_s = bit(TCP_RST, c), bit(TCP_RST, s)
    # Zeek calls an endpoint inactive when it sent nothing, or only picked up
    # mid-way without data of its own ("partial").
    client_quiet = not bit(TCP_ANY, c) or (not syn and not bit(TCP_DATA, c))
    server_quiet = not bit(TCP_ANY, s) or (not synack and not bit(TCP_DATA, s))
    no_data = not bit(TCP_DATA, c) and not bit(TCP_DATA, s)
    if rst_s:
        if (syn and not synack and not bit(TCP_DATA, c)) or (rst_c and no_data):
            return "REJ"
        return "RSTRH" if client_quiet else "RSTR"
    if rst_c:
        if server_quiet:
            # Zeek: RSTOS0 only for a client that opened with a SYN; a reset
            # from one that joined mid-way, to a silent server, is OTH.
            return "RSTOS0" if syn and not bit(TCP_DATA, c) else "OTH"
        return "RSTO"
    if fin_c and fin_s:
        return "SF"
    if fin_c:
        return "SH" if server_quiet else "S2"
    if fin_s:
        return "SHR" if client_quiet else "S3"
    if syn and not bit(TCP_ANY, s):
        return "S0"
    if syn and synack:
        return "S1"
    return "OTH"


def _data_features(pkts, client) -> dict:
    """Packets that carried data, and the bytes in the client's short ones."""
    if any(p.get("payload", -1) < 0 for p in pkts):
        return {"data_pkt_up": None, "data_pkt_down": None, "small_data_up_bytes": None}
    up = down = small_bytes = 0
    for p in pkts:
        if p["payload"] <= 0:
            continue
        if p["src"] == client:
            up += 1
            if p["payload"] <= KEYSTROKE_PAYLOAD:
                small_bytes += p["payload"]
        else:
            down += 1
    return {"data_pkt_up": up, "data_pkt_down": down, "small_data_up_bytes": small_bytes}


def _handshake(pkts, client):
    """(completed, refused, rtt_ms) of the TCP handshake, from the first packets."""
    syn = synack = ack = None
    refused = 0
    for p in pkts[:16]:
        fl = p["flags"] or ""
        mine = p["src"] == client
        if syn is None:
            if mine and "S" in fl and "." not in fl:
                syn = p["ts"]
            continue
        if synack is None:
            if not mine and "R" in fl:
                refused = 1
                break
            if not mine and "S" in fl and "." in fl:
                synack = p["ts"]
            continue
        if mine and "." in fl and "S" not in fl:
            ack = p["ts"]
            break
    if syn is None:
        return None, None, None
    rtt = round((synack - syn) * 1000.0, 3) if synack is not None else None
    return int(ack is not None), refused, rtt


def _session_context(pkts, client, sess: Session, client_is_a: bool) -> dict:
    from datetime import datetime
    from zoneinfo import ZoneInfo

    c_priv = sess.a_private if client_is_a else sess.b_private
    s_priv = sess.b_private if client_is_a else sess.a_private
    start = datetime.fromtimestamp(pkts[0]["ts"], ZoneInfo(OFFICE_TZ))
    hour = start.hour + start.minute / 60.0
    dow = start.weekday()
    rtt = None
    # Only a session whose opening is in this row can say how it opened.
    if sess.proto == "tcp" and sess.start_observed and sess.segment_index == 0:
        _, _, rtt = _handshake(pkts, client)
    return {
        "client_internal": int(bool(c_priv)),
        "server_internal": int(bool(s_priv)),
        "internal_pair": int(bool(c_priv) and bool(s_priv)),
        "admin_service_by_port": ADMIN_SERVICE_PORTS.get(_server_port(sess, client_is_a), ""),
        "conn_state": conn_state(sess, client_is_a),
        "tcp_handshake_rtt_ms": rtt,
        **_data_features(pkts, client),
        "start_hour_sin": round(math.sin(2 * math.pi * hour / 24), 6),
        "start_hour_cos": round(math.cos(2 * math.pi * hour / 24), 6),
        "start_dow_sin": round(math.sin(2 * math.pi * dow / 7), 6),
        "start_dow_cos": round(math.cos(2 * math.pi * dow / 7), 6),
    }


def _remote_admin_features(pkts, client, sess: Session) -> dict:
    """Does this look like a person typing into a remote session?

    Counted on data packets only (see KEYSTROKE_PAYLOAD). Where the packet
    source did not carry payload lengths, the block is left empty rather than
    guessed from frame sizes.
    """
    from datetime import datetime
    from zoneinfo import ZoneInfo

    start = datetime.fromtimestamp(pkts[0]["ts"], ZoneInfo(OFFICE_TZ))
    out = {
        "ra_off_hours": int(start.weekday() >= 5
                            or not (OFFICE_HOURS[0] <= start.hour < OFFICE_HOURS[1])),
    }
    names = ("ra_small_up_count", "ra_small_up_share", "ra_keystroke_iat_p50",
             "ra_echo_ratio", "ra_echo_latency_p50", "ra_interactive_score",
             "ra_burst_after_idle")
    if any(p.get("payload", -1) < 0 for p in pkts):
        return {**out, **{n: None for n in names}}

    up_data = 0
    keys: list[float] = []          # times of the client's small data packets
    echoes: list[float] = []        # keystroke -> next server data packet
    answered = 0
    pending = None
    for p in pkts:
        if p["payload"] <= 0:
            continue                # ACKs and other empty segments say nothing here
        if p["src"] == client:
            up_data += 1
            if p["payload"] <= KEYSTROKE_PAYLOAD:
                keys.append(p["ts"])
                pending = p["ts"]
        elif pending is not None:
            lat = p["ts"] - pending
            echoes.append(lat)
            answered += lat <= ECHO_WINDOW
            pending = None
    gaps = sorted(b - a for a, b in zip(keys, keys[1:]))
    echo_p50 = _pct(sorted(echoes), 50)
    share = len(keys) / up_data if up_data else 0.0
    # The mirror sees some sessions from one side only. With no server packet
    # at all, "no echo" would be a claim the capture cannot make: empty, not 0.
    server_seen = any(p["src"] != client for p in pkts)
    if not server_seen:
        echo_ratio = echo_lat = interactive = None
    else:
        echo_ratio = answered / len(keys) if keys else 0.0
        echo_lat = echo_p50
        interactive = (share if len(keys) >= MIN_KEYSTROKES and echoes
                       and echo_p50 < INTERACTIVE_ECHO else 0.0)

    # Activity resumed after a pause of more than a minute, counted per pause.
    resumed, idle = 0, False
    for a, b in zip(pkts, pkts[1:]):
        if b["ts"] - a["ts"] > 60.0:
            idle = True
        elif idle:
            resumed += 1
            idle = False
    return {**out,
            "ra_small_up_count": len(keys),
            "ra_small_up_share": share,
            "ra_keystroke_iat_p50": _pct(gaps, 50),
            "ra_echo_ratio": echo_ratio,
            "ra_echo_latency_p50": echo_lat,
            "ra_interactive_score": interactive,
            "ra_burst_after_idle": resumed}


BURST_GAP = 0.05   # the lab's `burst_count`: packets less than 50 ms apart


def _burst_features(dirs, iats) -> dict:
    """Bursts two ways: by time and by direction.

    `burst_count` (lab schema) counts runs of packets that follow each other
    within 50 ms in either direction; here the same runs also get their length
    in packets. The direction version ignores time: a run of two or more
    packets in a row from the same side, whatever the gaps -- a request split
    over several segments, a download, a batch of keystrokes. A lone packet
    between two turns is not a burst in either version.
    """
    time_runs, run = [], 1
    for gap in iats:
        if gap < BURST_GAP:
            run += 1
        else:
            if run > 1:
                time_runs.append(run)
            run = 1
    if run > 1:
        time_runs.append(run)
    dir_runs, run = [], 1
    for a, b in zip(dirs, dirs[1:]):
        if a == b:
            run += 1
        else:
            if run > 1:
                dir_runs.append(run)
            run = 1
    if run > 1:
        dir_runs.append(run)
    mean = lambda xs: sum(xs) / len(xs) if xs else 0.0
    return {"burst_len_mean": mean(time_runs), "burst_len_max": max(time_runs, default=0),
            "dir_burst_count": len(dir_runs), "dir_burst_len_mean": mean(dir_runs),
            "dir_burst_len_max": max(dir_runs, default=0)}


def _behaviour_features(pkts, client, sess: Session) -> dict:
    n = len(pkts)
    t0, t1 = pkts[0]["ts"], pkts[-1]["ts"]
    duration = max(t1 - t0, 1e-6)
    iats, up_len, down_len, dirs = [], [], [], []
    prev = None
    idle_gt60 = 0
    for p in pkts:
        d = 1 if p["src"] == client else -1
        dirs.append(d)
        gap = 0.0 if prev is None else max(p["ts"] - prev, 0.0)
        if prev is not None:
            iats.append(gap)
            if gap > 60.0:
                idle_gt60 += 1
        prev = p["ts"]
        if d > 0:
            up_len.append(p["length"])
        else:
            down_len.append(p["length"])
    mean_iat = sum(iats) / len(iats) if iats else 0.0
    std_iat = (sum((x - mean_iat) ** 2 for x in iats) / len(iats)) ** 0.5 if iats else 0.0
    siat = sorted(iats)
    up_b, down_b = sum(up_len), sum(down_len)
    total_b = up_b + down_b
    # Quantised so that "the same interval over and over" is measurable rather
    # than defeated by microsecond jitter.
    q_iat = [round(x, 3) for x in iats]
    q_counts = Counter(q_iat)
    row = {
        "iat_entropy": _entropy(q_iat),
        "iat_cv": (std_iat / mean_iat) if mean_iat > 0 else 0.0,
        "iat_p50": _pct(siat, 50),
        "iat_p99": _pct(siat, 99),
        "iat_regularity": (q_counts.most_common(1)[0][1] / len(q_iat)) if q_iat else 0.0,
        "len_entropy_up": _entropy(up_len),
        "len_entropy_down": _entropy(down_len),
        "len_unique_up": len(set(up_len)),
        "len_unique_down": len(set(down_len)),
        "small_pkt_share": sum(1 for p in pkts if p["length"] < SMALL_PACKET) / n,
        "low_rate_long": int(duration > 300.0 and (total_b / duration) < 1000.0),
        "dir_entropy": _entropy(dirs),
        "idle_gt60_count": idle_gt60,
        "up_bytes_per_pkt": (up_b / len(up_len)) if up_len else 0.0,
        "down_bytes_per_pkt": (down_b / len(down_len)) if down_len else 0.0,
        "const_len_share_up": (Counter(up_len).most_common(1)[0][1] / len(up_len)) if up_len else 0.0,
        **_burst_features(dirs, iats),
        **_remote_admin_features(pkts, client, sess),
        "pkt_len_p95": _pct(sorted(p["length"] for p in pkts), 95),
        "psh_count": sum(1 for p in pkts if "P" in (p["flags"] or "")),
        "ack_count": sum(1 for p in pkts if "." in (p["flags"] or "")),
        "urg_count": sum(1 for p in pkts if "U" in (p["flags"] or "")),
        # A bare SYN inside a session that is already running is a restart the
        # instance rule chose not to split on -- worth counting, not hiding.
        "flow_boundary_count": sum(
            1 for p in pkts[1:]
            if "S" in (p["flags"] or "") and "." not in (p["flags"] or "")),
    }
    return row


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--pcap-dir", required=True)
    ap.add_argument("--glob", default="chunk-*.pcap")
    ap.add_argument("--out-sessions", required=True)
    ap.add_argument("--out-lots-conns", required=True)
    ap.add_argument("--stats-json", default="")
    ap.add_argument("--name-map", default="", help="write host_key -> address here; keep it local")
    ap.add_argument("--session-index", default="",
                    help="private index (addresses + time span + uid) for the payload pass; never upload")
    ap.add_argument("--salt-file", default="~/.office_iter_salt")
    ap.add_argument("--min-packets", type=int, default=4)
    # The wide `ext_*` block is off by default now: the arrays carry the whole
    # sequence, nothing in the repository reads `ext_*`, and 320 columns that
    # stop at packet 100 are cost without a reader. Pass a value above SEQ_N to
    # get it back.
    ap.add_argument("--seq-ext", type=int, default=0)
    ap.add_argument("--max-held-packets", type=int, default=MAX_HELD_PACKETS,
                    help="emit a numbered segment once an open session holds this many packets")
    ap.add_argument("--state-in", type=Path, help="checkpoint from the previous batch")
    ap.add_argument("--state-out", type=Path, help="checkpoint for the next batch")
    ap.add_argument("--shard-index", type=int, default=0)
    ap.add_argument("--shard-count", type=int, default=1,
                    help="process only the flows of shard k of N (packet rows only)")
    ap.add_argument("--live-out", type=Path,
                    help="flows still open at the end of this batch (private: addresses)")
    ap.add_argument("--finalize", action="store_true",
                    help="emit still-open sessions as explicitly truncated; otherwise save them")
    args = ap.parse_args()

    salt_path = Path(os.path.expanduser(args.salt_file))
    if not salt_path.exists():
        salt_path.write_bytes(os.urandom(32))
        salt_path.chmod(0o600)
    salt = salt_path.read_bytes()

    pcaps = sorted(Path(args.pcap_dir).glob(args.glob))
    # With a checkpoint and --finalize, no files is a real request: the capture
    # ended after the last batch was cut, and what is still open has to be
    # written out as truncated rather than left in a pickle.
    if not pcaps and not (args.state_in and args.finalize):
        print(json.dumps({"status": "error", "reason": "no pcap matched"}))
        return 1

    seq_ext = max(args.seq_ext, 0)
    cols = (list(SCALAR_FEATURE_NAMES)
            + (ext_names(SEQ_N, seq_ext) if seq_ext > SEQ_N else [])
            + SEQ_ARRAY_NAMES + CC_NAMES + RA_NAMES + CONTEXT_NAMES
            + ["proto", "dest_port", "host_key", "server_key", "session_uid",
               "segment_uid", "segment_index", "session_continues",
               "time_bucket", "session_start_epoch", "start_observed",
               "truncated_at_capture_end", "closed_cleanly",
               "out_of_scope_vpn",
               "y_presumed", "label_source", "label_family"])
    lots_cols = ["ts", "duration", "bytes_up", "bytes_down", "host", "dst",
                 "dest_port", "proto", "session_uid", "segment_uid"]

    stats = Counter()
    name_map: dict[str, str] | None = {} if args.name_map else None
    wall0 = time.time()
    sp = Path(args.out_sessions)
    lp = Path(args.out_lots_conns)
    sp.parent.mkdir(parents=True, exist_ok=True)
    with sp.open("w", newline="", encoding="utf-8") as sfh, \
         lp.open("w", newline="", encoding="utf-8") as lfh:
        sw = csv.DictWriter(sfh, fieldnames=cols)
        sw.writeheader()
        lw = csv.DictWriter(lfh, fieldnames=lots_cols)
        lw.writeheader()
        index_fh = None
        iw = None
        if args.session_index:
            index_fh = open(args.session_index, "w", newline="", encoding="utf-8")
            os.chmod(args.session_index, 0o600)
            iw = csv.writer(index_fh)
            iw.writerow(["ip_a", "port_a", "ip_b", "port_b", "proto",
                         "t_start", "t_end", "segment_uid",
                         "client_ip", "client_port"])
        try:
            for row, lots, idx in session_rows(
                pcaps, salt, seq_ext, args.min_packets, stats, name_map,
                state_in=args.state_in, state_out=args.state_out,
                finalize=args.finalize or args.state_out is None,
                max_held=args.max_held_packets, live_out=args.live_out,
                shard=(args.shard_index, args.shard_count),
            ):
                sw.writerow(row)
                lw.writerow(lots)
                if iw is not None:
                    iw.writerow(idx)
        finally:
            if index_fh is not None:
                index_fh.close()

    if name_map is not None:
        Path(args.name_map).write_text(json.dumps(name_map, indent=1))
        Path(args.name_map).chmod(0o600)

    report = {
        "status": "ok",
        "pcap_files": len(pcaps),
        "sessions_csv": str(sp),
        "lots_conns_csv": str(lp),
        "seconds": round(time.time() - wall0, 1),
        "seq_ext": seq_ext,
        **{k: int(v) for k, v in stats.items()},
        "note": "one row per session SEGMENT; segment_uid is unique, session_uid repeats across the segments of one instance; a reused 4-tuple is a new instance",
    }
    print(json.dumps(report))
    if args.stats_json:
        Path(args.stats_json).write_text(json.dumps(report, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
