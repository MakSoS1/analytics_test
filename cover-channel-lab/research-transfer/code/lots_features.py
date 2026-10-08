#!/usr/bin/env python3
"""Sensor-agnostic feature contract for the LoTS NGFW detector.

ONE definition of the feature vector, THREE readers that normalize into it (Suricata eve.json for
production, Zeek conn.log/ssl.log in either TSV or JSON form for training corpora). The point of
the shared canonical connection schema is that a feature can never mean one thing at training
time and another at inference time -- the failure mode that cost this project three separate
reporting corrections.

Why the feature set and the grid are what they are
--------------------------------------------------
Everything below is a measurement on the full pilot_v4 corpus (1231 campaigns, 12 pairs, 6
services) scored against 2425 host-hours of real office traffic. See `WINDOW_SWEEP.md`.

* `WINDOW_S = 1200`, `STRIDE_S = 600`. Swept 60/120/180/300/600/900/1200/1800/2700 over 5
  redraws of the background split. Incident recall:

      60 s  0.138          600 s  0.846 +-0.015
     120 s  0.315 +-0.249  900 s  0.863 +-0.038
     180 s  0.499 +-0.137 1200 s  0.897 +-0.020   <- plateau starts
     300 s  0.726 +-0.059 1800 s  0.896 +-0.021
                          2700 s  0.835

  Short windows do not merely lose a little: at 120 s recall is 0.315 with a 0.249 standard
  deviation -- the model is unstable, not just weak. 300 s (the previous shipped value) sits
  well below the plateau. 1800 s ties 1200 s within noise but costs 50 % more detection latency
  and state, and is worse on staging (0.871 vs 0.902), so 1200 s is the pick.

  NOTE the earlier rationale for 300 s ("campaigns run ~500 s so a 120 s window cannot hold an
  exfil episode") does not survive contact with the corpus: `lots_exfiltration` campaigns have a
  MEDIAN SPAN OF 0 s -- they are bursts. It is `lots_c2` that runs long (median 573 s). Window
  length matters because it sets the scale of `active_fraction`, `conns_per_min` and
  `longest_idle_frac`, not because it has to contain an episode.

* **`n_distinct_ja3` / `n_distinct_ja4` are EXCLUDED.** In the shipped 300 s model they carried
  0.01 % of gain between them (7 and 2 splits, both at threshold 0.0) -- forcing them to a
  non-empty value left the alert count bit-identical. They are also actively dangerous: office
  Zeek logs have no such column, so the value is 0 in 100 % of office windows against 1 in the
  lab, and the moment real background was added as a negative class LightGBM took **41 % + 29 %
  of its gain** on that difference and reported a perfect, entirely fake, separation. Identical
  failure to `resumed_fraction`; caught only by ablation, never by importance rank. They are
  still parsed into the canonical record so a corpus with real client-stack variety can re-test
  them -- but a model must not consume them until that corpus exists.

* **Seven CV/IAT features are EXCLUDED** (`iat_mean`, `iat_median`, `iat_cv`,
  `periodicity_score`, `conn_dur_cv`, `orig_bytes_cv`, `resp_bytes_cv`). They are undefined when
  a window holds <2 connections, and definedness correlates with class, so a tree learns the NaN
  branch as a label. Dropping them costs nothing.

* **`resumed_fraction` is EXCLUDED.** Not portable across sensors: on the identical browser pcap
  Zeek reports 30.76 % resumed and Suricata 4.90 % -- the two infer TLS-1.3 resumption
  differently.

* **Bytes are IP bytes (header-inclusive) on both sides**, because that is what Suricata's
  `flow.bytes_toserver`/`bytes_toclient` are and there is no payload-only equivalent.

* **Duration comes from `flow.start`/`flow.end`, never `flow.age`** (`age` is integer seconds).

* **The window grid is anchored on absolute epoch**, not on a key's first packet. The previous
  code used `t0 = first connection of this key`, which gave every key its own phase and moved
  the grid between ticks -- the same traffic scored twice produced different features. A live
  stream needs a grid that does not depend on when a key happened to start.
"""
from __future__ import annotations

import gzip
import json
import math
import statistics
from collections import defaultdict
from datetime import datetime
from pathlib import Path

WINDOW_S = 1200.0
STRIDE_S = 600.0

# The 12 always-defined model features. Order is the model's input order -- never reorder.
FEATURES = [
    "n_conns", "conns_per_min", "active_fraction", "longest_idle_frac",
    "conn_dur_mean",
    "orig_bytes_mean", "resp_bytes_mean", "up_down_ratio", "bytes_up", "bytes_down",
    "n_distinct_dst", "resp_over_orig_max",
]

EXCLUDED_WITH_REASON = {
    "iat_mean": "undefined at <2 conns; definedness correlates with class",
    "iat_median": "same",
    "iat_cv": "same",
    "periodicity_score": "same",
    "conn_dur_cv": "same",
    "orig_bytes_cv": "same",
    "resp_bytes_cv": "same",
    "resumed_fraction": "not portable across sensors: Zeek 30.8% vs Suricata 4.9% on one pcap",
    "n_distinct_ja3": "0.01% gain, AND a perfect office-vs-lab corpus identifier (41% gain "
                      "when real background negatives are added). Parsed, never fed to a model.",
    "n_distinct_ja4": "same",
}


def _parse_ts(s) -> float:
    """Suricata timestamps are ISO-8601 with offset; Zeek's are epoch floats."""
    if isinstance(s, (int, float)):
        return float(s)
    try:
        return datetime.fromisoformat(str(s)).timestamp()
    except ValueError:
        return float("nan")


def _num(x, default=0.0) -> float:
    try:
        return float(x)
    except (TypeError, ValueError):
        return default


# =====================================================================================
# Canonical connection record. Every reader MUST produce exactly these keys.
#   ts, duration, bytes_up, bytes_down, host, service, dst, ja3, ja4, has_sni
# =====================================================================================

def read_suricata_eve(path: Path, offset: int = 0,
                      end_offset: int | None = None) -> tuple[list[dict], int]:
    """Suricata eve.json -> canonical records. Production reader.

    Joins `event_type: flow` (the bidirectional record; NOT `netflow`, which is unidirectional
    and would double-count) with `event_type: tls` on `flow_id` for SNI/JA3/JA4.

    Reads from `offset` and returns the new offset, so a tick costs the bytes appended since
    the last tick rather than the whole file. On a live appliance eve.json reaches tens of GB;
    re-reading it every tick is quadratic and was the single largest runtime defect here.
    """
    tls: dict[int, dict] = {}
    flows: list[dict] = []
    with open(path, "r", errors="replace") as fh:
        fh.seek(offset)
        # readline(), а не `for line in fh`: итератор файла включает буферизацию с забеганием
        # вперёд, и Python запрещает tell() внутри неё ("telling position disabled by next()").
        # Позиция нужна на каждой строке, чтобы соблюдать end_offset.
        while True:
            if end_offset is not None and fh.tell() >= end_offset:
                break
            line = fh.readline()
            if not line:
                break
            line = line.strip()
            if not line or line[0] != "{":
                continue
            try:
                d = json.loads(line)
            except ValueError:
                continue
            et = d.get("event_type")
            if et == "tls":
                fid = d.get("flow_id")
                if fid is not None:
                    tls[fid] = d.get("tls", {})
            elif et == "flow":
                flows.append(d)
        new_offset = fh.tell()

    out = []
    for d in flows:
        f = d.get("flow", {})
        start, end = _parse_ts(f.get("start")), _parse_ts(f.get("end"))
        if start != start:
            continue
        dur = (end - start) if (end == end and end >= start) else 0.0
        t = tls.get(d.get("flow_id"), {})
        ja3 = (t.get("ja3") or {}).get("hash") if isinstance(t.get("ja3"), dict) else t.get("ja3")
        sni = t.get("sni") or ""
        out.append({
            "ts": start, "duration": dur,
            "bytes_up": _num(f.get("bytes_toserver")),
            "bytes_down": _num(f.get("bytes_toclient")),
            "host": str(d.get("src_ip", "?")),
            "service": sni or str(d.get("dest_ip") or "unknown"),
            "dst": str(d.get("dest_ip") or ""),
            "ja3": ja3 or "", "ja4": t.get("ja4") or "",
            "has_sni": bool(sni),
        })
    out.sort(key=lambda r: r["ts"])
    return out, new_offset


def _open_maybe_gz(p: Path):
    return gzip.open(p, "rt", errors="replace") if p.suffix == ".gz" \
        else open(p, "r", errors="replace")


def _zeek_rows(zeek_dir: Path, name: str) -> list[dict]:
    """Zeek logs come in TSV (`#fields` header) or JSON-lines. Production Zeek deployments
    overwhelmingly ship JSON; the previous reader handled only TSV and returned an empty list
    on JSON without saying so."""
    for cand in (zeek_dir / name, zeek_dir / f"{name}.gz"):
        if not cand.exists():
            continue
        rows, fields = [], []
        with _open_maybe_gz(cand) as fh:
            for line in fh:
                line = line.rstrip("\n")
                if not line:
                    continue
                if line[0] == "{":
                    try:
                        rows.append(json.loads(line))
                    except ValueError:
                        pass
                elif line.startswith("#fields"):
                    fields = line.split("\t")[1:]
                elif line[0] == "#":
                    continue
                elif fields:
                    parts = line.split("\t")
                    if len(parts) == len(fields):
                        rows.append(dict(zip(fields, parts)))
        return rows
    return []


def read_zeek(zeek_dir: Path) -> list[dict]:
    """Zeek conn.log + ssl.log (TSV or JSON) -> the SAME canonical records.

    Uses `orig_ip_bytes`/`resp_ip_bytes` (header-inclusive) so the quantity matches Suricata's
    `bytes_toserver`/`bytes_toclient`. Falls back to payload bytes only if the ip_bytes columns
    are absent, and that is a degraded path -- a model trained on the fallback must not be
    scored on Suricata output.
    """
    conns = _zeek_rows(zeek_dir, "conn.log")
    ssl = {r.get("uid"): r for r in _zeek_rows(zeek_dir, "ssl.log")}

    out = []
    for c in conns:
        ts = _num(c.get("ts"), float("nan"))
        if ts != ts:
            continue
        s = ssl.get(c.get("uid"), {})
        up, down = c.get("orig_ip_bytes"), c.get("resp_ip_bytes")
        if up in (None, "", "-"):
            up, down = c.get("orig_bytes"), c.get("resp_bytes")
        sni = s.get("server_name", "")
        sni = "" if sni in ("-", None) else sni
        ja3 = s.get("ja3", "")
        ja4 = s.get("ja4", "")
        out.append({
            "ts": ts, "duration": _num(c.get("duration")),
            "bytes_up": _num(up), "bytes_down": _num(down),
            "host": str(c.get("id.orig_h", "?")),
            "service": sni or str(c.get("id.resp_h") or "unknown"),
            "dst": str(c.get("id.resp_h") or ""),
            "ja3": "" if ja3 in ("-", None) else ja3,
            "ja4": "" if ja4 in ("-", None) else ja4,
            "has_sni": bool(sni),
        })
    out.sort(key=lambda r: r["ts"])
    return out


def in_scope(c: dict) -> bool:
    """The model's scope is TLS sessions to named services. Without this filter the detector
    also scores DNS, NTP and internal RPC, whose `service` is a bare dest_ip -- measured on the
    office corpus, scoping here removes 58 % of keys and 2.13x of the alert volume, and the
    smoke test's single loudest alert was a flow to the default gateway."""
    return bool(c.get("has_sni"))


# =====================================================================================
# The feature vector
# =====================================================================================

def window_row(conns: list[dict], window_s: float) -> dict:
    """Every feature here is defined for n_conns >= 1. That is the whole design constraint:
    no NaN branch can encode the label (see module docstring).

    Normalised by the window LENGTH, not by the observed span, so the value of a feature does
    not depend on where inside the window the traffic happened to fall.
    """
    if not conns:
        return {f: 0.0 for f in FEATURES}

    starts = sorted(c["ts"] for c in conns)
    gaps = [starts[i + 1] - starts[i] for i in range(len(starts) - 1)]
    durs = [c["duration"] for c in conns]
    up = [c["bytes_up"] for c in conns]
    down = [c["bytes_down"] for c in conns]
    bu, bd = sum(up), sum(down)
    ratios = [(c["bytes_down"] / c["bytes_up"]) if c["bytes_up"] > 0 else 0.0 for c in conns]

    return {
        "n_conns": float(len(conns)),
        "conns_per_min": len(conns) / (window_s / 60.0),
        "active_fraction": min(1.0, sum(durs) / window_s),
        # no gap -> one idle stretch of the whole window; keeps this defined at n_conns == 1
        "longest_idle_frac": (max(gaps) / window_s if gaps else 1.0),
        "conn_dur_mean": statistics.fmean(durs),
        "orig_bytes_mean": statistics.fmean(up),
        "resp_bytes_mean": statistics.fmean(down),
        "up_down_ratio": (bu / bd) if bd > 0 else float(bu),
        "bytes_up": float(bu), "bytes_down": float(bd),
        "n_distinct_dst": float(len({c["dst"] for c in conns if c["dst"]})),
        # "small request -> large response" asymmetry, the retrieval signal; max rather than
        # mean so one big pull inside an otherwise quiet window still shows
        "resp_over_orig_max": float(max(ratios)) if ratios else 0.0,
    }


def key_of(c: dict, key: str = "host_service") -> tuple:
    return (c["host"], c["service"]) if key == "host_service" else (c["host"],)


def tile_key(conns: list[dict], window_s: float = WINDOW_S, stride_s: float = STRIDE_S,
             t_from: float | None = None, t_to: float | None = None) -> list[dict]:
    """Windows for ONE key, on a grid anchored to absolute epoch.

    `floor(t / stride) * stride` means window boundaries are the same for every key and every
    tick, so the same traffic always produces the same feature vector. The previous per-key
    origin made features depend on when the key's first packet arrived.
    """
    if not conns:
        return []
    lo = min(c["ts"] for c in conns) if t_from is None else t_from
    hi = max(c["ts"] + (c["duration"] or 0.0) for c in conns) if t_to is None else t_to
    start = math.floor(lo / stride_s) * stride_s
    rows, idx = [], 0
    while start < max(hi, lo + window_s):
        end = start + window_s
        inside = [c for c in conns if start <= c["ts"] < end]
        rows.append({"window_index": idx, "window_start_epoch": start,
                     **window_row(inside, window_s)})
        idx += 1
        start += stride_s
    n = len(rows)
    for r in rows:
        r["n_windows_in_key"] = n
        r["row_weight"] = 1.0 / n      # windows of one key are not independent samples
    return rows


def tile_key_streaming(conns: list[dict], window_s: float, stride_s: float,
                       horizon: float) -> list[dict]:
    """Окна для потокового режима: те же, что у `tile_key`, но НЕПОЛНЫЕ отброшены.

    Сайдкар хранит только последние секунды истории ключа. Окно `[T, T+window)` посчитано верно
    только если сохранены все соединения с `ts` в этом интервале, то есть если `T >= horizon`.
    Без этой проверки самое старое окно каждого тика считается по обрезанным данным и расходится
    с офлайновым: измерено — 13 окон из 151 на синтетике, у одного `n_conns` 1 против 2 и
    `bytes_up` 121 793 против 405 619.

    Это и есть критерий приёмки «offline и streaming формируют одинаковые окна и признаки».
    """
    return [r for r in tile_key(conns, window_s, stride_s)
            if r["window_start_epoch"] >= horizon]


def build_windows(conns: list[dict], window_s: float = WINDOW_S, stride_s: float = STRIDE_S,
                  key: str = "host_service", scope: bool = True) -> list[dict]:
    """Tile the absolute grid per key. `scope=True` keeps only TLS-with-SNI connections."""
    if scope:
        conns = [c for c in conns if in_scope(c)]
    buckets: dict[tuple, list[dict]] = defaultdict(list)
    for c in conns:
        buckets[key_of(c, key)].append(c)

    rows = []
    for k, cs in buckets.items():
        cs.sort(key=lambda r: r["ts"])
        for r in tile_key(cs, window_s, stride_s):
            r["host"] = k[0]
            r["service"] = k[1] if len(k) > 1 else ""
            rows.append(r)
    return rows
