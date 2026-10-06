#!/usr/bin/env python3
"""Check every number the office pipeline produces against tools that share none
of its code: Wireshark's tshark for packets, Zeek for connections.

The pipeline parses frames itself, stitches sessions itself and fingerprints TLS
itself. A test suite written by the same hand checks that the code does what the
author meant; it cannot check that the author meant the right thing. Two
independent parsers can.

What is compared, and against what:

  packets     each TCP/UDP row -- time, on-wire length, ports, payload length,
              flags -- against the same frame in tshark, in order
  arrays      each session's `seq_signed_len`, `seq_iat_us`, `seq_flags`
              rebuilt from tshark's frames for that 4-tuple and time span
  sessions    packets, IP bytes and duration against Zeek's conn.log
  TLS         JA4, SNI and ALPN against tshark's own TLS dissector
  DNS         query types against tshark's DNS dissector
  damage      malformed frames, bad checksums, retransmissions, capture gaps --
              counted by tshark and Zeek, set beside what the pipeline counted

Everything reported is a count of agreements and disagreements, with examples
of the disagreements. A "match rate" without the examples would hide exactly the
cases worth reading.
"""
from __future__ import annotations

import argparse
import csv
import json
import struct
import subprocess
import sys
from collections import Counter, defaultdict
from pathlib import Path

csv.field_size_limit(1 << 24)
HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))

ROW = struct.Struct("<d8s8sHHHHBBB")
EPS = 2e-6

FIELDS = [
    "frame.number", "frame.time_epoch", "frame.len", "frame.cap_len",
    "ip.proto", "ipv6.nxt", "ip.frag_offset",
    "ip.src", "ipv6.src", "ip.dst", "ipv6.dst",
    "tcp.srcport", "tcp.dstport", "udp.srcport", "udp.dstport",
    "tcp.flags", "tcp.len", "udp.length",
    "tls.handshake.type", "tls.handshake.ja4",
    "tls.handshake.extensions_server_name", "tls.handshake.extensions_alpn_str",
    "dns.flags.response", "dns.qry.type",
    "_ws.expert.message", "frame.protocols", "tls.handshake.ja4_r",
]

# FoxIO: «ignore GREASE values anywhere it sees them»; эталонный
# get_signature_algorithms() заканчивается фильтром по GREASE_TABLE.
# tshark 4.2.2 оставляет GREASE в sigalgs, поэтому его JA4 сравнивается ещё и
# в приведённом к спецификации виде.
GREASE_HEX = {f"{0x0a0a + 0x1010 * i:04x}" for i in range(16)}


def ja4_per_spec(ja4: str, raw: str) -> str:
    import hashlib
    r = raw.split("_")
    if len(r) < 3:
        return ja4
    sig = [x for x in (r[3].split(",") if len(r) > 3 and r[3] else []) if x not in GREASE_HEX]
    c = hashlib.sha256((r[2] + ("_" + ",".join(sig) if sig else "")).encode()).hexdigest()[:12]
    return "_".join(ja4.split("_")[:2] + [c])


def run_tshark(pcap: Path, out: Path) -> None:
    cmd = ["tshark", "-r", str(pcap), "-n",
           # Кадры классифицируются так же, как у нас: без сборки IP-фрагментов.
           "-o", "ip.defragment:FALSE",
           # Контрольные суммы tshark по умолчанию не проверяет.
           "-o", "ip.check_checksum:TRUE", "-o", "tcp.check_checksum:TRUE",
           "-o", "udp.check_checksum:TRUE",
           "-T", "fields", "-E", "separator=\t", "-E", "occurrence=a",
           "-E", "aggregator=|"]
    for f in FIELDS:
        cmd += ["-e", f]
    with out.open("w") as fh:
        subprocess.run(cmd, stdout=fh, stderr=subprocess.DEVNULL, check=True)


def first(v: str) -> str:
    return v.split("|", 1)[0] if v else ""


def read_frames(tsv: Path):
    with tsv.open() as fh:
        for line in fh:
            parts = line.rstrip("\n").split("\t")
            parts += [""] * (len(FIELDS) - len(parts))
            yield dict(zip(FIELDS, parts))


def is_row(f: dict) -> tuple | None:
    """The frame in the pipeline's terms, or None if it is not a session packet."""
    proto = first(f["ip.proto"]) or first(f["ipv6.nxt"])
    if proto not in ("6", "17"):
        return None
    frag = first(f["ip.frag_offset"])
    if frag and frag != "0":
        return None
    src = first(f["ip.src"]) or first(f["ipv6.src"])
    dst = first(f["ip.dst"]) or first(f["ipv6.dst"])
    if proto == "6":
        sp, dp = first(f["tcp.srcport"]), first(f["tcp.dstport"])
        if not sp:
            return None
        paylen = int(first(f["tcp.len"]) or 0)
        flags = int(first(f["tcp.flags"]) or "0", 16) & 0xFF
    else:
        sp, dp = first(f["udp.srcport"]), first(f["udp.dstport"])
        if not sp:
            return None
        ul = first(f["udp.length"])
        paylen = max(0, int(ul) - 8) if ul else 0
        flags = 0
    return (float(f["frame.time_epoch"]), int(f["frame.len"]), src, int(sp),
            dst, int(dp), int(proto), paylen, flags, int(f["frame.number"]))


def load_rows(path: Path):
    data = path.read_bytes()
    for off in range(0, len(data), ROW.size):
        yield ROW.unpack_from(data, off)


def quic_and_capwap(V: Path, addresses: dict, index: dict, sessions: dict) -> dict:
    """QUIC hellos and the CAPWAP mark, from the pipeline's own session table."""
    import payload_sidecar as ps
    import extract_payload_features as epf
    names = json.loads((V / "sni_names.json").read_text()) if (V / "sni_names.json").exists() else {}

    # tshark: ClientHello внутри QUIC, по внешнему UDP 4-tuple
    out = subprocess.run(["tshark", "-r", str(V / "v.pcap"), "-n", "-Y",
                          "quic && tls.handshake.type==1 && !capwap", "-T", "fields",
                          "-E", "separator=/t", "-E", "occurrence=f",
                          "-e", "ip.src", "-e", "udp.srcport", "-e", "ip.dst", "-e", "udp.dstport",
                          "-e", "tls.handshake.ja4", "-e", "tls.handshake.ja4_r",
                          "-e", "tls.handshake.extensions_server_name",
                          "-e", "tls.handshake.extensions_alpn_str"],
                         capture_output=True, text=True).stdout
    ts_q = {}
    for line in out.splitlines():
        s_, sp, d, dp, j, raw, sni, alpn = (line.split("\t") + [""] * 8)[:8]
        key = frozenset([(s_, int(sp or 0)), (d, int(dp or 0))])
        spec = ja4_per_spec(j, raw)
        # Спецификация FoxIO: «QUIC="q"»; tshark 4.2.2 пишет «u».
        spec = ("q" + spec[1:]) if spec.startswith("u") else spec
        ts_q.setdefault(key, {"ja4": spec, "sni": sni, "alpn": alpn})

    # наша таблица сессий
    ours = {}
    for uid, s_ in sessions.items():
        ix = index[uid]
        key = frozenset([(addresses[ix["ip_a"]], int(ix["port_a"])),
                         (addresses[ix["ip_b"]], int(ix["port_b"]))])
        ours.setdefault(key, []).append(s_)

    # наш сырой JA4 для QUIC — тем же кодом сайдкара, но без соли
    class RawKeys(ps.SidecarWriter):
        def _key(self, value):
            return value
    w = RawKeys(b"x", names=None)
    for ts, src, sport, dst, dport, proto, payload, ipb in epf.iter_packets(V / "v.pcap"):
        w.add(ts, src.encode(), sport, dst.encode(), dport,
              6 if proto == "tcp" else 17, ipb, payload)
    raw_ja4 = {}
    for fp in [*w._done, *w._flows.values()]:
        if fp.tls_flags & ps.TLS_JA4 and fp.tls_flags & ps.TLS_OVER_QUIC:
            raw_ja4.setdefault(frozenset([(fp.a_key.decode(), fp.a_port),
                                          (fp.b_key.decode(), fp.b_port)]), fp.ja4_key)

    q = Counter()
    ex = []
    for key, t in ts_q.items():
        rows = ours.get(key, [])
        have = [r for r in rows if r.get("tls_ja4_present") == "1"]
        if not have:
            q["tshark видит QUIC-ClientHello, в таблице JA4 нет"] += 1
            continue
        r = have[0]
        sni = names.get(r.get("service_key", ""), "")
        alpn_col = next((c for c in ("tls_alpn_h2", "tls_alpn_h3", "tls_alpn_http11",
                                     "tls_alpn_other") if r.get(c) == "1"), "")
        want = {1: "tls_alpn_h2", 2: "tls_alpn_h3", 3: "tls_alpn_http11", 4: "tls_alpn_other"}
        checks = {
            "SNI": sni == t["sni"],
            "ALPN": alpn_col == want.get(ps.alpn_category(t["alpn"]), ""),
            "JA4 (сырой, по спецификации)": raw_ja4.get(key) == t["ja4"],
        }
        for name, ok in checks.items():
            q[f"{name}: {'совпало' if ok else 'расходится'}"] += 1
            if not ok and len(ex) < 4:
                ex.append({"поле": name, "tshark": t, "наш JA4": raw_ja4.get(key), "наш SNI": sni})

    # CAPWAP: флаг против кадров, которые tshark распознал как CAPWAP
    # «capwap» у tshark — это только управляющий канал; данные — «capwap.data».
    out = subprocess.run(["tshark", "-r", str(V / "v.pcap"), "-n", "-Y", "capwap || capwap.data",
                          "-T", "fields", "-E", "separator=/t", "-E", "occurrence=f",
                          "-e", "ip.src", "-e", "udp.srcport", "-e", "ip.dst", "-e", "udp.dstport"],
                         capture_output=True, text=True).stdout
    cap_frames = Counter()
    for line in out.splitlines():
        s_, sp, d, dp = (line.split("\t") + [""] * 4)[:4]
        cap_frames[frozenset([(s_, int(sp or 0)), (d, int(dp or 0))])] += 1
    flagged = {k for k, rows in ours.items() if any(r.get("is_capwap_tunnel") == "1" for r in rows)}
    c = {
        "сессий-носителей по tshark": len(cap_frames),
        "помечено у нас is_capwap_tunnel=1": len(flagged),
        "tshark видит, у нас не помечено": len(set(cap_frames) - flagged),
        "помечено у нас, у tshark не CAPWAP": len(flagged - set(cap_frames)),
        "CAPWAP-кадров у tshark": sum(cap_frames.values()),
        "capwap_packets у нас (сумма)": sum(int(r.get("capwap_packets") or 0)
                                           for k in flagged for r in ours[k]),
    }
    return {"QUIC ClientHello у tshark": len(ts_q), "QUIC": dict(q), "примеры QUIC": ex,
            "CAPWAP": c}


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--dir", type=Path, required=True)
    args = ap.parse_args()
    V = args.dir
    report: dict = {}

    tsv = V / "tshark.tsv"
    if not tsv.exists():
        run_tshark(V / "v.pcap", tsv)
    addresses = json.loads((V / "addresses.json").read_text())

    # --- A. пакеты -------------------------------------------------------
    frames = list(read_frames(tsv))
    ts_rows = [r for r in (is_row(f) for f in frames) if r]
    ours = list(load_rows(next((V / "rows").glob("*.pkts"))))
    mism = Counter()
    examples = []
    for o, t in zip(ours, ts_rows):
        ts, sk, dk, origlen, sport, dport, paylen, proto, flags, meta = o
        tts, tlen, tsrc, tsp, tdst, tdp, tproto, tpay, tflags, fno = t
        checks = {
            "время": abs(ts - tts) <= EPS,
            "длина на проводе": origlen == tlen,
            "src адрес": addresses.get(sk.hex()) == tsrc,
            "dst адрес": addresses.get(dk.hex()) == tdst,
            "порты": (sport, dport) == (tsp, tdp),
            "протокол": proto == tproto,
            "длина payload": paylen == tpay,
            "TCP-флаги": flags == tflags,
        }
        for k, ok in checks.items():
            if not ok:
                mism[k] += 1
                if len(examples) < 8:
                    examples.append({"кадр": fno, "поле": k,
                                     "у нас": {"время": ts, "длина на проводе": origlen,
                                               "длина payload": paylen, "TCP-флаги": flags,
                                               "порты": (sport, dport)}.get(k),
                                     "tshark": {"время": tts, "длина на проводе": tlen,
                                                "длина payload": tpay, "TCP-флаги": tflags,
                                                "порты": (tsp, tdp)}.get(k)})
    report["A_пакеты"] = {
        "кадров всего (tshark)": len(frames),
        "сессионных пакетов: tshark": len(ts_rows),
        "сессионных пакетов: у нас": len(ours),
        "сравнено попарно": min(len(ours), len(ts_rows)),
        "расхождений по полям": dict(mism) or 0,
        "примеры": examples,
    }

    # --- B. массивы сессий -----------------------------------------------
    by_tuple = defaultdict(list)
    for r in ts_rows:
        ts, tlen, src, sp, dst, dp, proto, pay, flags, fno = r
        a, b = (src, sp), (dst, dp)
        key = (min(a, b), max(a, b), proto)
        by_tuple[key].append(r)
    index = {}
    with (V / "out/index.csv").open(newline="") as fh:
        for r in csv.DictReader(fh):
            index[r["segment_uid"]] = r
    from lab_pipeline.extract_lab_features import MAX_ETHERNET_FRAME  # noqa
    arr_ok = arr_bad = arr_skip_jumbo = 0
    arr_fields = Counter()
    arr_examples = []
    sessions = {}
    with (V / "out/office_sessions.csv").open(newline="") as fh:
        for s in csv.DictReader(fh):
            sessions[s["segment_uid"]] = s
    for uid, s in sessions.items():
        ix = index[uid]
        ipa, ipb = addresses[ix["ip_a"]], addresses[ix["ip_b"]]
        pa, pb = int(ix["port_a"]), int(ix["port_b"])
        proto = 6 if s["proto"] == "tcp" else 17
        a, b = (ipa, pa), (ipb, pb)
        key = (min(a, b), max(a, b), proto)
        t0, t1 = float(ix["t_start"]), float(ix["t_end"])
        pk = [r for r in by_tuple.get(key, []) if t0 - EPS <= r[0] <= t1 + EPS]
        if any(r[1] > MAX_ETHERNET_FRAME for r in pk):
            arr_skip_jumbo += 1
            continue
        client = (addresses[ix["client_ip"]], int(ix["client_port"]))
        exp_len = " ".join(str(r[1] if (r[2], r[3]) == client else -r[1]) for r in pk)
        gaps, prev = [], None
        for r in pk:
            gaps.append("0" if prev is None else str(max(0, int(round((r[0] - prev) * 1e6)))))
            prev = r[0]
        exp_iat = " ".join(gaps)
        exp_flags = " ".join(str(r[8] & 0x3F) for r in pk)
        diff = [n for n, e in (("seq_signed_len", exp_len), ("seq_iat_us", exp_iat),
                               ("seq_flags", exp_flags)) if s[n] != e]
        if int(s["pkt_count"]) != len(pk):
            diff.append("pkt_count")
        if diff:
            arr_bad += 1
            arr_fields.update(diff)
            if len(arr_examples) < 5:
                arr_examples.append({"segment_uid": uid, "поля": diff,
                                     "пакетов у нас": s["pkt_count"],
                                     "пакетов у tshark": len(pk)})
        else:
            arr_ok += 1
    report["B_массивы"] = {
        "сессий сверено": arr_ok + arr_bad,
        "совпали целиком": arr_ok,
        "расходятся": arr_bad,
        "по каким массивам": dict(arr_fields) or 0,
        "пропущено из-за кадров > MTU": arr_skip_jumbo,
        "примеры": arr_examples,
    }

    # --- C. сессии против Zeek --------------------------------------------
    def zeek_rows(path: Path):
        names = None
        with path.open() as fh:
            for line in fh:
                if line.startswith("#fields"):
                    names = line.rstrip("\n").split("\t")[1:]
                    continue
                if line.startswith("#") or names is None:
                    continue
                yield dict(zip(names, line.rstrip("\n").split("\t")))
    zconn = defaultdict(list)
    for z in zeek_rows(V / "zeek_c/conn.log"):
        if z["proto"] not in ("tcp", "udp"):
            continue
        a = (z["id.orig_h"], int(z["id.orig_p"]))
        b = (z["id.resp_h"], int(z["id.resp_p"]))
        key = (min(a, b), max(a, b), 6 if z["proto"] == "tcp" else 17)
        zconn[key].append(z)
    sess_cmp = Counter()
    sess_ex = defaultdict(list)
    for uid, s in sessions.items():
        ix = index[uid]
        a = (addresses[ix["ip_a"]], int(ix["port_a"]))
        b = (addresses[ix["ip_b"]], int(ix["port_b"]))
        proto = 6 if s["proto"] == "tcp" else 17
        key = (min(a, b), max(a, b), proto)
        t0, t1 = float(ix["t_start"]), float(ix["t_end"])
        cands = []
        for z in zconn.get(key, []):
            zs = float(z["ts"])
            zd = float(z["duration"]) if z["duration"] not in ("-", "") else 0.0
            if zs - EPS <= t1 and t0 <= zs + zd + EPS:
                cands.append(z)
        if len(cands) != 1:
            sess_cmp["нет пары 1:1 в Zeek" if not cands else "Zeek делит на несколько"] += 1
            continue
        z = cands[0]
        sess_cmp["сопоставлено"] += 1
        zp = int(z["orig_pkts"]) + int(z["resp_pkts"])
        zb = int(z["orig_ip_bytes"]) + int(z["resp_ip_bytes"])
        our_p = int(s["pkt_count"])
        our_b = int(s["bytes_up_ip"] or 0) + int(s["bytes_down_ip"] or 0)
        zd = float(z["duration"]) if z["duration"] not in ("-", "") else 0.0
        our_d = t1 - t0
        for name, ok, mine, theirs in (
                ("пакеты", our_p == zp, our_p, zp),
                ("IP-байты", our_b == zb, our_b, zb),
                ("длительность", abs(our_d - zd) <= 1e-5, round(our_d, 6), zd)):
            if ok:
                sess_cmp[f"{name}: совпало"] += 1
            else:
                sess_cmp[f"{name}: расходится"] += 1
                if len(sess_ex[name]) < 4:
                    sess_ex[name].append({"у нас": mine, "zeek": theirs,
                                          "zeek conn_state": z["conn_state"],
                                          "zeek history": z["history"]})
        if abs(our_d - zd) > 1e-5:
            sess_cmp["длительность: у нас длиннее" if our_d > zd
                     else "длительность: у нас короче"] += 1
        orig = (z["id.orig_h"], int(z["id.orig_p"]))
        client = (addresses[ix["client_ip"]], int(ix["client_port"]))
        seen_syn = s["start_observed"] == "1" and s["proto"] == "tcp"
        tag = "SYN виден" if seen_syn else "без SYN"
        sess_cmp[f"клиент = orig Zeek ({tag})" if orig == client
                 else f"клиент ≠ orig Zeek ({tag})"] += 1
        if orig != client and seen_syn and len(sess_ex["клиент при видимом SYN"]) < 4:
            sess_ex["клиент при видимом SYN"].append(
                {"наш клиент": client, "zeek orig": orig, "zeek history": z["history"]})
    report["C_сессии_vs_Zeek"] = {"счётчики": dict(sess_cmp),
                                  "примеры расхождений": dict(sess_ex)}

    # --- D. TLS против tshark ---------------------------------------------
    from payload_sidecar import SidecarWriter
    import extract_payload_features as epf

    class RawKeys(SidecarWriter):
        def _key(self, value):
            return value

    w = RawKeys(b"x", names=None)
    for ts, src, sport, dst, dport, proto, payload, ip_bytes in epf.iter_packets(V / "v.pcap"):
        w.add(ts, src.encode(), sport, dst.encode(), dport,
              6 if proto == "tcp" else 17, ip_bytes, payload)
    ours_tls, ours_dns = {}, defaultdict(Counter)
    for fp in [*w._done, *w._flows.values()]:
        key = ((fp.a_key.decode(), fp.a_port), (fp.b_key.decode(), fp.b_port))
        if fp.tls_flags & 1 and key not in ours_tls:
            ours_tls[key] = {"ja4": fp.ja4_key, "sni": fp.service_key if fp.sni_len else "",
                             "alpn": fp.alpn}
        ours_dns[key].update(fp.dns_qtypes)
    ts_tls, ts_dns = {}, defaultdict(Counter)
    for f in frames:
        types = f["tls.handshake.type"].split("|") if f["tls.handshake.type"] else []
        src = first(f["ip.src"]) or first(f["ipv6.src"])
        dst = first(f["ip.dst"]) or first(f["ipv6.dst"])
        if "1" in types and f["tls.handshake.ja4"]:
            # Внутри CAPWAP (Wi-Fi-туннель) tshark ключует поток по ВНУТРЕННИМ
            # адресам, а они у него идут последними.
            ips = (f["ip.src"] or f["ipv6.src"]).split("|")
            ipd = (f["ip.dst"] or f["ipv6.dst"]).split("|")
            src_i, dst_i = ips[-1], ipd[-1]
            sp = int((f["tcp.srcport"].split("|") or ["0"])[-1] or 0)
            dp = int((f["tcp.dstport"].split("|") or ["0"])[-1] or 0)
            a, b = (src_i, sp), (dst_i, dp)
            key = (min(a, b), max(a, b))
            ts_tls.setdefault(key, {"ja4": first(f["tls.handshake.ja4"]),
                                    "ja4_spec": ja4_per_spec(first(f["tls.handshake.ja4"]),
                                                             first(f["tls.handshake.ja4_r"])),
                                    "sni": first(f["tls.handshake.extensions_server_name"]),
                                    "alpn": first(f["tls.handshake.extensions_alpn_str"]),
                                    "capwap": "capwap" in f["frame.protocols"]})
        if f["dns.flags.response"] and first(f["dns.flags.response"]) in ("0", "False") \
                and first(f["udp.dstport"]) == "53" and f["dns.qry.type"]:
            sp, dp = int(first(f["udp.srcport"])), 53
            a, b = (src, sp), (dst, dp)
            key = (min(a, b), max(a, b))
            ts_dns[key][int(first(f["dns.qry.type"]))] += 1
    tls_cmp = Counter()
    tls_ex = []
    for key, t in ts_tls.items():
        o = ours_tls.get(key)
        if o is None:
            tls_cmp["tshark видит ClientHello, у нас нет JA4" +
                    (" (он внутри CAPWAP)" if t["capwap"] else " (обычный)")] += 1
            continue
        tls_cmp["ja4 по спецификации: совпало" if o["ja4"] == t["ja4_spec"]
                else "ja4 по спецификации: расходится"] += 1
        for name in ("ja4", "sni", "alpn"):
            if o[name] == t[name]:
                tls_cmp[f"{name}: совпало"] += 1
            else:
                tls_cmp[f"{name}: расходится"] += 1
                if len(tls_ex) < 6:
                    tls_ex.append({"поле": name, "у нас": o[name], "tshark": t[name]})
    only_ours = set(ours_tls) - set(ts_tls)
    tls_cmp["у нас JA4 есть, у tshark нет"] = len(only_ours)
    report_ports = Counter(min(a[1], b[1]) for a, b in only_ours)
    report["D_TLS"] = {"ClientHello у tshark": len(ts_tls), "JA4 у нас": len(ours_tls),
                       "счётчики": dict(tls_cmp), "примеры": tls_ex,
                       "порты там, где JA4 только у нас": dict(report_ports.most_common(6))}
    dns_cmp = Counter()
    for key, c in ts_dns.items():
        dns_cmp["совпало" if ours_dns.get(key) == c else "расходится"] += 1
    report["E_DNS_типы"] = {"потоков с DNS-запросами у tshark": len(ts_dns),
                            **dict(dns_cmp)}

    # --- F. битые пакеты и ретрансмиты -----------------------------------
    expert = Counter()
    for f in frames:
        msgs = f["_ws.expert.message"]
        if not msgs:
            continue
        seen = set()
        for m in msgs.split("|"):
            for label, needle in (
                    ("ретрансмит", "(suspected) retransmission"),
                    ("быстрый ретрансмит", "fast retransmission"),
                    ("ложный ретрансмит", "spurious retransmission"),
                    ("вне порядка", "out-of-order"),
                    ("дубль ACK", "Duplicate ACK"),
                    ("пропущен предыдущий сегмент", "Previous segment"),
                    ("ACK на непойманный сегмент", "ACKed segment that wasn't captured"),
                    ("битая контрольная сумма", "Bad checksum"),
                    ("битый пакет (malformed)", "Malformed"),
                    ("zero window", "Zero window")):
                if needle.lower() in m.lower() and label not in seen:
                    expert[label] += 1
                    seen.add(label)
    truncated = sum(1 for f in frames if f["frame.len"] != f["frame.cap_len"])
    weird = Counter()
    for z in zeek_rows(V / "zeek/weird.log"):
        weird[z.get("name", "?")] += 1
    zc = list(zeek_rows(V / "zeek_c/conn.log"))
    retr_conns = sum(1 for z in zc if any(ch in z.get("history", "") for ch in "tT"))
    gap_conns = [int(z["missed_bytes"]) for z in zc
                 if z.get("missed_bytes", "0") not in ("0", "-", "")]
    tunnels = sum(1 for _ in zeek_rows(V / "zeek_c/tunnel.log")) \
        if (V / "zeek_c/tunnel.log").exists() else 0
    stats = json.loads((V / "out/sessions.stats.json").read_text())
    capwap_s = [s for s in sessions.values() if s["dest_port"] in ("5246", "5247")]
    capwap_frames = sum(1 for f in frames if "capwap" in f["frame.protocols"])
    report["F_битые_и_ретрансмиты"] = {
        "tshark (кадров с признаком)": dict(expert),
        "усечённых кадров (cap_len < len)": truncated,
        "Zeek weird.log": dict(weird.most_common(12)),
        "Zeek: соединений с ретрансмитом (history t/T)": retr_conns,
        "Zeek: соединений с дырами в потоке (missed_bytes>0)": len(gap_conns),
        "Zeek: пропущено байт всего": sum(gap_conns),
        "Zeek: туннелей распаковано": tunnels,
        "кадров внутри CAPWAP (tshark)": capwap_frames,
        "наших сессий-носителей CAPWAP (UDP 5246/5247)": len(capwap_s),
        "пакетов в них": sum(int(s["pkt_count"]) for s in capwap_s),
        "наш конвейер: не-сессионные кадры": stats.get("nonflow", "см. журнал экспорта"),
    }

    report["G_QUIC_и_CAPWAP"] = quic_and_capwap(V, addresses, index, sessions)

    out = V / "validation_report.json"
    out.write_text(json.dumps(report, ensure_ascii=False, indent=1, default=str))
    print(json.dumps(report, ensure_ascii=False, indent=1, default=str))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
