#!/usr/bin/env python3
"""Payload facts collected in the same pass that writes the packet rows.

The sensor deletes its pcaps, so anything the bytes alone can answer has to be
answered while the frame is still in memory. That is the whole reason this
module exists next to `export_full_packets.py` instead of being a second pass:
a second pass would need the pcap, and by then there is none.

What the bytes answer, and nothing else does: the TLS server name LoTS keys its
windows on, the shape of the payload that covert-channel work asks for, the DNS
question names, and the IP byte counts the LoTS contract wants (header
inclusive, unlike the L2 frame bytes the session table carries).

**Payload shape travels as a histogram, not as bytes.** Entropy, printable
share, null share and base64 share are all functions of how often each byte
value occurred, so 256 counters answer every one of them exactly -- and unlike
the bytes themselves, counters from two minutes of the same flow can simply be
added. That is what lets minute files be converted in parallel while sessions
are still stitched in order. No payload byte is ever written out.

**Names travel hashed.** The server name and the DNS labels are salted-hashed
here, on the sensor. Entropy over hashed labels equals entropy over the labels,
so `cc_dns_label_entropy` is unaffected; the lengths that the features need are
carried as numbers alongside.

The file is `OPAY` + version, then one record per flow per minute. Histograms
are written sparsely when few byte values occurred -- an ACK-only flow costs
nothing, a plaintext one costs little, an encrypted one costs the full 512.
"""
from __future__ import annotations

import hashlib
import hmac
import math
import re
import struct
import sys
from collections import Counter
from pathlib import Path as _Path

sys.path.insert(0, str(_Path(__file__).resolve().parent))
import quic_initial  # noqa: E402

MAGIC = b"OPAY"
VERSION = 4
PAY_PKTS = 8            # payload-bearing packets per direction that are sampled
PAY_BYTES = 256         # bytes taken from each of them
MAX_DNS_LABELS = 64     # distinct labels kept per flow per minute
# A ClientHello does not have to fit in one segment, and a big one usually does
# not: measured on a 60-second office capture, 168 hellos were split against 95
# that fitted -- so two thirds of the fingerprints were being missed. The first
# bytes of a flow are buffered until a hello parses or this budget is spent.
HELLO_BUDGET = 8192
# QUIC: long-header datagrams tried per flow before giving up on a hello.
QUIC_MAX_TRIES = 8
# CAPWAP (RFC 5415): Wi-Fi access points tunnel client traffic to the wireless
# controller over UDP 5246 (control) and 5247 (data). On this office mirror it
# was 30% of all packets -- legitimate tunnels sitting in "ordinary" traffic,
# exactly the shape a tunnel detector is trained to find. They are marked, not
# dropped: a model has to be able to tell them apart, not be spared them.
CAPWAP_PORTS = (5246, 5247)

# ALPN is categorised HERE, from the whole protocol name. The record used to keep
# only its first and last character -- JA4's two-letter code -- and categorise
# later, which put "h3-alias-02" under HTTP/2 ("h2") and never recognised
# "http/1.1" at all ("h1"). Found by comparing with tshark on office traffic.
ALPN_NONE, ALPN_H2, ALPN_H3, ALPN_HTTP11, ALPN_OTHER = 0, 1, 2, 3, 4


def alpn_category(name: str) -> int:
    if not name:
        return ALPN_NONE
    if name == "h2":
        return ALPN_H2
    if name == "h3" or re.fullmatch(r"h3-\d+", name):     # h3 and its IETF drafts
        return ALPN_H3
    if name == "http/1.1":
        return ALPN_HTTP11
    return ALPN_OTHER
# A 4-tuple reused inside one interval is two sessions, and one record shared
# between them hands all of its bytes to one and nothing to the other. Measured
# on a 10-second office capture with every session kept: 225 reopened sessions,
# 225 left without payload. So a record is cut where a new session can begin --
# at a bare SYN, and after a gap longer than the shortest idle timeout the
# session builder uses. Cutting too often is harmless: the merge puts records
# back together by overlap with the session. Cutting too rarely loses data.
SPLIT_GAP_TCP = 10.0      # online_schema's closed-TCP timeout, the shortest
SPLIT_GAP_UDP = 30.0
_PRINT = frozenset(range(32, 127))
_B64 = frozenset(b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=-_")

# v2 appends the TLS, QUIC and DNS-type fields to v1's layout. The version
# byte is checked on read, so a v1 file is refused by name rather than
# misread field by field.
_HEAD_V1 = struct.Struct("<8sH8sHBBddIIHHHH8sHIIHH")
_HEAD_V2 = struct.Struct("<8sH8sHBBddIIHHHH8sHIIHH"   # v1
                         "8s8sBBHHHHBBHIIH")          # v2
# v3: packets of the record, and how many of them are CAPWAP.
_HEAD_V3 = struct.Struct("<8sH8sHBBddIIHHHH8sHIIHH"   # v1
                         "8s8sBBHHHHBBHIIH"           # v2
                         "II")                        # v3
# v4: TCP retransmissions per direction (segments, payload bytes); SSH software
# family per direction and the salted HASSH of each direction's KEXINIT.
_HEAD = struct.Struct("<8sH8sHBBddIIHHHH8sHIIHH"      # v1
                      "8s8sBBHHHHBBHIIH"              # v2
                      "II"                            # v3
                      "IIIIBB8s8s")                   # v4
_LABEL = struct.Struct("<8sH")
_QTYPE = struct.Struct("<HH")

TLS_JA4 = 1 << 0          # a ClientHello was fingerprinted
TLS_JA4S = 1 << 1         # a ServerHello was fingerprinted
TLS_EARLY_DATA = 1 << 2   # 0-RTT was offered
TLS_PSK = 1 << 3          # a pre-shared key was offered: resumption
TLS_OVER_QUIC = 1 << 4
# Направление, в котором рукопожатие так и не собралось в бюджет. Без этого
# признака буфер либо растёт без предела, либо разбирается заново на каждом
# пакете потока — и то и другое на горячем пути.
TLS_GAVE_UP_A2B = 1 << 5
TLS_GAVE_UP_B2A = 1 << 6
_TLS_BOTH = TLS_JA4 | TLS_JA4S
_DENSE = struct.Struct("<256H")


class FlowPayload:
    """One flow's payload facts inside one minute file."""

    __slots__ = ("a_key", "a_port", "b_key", "b_port", "proto",
                 "first_ts", "last_ts", "ip_a2b", "ip_b2a",
                 "n_a2b", "n_b2a", "bytes_a2b", "bytes_b2a",
                 "hist_a2b", "hist_b2a", "service_key", "sni_len",
                 "dns_q", "dns_len_sum", "dns_len_max", "dns_labels",
                 "dns_qtypes", "ja4_key", "ja4s_key", "tls_flags",
                 "tls_version", "cipher_count", "ext_count", "group_count",
                 "sigalg_count", "alpn", "quic_cids", "quic_datagrams",
                 "quic_datagram_bytes", "hello_buf_a2b", "hello_buf_b2a",
                 "pkts", "capwap_pkts", "quic_odcid", "quic_version",
                 "quic_client_a2b", "quic_crypto_c", "quic_crypto_s",
                 "quic_tries", "quic_keys", "seq_next_a2b", "seq_next_b2a",
                 "retx_pkts_a2b", "retx_pkts_b2a", "retx_bytes_a2b", "retx_bytes_b2a",
                 "ssh_sw_a2b", "ssh_sw_b2a", "hassh_a2b", "hassh_b2a",
                 "ssh_buf_a2b", "ssh_buf_b2a", "ssh_done")

    def __init__(self, a_key, a_port, b_key, b_port, proto, ts):
        self.a_key, self.a_port = a_key, a_port
        self.b_key, self.b_port = b_key, b_port
        self.proto = proto
        self.first_ts = self.last_ts = ts
        self.ip_a2b = self.ip_b2a = 0
        self.n_a2b = self.n_b2a = 0
        self.bytes_a2b = self.bytes_b2a = 0
        self.hist_a2b: Counter = Counter()
        self.hist_b2a: Counter = Counter()
        self.service_key = b"\0" * 8
        self.sni_len = 0
        self.dns_q = 0
        self.dns_len_sum = 0
        self.dns_len_max = 0
        self.dns_labels: Counter = Counter()
        self.dns_qtypes: Counter = Counter()
        self.ja4_key = b"\0" * 8
        self.ja4s_key = b"\0" * 8
        self.tls_flags = 0
        self.tls_version = 0
        self.cipher_count = 0
        self.ext_count = 0
        self.group_count = 0
        self.sigalg_count = 0
        self.alpn = ""
        # Distinct QUIC destination connection IDs seen in long headers. A
        # client that keeps changing them is doing connection migration, which
        # is exactly what a tunnel hiding in QUIC looks like.
        self.quic_cids: set = set()
        self.quic_datagrams = 0
        self.quic_datagram_bytes = 0
        # Leading payload of each direction, kept only until a hello is read.
        self.hello_buf_a2b = bytearray()
        self.hello_buf_b2a = bytearray()
        self.pkts = 0
        self.capwap_pkts = 0
        # QUIC Initial keys come from the client's ORIGINAL destination
        # connection id; later packets carry other ids but the same keys.
        self.quic_odcid = None
        self.quic_version = 0
        self.quic_client_a2b = None
        self.quic_crypto_c: dict = {}
        self.quic_crypto_s: dict = {}
        self.quic_tries = 0
        self.quic_keys: dict = {}
        # TCP: the next sequence number each direction has not sent yet. A
        # data segment that ends at or before it repeats bytes already seen.
        self.seq_next_a2b = self.seq_next_b2a = None
        self.retx_pkts_a2b = self.retx_pkts_b2a = 0
        self.retx_bytes_a2b = self.retx_bytes_b2a = 0
        # SSH: software family from the identification string, HASSH from
        # the KEXINIT that follows it (RFC 4253 section 7.1).
        self.ssh_sw_a2b = self.ssh_sw_b2a = 0
        self.hassh_a2b = self.hassh_b2a = b"\0" * 8
        self.ssh_buf_a2b = bytearray()
        self.ssh_buf_b2a = bytearray()
        self.ssh_done = False


def parse_sni(payload: bytes) -> str:
    """Server name from a TLS ClientHello that fits in this record."""
    try:
        if len(payload) < 45 or payload[0] != 0x16 or payload[1] != 0x03:
            return ""
        if payload[5] != 0x01:
            return ""
        p = 43
        sid = payload[p]; p += 1 + sid
        cs = struct.unpack("!H", payload[p:p + 2])[0]; p += 2 + cs
        comp = payload[p]; p += 1 + comp
        if p + 2 > len(payload):
            return ""
        ext_total = struct.unpack("!H", payload[p:p + 2])[0]; p += 2
        end = min(p + ext_total, len(payload))
        while p + 4 <= end:
            etype, elen = struct.unpack("!HH", payload[p:p + 4]); p += 4
            if etype == 0x0000 and p + 5 <= len(payload):
                nlen = struct.unpack("!H", payload[p + 3:p + 5])[0]
                return payload[p + 5:p + 5 + nlen].decode("ascii", "ignore")
            p += elen
    except Exception:                                  # noqa: BLE001
        return ""
    return ""


# GREASE values exist to be ignored; JA4 removes them before counting or
# hashing, and a fingerprint that kept them would differ run to run for the
# same client.
_GREASE = frozenset(range(0x0A0A, 0xFAFA + 1, 0x1010))


def _u16(buf: bytes, off: int) -> int:
    return (buf[off] << 8) | buf[off + 1]


def _tls_records(payload: bytes):
    """Yield (content_type, body) for the handshake records in this segment."""
    off = 0
    while off + 5 <= len(payload):
        ctype = payload[off]
        if payload[off + 1] != 0x03:
            return
        length = _u16(payload, off + 3)
        body = payload[off + 5:off + 5 + length]
        if len(body) < length:
            return
        yield ctype, body
        off += 5 + length


def parse_handshake_message(body: bytes) -> dict | None:
    """Fields of one ClientHello or ServerHello handshake message.

    `body` starts at the handshake type byte. Over TCP it sits inside a TLS
    record; over QUIC it arrives in CRYPTO frames with no record layer at all,
    which is why this is separate from `parse_hello`.
    """
    if not body or body[0] not in (0x01, 0x02):
        return None
    htype = body[0]
    try:
        p = 4 + 2 + 32                       # header, version, random
        if p >= len(body):
            return None
        sid = body[p]; p += 1 + sid
        if htype == 0x01:
            cs_len = _u16(body, p); p += 2
            ciphers = [_u16(body, p + i) for i in range(0, cs_len, 2)]
            p += cs_len
            comp = body[p]; p += 1 + comp
        else:
            ciphers = [_u16(body, p)]; p += 2
            p += 1                            # compression method
        out = {
            "is_client": htype == 0x01,
            "legacy_version": _u16(body, 4),
            "ciphers": [c for c in ciphers if c not in _GREASE],
            "extensions": [], "sni": "", "alpn": "", "sigalgs": [],
            "groups": 0, "supported_versions": [], "early_data": 0,
            "psk_offered": 0,
        }
        if p + 2 > len(body):
            return out
        ext_total = _u16(body, p); p += 2
        end = min(p + ext_total, len(body))
        while p + 4 <= end:
            etype = _u16(body, p); elen = _u16(body, p + 2); p += 4
            data = body[p:p + elen]; p += elen
            if etype in _GREASE:
                continue
            out["extensions"].append(etype)
            if etype == 0x0000 and len(data) >= 5:          # server_name
                nlen = _u16(data, 3)
                out["sni"] = data[5:5 + nlen].decode("ascii", "ignore")
            elif etype == 0x0010 and len(data) >= 3:        # ALPN
                plen = data[2]
                out["alpn"] = data[3:3 + plen].decode("ascii", "ignore")
            elif etype == 0x000D and len(data) >= 2:        # signature_algorithms
                n = _u16(data, 0)
                out["sigalgs"] = [_u16(data, 2 + i) for i in range(0, n, 2)
                                  if _u16(data, 2 + i) not in _GREASE]
            elif etype == 0x000A and len(data) >= 2:        # supported_groups
                out["groups"] = _u16(data, 0) // 2
            elif etype == 0x002B and data:                  # supported_versions
                if out["is_client"] and len(data) >= 1:
                    n = data[0]
                    out["supported_versions"] = [
                        _u16(data, 1 + i) for i in range(0, n, 2)
                        if _u16(data, 1 + i) not in _GREASE]
                elif len(data) >= 2:
                    out["supported_versions"] = [_u16(data, 0)]
            elif etype == 0x002A:                           # early_data
                out["early_data"] = 1
            elif etype == 0x0029:                           # pre_shared_key
                out["psk_offered"] = 1
        return out
    except (IndexError, ValueError):
        return None
    return None



def parse_hello(payload: bytes) -> dict | None:
    """Fields of a TLS ClientHello or ServerHello, or None if this is neither.

    Everything JA4 needs comes from here, and so do the handshake features the
    catalog asks for separately -- version, ALPN, how many ciphers, extensions
    and groups were offered. One parse, because a second one would be a second
    definition of the same bytes.
    """
    for ctype, body in _tls_records(payload):
        if ctype != 0x16 or not body or body[0] not in (0x01, 0x02):
            continue
        return parse_handshake_message(body)
    return None

def tls_version_label(hello: dict) -> str:
    """Two digits, as JA4 writes them: the negotiated version wins."""
    best = max(hello["supported_versions"], default=0) or hello["legacy_version"]
    return {0x0304: "13", 0x0303: "12", 0x0302: "11", 0x0301: "10",
            0x0300: "s3", 0xFEFF: "d1", 0xFEFD: "d2", 0xFEFC: "d3"}.get(best, "00")


def ja4(hello: dict, over_quic: bool = False) -> str:
    """The JA4 (client) or JA4S (server) string for this hello.

    Kept as a string only long enough to be hashed. The raw fingerprint names
    the client software, which is one step from naming the label, and the
    repository already lists `ja4_hash_int` as leakage. What leaves here is a
    salted hash, and what reaches a model is whether one was seen -- never the
    value itself.
    """
    proto = "q" if over_quic else "t"
    ver = tls_version_label(hello)
    alpn = hello["alpn"]
    alpn_code = (alpn[0] + alpn[-1]) if alpn else "00"
    if hello["is_client"]:
        sni = "d" if hello["sni"] else "i"
        ciphers = sorted(hello["ciphers"])
        exts = sorted(e for e in hello["extensions"] if e not in (0x0000, 0x0010))
        a = f"{proto}{ver}{sni}{min(len(ciphers), 99):02d}{min(len(hello['extensions']), 99):02d}{alpn_code}"
        b = hashlib.sha256(",".join(f"{c:04x}" for c in ciphers).encode()).hexdigest()[:12]
        tail = ",".join(f"{e:04x}" for e in exts)
        if hello["sigalgs"]:
            tail += "_" + ",".join(f"{x:04x}" for x in hello["sigalgs"])
        c = hashlib.sha256(tail.encode()).hexdigest()[:12]
        return f"{a}_{b}_{c}"
    a = f"{proto}{ver}{min(len(hello['extensions']), 99):02d}{alpn_code}"
    b = f"{hello['ciphers'][0]:04x}" if hello["ciphers"] else "0000"
    # JA4S hashes the server's extensions in the ORDER THEY APPEAR -- unlike
    # JA4, which sorts. Sorting here would make it a different fingerprint that
    # only happens to share the name.
    c = hashlib.sha256(",".join(f"{e:04x}" for e in hello["extensions"]).encode()).hexdigest()[:12]
    return f"{a}_{b}_{c}"


_VERSION_CODE = {"00": 0, "s3": 1, "10": 2, "11": 3, "12": 4, "13": 5,
                 "d1": 6, "d2": 7, "d3": 8}


def dns_qtype(payload: bytes) -> int:
    """Query type of the first question, or 0 when it cannot be read."""
    try:
        p = 12
        while p < len(payload):
            ln = payload[p]
            if ln == 0:
                p += 1
                break
            if ln > 63:
                return 0
            p += 1 + ln
        if p + 2 > len(payload):
            return 0
        return _u16(payload, p)
    except IndexError:
        return 0


def looks_like_capwap(payload: bytes) -> bool:
    """A CAPWAP header (RFC 5415 section 4.3), not just traffic on its ports.

    The preamble is version 0 with type 0 (clear header) or 1 (DTLS). A clear
    header also states its own length in 4-byte words (HLEN, at least 2) and
    the wireless binding (WBID 1 for 802.11); both have to be consistent.
    """
    if len(payload) < 8:
        return False
    if payload[0] == 0x01:                         # DTLS-protected CAPWAP
        return True
    if payload[0] != 0x00:
        return False
    hlen = payload[1] >> 3
    wbid = (payload[2] >> 1) & 0x1F
    return hlen >= 2 and hlen * 4 <= len(payload) and wbid == 1


def dns_labels(payload: bytes) -> list[str]:
    try:
        if len(payload) < 13:
            return []
        p, out = 12, []
        while p < len(payload):
            ln = payload[p]
            if ln == 0 or ln > 63:
                break
            out.append(payload[p + 1:p + 1 + ln].decode("ascii", "ignore"))
            p += 1 + ln
        return out
    except Exception:                                  # noqa: BLE001
        return []


SSH_SOFTWARE = ("", "OpenSSH", "PuTTY", "libssh", "Dropbear", "paramiko", "Go",
                "WinSCP", "Cisco", "other")
SSH_BUDGET = 4096        # bytes per direction buffered to find banner and KEXINIT
SSH_DONE = b"SSH-done\n"  # a direction's buffer once its banner and KEXINIT are read


def ssh_software(banner: bytes) -> int:
    """Index into SSH_SOFTWARE for an identification string `SSH-2.0-<software>`."""
    sw = banner.split(b"-", 2)[2] if banner.count(b"-") >= 2 else b""
    low = sw.lower()
    for i, name in enumerate(SSH_SOFTWARE[1:-1], start=1):
        if low.startswith(name.lower().encode()) or (name == "Go" and low.startswith(b"go")):
            return i
    if b"putty" in low or b"plink" in low:
        return SSH_SOFTWARE.index("PuTTY")
    if b"libssh" in low:
        return SSH_SOFTWARE.index("libssh")
    return len(SSH_SOFTWARE) - 1


def parse_ssh(buf: bytes):
    """(software index, hassh text or None) from a direction's first bytes.

    HASSH is md5("kex;enc;mac;cmp") of the algorithm lists this side offered,
    client-to-server lists for the client and server-to-client for the server;
    here each direction's own KEXINIT gives its own lists, and which of the two
    is the client is decided later, as for everything else.
    """
    if not buf.startswith(b"SSH-"):
        return None, None
    end = buf.find(b"\n")
    if end < 0:
        return None, None
    sw = ssh_software(buf[:end].rstrip(b"\r"))
    rest = buf[end + 1:]
    # Binary packet: uint32 length, byte padding, byte msg (20 = KEXINIT),
    # 16 bytes cookie, then name-lists.
    if len(rest) < 22 or rest[5] != 20:
        return sw, None
    pos, lists = 6 + 16, []
    try:
        for _ in range(10):
            n = int.from_bytes(rest[pos:pos + 4], "big")
            if pos + 4 + n > len(rest):
                return sw, None
            lists.append(rest[pos + 4:pos + 4 + n].decode("ascii", "replace"))
            pos += 4 + n
    except ValueError:
        return sw, None
    kex, _hk, enc_cs, enc_sc, mac_cs, mac_sc, cmp_cs, cmp_sc = lists[:8]
    return sw, (kex, (enc_cs, mac_cs, cmp_cs), (enc_sc, mac_sc, cmp_sc))


def _seq_after(a: int, b: int) -> bool:
    """a is later than b in 32-bit sequence space."""
    return 0 < ((a - b) & 0xFFFFFFFF) < 0x80000000


class SidecarWriter:
    """Accumulates one minute of flows, then writes them once."""

    def __init__(self, salt: bytes, names: dict[str, str] | None = None):
        self._salt = salt
        self._flows: dict[tuple, FlowPayload] = {}
        # Records closed at a session boundary inside this interval.
        self._done: list[FlowPayload] = []
        self.incomplete_hellos = 0
        # Cleartext names, if the caller wants them: they stay on the sensor.
        self.names = names

    def _key(self, value: str) -> bytes:
        return hmac.new(self._salt, value.encode(), hashlib.sha256).digest()[:8]

    def add(self, ts, src_key, sport, dst_key, dport, proto_n, ip_bytes, payload,
            tcp_flags: int = 0, tcp_seq: int | None = None):
        a, b = (src_key, sport), (dst_key, dport)
        if a <= b:
            ident, a2b = (a, b, proto_n), True
        else:
            ident, a2b = (b, a, proto_n), False
        fp = self._flows.get(ident)
        if fp is not None:
            bare_syn = proto_n == 6 and (tcp_flags & 0x12) == 0x02
            gap = ts - fp.last_ts
            limit = SPLIT_GAP_TCP if proto_n == 6 else SPLIT_GAP_UDP
            if bare_syn or gap > limit:
                self._done.append(fp)
                fp = None
        if fp is None:
            fp = self._flows[ident] = FlowPayload(
                ident[0][0], ident[0][1], ident[1][0], ident[1][1], proto_n, ts)
        fp.last_ts = ts
        fp.pkts += 1
        if proto_n == 17 and (sport in CAPWAP_PORTS or dport in CAPWAP_PORTS) \
                and looks_like_capwap(payload):
            fp.capwap_pkts += 1
        if a2b:
            fp.ip_a2b += ip_bytes
        else:
            fp.ip_b2a += ip_bytes
        if proto_n == 6 and tcp_seq is not None:
            self._note_retransmission(fp, tcp_seq, len(payload), a2b, tcp_flags)
        if not payload:
            return
        if proto_n == 6 and tcp_seq is not None:
            if not fp.ssh_done:
                self._note_ssh(fp, payload, a2b)
        if a2b:
            if fp.n_a2b < PAY_PKTS:
                chunk = payload[:PAY_BYTES]
                fp.hist_a2b.update(chunk)
                fp.bytes_a2b += len(chunk)
                fp.n_a2b += 1
        elif fp.n_b2a < PAY_PKTS:
            chunk = payload[:PAY_BYTES]
            fp.hist_b2a.update(chunk)
            fp.bytes_b2a += len(chunk)
            fp.n_b2a += 1

        # Which side is the client is decided by session assembly, not here --
        # the canonical A side is whichever endpoint sorts first, which has
        # nothing to do with who opened the connection. So both of these are
        # recognised from the bytes and the destination port instead of from a
        # direction this module has no business guessing.
        # Keep looking until BOTH sides have been fingerprinted: the server's
        # hello arrives after the client's, and a guard that stopped at the
        # first one would never see it.
        if proto_n == 6 and (fp.tls_flags & _TLS_BOTH) != _TLS_BOTH:
            self._note_tls(fp, payload, a2b)
        elif proto_n == 17 and dport == 53:
            labels = dns_labels(payload)
            if labels:
                fp.dns_q += 1
                qlen = len(".".join(labels))
                fp.dns_len_sum += qlen
                fp.dns_len_max = max(fp.dns_len_max, qlen)
                qtype = dns_qtype(payload)
                if qtype:
                    fp.dns_qtypes[qtype] += 1
                if len(fp.dns_labels) < MAX_DNS_LABELS:
                    for label in labels:
                        # Entropy is invariant under an injective relabelling,
                        # so hashing here does not change the feature.
                        fp.dns_labels[self._key(label)] += 1
        elif proto_n == 17:
            self._note_quic(fp, payload, a2b)

    def _note_retransmission(self, fp, seq: int, length: int, a2b: bool, flags: int = 0) -> None:
        """tshark's rule: data that starts below the highest byte already sent.

        Every segment moves the edge, empty ones too: the mirror drops some
        packets, and a bare FIN or ACK is often the only proof that the bytes
        before it were already sent. SYN and FIN take one number each. A resend
        may carry more than the original (1188 bytes, then 1238 from the same
        number); it still starts below the edge, so it still counts.
        """
        end = (seq + length + bool(flags & 0x02) + bool(flags & 0x01)) & 0xFFFFFFFF
        nxt = fp.seq_next_a2b if a2b else fp.seq_next_b2a
        if nxt is None or _seq_after(end, nxt):
            if a2b:
                fp.seq_next_a2b = end
            else:
                fp.seq_next_b2a = end
        if nxt is None or length == 0 or not _seq_after(nxt, seq):
            return
        # A one-byte segment just below the edge is a keep-alive probe, which
        # repeats a byte on purpose; tshark and Zeek do not call it a retransmission.
        if length == 1 and ((nxt - seq) & 0xFFFFFFFF) == 1:
            return
        if a2b:
            fp.retx_pkts_a2b += 1
            fp.retx_bytes_a2b += length
        else:
            fp.retx_pkts_b2a += 1
            fp.retx_bytes_b2a += length

    def _note_ssh(self, fp, payload: bytes, a2b: bool) -> None:
        buf = fp.ssh_buf_a2b if a2b else fp.ssh_buf_b2a
        if not buf and not payload.startswith(b"SSH-"):
            if not fp.ssh_buf_a2b and not fp.ssh_buf_b2a:
                fp.ssh_done = fp.pkts > 16     # not SSH: stop looking early
            return
        # This side is finished; with the other side unseen (one-sided mirror)
        # the flow keeps coming here, and must not re-read its own marker.
        if len(buf) >= SSH_BUDGET or buf.startswith(SSH_DONE):
            return
        buf += payload[:SSH_BUDGET - len(buf)]
        sw, kex = parse_ssh(bytes(buf))
        if sw is None:
            return
        if a2b:
            fp.ssh_sw_a2b = sw
        else:
            fp.ssh_sw_b2a = sw
        if kex is not None:
            kex_algs, cs, sc = kex
            # This side's own lists: the client offers c2s, the server s2c. Both
            # are kept so the merge can pick once it knows who the client is.
            both = hashlib.md5(";".join([kex_algs, *cs]).encode()).hexdigest() + \
                "|" + hashlib.md5(";".join([kex_algs, *sc]).encode()).hexdigest()
            key = self._key(both)
            if a2b:
                fp.hassh_a2b = key
            else:
                fp.hassh_b2a = key
            buf.clear()
            buf += SSH_DONE
        if fp.hassh_a2b != b"\0" * 8 and fp.hassh_b2a != b"\0" * 8:
            fp.ssh_done = True

    def _note_tls(self, fp, payload: bytes, a2b: bool) -> None:
        """Parse a hello, reassembling it across segments when it needs to be.

        A partial extension list would give a stable-looking fingerprint that is
        simply wrong, so nothing is guessed from an incomplete record: the
        leading bytes are held until the whole one has arrived, or until the
        budget says this is not a handshake at all.
        """
        gave_up = TLS_GAVE_UP_A2B if a2b else TLS_GAVE_UP_B2A
        if fp.tls_flags & gave_up:
            return
        buf = fp.hello_buf_a2b if a2b else fp.hello_buf_b2a
        if buf or (len(payload) >= 3 and payload[0] == 0x16 and payload[1] == 0x03):
            buf += payload[:HELLO_BUDGET - len(buf)]
            candidate = bytes(buf)
        else:
            candidate = payload
        hello = parse_hello(candidate)
        if hello is None:
            if len(buf) >= HELLO_BUDGET:
                # Budget spent without a whole record. Give up on this
                # direction once and say so, rather than re-parsing the same
                # kilobytes for every packet of the flow.
                self.incomplete_hellos += 1
                fp.tls_flags |= gave_up
                buf.clear()
            return
        buf.clear()
        self._record_hello(fp, hello, over_quic=False)

    def _record_hello(self, fp, hello: dict, over_quic: bool) -> None:
        """Store what a ClientHello or ServerHello says, from TCP or from QUIC."""
        if over_quic:
            fp.tls_flags |= TLS_OVER_QUIC
        if hello["is_client"]:
            if fp.tls_flags & TLS_JA4:
                return
            fp.tls_flags |= TLS_JA4
            fp.ja4_key = self._key(ja4(hello, over_quic))
            fp.cipher_count = min(len(hello["ciphers"]), 0xFFFF)
            fp.ext_count = min(len(hello["extensions"]), 0xFFFF)
            fp.group_count = min(hello["groups"], 0xFFFF)
            fp.sigalg_count = min(len(hello["sigalgs"]), 0xFFFF)
            fp.alpn = hello["alpn"]
            if hello["early_data"]:
                fp.tls_flags |= TLS_EARLY_DATA
            if hello["psk_offered"]:
                fp.tls_flags |= TLS_PSK
            name = hello["sni"]
            if name and not fp.sni_len:
                fp.service_key = self._key(name)
                fp.sni_len = min(len(name), 0xFFFF)
                if self.names is not None:
                    self.names[fp.service_key.hex()] = name
        else:
            if fp.tls_flags & TLS_JA4S:
                return
            fp.tls_flags |= TLS_JA4S
            fp.ja4s_key = self._key(ja4(hello, over_quic))
        fp.tls_version = _VERSION_CODE.get(tls_version_label(hello), 0)

    def _note_quic(self, fp, payload: bytes, a2b: bool = True) -> None:
        """Datagram counts, and connection IDs from QUIC long headers.

        Only long headers carry a length-prefixed connection ID; a short header
        needs the connection state to find where the ID ends, and this pass has
        none. So the count is of the IDs that can be read honestly.
        """
        fp.quic_datagrams += 1
        fp.quic_datagram_bytes += len(payload)
        if len(payload) < 7 or not (payload[0] & 0x80):
            return
        dcid_len = payload[5]
        if 0 < dcid_len <= 20 and len(payload) >= 6 + dcid_len:
            if len(fp.quic_cids) < 64:
                fp.quic_cids.add(bytes(payload[6:6 + dcid_len]))
        if (fp.tls_flags & _TLS_BOTH) != _TLS_BOTH and fp.quic_tries < QUIC_MAX_TRIES:
            self._quic_hello(fp, bytes(payload), a2b)

    def _quic_hello(self, fp, dgram: bytes, a2b: bool) -> None:
        """Decrypt Initial packets and read the TLS hellos out of them.

        Which side is the client is not guessed: the first Initial whose tag
        verifies under CLIENT keys derived from its own destination id is the
        client's, and that id is the one every later Initial of the connection
        is decrypted with.
        """
        if int.from_bytes(dgram[1:5], "big") not in quic_initial.VERSIONS:
            return
        fp.quic_tries += 1
        pos = 0
        while pos < len(dgram):
            hdr = quic_initial.long_header(dgram, pos)
            if hdr is None:
                break
            version, _ptype, dcid, _pn, end = hdr
            if fp.quic_odcid is None:
                pt, end, _ = quic_initial.open_initial(dgram, pos, dcid, True)
                if pt is not None:
                    fp.quic_odcid, fp.quic_version, fp.quic_client_a2b = dcid, version, a2b
                    self._quic_crypto(fp, pt, True)
            else:
                is_client = a2b == fp.quic_client_a2b
                keys = fp.quic_keys.get(is_client)
                if keys is None:
                    keys = fp.quic_keys[is_client] = quic_initial.initial_keys(
                        fp.quic_version, fp.quic_odcid, is_client)
                pt, end, _ = quic_initial.open_initial(dgram, pos, None, is_client, keys)
                if pt is not None:
                    self._quic_crypto(fp, pt, is_client)
            if end <= pos:
                break
            pos = end

    def _quic_crypto(self, fp, plaintext: bytes, is_client: bool) -> None:
        pieces = fp.quic_crypto_c if is_client else fp.quic_crypto_s
        for off, data in quic_initial.crypto_frames(plaintext):
            if off < HELLO_BUDGET:
                pieces[off] = data
        message = quic_initial.complete_handshake(quic_initial.assemble(pieces))
        if message is None:
            return
        hello = parse_handshake_message(message)
        if hello is not None and hello["is_client"] == is_client:
            self._record_hello(fp, hello, over_quic=True)
            pieces.clear()

    def _hist_blob(self, hist: Counter) -> bytes:
        if not hist:
            return b""
        if len(hist) <= 64:
            out = [bytes((len(hist),))]
            for value, count in sorted(hist.items()):
                out.append(struct.pack("<BH", value, min(count, 0xFFFF)))
            return b"".join(out)
        dense = [0] * 256
        for value, count in hist.items():
            dense[value] = min(count, 0xFFFF)
        return b"\xff" + _DENSE.pack(*dense)

    def write(self, out) -> dict:
        out.write(MAGIC + bytes((VERSION, 0, 0, 0)))
        flows = 0
        for fp in [*self._done, *self._flows.values()]:
            labels = list(fp.dns_labels.items())
            qtypes = list(fp.dns_qtypes.items())[:16]
            up_blob = self._hist_blob(fp.hist_a2b)
            down_blob = self._hist_blob(fp.hist_b2a)
            # v3: the first ALPN byte is the category, the second is unused.
            alpn_a, alpn_b = alpn_category(fp.alpn), 0
            out.write(_HEAD.pack(
                fp.a_key, fp.a_port, fp.b_key, fp.b_port, fp.proto, 0,
                fp.first_ts, fp.last_ts, fp.ip_a2b, fp.ip_b2a,
                fp.n_a2b, fp.n_b2a, fp.bytes_a2b, fp.bytes_b2a,
                fp.service_key, fp.sni_len,
                fp.dns_q, fp.dns_len_sum, fp.dns_len_max, len(labels),
                fp.ja4_key, fp.ja4s_key, fp.tls_flags, fp.tls_version,
                fp.cipher_count, fp.ext_count, fp.group_count, fp.sigalg_count,
                alpn_a, alpn_b, len(fp.quic_cids),
                fp.quic_datagrams, fp.quic_datagram_bytes, len(qtypes),
                fp.pkts, fp.capwap_pkts,
                fp.retx_pkts_a2b, fp.retx_pkts_b2a, fp.retx_bytes_a2b, fp.retx_bytes_b2a,
                fp.ssh_sw_a2b, fp.ssh_sw_b2a, fp.hassh_a2b, fp.hassh_b2a))
            for label_key, count in labels:
                out.write(_LABEL.pack(label_key, min(count, 0xFFFF)))
            for qtype, count in qtypes:
                out.write(_QTYPE.pack(qtype, min(count, 0xFFFF)))
            out.write(struct.pack("<HH", len(up_blob), len(down_blob)))
            out.write(up_blob)
            out.write(down_blob)
            flows += 1
        return {"payload_flows": flows,
                "tls_hellos_split_across_packets": self.incomplete_hellos,
                "quic_crypto_backend": quic_initial.BACKEND}


def _read_hist(buf: bytes) -> Counter:
    if not buf:
        return Counter()
    if buf[0] == 0xFF:
        values = _DENSE.unpack_from(buf, 1)
        return Counter({i: c for i, c in enumerate(values) if c})
    n = buf[0]
    out = Counter()
    for i in range(n):
        value, count = struct.unpack_from("<BH", buf, 1 + i * 3)
        out[value] = count
    return out


def read_sidecar(path):
    """Yield every flow record of one minute sidecar, in write order.

    Version 1 files are read too, and say so. They were written before the TLS,
    QUIC and DNS-type fields existed, so those come back as None -- NOT as zero.
    The difference matters: zero would claim "this session had no TLS
    handshake", and what actually happened is that nobody looked. A table
    mixing the two would let a model separate rows by which capture they came
    from.
    """
    data = path.read_bytes()
    if len(data) < 8 or data[:4] != MAGIC:
        raise ValueError(f"{path}: not a payload sidecar")
    version = data[4]
    if version not in (1, 2, 3, VERSION):
        raise ValueError(f"{path}: sidecar version {version}, expected 1..{VERSION}")
    pos = 8
    head = {1: _HEAD_V1, 2: _HEAD_V2, 3: _HEAD_V3}.get(version, _HEAD).size
    while pos < len(data):
        if len(data) - pos < head:
            raise ValueError(f"{path}: truncated record at {pos}")
        if version == 1:
            (a_key, a_port, b_key, b_port, proto, _flags, first_ts, last_ts,
             ip_a2b, ip_b2a, n_a2b, n_b2a, bytes_a2b, bytes_b2a,
             service_key, sni_len, dns_q, dns_len_sum, dns_len_max, label_n) = \
                _HEAD_V1.unpack_from(data, pos)
            ja4_key = ja4s_key = b"\0" * 8
            tls_flags = tls_version = cipher_count = ext_count = 0
            group_count = sigalg_count = alpn_a = alpn_b = 0
            quic_cids = quic_datagrams = quic_datagram_bytes = qtype_n = 0
            pkts = capwap_pkts = None
        elif version == 2:
            (a_key, a_port, b_key, b_port, proto, _flags, first_ts, last_ts,
             ip_a2b, ip_b2a, n_a2b, n_b2a, bytes_a2b, bytes_b2a,
             service_key, sni_len, dns_q, dns_len_sum, dns_len_max, label_n,
             ja4_key, ja4s_key, tls_flags, tls_version, cipher_count, ext_count,
             group_count, sigalg_count, alpn_a, alpn_b, quic_cids,
             quic_datagrams, quic_datagram_bytes, qtype_n) = \
                _HEAD_V2.unpack_from(data, pos)
            pkts = capwap_pkts = None
        if version <= 3:
            retx = ssh = None
        if version == 3:
            (a_key, a_port, b_key, b_port, proto, _flags, first_ts, last_ts,
             ip_a2b, ip_b2a, n_a2b, n_b2a, bytes_a2b, bytes_b2a,
             service_key, sni_len, dns_q, dns_len_sum, dns_len_max, label_n,
             ja4_key, ja4s_key, tls_flags, tls_version, cipher_count, ext_count,
             group_count, sigalg_count, alpn_a, alpn_b, quic_cids,
             quic_datagrams, quic_datagram_bytes, qtype_n, pkts, capwap_pkts) = \
                _HEAD_V3.unpack_from(data, pos)
        elif version >= 4:
            (a_key, a_port, b_key, b_port, proto, _flags, first_ts, last_ts,
             ip_a2b, ip_b2a, n_a2b, n_b2a, bytes_a2b, bytes_b2a,
             service_key, sni_len, dns_q, dns_len_sum, dns_len_max, label_n,
             ja4_key, ja4s_key, tls_flags, tls_version, cipher_count, ext_count,
             group_count, sigalg_count, alpn_a, alpn_b, quic_cids,
             quic_datagrams, quic_datagram_bytes, qtype_n, pkts, capwap_pkts,
             rx_pa, rx_pb, rx_ba, rx_bb, sw_a, sw_b, hs_a, hs_b) = \
                _HEAD.unpack_from(data, pos)
            retx = (rx_pa, rx_pb, rx_ba, rx_bb)
            ssh = (sw_a, sw_b, hs_a, hs_b)
        pos += head
        labels = Counter()
        for _ in range(label_n):
            label_key, count = _LABEL.unpack_from(data, pos)
            labels[label_key] = count
            pos += _LABEL.size
        qtypes = Counter()
        for _ in range(qtype_n):
            qtype, count = _QTYPE.unpack_from(data, pos)
            qtypes[qtype] = count
            pos += _QTYPE.size
        up_len, down_len = struct.unpack_from("<HH", data, pos)
        pos += 4
        up_blob, down_blob = data[pos:pos + up_len], data[pos + up_len:pos + up_len + down_len]
        pos += up_len + down_len
        yield {
            "schema_version": version,
            "a": (a_key.hex(), a_port), "b": (b_key.hex(), b_port), "proto": proto,
            "first_ts": first_ts, "last_ts": last_ts,
            "ip_a2b": ip_a2b, "ip_b2a": ip_b2a,
            "n_a2b": n_a2b, "n_b2a": n_b2a,
            "bytes_a2b": bytes_a2b, "bytes_b2a": bytes_b2a,
            "hist_a2b": _read_hist(up_blob), "hist_b2a": _read_hist(down_blob),
            "service_key": service_key.hex() if sni_len else "",
            "sni_len": sni_len, "dns_q": dns_q, "dns_len_sum": dns_len_sum,
            "dns_len_max": dns_len_max, "dns_labels": labels,
            "dns_qtypes": qtypes,
            # The fingerprints leave as salted hashes and are only ever used to
            # answer "was there one" and "how many distinct ones".
            "ja4_key": ja4_key.hex() if tls_flags & TLS_JA4 else "",
            "ja4s_key": ja4s_key.hex() if tls_flags & TLS_JA4S else "",
            "tls_flags": tls_flags, "tls_version": tls_version,
            "cipher_count": cipher_count, "ext_count": ext_count,
            "group_count": group_count, "sigalg_count": sigalg_count,
            "alpn": (chr(alpn_a) + chr(alpn_b)) if (alpn_a and version == 2) else "",
            "alpn_category": alpn_a if version >= 3 else None,
            "quic_cids": quic_cids, "quic_datagrams": quic_datagrams,
            "quic_datagram_bytes": quic_datagram_bytes,
            "pkts": pkts, "capwap_pkts": capwap_pkts,
            # v4; None where the sidecar is older and nobody counted.
            "retx_pkts_a2b": retx[0] if retx else None, "retx_pkts_b2a": retx[1] if retx else None,
            "retx_bytes_a2b": retx[2] if retx else None, "retx_bytes_b2a": retx[3] if retx else None,
            "ssh_sw_a2b": ssh[0] if ssh else None, "ssh_sw_b2a": ssh[1] if ssh else None,
            "hassh_a2b": ssh[2].hex() if ssh and ssh[2] != b"\0" * 8 else "",
            "hassh_b2a": ssh[3].hex() if ssh and ssh[3] != b"\0" * 8 else "",
        }


def entropy_from_hist(hist: Counter) -> float:
    n = sum(hist.values())
    if not n:
        return 0.0
    return -sum((c / n) * math.log2(c / n) for c in hist.values() if c)


def share_from_hist(hist: Counter, wanted) -> float:
    n = sum(hist.values())
    if not n:
        return 0.0
    return sum(c for v, c in hist.items() if v in wanted) / n


def label_entropy(labels: Counter) -> float:
    n = sum(labels.values())
    if not n:
        return 0.0
    return -sum((c / n) * math.log2(c / n) for c in labels.values() if c)
