from __future__ import annotations

"""Local authoritative/recursive DNS fixture used by Stage M.

The resolver only forwards to the fixed in-lab authoritative address supplied on
its command line. It has no system resolver fallback and therefore cannot be
used as a general recursive resolver or tunnel to the Internet.
"""

import argparse
import socketserver
import struct
from dataclasses import dataclass

import dns.message
import dns.rcode
import dns.rdatatype
import dns.rrset
import dns.query


@dataclass(frozen=True)
class Config:
    mode: str
    upstream: str | None = None
    upstream_port: int = 53


def _authoritative_response(wire: bytes) -> bytes:
    query = dns.message.from_wire(wire)
    response = dns.message.make_response(query)
    if not query.question:
        response.set_rcode(dns.rcode.FORMERR)
        return response.to_wire()
    q = query.question[0]
    qname = q.name.to_text().lower()
    if ".nx." in qname or qname.startswith("nx."):
        response.set_rcode(dns.rcode.NXDOMAIN)
        return response.to_wire()
    ttl = 30
    if q.rdtype == dns.rdatatype.A:
        response.answer.append(dns.rrset.from_text(q.name, ttl, "IN", "A", "10.20.0.20"))
    elif q.rdtype == dns.rdatatype.AAAA:
        response.answer.append(dns.rrset.from_text(q.name, ttl, "IN", "AAAA", "fd00:20::20"))
    elif q.rdtype == dns.rdatatype.TXT:
        response.answer.append(dns.rrset.from_text(q.name, ttl, "IN", "TXT", '"stage-m-local"'))
    else:
        response.set_rcode(dns.rcode.NOERROR)
    return response.to_wire()


def _resolve(cfg: Config, wire: bytes, tcp: bool) -> bytes:
    if cfg.mode == "authoritative":
        return _authoritative_response(wire)
    if cfg.mode != "resolver" or not cfg.upstream:
        raise RuntimeError("invalid DNS fixture mode")
    query = dns.message.from_wire(wire)
    if tcp:
        response = dns.query.tcp(query, cfg.upstream, port=cfg.upstream_port, timeout=2.0)
    else:
        response = dns.query.udp(query, cfg.upstream, port=cfg.upstream_port, timeout=2.0)
    return response.to_wire()


class UDPHandler(socketserver.BaseRequestHandler):
    def handle(self) -> None:
        data, sock = self.request
        try:
            out = _resolve(self.server.cfg, data, False)  # type: ignore[attr-defined]
        except Exception:
            try:
                q = dns.message.from_wire(data)
                r = dns.message.make_response(q); r.set_rcode(dns.rcode.SERVFAIL); out = r.to_wire()
            except Exception:
                return
        sock.sendto(out, self.client_address)


class TCPHandler(socketserver.BaseRequestHandler):
    def handle(self) -> None:
        head = self.request.recv(2)
        if len(head) != 2:
            return
        n = struct.unpack("!H", head)[0]
        chunks = bytearray()
        while len(chunks) < n:
            part = self.request.recv(n - len(chunks))
            if not part:
                return
            chunks.extend(part)
        try:
            out = _resolve(self.server.cfg, bytes(chunks), True)  # type: ignore[attr-defined]
        except Exception:
            try:
                q = dns.message.from_wire(bytes(chunks))
                r = dns.message.make_response(q); r.set_rcode(dns.rcode.SERVFAIL); out = r.to_wire()
            except Exception:
                return
        self.request.sendall(struct.pack("!H", len(out)) + out)


class ThreadingUDP(socketserver.ThreadingUDPServer):
    allow_reuse_address = True


class ThreadingTCP(socketserver.ThreadingTCPServer):
    allow_reuse_address = True


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--host", required=True)
    ap.add_argument("--port", type=int, default=53)
    ap.add_argument("--mode", choices=["authoritative", "resolver"], required=True)
    ap.add_argument("--upstream")
    ap.add_argument("--upstream-port", type=int, default=53)
    args = ap.parse_args()
    cfg = Config(args.mode, args.upstream, args.upstream_port)
    if cfg.mode == "resolver" and not cfg.upstream:
        raise SystemExit("--upstream is required in resolver mode")
    udp = ThreadingUDP((args.host, args.port), UDPHandler); udp.cfg = cfg  # type: ignore[attr-defined]
    tcp = ThreadingTCP((args.host, args.port), TCPHandler); tcp.cfg = cfg  # type: ignore[attr-defined]
    import threading
    t = threading.Thread(target=tcp.serve_forever, daemon=True); t.start()
    try:
        udp.serve_forever()
    finally:
        udp.shutdown(); tcp.shutdown(); tcp.server_close(); udp.server_close()


if __name__ == "__main__":
    main()
