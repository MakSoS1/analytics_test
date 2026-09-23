from __future__ import annotations

"""Local-only DNS authoritative/forwarding fixture for Stage M.

No recursion to the Internet is implemented. Forward mode accepts exactly one
lab upstream address and is used only to create client->resolver->authoritative
wire topology inside the isolated namespace.
"""

import argparse
import socket
import socketserver
import threading

import dns.message
import dns.rcode
import dns.rdatatype
import dns.rrset


def answer_query(wire: bytes, *, upstream: str | None = None) -> bytes:
    if upstream:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.settimeout(3)
            s.sendto(wire, (upstream, 53))
            data, _ = s.recvfrom(65535)
            return data
    q = dns.message.from_wire(wire)
    r = dns.message.make_response(q)
    if not q.question:
        r.set_rcode(dns.rcode.FORMERR)
        return r.to_wire()
    question = q.question[0]
    name = question.name.to_text()
    first = name.split(".", 1)[0].lower()
    if first.startswith("nx-"):
        r.set_rcode(dns.rcode.NXDOMAIN)
        return r.to_wire()
    ttl = 30
    if question.rdtype == dns.rdatatype.A:
        r.answer.append(dns.rrset.from_text(name, ttl, "IN", "A", "10.20.0.20"))
    elif question.rdtype == dns.rdatatype.AAAA:
        r.answer.append(dns.rrset.from_text(name, ttl, "IN", "AAAA", "fd20::20"))
    elif question.rdtype == dns.rdatatype.TXT:
        r.answer.append(dns.rrset.from_text(name, ttl, "IN", "TXT", '"stage-m-lab"'))
    else:
        r.set_rcode(dns.rcode.NOERROR)
    return r.to_wire()


class UDPHandler(socketserver.BaseRequestHandler):
    upstream: str | None = None
    def handle(self):
        data, sock = self.request
        try:
            sock.sendto(answer_query(data, upstream=self.upstream), self.client_address)
        except Exception:
            return


class TCPHandler(socketserver.BaseRequestHandler):
    upstream: str | None = None
    def handle(self):
        head = self.request.recv(2)
        if len(head) != 2:
            return
        need = int.from_bytes(head, "big")
        data = b""
        while len(data) < need:
            chunk = self.request.recv(need - len(data))
            if not chunk:
                return
            data += chunk
        try:
            reply = answer_query(data, upstream=self.upstream)
            self.request.sendall(len(reply).to_bytes(2, "big") + reply)
        except Exception:
            return


class UDPServer(socketserver.ThreadingUDPServer):
    allow_reuse_address = True


class TCPServer(socketserver.ThreadingTCPServer):
    allow_reuse_address = True


def main() -> None:
    p = argparse.ArgumentParser()
    p.add_argument("--bind", required=True)
    p.add_argument("--port", type=int, default=53)
    p.add_argument("--upstream")
    a = p.parse_args()
    if a.upstream and a.upstream not in {"10.20.0.20"}:
        raise SystemExit("Stage M DNS forwarder only permits the local authoritative fixture")
    UDPHandler.upstream = a.upstream
    TCPHandler.upstream = a.upstream
    udp = UDPServer((a.bind, a.port), UDPHandler)
    tcp = TCPServer((a.bind, a.port), TCPHandler)
    tu = threading.Thread(target=udp.serve_forever, daemon=True)
    tt = threading.Thread(target=tcp.serve_forever, daemon=True)
    tu.start(); tt.start()
    try:
        tu.join(); tt.join()
    finally:
        udp.shutdown(); tcp.shutdown()


if __name__ == "__main__":
    main()
