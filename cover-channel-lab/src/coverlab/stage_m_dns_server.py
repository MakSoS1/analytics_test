from __future__ import annotations

import argparse
import asyncio
import json
import socket
import struct
import time
from pathlib import Path

import dns.message
import dns.query
import dns.rcode
import dns.rdatatype
import dns.rrset

ZONE_SUFFIX = ".stage-m.test."
TRACE = Path("/tmp/coverlab_stage_m_dns_trace.jsonl")


def _trace(record: dict) -> None:
    with TRACE.open("a", encoding="utf-8") as f:
        f.write(json.dumps(record, separators=(",", ":"), default=str) + "\n")


def _allowed(qname: str) -> bool:
    return qname.lower().endswith(ZONE_SUFFIX)


def _authoritative_answer(wire: bytes) -> bytes:
    query = dns.message.from_wire(wire)
    response = dns.message.make_response(query)
    if not query.question:
        response.set_rcode(dns.rcode.FORMERR)
        return response.to_wire()
    q = query.question[0]
    qname = q.name.to_text()
    if not _allowed(qname):
        response.set_rcode(dns.rcode.REFUSED)
        return response.to_wire()
    if qname.lower().startswith("nx-") or ".nx-" in qname.lower():
        response.set_rcode(dns.rcode.NXDOMAIN)
        return response.to_wire()
    ttl = 30
    if q.rdtype == dns.rdatatype.A:
        response.answer.append(dns.rrset.from_text(qname, ttl, "IN", "A", "10.20.0.20"))
    elif q.rdtype == dns.rdatatype.AAAA:
        response.answer.append(dns.rrset.from_text(qname, ttl, "IN", "AAAA", "fd00::20"))
    elif q.rdtype == dns.rdatatype.TXT:
        response.answer.append(dns.rrset.from_text(qname, ttl, "IN", "TXT", '"stage-m-synthetic"'))
    else:
        response.set_rcode(dns.rcode.NOERROR)
    return response.to_wire()


def _recursive_answer(wire: bytes, upstream: str, timeout: float = 2.0) -> bytes:
    query = dns.message.from_wire(wire)
    if not query.question or not _allowed(query.question[0].name.to_text()):
        response = dns.message.make_response(query)
        response.set_rcode(dns.rcode.REFUSED)
        return response.to_wire()
    try:
        response = dns.query.udp(query, upstream, port=53, timeout=timeout)
        return response.to_wire()
    except Exception:
        response = dns.message.make_response(query)
        response.set_rcode(dns.rcode.SERVFAIL)
        return response.to_wire()


class UDPProtocol(asyncio.DatagramProtocol):
    def __init__(self, role: str, upstream: str):
        self.role = role
        self.upstream = upstream
        self.transport = None

    def connection_made(self, transport):
        self.transport = transport

    def datagram_received(self, data: bytes, addr):
        try:
            q = dns.message.from_wire(data)
            qname = q.question[0].name.to_text() if q.question else ""
            qtype = dns.rdatatype.to_text(q.question[0].rdtype) if q.question else ""
            out = _authoritative_answer(data) if self.role == "authoritative" else _recursive_answer(data, self.upstream)
            _trace({"ts": time.time(), "role": self.role, "transport": "udp", "client": addr[0], "qname": qname, "qtype": qtype, "bytes": len(data)})
            self.transport.sendto(out, addr)
        except Exception as exc:
            _trace({"ts": time.time(), "role": self.role, "transport": "udp", "client": addr[0], "error": str(exc)})


async def _handle_tcp(reader: asyncio.StreamReader, writer: asyncio.StreamWriter, role: str, upstream: str):
    peer = writer.get_extra_info("peername") or ("", 0)
    try:
        header = await reader.readexactly(2)
        n = struct.unpack("!H", header)[0]
        data = await reader.readexactly(n)
        q = dns.message.from_wire(data)
        qname = q.question[0].name.to_text() if q.question else ""
        qtype = dns.rdatatype.to_text(q.question[0].rdtype) if q.question else ""
        if role == "authoritative":
            out = _authoritative_answer(data)
        else:
            if not q.question or not _allowed(qname):
                resp = dns.message.make_response(q); resp.set_rcode(dns.rcode.REFUSED); out = resp.to_wire()
            else:
                try:
                    resp = await asyncio.to_thread(dns.query.tcp, q, upstream, 2.0, 53)
                    out = resp.to_wire()
                except Exception:
                    resp = dns.message.make_response(q); resp.set_rcode(dns.rcode.SERVFAIL); out = resp.to_wire()
        _trace({"ts": time.time(), "role": role, "transport": "tcp", "client": peer[0], "qname": qname, "qtype": qtype, "bytes": len(data)})
        writer.write(struct.pack("!H", len(out)) + out)
        await writer.drain()
    except Exception as exc:
        _trace({"ts": time.time(), "role": role, "transport": "tcp", "client": peer[0], "error": str(exc)})
    finally:
        writer.close()
        await writer.wait_closed()


async def main_async(host: str, role: str, upstream: str):
    loop = asyncio.get_running_loop()
    transport, _ = await loop.create_datagram_endpoint(lambda: UDPProtocol(role, upstream), local_addr=(host, 53))
    server = await asyncio.start_server(lambda r, w: _handle_tcp(r, w, role, upstream), host, 53)
    try:
        async with server:
            await server.serve_forever()
    finally:
        transport.close()


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--host", required=True)
    ap.add_argument("--role", choices=["authoritative", "recursive"], required=True)
    ap.add_argument("--upstream", default="10.20.0.20")
    args = ap.parse_args()
    asyncio.run(main_async(args.host, args.role, args.upstream))


if __name__ == "__main__":
    main()
