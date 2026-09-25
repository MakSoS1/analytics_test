from __future__ import annotations

"""Local wire-real DNS-over-QUIC (RFC 9250 framing) fixture for CoverLab.

The fixture is intentionally bounded to the isolated .test lab. It implements
DoQ ALPN and the two-octet DNS message length prefix on one query per
bidirectional QUIC stream. It is not a public recursive resolver.
"""

import argparse
import asyncio
import ssl
from collections import defaultdict

import dns.message
from aioquic.asyncio import QuicConnectionProtocol, serve
from aioquic.asyncio.client import connect
from aioquic.quic.configuration import QuicConfiguration
from aioquic.quic.events import StreamDataReceived

from .stage_m_dns_server import answer_query

DOQ_ALPN = ["doq"]


class DoQServerProtocol(QuicConnectionProtocol):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.buffers = defaultdict(bytearray)

    def quic_event_received(self, event):
        if not isinstance(event, StreamDataReceived):
            return
        self.buffers[event.stream_id].extend(event.data)
        if not event.end_stream:
            return
        data = bytes(self.buffers.pop(event.stream_id, b""))
        if len(data) < 2:
            self._quic.reset_stream(event.stream_id, error_code=0x02)
            self.transmit()
            return
        n = int.from_bytes(data[:2], "big")
        query = data[2:]
        if n != len(query) or n == 0:
            self._quic.reset_stream(event.stream_id, error_code=0x02)
            self.transmit()
            return
        try:
            response = answer_query(query)
        except Exception:
            q = dns.message.from_wire(query)
            response = dns.message.make_response(q).to_wire()
        framed = len(response).to_bytes(2, "big") + response
        self._quic.send_stream_data(event.stream_id, framed, end_stream=True)
        self.transmit()


class DoQClientProtocol(QuicConnectionProtocol):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.buffers = defaultdict(bytearray)
        self.waiters = {}

    def quic_event_received(self, event):
        if not isinstance(event, StreamDataReceived):
            return
        self.buffers[event.stream_id].extend(event.data)
        if event.end_stream:
            fut = self.waiters.get(event.stream_id)
            if fut and not fut.done():
                fut.set_result(bytes(self.buffers.pop(event.stream_id, b"")))

    async def query(self, wire: bytes, timeout: float = 8.0) -> bytes:
        sid = self._quic.get_next_available_stream_id()
        fut = asyncio.get_running_loop().create_future()
        self.waiters[sid] = fut
        framed = len(wire).to_bytes(2, "big") + wire
        self._quic.send_stream_data(sid, framed, end_stream=True)
        self.transmit()
        try:
            response = await asyncio.wait_for(fut, timeout=timeout)
        finally:
            self.waiters.pop(sid, None)
        if len(response) < 2:
            raise RuntimeError("short DoQ response")
        n = int.from_bytes(response[:2], "big")
        payload = response[2:]
        if n != len(payload):
            raise RuntimeError(f"invalid DoQ length prefix expected={n} got={len(payload)}")
        return payload


async def run_server(host: str, port: int, cert: str, key: str) -> None:
    cfg = QuicConfiguration(is_client=False, alpn_protocols=DOQ_ALPN)
    cfg.load_cert_chain(cert, key)
    server = await serve(host, port, configuration=cfg, create_protocol=DoQServerProtocol)
    try:
        await asyncio.Future()
    finally:
        server.close()


async def one_query(host: str, port: int, qname: str, qtype: str) -> dict:
    cfg = QuicConfiguration(is_client=True, alpn_protocols=DOQ_ALPN)
    cfg.verify_mode = ssl.CERT_NONE
    wire = dns.message.make_query(qname, qtype).to_wire()
    async with connect(
        host,
        port,
        configuration=cfg,
        create_protocol=DoQClientProtocol,
        server_name=host,
    ) as proto:
        response = await proto.query(wire)
    parsed = dns.message.from_wire(response)
    return {
        "qname": qname,
        "qtype": qtype,
        "request_bytes": len(wire),
        "response_bytes": len(response),
        "rcode": parsed.rcode(),
    }


def main() -> None:
    ap = argparse.ArgumentParser()
    sub = ap.add_subparsers(dest="cmd", required=True)
    s = sub.add_parser("server")
    s.add_argument("--host", default="10.20.0.20")
    s.add_argument("--port", type=int, default=8853)
    s.add_argument("--cert", required=True)
    s.add_argument("--key", required=True)
    q = sub.add_parser("query")
    q.add_argument("--host", default="doq-resolver.test")
    q.add_argument("--port", type=int, default=8853)
    q.add_argument("--qname", default="probe.stage-m.test.")
    q.add_argument("--qtype", default="A")
    a = ap.parse_args()
    if a.cmd == "server":
        asyncio.run(run_server(a.host, a.port, a.cert, a.key))
    else:
        print(asyncio.run(one_query(a.host, a.port, a.qname, a.qtype)))


if __name__ == "__main__":
    main()
