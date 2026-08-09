from __future__ import annotations

import argparse
import asyncio
import json
import ssl
from collections import defaultdict

from aioquic.asyncio import QuicConnectionProtocol, serve
from aioquic.asyncio.client import connect
from aioquic.h3.connection import H3_ALPN, H3Connection
from aioquic.h3.events import DataReceived, DatagramReceived, HeadersReceived, WebTransportStreamDataReceived
from aioquic.quic.configuration import QuicConfiguration
from aioquic.quic.events import ProtocolNegotiated, StreamDataReceived


class LabH3Server(QuicConnectionProtocol):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.h3: H3Connection | None = None
        self.headers = {}
        self.body = defaultdict(bytearray)

    def quic_event_received(self, event):
        if isinstance(event, ProtocolNegotiated) and event.alpn_protocol in H3_ALPN:
            self.h3 = H3Connection(self._quic, enable_webtransport=True)
        if self.h3 is None:
            return
        for he in self.h3.handle_event(event):
            self.http_event(he)

    def http_event(self, event):
        if self.h3 is None:
            return
        if isinstance(event, HeadersReceived):
            headers = dict(event.headers)
            self.headers[event.stream_id] = headers
            method = headers.get(b":method", b"GET")
            protocol = headers.get(b":protocol")
            if method == b"CONNECT" and protocol in {b"connect-udp", b"webtransport"}:
                response = [(b":status", b"200"), (b"server", b"coverlab-h3")]
                if protocol == b"webtransport":
                    response.append((b"sec-webtransport-http3-draft", b"draft02"))
                self.h3.send_headers(event.stream_id, response, end_stream=False)
                self.transmit()
            elif event.stream_ended:
                self.respond(event.stream_id)
        elif isinstance(event, DataReceived):
            self.body[event.stream_id].extend(event.data)
            if event.stream_ended:
                self.respond(event.stream_id)
        elif isinstance(event, DatagramReceived):
            self.h3.send_datagram(event.stream_id, event.data)
            self.transmit()
        elif isinstance(event, WebTransportStreamDataReceived):
            # Once the WebTransport stream prefix has established the session,
            # both directions carry raw QUIC stream bytes. Echo them directly.
            self._quic.send_stream_data(
                event.stream_id,
                event.data,
                end_stream=event.stream_ended,
            )
            self.transmit()

    def respond(self, stream_id: int):
        if self.h3 is None:
            return
        h = self.headers.get(stream_id, {})
        payload = json.dumps(
            {
                "ok": True,
                "method": h.get(b":method", b"GET").decode(errors="replace"),
                "path": h.get(b":path", b"/").decode(errors="replace"),
                "request_bytes": len(self.body.get(stream_id, b"")),
            },
            separators=(",", ":"),
        ).encode()
        self.h3.send_headers(
            stream_id,
            [(b":status", b"200"), (b"content-type", b"application/json")],
        )
        self.h3.send_data(stream_id, payload, end_stream=True)
        self.transmit()


class LabH3Client(QuicConnectionProtocol):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.h3 = H3Connection(self._quic, enable_webtransport=True)
        self.events = defaultdict(list)
        self.waiters = {}
        self.header_waiters = {}
        self.datagrams = {}
        self.pending_datagrams = defaultdict(list)
        self.webtransport_streams: set[int] = set()
        self.webtransport_waiters = {}
        self.webtransport_buffers = defaultdict(bytearray)

    def quic_event_received(self, event):
        # For a client-created bidirectional WebTransport stream, the peer's
        # direction is raw QUIC stream data, not a second HTTP/3 frame sequence.
        # Intercept it before H3Connection attempts request-stream parsing.
        if isinstance(event, StreamDataReceived) and event.stream_id in self.webtransport_streams:
            self.webtransport_buffers[event.stream_id].extend(event.data)
            if event.end_stream:
                fut = self.webtransport_waiters.get(event.stream_id)
                if fut and not fut.done():
                    fut.set_result(bytes(self.webtransport_buffers[event.stream_id]))
            return

        for he in self.h3.handle_event(event):
            sid = getattr(he, "stream_id", None)
            if isinstance(he, DatagramReceived):
                fut = self.datagrams.get(he.stream_id)
                if fut and not fut.done():
                    fut.set_result(he.data)
                else:
                    self.pending_datagrams[he.stream_id].append(he.data)
                continue
            if sid is not None:
                self.events[sid].append(he)
                if isinstance(he, HeadersReceived):
                    fut = self.header_waiters.get(sid)
                    if fut and not fut.done():
                        fut.set_result(he)
                if isinstance(he, (HeadersReceived, DataReceived)) and he.stream_ended:
                    fut = self.waiters.get(sid)
                    if fut and not fut.done():
                        fut.set_result(self.events[sid])

    @staticmethod
    def _status(headers_event: HeadersReceived) -> int:
        for k, v in headers_event.headers:
            if k == b":status":
                return int(v)
        return 0

    async def _await_connect_headers(self, sid: int, timeout: float = 5.0) -> int:
        for event in self.events[sid]:
            if isinstance(event, HeadersReceived):
                status = self._status(event)
                if 200 <= status < 300:
                    return status
                raise RuntimeError(f"H3 CONNECT rejected on stream {sid}: status={status}")
        fut = asyncio.get_running_loop().create_future()
        self.header_waiters[sid] = fut
        try:
            event = await asyncio.wait_for(fut, timeout=timeout)
        finally:
            self.header_waiters.pop(sid, None)
        status = self._status(event)
        if not 200 <= status < 300:
            raise RuntimeError(f"H3 CONNECT rejected on stream {sid}: status={status}")
        return status

    async def request(self, authority: str, path: str, method: str = "GET", body: bytes = b""):
        sid = self._quic.get_next_available_stream_id()
        fut = asyncio.get_running_loop().create_future()
        self.waiters[sid] = fut
        self.h3.send_headers(
            sid,
            [
                (b":method", method.encode()),
                (b":scheme", b"https"),
                (b":authority", authority.encode()),
                (b":path", path.encode()),
                (b"user-agent", b"coverlab-aioquic/1"),
            ],
            end_stream=(not body),
        )
        if body:
            self.h3.send_data(sid, body, end_stream=True)
        self.transmit()
        try:
            events = await asyncio.wait_for(fut, timeout=8)
        finally:
            self.waiters.pop(sid, None)
        status = 0
        response_bytes = 0
        for e in events:
            if isinstance(e, HeadersReceived):
                status = self._status(e)
            elif isinstance(e, DataReceived):
                response_bytes += len(e.data)
        return {"stream_id": sid, "status": status, "response_bytes": response_bytes}

    async def _datagram_roundtrip(self, sid: int, payload: bytes) -> bytes:
        if len(payload) > 1000:
            raise ValueError("single H3 datagram payload must be <= 1000 bytes")
        for attempt in range(3):
            if self.pending_datagrams[sid]:
                return self.pending_datagrams[sid].pop(0)
            fut = asyncio.get_running_loop().create_future()
            self.datagrams[sid] = fut
            self.h3.send_datagram(sid, payload)
            self.transmit()
            try:
                return await asyncio.wait_for(fut, timeout=1.5 + attempt * 0.5)
            except TimeoutError:
                # RFC 9297 DATAGRAM is unreliable. Bounded retry keeps the
                # synthetic lab deterministic without changing the wire type.
                continue
            finally:
                self.datagrams.pop(sid, None)
        raise TimeoutError(f"no H3 datagram echo after 3 attempts on stream {sid}")

    async def connect_udp(self, authority: str, payload: bytes):
        sid = self._quic.get_next_available_stream_id()
        self.h3.send_headers(
            sid,
            [
                (b":method", b"CONNECT"),
                (b":scheme", b"https"),
                (b":authority", authority.encode()),
                (b":path", b"/.well-known/masque/udp/echo.test/7/"),
                (b":protocol", b"connect-udp"),
                (b"capsule-protocol", b"?1"),
            ],
            end_stream=False,
        )
        self.transmit()
        status = await self._await_connect_headers(sid)

        echoed_total = 0
        chunks = [payload[i : i + 1000] for i in range(0, len(payload), 1000)] or [b""]
        for chunk in chunks:
            echoed = await self._datagram_roundtrip(sid, chunk)
            if echoed != chunk:
                raise RuntimeError(
                    f"H3 datagram echo mismatch on stream {sid}: sent={len(chunk)} received={len(echoed)}"
                )
            echoed_total += len(echoed)

        self.h3.send_data(sid, b"", end_stream=True)
        self.transmit()
        return {
            "stream_id": sid,
            "status": status,
            "datagram_bytes": echoed_total,
            "datagram_count": len(chunks),
        }

    async def webtransport(self, authority: str, payload: bytes):
        sid = self._quic.get_next_available_stream_id()
        self.h3.send_headers(
            sid,
            [
                (b":method", b"CONNECT"),
                (b":scheme", b"https"),
                (b":authority", authority.encode()),
                (b":path", b"/webtransport"),
                (b":protocol", b"webtransport"),
                (b"sec-webtransport-http3-draft", b"draft02"),
            ],
            end_stream=False,
        )
        self.transmit()
        status = await self._await_connect_headers(sid)

        stream_id = self.h3.create_webtransport_stream(sid, is_unidirectional=False)
        self.webtransport_streams.add(stream_id)
        fut = asyncio.get_running_loop().create_future()
        self.webtransport_waiters[stream_id] = fut
        self._quic.send_stream_data(stream_id, payload, end_stream=True)
        self.transmit()
        try:
            echoed = await asyncio.wait_for(fut, timeout=5)
        finally:
            self.webtransport_waiters.pop(stream_id, None)
            self.webtransport_streams.discard(stream_id)
        if echoed != payload:
            raise RuntimeError(
                f"WebTransport echo mismatch: sent={len(payload)} received={len(echoed)}"
            )

        self.h3.send_data(sid, b"", end_stream=True)
        self.transmit()
        return {
            "stream_id": sid,
            "status": status,
            "webtransport_stream": stream_id,
            "sent_bytes": len(payload),
            "echo_bytes": len(echoed),
        }


async def run_server(cert: str, key: str, host: str, port: int):
    cfg = QuicConfiguration(
        is_client=False,
        alpn_protocols=H3_ALPN,
        max_datagram_frame_size=65536,
    )
    cfg.load_cert_chain(cert, key)
    await serve(host, port, configuration=cfg, create_protocol=LabH3Server)
    await asyncio.Future()


async def run_client(host: str, port: int, mode: str, path: str, body: bytes):
    cfg = QuicConfiguration(
        is_client=True,
        alpn_protocols=H3_ALPN,
        max_datagram_frame_size=65536,
    )
    cfg.verify_mode = ssl.CERT_NONE
    authority = f"{host}:{port}"
    async with connect(
        host,
        port,
        configuration=cfg,
        create_protocol=LabH3Client,
        server_name=host,
    ) as proto:
        if mode == "request":
            return await proto.request(authority, path, "POST" if body else "GET", body)
        if mode == "connect-udp":
            return await proto.connect_udp(authority, body or b"synthetic-datagram")
        if mode == "webtransport":
            return await proto.webtransport(authority, body or b"synthetic-webtransport")
        raise ValueError(mode)


def main():
    p = argparse.ArgumentParser()
    sub = p.add_subparsers(dest="cmd", required=True)
    ps = sub.add_parser("server")
    ps.add_argument("--cert", required=True)
    ps.add_argument("--key", required=True)
    ps.add_argument("--host", default="10.20.0.20")
    ps.add_argument("--port", type=int, default=8444)
    pc = sub.add_parser("client")
    pc.add_argument("--host", default="cover-h3.test")
    pc.add_argument("--port", type=int, default=8444)
    pc.add_argument("--mode", choices=["request", "connect-udp", "webtransport"], default="request")
    pc.add_argument("--path", default="/h3/status")
    pc.add_argument("--body", default="")
    args = p.parse_args()
    if args.cmd == "server":
        asyncio.run(run_server(args.cert, args.key, args.host, args.port))
    else:
        print(json.dumps(asyncio.run(run_client(args.host, args.port, args.mode, args.path, args.body.encode()))))


if __name__ == "__main__":
    main()
