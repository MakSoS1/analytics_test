#!/usr/bin/env python3
from __future__ import annotations

import json
import shutil
from pathlib import Path

from scapy.all import wrpcap

import generate_corpus as base

ROOT = Path(__file__).resolve().parent
ARTIFACTS = ROOT / "edge-artifacts"
PCAP_DIR = ARTIFACTS / "pcap"


def add_case(cases: list[dict], name: str, packets: list, required: list[str], allowed: list[str] | None = None) -> None:
    path = PCAP_DIR / f"{name}.pcap"
    wrpcap(str(path), packets)
    cases.append(
        {
            "name": name,
            "pcap": str(path.relative_to(ARTIFACTS)),
            "required": list(dict.fromkeys(required)),
            "allowed": list(dict.fromkeys(required if allowed is None else allowed)),
        }
    )


def tls_ext(ext_type: int, data: bytes) -> bytes:
    return ext_type.to_bytes(2, "big") + len(data).to_bytes(2, "big") + data


def tls_client_hello_custom(*, hostname: str | None = None, ech: bool = False, random_bytes: bytes | None = None) -> bytes:
    if random_bytes is None:
        random_bytes = bytes(range(32))
    if len(random_bytes) != 32:
        raise ValueError("TLS random must be 32 bytes")

    extensions = b""
    if hostname is not None:
        host = hostname.encode("ascii")
        name = b"\x00" + len(host).to_bytes(2, "big") + host
        extensions += tls_ext(0x0000, len(name).to_bytes(2, "big") + name)

    # signature_algorithms, supported_groups, ec_point_formats, supported_versions, ALPN
    extensions += tls_ext(0x000D, b"\x00\x06\x04\x03\x08\x04\x04\x01")
    extensions += tls_ext(0x000A, b"\x00\x04\x00\x1d\x00\x17")
    extensions += tls_ext(0x000B, b"\x01\x00")
    extensions += tls_ext(0x002B, b"\x04\x03\x04\x03\x03")
    extensions += tls_ext(0x0010, b"\x00\x0c\x02h2\x08http/1.1")
    if ech:
        # RFC-style ECH extension codepoint 0xfe0d. The payload is deterministic
        # test material, sufficient for validating extension recognition, not cryptography.
        extensions += tls_ext(0xFE0D, b"\x01\x00\x20" + bytes(range(32)) + b"\x00\x10" + b"E" * 16)

    cipher_suites = b"\x13\x01\x13\x02\x13\x03\xc0\x2f\xc0\x2b\x00\x9e"
    body = (
        b"\x03\x03"
        + random_bytes
        + b"\x00"
        + len(cipher_suites).to_bytes(2, "big")
        + cipher_suites
        + b"\x01\x00"
        + len(extensions).to_bytes(2, "big")
        + extensions
    )
    handshake = b"\x01" + len(body).to_bytes(3, "big") + body
    return b"\x16\x03\x01" + len(handshake).to_bytes(2, "big") + handshake


def bgp_message(msg_type: int, body: bytes = b"") -> bytes:
    return b"\xff" * 16 + (19 + len(body)).to_bytes(2, "big") + bytes([msg_type]) + body


def dtls_server_hello(version: bytes) -> bytes:
    hello = bytearray(base.dtls_client_hello())
    hello[1:3] = version
    hello[13] = 0x02
    # Also change the ServerHello legacy version inside the handshake body.
    hello[25:27] = version
    return bytes(hello)


def sip_request(method: str) -> bytes:
    return (
        f"{method} sip:bob@example.test SIP/2.0\r\n".encode()
        + b"Via: SIP/2.0/UDP edge.example.test;branch=z9hG4bK-edge\r\n"
        + b"From: <sip:alice@example.test>;tag=edge\r\n"
        + b"To: <sip:bob@example.test>\r\n"
        + f"CSeq: 2 {method}\r\n".encode()
        + b"Call-ID: edge@example.test\r\nContent-Length: 0\r\n\r\n"
    )


def sip_response() -> bytes:
    return (
        b"SIP/2.0 200 OK\r\n"
        b"Via: SIP/2.0/TCP edge.example.test;branch=z9hG4bK-edge\r\n"
        b"From: <sip:alice@example.test>;tag=edge\r\n"
        b"To: <sip:bob@example.test>;tag=server\r\n"
        b"CSeq: 2 OPTIONS\r\nCall-ID: edge@example.test\r\nContent-Length: 0\r\n\r\n"
    )


def main() -> None:
    if ARTIFACTS.exists():
        shutil.rmtree(ARTIFACTS)
    PCAP_DIR.mkdir(parents=True, exist_ok=True)
    cases: list[dict] = []
    port = 50000

    def tcp(name: str, dport: int, events: list[tuple[str, bytes]], required: list[str], allowed: list[str] | None = None) -> None:
        nonlocal port
        add_case(cases, name, base.tcp_conversation(port, dport, events), required, allowed)
        port += 1

    def udp(name: str, dport: int, payload: bytes, required: list[str], allowed: list[str] | None = None, response: bytes | None = None) -> None:
        nonlocal port
        add_case(cases, name, base.udp_exchange(port, dport, payload, response), required, allowed)
        port += 1

    # BitTorrent DHT query diversity.
    udp("dht-get-peers", 16881, b"d1:ad2:id20:abcdefghijklmnopqrste1:q9:get_peers1:t2:aa1:y1:qe", ["bt-dht"])
    udp("dht-announce-peer", 16882, b"d1:ad2:id20:abcdefghijklmnopqrste1:q13:announce_peer1:t2:ab1:y1:qe", ["bt-dht"])

    # Upgrade-to-encryption commands, including TCP segmentation across the marker.
    tcp("ftp-auth-tls-segmented", 2121, [("s", b"220 edge FTP ready\r\n"), ("c", b"AUTH "), ("c", b"TLS\r\n")], ["ftp"])
    tcp("ftp-auth-ssl", 2122, [("s", b"220 edge FTP ready\r\n"), ("c", b"AUTH SSL\r\n")], ["ftp"])
    tcp("http2-prior-knowledge-segmented", 18081, [("c", b"PRI * HTTP/2.0\r\n\r\n"), ("c", b"SM\r\n\r\n")], ["http"])
    tcp("imap-starttls-segmented", 1143, [("s", b"* OK edge IMAP ready\r\n"), ("c", b"A42 START"), ("c", b"TLS\r\n")], ["imap"])
    tcp("ldap-starttls-oid", 1389, [("c", b"\x30\x25\x02\x01\x01\x77\x20\x80\x161.3.6.1.4.1.1466.20037")], ["ldap"])
    mqtt31 = b"\x10\x16\x00\x06MQIsdp\x03\x02\x00\x3c\x00\x08edge-v31"
    tcp("mqtt-v31-offport", 11883, [("c", mqtt31)], ["mqtt"])
    udp("ntp-v4-offport", 40123, b"\x23" + b"\x00" * 47, ["ntp"])
    udp("ntp-v3-offport", 40124, b"\x1b" + b"\x00" * 47, ["ntp"])
    tcp("pop3-stls-segmented", 1110, [("s", b"+OK edge POP3 ready\r\n"), ("c", b"ST"), ("c", b"LS\r\n")], ["pop3"])

    # RDP negotiation variants.
    rdp_cookie = b"\x03\x00\x00\x2a\x25\xe0\x00\x00\x00\x00\x00Cookie: mstshash=edge\r\n\x01\x00\x08\x00\x03\x00\x00\x00"
    tcp("rdp-cookie-offport", 13389, [("c", rdp_cookie)], ["rdp"])
    rdp_response = bytes.fromhex("030000130ed000001234000200080003000000")
    tcp("rdp-negotiation-response", 13390, [("s", rdp_response)], ["rdp"])

    # SIP method/response breadth, UDP/TCP and non-default ports.
    udp("sip-register-udp", 15060, sip_request("REGISTER"), ["sip"])
    tcp("sip-options-tcp", 15061, [("c", sip_request("OPTIONS"))], ["sip"])
    udp("sip-bye-udp", 15062, sip_request("BYE"), ["sip"])
    tcp("sip-response-tcp", 15063, [("s", sip_response())], ["sip"])

    # SNMP versions and generic Telnet negotiation.
    udp("snmp-v1", 1161, bytes.fromhex("301002010004067075626c6963a003020100"), ["snmp"])
    udp("snmp-v2c", 1162, bytes.fromhex("301002010104067075626c6963a003020100"), ["snmp"])
    udp("snmp-v3", 1163, bytes.fromhex("3010020103300b0201010201000403000000"), ["snmp"])
    tcp("telnet-generic-iac", 2323, [("s", b"\xff\xfd\x18edge login: ")], ["telnet"])

    # TLS with actual ECH extension, segmented ClientHello, and hard negative where FE0D
    # occurs in Random but is NOT an extension.
    ech_hello = tls_client_hello_custom(hostname="public.example", ech=True)
    tcp("tls-ech", 443, [("c", ech_hello)], ["tls", "tls-ech"], ["tls", "tls-ech"])
    cut = len(ech_hello) // 2
    tcp("tls-ech-segmented", 8443, [("c", ech_hello[:cut]), ("c", ech_hello[cut:])], ["tls", "tls-ech"], ["tls", "tls-ech"])
    fake_random = b"\x01\x02\xfe\x0d" + bytes(range(4, 32))
    no_ech = tls_client_hello_custom(hostname="ordinary.example", ech=False, random_bytes=fake_random)
    tcp("tls-fe0d-random-not-ech", 9443, [("c", no_ech)], ["tls"], ["tls"])

    # SSH legacy identification and QUIC variants.
    tcp("ssh-v1-offport", 2022, [("s", b"SSH-1.5-OpenSSH_3.9\r\n")], ["ssh"])
    quic_v2 = b"\xc3\x6b\x33\x43\xcf\x08V2DCID00\x08V2SCID00\x00\x14" + b"\x00" * 20
    udp("quic-v2", 1443, quic_v2, ["quic"])
    quic_vn = b"\xc0\x00\x00\x00\x00\x08VNDCID00\x08VNSCID00\x00\x00\x00\x01\x6b\x33\x43\xcf"
    udp("quic-version-negotiation", 2443, quic_vn, ["quic"])

    # IEC104 U-frame breadth.
    for name, frame in (
        ("iec104-startdt-con", "68040b000000"),
        ("iec104-stopdt-con", "680423000000"),
        ("iec104-testfr-act", "680443000000"),
        ("iec104-testfr-con", "680483000000"),
    ):
        tcp(name, 12404, [("c", bytes.fromhex(frame))], ["iec104"])

    # BGP message types 3/4/5.
    tcp("bgp-notification", 1179, [("c", bgp_message(3, b"\x06\x00"))], ["bgp"])
    tcp("bgp-keepalive", 2179, [("c", bgp_message(4))], ["bgp"])
    tcp("bgp-route-refresh", 3179, [("c", bgp_message(5, b"\x00\x01\x00\x01"))], ["bgp"])

    # PostgreSQL TLS negotiation and cancellation are visible before encryption.
    tcp("postgres-sslrequest", 15432, [("c", bytes.fromhex("0000000804d2162f"))], ["postgresql"])
    tcp("postgres-cancelrequest", 25432, [("c", bytes.fromhex("0000001004d2162e0000000100000002"))], ["postgresql"])

    # RADIUS request/response flow variants. The negative below is intentionally crafted
    # to catch stateless response rules that classify arbitrary UDP starting with code 2.
    access_req = base.radius_access_request()
    radius_accept = b"\x02\x2a\x00\x14" + bytes(range(16))
    radius_reject = b"\x03\x2a\x00\x14" + bytes(range(16))
    radius_challenge = b"\x0b\x2a\x00\x14" + bytes(range(16))
    udp("radius-accept-flow", 1812, access_req, ["radius"], ["radius"], radius_accept)
    udp("radius-reject-flow", 2812, access_req, ["radius"], ["radius"], radius_reject)
    udp("radius-challenge-flow", 3812, access_req, ["radius"], ["radius"], radius_challenge)
    udp("radius-random-code2-negative", 45670, b"\x02RANDOM-UDP-THAT-IS-NOT-RADIUS-0123456789", [], [])

    # RTSP/2.0 and octet-counted syslog.
    rtsp2 = b"OPTIONS rtsp://media.example.test/movie RTSP/2.0\r\nCSeq: 7\r\nUser-Agent: edge\r\n\r\n"
    tcp("rtsp2-request", 1554, [("c", rtsp2)], ["rtsp"])
    rtsp2_resp = b"RTSP/2.0 200 OK\r\nCSeq: 7\r\nContent-Length: 0\r\n\r\n"
    tcp("rtsp2-response", 2554, [("s", rtsp2_resp)], ["rtsp"])
    syslog_payload = b"<165>1 2026-08-25T10:00:00Z edge app 1 ID47 - edge"
    framed = str(len(syslog_payload)).encode() + b" " + syslog_payload
    tcp("syslog-octet-counted", 1514, [("c", framed)], ["syslog"])

    # STUN over TCP and DTLS ServerHello variants.
    stun = b"\x01\x01\x00\x00\x21\x12\xa4\x42" + b"EDGE-STUN-12"
    tcp("stun-tcp", 13478, [("c", stun)], ["stun"])
    udp("dtls12-serverhello", 14433, dtls_server_hello(b"\xfe\xfd"), ["dtls"])
    udp("dtls10-serverhello", 24433, dtls_server_hello(b"\xfe\xff"), ["dtls"])

    # OPC UA message type breadth.
    for name, payload in (
        ("opc-ack", b"ACKF\x08\x00\x00\x00"),
        ("opc-err", b"ERRF\x10\x00\x00\x00\x00\x00\x00\x00edge"),
        ("opc-opn", b"OPNF\x10\x00\x00\x00" + b"\x00" * 8),
    ):
        tcp(name, 14840, [("c", payload)], ["opc"])

    # OpenVPN control packet after a validated reset exchange.
    ovpn_client = base.openvpn_packet(0x38, b"CLNTEDGE")
    ovpn_server = base.openvpn_packet(0x40, b"SRVREDGE")
    ovpn_control = base.openvpn_packet(0x20, b"CLNTEDGE")
    ovpn_ack = base.openvpn_packet(0x28, b"CLNTEDGE")
    add_case(cases, "openvpn-control-after-reset", base.udp_exchange(56000, 11194, ovpn_client, ovpn_server) + base.stamp([base.eth_ip(base.CLIENT_IP, base.SERVER_IP) / __import__('scapy.all', fromlist=['UDP']).UDP(sport=56000, dport=11194) / __import__('scapy.all', fromlist=['Raw']).Raw(ovpn_control)], base.BASE_TS + 1), ["openvpn"], ["openvpn"])
    add_case(cases, "openvpn-ack-after-reset", base.udp_exchange(56001, 21194, ovpn_client, ovpn_server) + base.stamp([base.eth_ip(base.CLIENT_IP, base.SERVER_IP) / __import__('scapy.all', fromlist=['UDP']).UDP(sport=56001, dport=21194) / __import__('scapy.all', fromlist=['Raw']).Raw(ovpn_ack)], base.BASE_TS + 1), ["openvpn"], ["openvpn"])

    # New precise TLS endpoint families.
    tls_services = {
        "outlook-new": ("outlook", "outlook.com"),
        "facebook-chat-new": ("facebook-chat", "mqtt.c10r.facebook.com"),
        "gmail-imap": ("gmail", "imap.gmail.com"),
        "gmail-smtp": ("gmail", "smtp.gmail.com"),
        "ms-update-download": ("microsoft-update", "download.windowsupdate.com"),
        "ms-update-delivery": ("microsoft-update", "dl.delivery.mp.microsoft.com"),
        "netflix-so": ("netflix", "nflxso.net"),
        "netflix-ext": ("netflix", "nflxext.com"),
        "skype-assets": ("skype", "skypeassets.com"),
        "webex-spark": ("webex", "ciscospark.com"),
        "youtube-nocookie": ("youtube", "youtube-nocookie.com"),
    }
    for name, (detector, hostname) in tls_services.items():
        hello = base.tls_client_hello(hostname)
        cut = max(20, len(hello) // 3)
        tcp(f"tls-service-{name}", 443, [("c", hello[:cut]), ("c", hello[cut:])], ["tls", detector], ["tls", detector])

    # HTTP Host service fallbacks (useful after TLS termination / explicit proxy visibility).
    http_services = {
        "outlook": "outlook.com",
        "gmail": "mail.google.com",
        "microsoft-update": "download.windowsupdate.com",
        "netflix": "www.netflix.com",
        "skype": "api.skype.com",
        "teamviewer": "router.teamviewer.com",
        "webex": "client.webex.com",
        "youtube": "www.youtube.com",
    }
    for detector, hostname in http_services.items():
        req = f"GET /edge HTTP/1.1\r\nHost: {hostname}\r\nUser-Agent: edge\r\nConnection: close\r\n\r\n".encode()
        tcp(f"http-host-{detector}", 18080, [("c", req)], ["http", detector], ["http", detector])

    # Hard-negative / near-miss traffic.
    tcp("negative-sip-no-via", 45671, [("c", b"OPTIONS sip:x@example.test SIP/2.0\r\nCSeq: 1 OPTIONS\r\n\r\n")], [], [])
    tcp("negative-rtsp-no-cseq", 45672, [("c", b"OPTIONS rtsp://example.test/x RTSP/1.0\r\nUser-Agent: ordinary\r\n\r\n")], [], [])
    udp("negative-stun-cookie-wrong-offset", 45673, b"\x00\x01\x21\x12\xa4\x42" + b"not-stun", [], [])
    tcp("negative-bgp-bad-marker", 45674, [("c", b"\xff" * 15 + b"\x00\x00\x13\x04")], [], [])
    tcp("negative-ftp-near-command", 45675, [("c", b"XAUTH TLS\r\nordinary\r\n")], [], [])

    # Domain-boundary negatives must never become service attribution.
    for idx, hostname in enumerate(("notyoutube.com", "youtube.com.evil.test", "notnetflix.com", "webex.com.evil.test")):
        tcp(f"negative-tls-domain-{idx}", 443, [("c", base.tls_client_hello(hostname))], ["tls"], ["tls"])
    for idx, hostname in enumerate(("notyoutube.com", "youtube.com.evil.test", "notnetflix.com", "webex.com.evil.test")):
        req = f"GET / HTTP/1.1\r\nHost: {hostname}\r\nConnection: close\r\n\r\n".encode()
        tcp(f"negative-http-domain-{idx}", 18080, [("c", req)], ["http"], ["http"])

    manifest = {
        "version": "2026-08-25-edge-v1",
        "generator": "deterministic-scapy-edge",
        "case_count": len(cases),
        "cases": cases,
    }
    (ARTIFACTS / "cases.json").write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
    print(f"generated {len(cases)} edge PCAP cases in {PCAP_DIR}")


if __name__ == "__main__":
    main()
