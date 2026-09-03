#!/usr/bin/env python3
from __future__ import annotations

import json
import shutil
import struct
from pathlib import Path
from typing import Iterable

from scapy.all import DNS, DNSQR, Ether, IP, Raw, TCP, UDP, wrpcap

BASE = Path(__file__).resolve().parent
ARTIFACTS = BASE / "artifacts"
PCAP_DIR = ARTIFACTS / "pcap"
INVENTORY = BASE / "inventory.json"

CLIENT_IP = "198.18.0.10"
SERVER_IP = "198.18.0.20"
CLIENT_MAC = "02:00:00:00:00:10"
SERVER_MAC = "02:00:00:00:00:20"
BASE_TS = 1_788_000_000.0

Case = dict[str, object]


def stamp(packets: Iterable, start: float = BASE_TS) -> list:
    result = list(packets)
    for idx, pkt in enumerate(result):
        pkt.time = start + idx * 0.001
    return result


def eth_ip(src_ip: str, dst_ip: str):
    if src_ip == CLIENT_IP:
        return Ether(src=CLIENT_MAC, dst=SERVER_MAC) / IP(src=src_ip, dst=dst_ip, ttl=64)
    return Ether(src=SERVER_MAC, dst=CLIENT_MAC) / IP(src=src_ip, dst=dst_ip, ttl=64)


def tcp_conversation(
    sport: int,
    dport: int,
    events: list[tuple[str, bytes]],
    *,
    client_isn: int = 1000,
    server_isn: int = 9000,
) -> list:
    """Build a valid TCP handshake and ordered payload exchange.

    events uses ('c', payload) for client->server and ('s', payload) for server->client.
    """
    packets = []
    cseq = client_isn
    sseq = server_isn

    packets.append(eth_ip(CLIENT_IP, SERVER_IP) / TCP(sport=sport, dport=dport, flags="S", seq=cseq))
    packets.append(
        eth_ip(SERVER_IP, CLIENT_IP)
        / TCP(sport=dport, dport=sport, flags="SA", seq=sseq, ack=cseq + 1)
    )
    packets.append(
        eth_ip(CLIENT_IP, SERVER_IP)
        / TCP(sport=sport, dport=dport, flags="A", seq=cseq + 1, ack=sseq + 1)
    )
    cseq += 1
    sseq += 1

    for side, payload in events:
        if not payload:
            continue
        if side == "c":
            packets.append(
                eth_ip(CLIENT_IP, SERVER_IP)
                / TCP(sport=sport, dport=dport, flags="PA", seq=cseq, ack=sseq)
                / Raw(payload)
            )
            cseq += len(payload)
            packets.append(
                eth_ip(SERVER_IP, CLIENT_IP)
                / TCP(sport=dport, dport=sport, flags="A", seq=sseq, ack=cseq)
            )
        elif side == "s":
            packets.append(
                eth_ip(SERVER_IP, CLIENT_IP)
                / TCP(sport=dport, dport=sport, flags="PA", seq=sseq, ack=cseq)
                / Raw(payload)
            )
            sseq += len(payload)
            packets.append(
                eth_ip(CLIENT_IP, SERVER_IP)
                / TCP(sport=sport, dport=dport, flags="A", seq=cseq, ack=sseq)
            )
        else:
            raise ValueError(f"unknown TCP side {side!r}")

    packets.append(
        eth_ip(CLIENT_IP, SERVER_IP)
        / TCP(sport=sport, dport=dport, flags="FA", seq=cseq, ack=sseq)
    )
    packets.append(
        eth_ip(SERVER_IP, CLIENT_IP)
        / TCP(sport=dport, dport=sport, flags="FA", seq=sseq, ack=cseq + 1)
    )
    packets.append(
        eth_ip(CLIENT_IP, SERVER_IP)
        / TCP(sport=sport, dport=dport, flags="A", seq=cseq + 1, ack=sseq + 1)
    )
    return stamp(packets)


def udp_exchange(sport: int, dport: int, client_payload: bytes, server_payload: bytes | None = None) -> list:
    packets = [
        eth_ip(CLIENT_IP, SERVER_IP) / UDP(sport=sport, dport=dport) / Raw(client_payload)
    ]
    if server_payload is not None:
        packets.append(
            eth_ip(SERVER_IP, CLIENT_IP) / UDP(sport=dport, dport=sport) / Raw(server_payload)
        )
    return stamp(packets)


def tls_client_hello(hostname: str) -> bytes:
    host = hostname.encode("ascii")
    name = b"\x00" + len(host).to_bytes(2, "big") + host
    sni_data = len(name).to_bytes(2, "big") + name
    sni_ext = b"\x00\x00" + len(sni_data).to_bytes(2, "big") + sni_data

    # Include common modern extensions so the generated ClientHello is structurally realistic.
    groups_data = b"\x00\x04\x00\x1d\x00\x17"
    groups_ext = b"\x00\x0a" + len(groups_data).to_bytes(2, "big") + groups_data
    points_data = b"\x01\x00"
    points_ext = b"\x00\x0b" + len(points_data).to_bytes(2, "big") + points_data
    sig_data = b"\x00\x06\x04\x03\x08\x04\x04\x01"
    sig_ext = b"\x00\x0d" + len(sig_data).to_bytes(2, "big") + sig_data
    versions_data = b"\x04\x03\x04\x03\x03"
    versions_ext = b"\x00\x2b" + len(versions_data).to_bytes(2, "big") + versions_data
    extensions = sni_ext + groups_ext + points_ext + sig_ext + versions_ext

    random_bytes = bytes(range(32))
    cipher_suites = b"\x13\x01\x13\x02\xc0\x2f\xc0\x2b\x00\x9e"
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


def dtls_client_hello() -> bytes:
    random_bytes = bytes(range(32))
    body = (
        b"\xfe\xfd"
        + random_bytes
        + b"\x00"
        + b"\x00"
        + b"\x00\x02\xc0\x2f"
        + b"\x01\x00"
        + b"\x00\x00"
    )
    hs_len = len(body)
    handshake = (
        b"\x01"
        + hs_len.to_bytes(3, "big")
        + b"\x00\x00"
        + b"\x00\x00\x00"
        + hs_len.to_bytes(3, "big")
        + body
    )
    return (
        b"\x16\xfe\xfd"
        + b"\x00\x00"
        + b"\x00\x00\x00\x00\x00\x00"
        + len(handshake).to_bytes(2, "big")
        + handshake
    )


def opcua_hello() -> bytes:
    endpoint = b"opc.tcp://example.test:4840"
    body = (
        struct.pack("<I", 0)
        + struct.pack("<I", 65535)
        + struct.pack("<I", 65535)
        + struct.pack("<I", 0)
        + struct.pack("<I", 0)
        + struct.pack("<i", len(endpoint))
        + endpoint
    )
    return b"HELF" + struct.pack("<I", 8 + len(body)) + body


def radius_access_request() -> bytes:
    attrs = b"\x01\x07alice" + b"\x04\x06\xc0\x00\x02\x01"
    length = 20 + len(attrs)
    return b"\x01\x2a" + length.to_bytes(2, "big") + bytes(range(16)) + attrs


def postgres_startup() -> bytes:
    params = b"user\x00alice\x00database\x00test\x00application_name\x00dpi-ci\x00\x00"
    body = b"\x00\x03\x00\x00" + params
    return (4 + len(body)).to_bytes(4, "big") + body


def bgp_open() -> bytes:
    body = b"\x04\xfc\x00\x00\x5a\xc0\x00\x02\x01\x00"
    return b"\xff" * 16 + (19 + len(body)).to_bytes(2, "big") + b"\x01" + body


def bittorrent_handshake() -> bytes:
    return (
        b"\x13BitTorrent protocol"
        + b"\x00" * 8
        + b"01234567890123456789"
        + b"-PC0001-ABCDEFGHIJKL"
    )


def snmp_get_request() -> bytes:
    return bytes.fromhex(
        "302602010104067075626c6963a0190204710f2f24020100020100300b300906052b060102010500"
    )


def sap_announcement() -> bytes:
    return (
        b"\x20\x00\x12\x34\xc0\x00\x02\x01"
        + b"application/sdp\x00"
        + b"v=0\r\no=- 1 1 IN IP4 192.0.2.1\r\ns=DPI CI\r\nt=0 0\r\n"
    )


def quic_v1_initial_like() -> bytes:
    return (
        b"\xc3\x00\x00\x00\x01"
        + b"\x08QUICDCID"
        + b"\x08QUICSCID"
        + b"\x00"
        + b"\x14"
        + b"\x00" * 20
    )


def openvpn_packet(opcode_byte: int, session_id: bytes) -> bytes:
    return bytes([opcode_byte]) + session_id + b"\x00" * 16


def tcp_framed(payload: bytes) -> bytes:
    return len(payload).to_bytes(2, "big") + payload


def add_case(cases: list[Case], name: str, packets: list, required: list[str], allowed: list[str] | None = None) -> None:
    path = PCAP_DIR / f"{name}.pcap"
    wrpcap(str(path), packets)
    allowed_set = list(dict.fromkeys(allowed if allowed is not None else required))
    cases.append(
        {
            "name": name,
            "pcap": str(path.relative_to(ARTIFACTS)),
            "required": list(dict.fromkeys(required)),
            "allowed": allowed_set,
        }
    )


def main() -> None:
    if ARTIFACTS.exists():
        shutil.rmtree(ARTIFACTS)
    PCAP_DIR.mkdir(parents=True, exist_ok=True)
    cases: list[Case] = []

    dht = b"d1:ad2:id20:abcdefghij0123456789e1:q4:ping1:t2:aa1:y1:qe"
    add_case(cases, "bt-dht", udp_exchange(42000, 6881, dht), ["bt-dht"])

    dns_msg = bytes(DNS(id=0x1234, rd=1, qd=DNSQR(qname="example.test", qtype="A")))
    add_case(cases, "dns-udp", udp_exchange(42001, 53, dns_msg), ["dns"])
    add_case(cases, "dns-tcp", tcp_conversation(42002, 53, [("c", len(dns_msg).to_bytes(2, "big") + dns_msg)]), ["dns"])

    add_case(
        cases,
        "ftp",
        tcp_conversation(
            42003,
            21,
            [
                ("s", b"220 test.example FTP server ready\r\n"),
                ("c", b"USER anonymous\r\n"),
                ("s", b"331 Password required\r\n"),
                ("c", b"PASS guest@example.test\r\n"),
                ("s", b"230 Login successful\r\n"),
            ],
        ),
        ["ftp"],
    )

    http_req = b"GET /dpi HTTP/1.1\r\nHost: example.test\r\nUser-Agent: dpi-ci/1.0\r\nConnection: close\r\n\r\n"
    http_resp = b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nOK"
    add_case(cases, "http", tcp_conversation(42004, 80, [("c", http_req), ("s", http_resp)]), ["http"])
    add_case(cases, "http-offport", tcp_conversation(42005, 18080, [("c", http_req), ("s", http_resp)]), ["http"])

    add_case(
        cases,
        "imap",
        tcp_conversation(
            42006,
            143,
            [
                ("s", b"* OK test.example IMAP4rev1 Service Ready\r\n"),
                ("c", b"A001 CAPABILITY\r\n"),
                ("s", b"* CAPABILITY IMAP4rev1 IDLE\r\nA001 OK CAPABILITY completed\r\n"),
            ],
        ),
        ["imap"],
    )

    ldap_bind = bytes.fromhex("300c020101600702010304008000")
    add_case(cases, "ldap", tcp_conversation(42007, 389, [("c", ldap_bind)]), ["ldap"])

    mqtt_body = b"\x00\x04MQTT\x04\x02\x00\x3c\x00\x04test"
    mqtt_connect = b"\x10" + bytes([len(mqtt_body)]) + mqtt_body
    add_case(cases, "mqtt", tcp_conversation(42008, 1883, [("c", mqtt_connect)]), ["mqtt"])

    add_case(cases, "ntp", udp_exchange(42009, 123, b"\x23" + b"\x00" * 47), ["ntp"])

    add_case(
        cases,
        "pop3",
        tcp_conversation(
            42010,
            110,
            [
                ("s", b"+OK test.example POP3 server ready\r\n"),
                ("c", b"USER alice\r\n"),
                ("s", b"+OK user accepted\r\n"),
                ("c", b"PASS example-password\r\n"),
                ("s", b"+OK mailbox locked and ready\r\n"),
            ],
        ),
        ["pop3"],
    )

    rdp_cr = bytes.fromhex("030000130ee000000000000100080003000000")
    add_case(cases, "rdp", tcp_conversation(42011, 3389, [("c", rdp_cr)]), ["rdp"])

    sip = (
        b"INVITE sip:bob@example.test SIP/2.0\r\n"
        b"Via: SIP/2.0/UDP client.example.test;branch=z9hG4bK-dpi-ci\r\n"
        b"From: <sip:alice@example.test>;tag=1\r\n"
        b"To: <sip:bob@example.test>\r\n"
        b"Call-ID: dpi-ci@example.test\r\n"
        b"CSeq: 1 INVITE\r\n"
        b"Contact: <sip:alice@client.example.test>\r\n"
        b"Max-Forwards: 70\r\n"
        b"Content-Length: 0\r\n\r\n"
    )
    add_case(cases, "sip-udp", udp_exchange(42012, 5060, sip), ["sip"])
    add_case(cases, "sip-tcp", tcp_conversation(42013, 5060, [("c", sip)]), ["sip"])

    add_case(cases, "snmp", udp_exchange(42014, 161, snmp_get_request()), ["snmp"])

    add_case(
        cases,
        "telnet",
        tcp_conversation(
            42015,
            23,
            [
                ("s", b"\xff\xfb\x01\xff\xfb\x03login: "),
                ("c", b"\xff\xfd\x01\xff\xfd\x03alice\r\n"),
            ],
        ),
        ["telnet"],
    )

    tls_example = tls_client_hello("example.org")
    add_case(cases, "tls-generic", tcp_conversation(42016, 443, [("c", tls_example)]), ["tls"])
    add_case(cases, "tls-boundary-negative", tcp_conversation(42017, 443, [("c", tls_client_hello("notyoutube.com"))]), ["tls"])

    ssh_events = [("s", b"SSH-2.0-OpenSSH_9.6p1 Ubuntu-3ubuntu13\r\n"), ("c", b"SSH-2.0-dpi-ci_1.0\r\n")]
    add_case(cases, "ssh", tcp_conversation(42018, 22, ssh_events), ["ssh"])
    add_case(cases, "ssh-offport", tcp_conversation(42019, 2222, ssh_events), ["ssh"])

    add_case(cases, "quic", udp_exchange(42020, 443, quic_v1_initial_like()), ["quic"])

    add_case(
        cases,
        "iec104",
        tcp_conversation(42021, 2404, [("c", bytes.fromhex("680407000000")), ("s", bytes.fromhex("68040b000000"))]),
        ["iec104"],
    )

    add_case(cases, "bgp", tcp_conversation(42022, 179, [("c", bgp_open())]), ["bgp"])
    add_case(cases, "bt-peer", tcp_conversation(42023, 6881, [("c", bittorrent_handshake())]), ["bt-peer"])
    add_case(cases, "postgresql", tcp_conversation(42024, 5432, [("c", postgres_startup())]), ["postgresql"])
    add_case(cases, "radius", udp_exchange(42025, 1812, radius_access_request()), ["radius"])

    rtsp = (
        b"OPTIONS rtsp://media.example.test/movie RTSP/1.0\r\n"
        b"CSeq: 1\r\n"
        b"User-Agent: dpi-ci/1.0\r\n\r\n"
    )
    add_case(cases, "rtsp", tcp_conversation(42026, 554, [("c", rtsp)]), ["rtsp"])

    add_case(cases, "sap", udp_exchange(42027, 9875, sap_announcement()), ["sap"])

    syslog_5424 = b"<34>1 2026-08-25T09:00:00Z host app 123 ID47 - dpi validation message"
    syslog_3164 = b"<34>Aug 25 09:00:00 host app[123]: dpi validation message\n"
    add_case(cases, "syslog-udp", udp_exchange(42028, 514, syslog_5424), ["syslog"])
    add_case(cases, "syslog-tcp", tcp_conversation(42029, 514, [("c", syslog_3164)]), ["syslog"])

    stun = b"\x00\x01\x00\x00\x21\x12\xa4\x42" + b"STUN-TRANS12"
    add_case(cases, "stun", udp_exchange(42030, 3478, stun), ["stun"])
    add_case(cases, "dtls", udp_exchange(42031, 4433, dtls_client_hello()), ["dtls"])
    add_case(cases, "opc", tcp_conversation(42032, 4840, [("c", opcua_hello())]), ["opc"])

    ovpn_client = openvpn_packet(0x38, b"CLNTSESS")
    ovpn_server = openvpn_packet(0x40, b"SRVRSESS")
    add_case(cases, "openvpn-udp", udp_exchange(42033, 1194, ovpn_client, ovpn_server), ["openvpn"])
    add_case(
        cases,
        "openvpn-tcp",
        tcp_conversation(42034, 4433, [("c", tcp_framed(ovpn_client)), ("s", tcp_framed(ovpn_server))]),
        ["openvpn"],
    )

    services = {
        "outlook": "outlook.office.com",
        "facebook-chat": "edge-mqtt.facebook.com",
        "gmail": "mail.google.com",
        "azure-signup": "signup.azure.com",
        "microsoft-update": "download.windowsupdate.com",
        "netflix": "assets.nflximg.net",
        "skype": "api.skype.com",
        "teamviewer": "router.teamviewer.com",
        "webex": "client.webex.com",
        "youtube": "www.youtube.com",
    }
    port = 43000
    for detector, hostname in services.items():
        add_case(
            cases,
            f"service-{detector}",
            tcp_conversation(port, 443, [("c", tls_client_hello(hostname))]),
            [detector, "tls"],
            [detector, "tls"],
        )
        port += 1

    add_case(
        cases,
        "negative-tcp",
        tcp_conversation(44000, 45678, [("c", b"ordinary application payload with no protocol marker\n")]),
        [],
        [],
    )
    add_case(cases, "negative-udp", udp_exchange(44001, 45679, b"ordinary-udp-payload-xyz"), [], [])

    inventory = json.loads(INVENTORY.read_text(encoding="utf-8"))
    expected = {item["detector"] for item in inventory["source_labels"]}
    exercised = {detector for case in cases for detector in case["required"]}
    missing = sorted(expected - exercised)
    if missing:
        raise SystemExit(f"corpus does not exercise inventory detector(s): {missing}")

    manifest = {
        "version": "2026-08-25-v1",
        "generator": "deterministic-scapy",
        "case_count": len(cases),
        "cases": cases,
    }
    (ARTIFACTS / "cases.json").write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
    print(f"generated {len(cases)} PCAP cases in {PCAP_DIR}")
    print(f"exercised {len(exercised)} normalized detectors: {', '.join(sorted(exercised))}")


if __name__ == "__main__":
    main()
