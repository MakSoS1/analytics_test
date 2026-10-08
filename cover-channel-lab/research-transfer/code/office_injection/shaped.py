"""Generate technique sessions on office skeletons, in disconnected namespaces on .18.

Every session gets its own client/server namespace pair joined by one veth,
without uplink or default route. The environment comes from one office
skeleton (templates.py): netem delay on the server side equals the office
handshake RTT as the sensor saw it (the sensor sits next to office clients),
the veth MTU equals the office path MTU, the client uses or omits TCP
timestamps as that office client did, the server waits the observed think
time before answering, and the side that closed the office connection closes
this one at the same offset. Frames shorter than the Ethernet minimum are
padded to 60 bytes, as a wire tap sees them.

The technique owns only the application content. `scenario` and `control`
share each skeleton; the control replaces the covert value by static bytes of
equal length. Techniques that own timing must not be run on skeleton timing
(`timing_owned_by_technique`). Nothing here connects to a production network.
"""
from __future__ import annotations
import argparse
import base64
import getpass
import hashlib
import json
import os
import random
import socket
import ssl
import struct
import subprocess
import sys
import threading
import time
import uuid
from collections import Counter
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

from .source import read_pcap, sha256, transport
from . import templates as tpl

CLIENT_IP, SERVER_IP, PORT = '172.21.254.10', '198.51.100.10', 443
COMMIT = '1028b4a922c9b59e841fc71d58ae1df60ded6da4'
SOURCE = f'MakSoS1/analytics_test@{COMMIT} cover-channel-lab/src/coverlab/stage_m.py'


# ------------------------------------------------------------- technique content
# One client/server pair per skeleton, one persistent TCP connection for the
# whole session: this always exercises the "reused connection" implementation
# profile of a family, since an office skeleton comes from one observed TCP
# flow. Families whose real generator opens a new connection per event, uses a
# different transport (UDP/DNS, QUIC, WebSocket/MQTT framing, HTTP/2, raw L3/L4
# fields), or spans multiple connections/protocols in one campaign are not
# modelled here -- see TECHNIQUES_NOT_IMPLEMENTED below for the concrete list
# and why each one doesn't fit this architecture.

def _payload(mode, i, size=48):
    # Mirrors stage_m.py's _payload(): same three modes, same per-event seed.
    rng = random.Random(100 + i)
    if mode == 'low_entropy':
        vals = (b'id=do', b'status=ok', b'cmd=1', str(uuid.UUID(int=rng.getrandbits(128))).encode())
        return vals[i % len(vals)]
    if mode == 'fragment_2_6':
        alphabet = 'abcdef0123456789'
        n = 2 + (i % 5)
        return ''.join(rng.choice(alphabet) for _ in range(n)).encode()
    raw = bytes(rng.randrange(0, 256) for _ in range(size))
    return base64.urlsafe_b64encode(raw).rstrip(b'=')


def _neutral(arm, data):
    """scenario keeps the real covert bytes; control replaces them with an
    equal-length placeholder. Everything else -- path shape, method, headers,
    timing -- is identical between arms by construction."""
    return data if arm == 'scenario' else b'x' * len(data)


def application_request(spec, i, n):
    """Ordinary application fixture versus a separate length-preserving ablation.

    This is synthetic benign intent, not a captured office application. It
    deliberately does not enforce equal payload lengths to the scenario.
    """
    tech = TECHNIQUES[spec['technique']]
    kind = spec.get('control_kind', 'equal_length_ablation')
    if kind not in ('equal_length_ablation', 'benign_application'):
        raise ValueError('unknown control kind')
    if spec['arm'] != 'control' or kind == 'equal_length_ablation':
        return tech['request'](spec['arm'], i, n)
    if spec['technique'] == 'M-DOH':
        from . import realclients
        wire = realclients.dns_wire_query(f'service{i % 3}.example.test.', 'A')
        return 'POST', '/dns-query', wire, {'Content-Type': 'application/dns-message'}
    if i % 3 != 2:return 'GET', f'/api/items?page={i % 4}', None, {'Accept': 'application/json'}
    return 'POST', '/api/preferences', json.dumps({'theme':'light','page_size':20+i%3}).encode(), {'Content-Type':'application/json'}


def application_message(spec, i, n):
    kind = spec.get('control_kind', 'equal_length_ablation')
    if kind not in ('equal_length_ablation', 'benign_application'):raise ValueError('unknown control kind')
    if spec['arm'] == 'control' and kind == 'benign_application':
        return json.dumps({'event':'chat','text':('hello','thanks','see you')[i%3]})
    return TECHNIQUES[spec['technique']]['ws_message'](spec['arm'], i, n)


def stage_m_https_lowent(arm, i, n):
    # stage_m.py _http_events, family branch M-HTTPS-LOWENT (_payload low_entropy).
    value = _neutral(arm, _payload('low_entropy', i))
    return 'POST', '/stage-m/status?q=' + value.decode(), b'{"status":"ok","id":"do"}', {'Content-Type': 'application/json'}


def stage_m_https_beacon(arm, i, n):
    # stage_m.py _http_events generic branch (no family-specific path/body override).
    data = _neutral(arm, _payload('high_entropy', i, 32 + (i % 4) * 24))
    return 'POST', '/stage-m/beacon', data, {}


def stage_m_https_frag(arm, i, n):
    # stage_m.py _http_events, family branch M-HTTPS-FRAG (_payload fragment_2_6).
    data = _neutral(arm, _payload('fragment_2_6', i))
    return 'GET', '/stage-m/item?id=' + data.decode(errors='ignore'), None, {}


def stage_m_http_443(arm, i, n):
    # stage_m.py _http_events, family branch M-HTTP-443. Real generator uses plain
    # HTTP (no TLS) on port 443; this technique sets tls: False below.
    data = _neutral(arm, _payload('low_entropy', i))
    return 'POST', '/fakeurl.htm', b'status=' + data[:24], {}


def stage_m_rmm_shape(arm, i, n):
    # stage_m.py _http_events, family branch M-RMM-SHAPE: GET polls for the first
    # half of the campaign, then POSTs with large bodies for the second half.
    if i < max(2, n // 2):
        return 'GET', f'/stage-m/poll?cursor={i}', None, {}
    size = 96 + (i % 5) * 192
    data = _neutral(arm, _payload('high_entropy', i, size))
    return 'POST', '/stage-m/interactive', data, {}


_CLOUD_TEMPLATES = (
    ('/v1.0/me/drive/items/{id}/content', 'GET'),
    ('/v4/spreadsheets/{id}/values/A1', 'GET'),
    ('/storage/v1/b/lab/o/{id}', 'PUT'),
    ('/yandex/disk/resources?path=/lab/{id}', 'GET'),
    ('/api/blob/{id}', 'POST'),
)


def stage_m_cloud_api(arm, i, n):
    # stage_m.py _cloud_events. Real generator rotates across 4 front hosts per
    # event; one persistent connection can only hold one host/SNI, so this models
    # a single representative front (technique 'sni' below) and keeps only the
    # path-template/method rotation -- a documented simplification, not a new family.
    ident = hashlib.sha256(f'cloud-api:{i}'.encode()).hexdigest()[:16]
    path_tpl, method = _CLOUD_TEMPLATES[i % len(_CLOUD_TEMPLATES)]
    path = path_tpl.format(id=ident)
    body = None if method == 'GET' else _neutral(arm, _payload('high_entropy', i, 32 + (i % 6) * 64))
    return method, path, body, {'X-Client-Request-Id': ident}


def stage_m_doh(arm, i, n):
    # stage_m.py _doh_events: DNS-over-HTTPS, alternating GET (RFC 8484 ?dns=)
    # and POST (application/dns-message body) by event parity. The wire query
    # is dnspython's real encoder (realclients.dns_wire_query), not a
    # hand-rolled one -- this runs under .venv_realclients (see client_lib below).
    from . import realclients
    raw = _neutral(arm, _payload('low_entropy', i, 16))
    label = base64.b32encode(raw).decode().rstrip('=').lower()[:50]
    qname = f'{label}.stage-m.test.'
    qtype = ('A', 'AAAA', 'TXT', 'CNAME')[i % 4]
    wire = realclients.dns_wire_query(qname, qtype)
    if i % 2 == 0:
        encoded = base64.urlsafe_b64encode(wire).decode().rstrip('=')
        return 'GET', f'/dns-query?dns={encoded}', None, {'Accept': 'application/dns-message'}
    return 'POST', '/dns-query', wire, {'Content-Type': 'application/dns-message', 'Accept': 'application/dns-message'}


def _doh_response(k):
    from . import realclients
    return realclients.dns_wire_answer(f'ans{k}.stage-m.test.', 'A')


def stage_m_wss_long(arm, i, n):
    # stage_m.py _python_wss(tunnel=False): a JSON control message per exchange,
    # alternating action, over one persistent WebSocket connection.
    data = _neutral(arm, _payload('high_entropy', i, 24 + (i % 5) * 32))
    msg = {'action': 'send' if i % 2 else 'recv', 'container': data.decode('latin-1'), 'target': 'LAB', 'message': 'STATUS'}
    return json.dumps(msg, separators=(',', ':'))


def stage_m_tunnel(arm, i, n):
    # stage_m.py _python_wss(tunnel=True): base64 payload framed as SOCKS-style
    # tunnel data over one of 4 rotating logical connection ids.
    data = _neutral(arm, _payload('high_entropy', i, 24 + (i % 5) * 32))
    msg = {'type': 'socks_data', 'conn_id': f'm{i % 4}', 'data': base64.b64encode(data).decode()}
    return json.dumps(msg, separators=(',', ':'))


def _wss_response(message):
    # The real server this pairs with is ours, not stage_m.py's; content is a
    # plausible JSON ack matching the received message's shape, never decoded
    # downstream (TLS-encrypted on the wire either way).
    try:kind = json.loads(message).get('type', 'ack')
    except (json.JSONDecodeError, AttributeError):kind = 'ack'
    return json.dumps({'ok': True, 'type': kind, 'value': '0123456789abcdef'}, separators=(',', ':'))


# client_lib='httpx': the exchange runs on the real httpx library (stage_m.py's
# own reusable-client branch), under .venv_realclients, instead of this
# module's hand-rolled HTTP/1.1 socket protocol. serve() is unaffected --
# it speaks plain HTTP/1.1 regardless of which client sent the request.
# Known, disclosed gap: httpx exposes no RST-vs-FIN control, so a skeleton
# recorded as closer='client', close_kind='rst' is closed via a normal FIN
# teardown instead when this client_lib is used (see client_httpx()).
TECHNIQUES = {
    'M-HTTPS-LOWENT': {'request': stage_m_https_lowent, 'sni': 'cover-api.test', 'client_lib': 'httpx',
                       'timing_owned_by_technique': False, 'source': SOURCE + ' _http_events(M-HTTPS-LOWENT)'},
    'M-HTTPS-BEACON': {'request': stage_m_https_beacon, 'sni': 'cover-api.test', 'client_lib': 'httpx',
                       'timing_owned_by_technique': False, 'source': SOURCE + ' _http_events(generic)'},
    'M-HTTPS-FRONT': {'request': stage_m_https_beacon, 'sni': 'edge-front.test', 'client_lib': 'httpx',
                      'timing_owned_by_technique': False,
                      'source': SOURCE + ' _http_events(generic, domain-fronted host from HTTPS_FRONTS)'},
    'M-HTTPS-FRAG': {'request': stage_m_https_frag, 'sni': 'cover-api.test', 'client_lib': 'httpx',
                     'timing_owned_by_technique': False, 'source': SOURCE + ' _http_events(M-HTTPS-FRAG)'},
    'M-HTTP-443': {'request': stage_m_http_443, 'sni': 'plain-front.test', 'tls': False, 'client_lib': 'httpx',
                  'timing_owned_by_technique': False, 'source': SOURCE + ' _http_events(M-HTTP-443)'},
    'M-RMM-SHAPE': {'request': stage_m_rmm_shape, 'sni': 'cover-api.test', 'client_lib': 'httpx',
                    'timing_owned_by_technique': False, 'source': SOURCE + ' _http_events(M-RMM-SHAPE)'},
    'M-CLOUD-API': {'request': stage_m_cloud_api, 'sni': 'graph-front.test', 'client_lib': 'httpx',
                    'timing_owned_by_technique': False, 'source': SOURCE + ' _cloud_events (single-front simplification)'},
    'M-DOH': {'request': stage_m_doh, 'sni': 'doh-relay.test', 'response_content_type': 'application/dns-message',
             'response_body': _doh_response, 'client_lib': 'httpx',
             'timing_owned_by_technique': False, 'source': SOURCE + ' _doh_events (real dnspython wire encoding)'},
    # client_lib='websockets': real RFC 6455 framing (Python `websockets`
    # library) on both ends, over the same TCP+TLS+netem+skeleton path as the
    # HTTP families. serve_ws()/client_ws() below, not serve()/client_httpx().
    'M-WSS-LONG': {'ws_message': stage_m_wss_long, 'ws_response': _wss_response, 'sni': 'cover-ws.test',
                  'client_lib': 'websockets', 'timing_owned_by_technique': False,
                  'source': SOURCE + ' _python_wss(tunnel=False)'},
    'M-TUNNEL': {'ws_message': stage_m_tunnel, 'ws_response': _wss_response, 'sni': 'cover-ws.test',
                'client_lib': 'websockets', 'timing_owned_by_technique': False,
                'source': SOURCE + ' _python_wss(tunnel=True)'},
    'M-TIMING-XCARRIER': {'request': None, 'sni': None, 'timing_owned_by_technique': True,
                          'source': SOURCE + ' _timing_xcarrier_events',
                          'excluded_reason': 'the technique IS its own cross-carrier timing schedule '
                              '(which carrier fires when); running it on a borrowed office skeleton would '
                              'overwrite that mechanism, not reproduce it -- refused by generate() below'},
}

# Not implemented -- and NOT because of the system-wide-change boundary
# (2026-09-28 scope decision): each of these needs either a transaction
# skeleton type this project has never extracted (DNS, QUIC), or an
# orchestration this architecture does not have (multi-connection campaigns,
# raw per-packet field crafting), regardless of which client library is used.
#   M-DNS-BEACON, M-DNS-BULK  -- UDP/TCP DNS transactions, not TCP+TLS+HTTP;
#       no DNS-transaction office skeleton exists yet (templates.py only
#       extracts TLS/443 TCP sessions). dnspython is already installed and
#       ready for this once that skeleton type exists.
#   M-DOQ, M-H3-QUIC          -- QUIC/UDP transport, not TCP; needs its own
#       skeleton concept (QUIC handshake RTT, not TCP SYN/SYN-ACK) and
#       verification that netem/veth behave correctly for UDP+QUIC. aioquic
#       is not yet installed in .venv_realclients.
#   M-PUBSUB-MQTT             -- paho-mqtt (real client) is installed, but the
#       real server is Mosquitto (deferred, system-wide). A from-scratch
#       minimal MQTT-over-WS server (no broker) is possible but unbuilt.
#   M-GRPC-BIDI               -- grpcio is installed; the real client sends
#       one continuous bidi stream, not per-exchange request/response like
#       every other family here -- needs its own orchestration, unbuilt.
#   M-DEAD-DROP, M-FALLBACK   -- two sequential connections to different
#       hosts/protocols in one campaign; this architecture is one skeleton = one
#       connection, so approximating them as a single connection would
#       misrepresent the channel-splitting mechanism itself.
#   M-L34-STORAGE             -- no TLS/application layer at all: a covert
#       channel in raw IP/UDP/ICMP/TCP header fields (IPv4 ID, ISN, TCP
#       timestamp) via Scapy. Needs a per-packet field model, not a session skeleton.
TECHNIQUES_NOT_IMPLEMENTED = (
    'M-DNS-BEACON', 'M-DNS-BULK', 'M-DOQ', 'M-H3-QUIC', 'M-PUBSUB-MQTT', 'M-GRPC-BIDI',
    'M-DEAD-DROP', 'M-FALLBACK', 'M-L34-STORAGE',
)


# ---------------------------------------------------------------- roles in namespaces
def _recv_http(sock, deadline):
    data = b''
    while b'\r\n\r\n' not in data:
        sock.settimeout(max(0.05, deadline - time.monotonic()))
        chunk = sock.recv(65536)
        if not chunk:return None
        data += chunk
    head, _, body = data.partition(b'\r\n\r\n')
    length = 0
    for line in head.split(b'\r\n')[1:]:
        k, _, v = line.partition(b':')
        if k.strip().lower() == b'content-length':length = int(v)
    while len(body) < length:
        sock.settimeout(max(0.05, deadline - time.monotonic()))
        chunk = sock.recv(65536)
        if not chunk:return None
        body += chunk
    return head, body


def _close(sock, kind):
    if kind == 'rst':
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, struct.pack('ii', 1, 0))
    try:sock.close()
    except OSError:pass


def serve(spec):
    s = spec['skeleton']; root = Path(spec['dir']); tech = TECHNIQUES[spec['technique']]
    tls = tech.get('tls', True)
    if tls:ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER); ctx.load_cert_chain(root / 'cert.pem', root / 'key.pem')
    lsock = socket.socket(); lsock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    lsock.bind((SERVER_IP, PORT)); lsock.listen(1)
    (root / 'server.ready').write_text('1')
    lsock.settimeout(30); raw, _ = lsock.accept(); t0 = time.monotonic()
    events = []
    thinks = [e['server_think'] or 0.0 for e in s['exchanges']]
    time.sleep(min(thinks[0], 5.0))                 # office server's delay before ServerHello (or first byte)
    conn = ctx.wrap_socket(raw, server_side=True) if tls else raw
    close_at = t0 + s['close_at'] if s['closer'] == 'server' else None
    content_type = tech.get('response_content_type', 'application/json')
    response_body = tech.get('response_body')
    k = 0
    while True:
        deadline = close_at if close_at else t0 + s['close_at'] + 10
        try:got = _recv_http(conn, deadline)
        except (socket.timeout, ssl.SSLError, OSError):got = None
        if got is None:break
        answered = k < len(s['exchanges']) and s['exchanges'][k]['server_think'] is not None
        if not answered:
            # The office server never answered this request (refusal, then close).
            events.append({'k': k, 'rel': time.monotonic() - t0, 'answered': False}); k += 1
            continue
        # First response: the TLS think was already spent; later ones use their own.
        think = 0.0 if k == 0 else min(thinks[k] if k < len(thinks) else 0.0, 30.0)
        time.sleep(think)
        body = response_body(k) if response_body else json.dumps(
            {'ok': True, 'value': '0123456789abcdef'}, separators=(',', ':')).encode()
        conn.sendall(f'HTTP/1.1 200 OK\r\nContent-Type: {content_type}\r\nContent-Length: '.encode()
                     + str(len(body)).encode() + b'\r\nConnection: keep-alive\r\n\r\n' + body)
        events.append({'k': k, 'rel': time.monotonic() - t0, 'think': think}); k += 1
    if close_at:
        time.sleep(max(0.0, close_at - time.monotonic()))
    _close(conn, s['close_kind'] if s['closer'] == 'server' else 'fin')
    (root / 'server.json').write_text(json.dumps({'responses': events}) + '\n')


def client(spec):
    s = spec['skeleton']; root = Path(spec['dir']); tech = TECHNIQUES[spec['technique']]
    tls = tech.get('tls', True)
    raw = socket.create_connection((SERVER_IP, PORT), timeout=30); t0 = time.monotonic()
    if tls:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT); ctx.check_hostname = False; ctx.verify_mode = ssl.CERT_NONE
        conn = ctx.wrap_socket(raw, server_hostname=tech['sni'])
    else:
        conn = raw
    journal = []; server_closed = False
    for k, ex in enumerate(s['exchanges']):
        if k:time.sleep(max(0.0, t0 + ex['at'] - time.monotonic()))
        method, path, body, extra_headers = application_request(spec, k, len(s['exchanges']))
        headers = {'Host': tech['sni'], 'User-Agent': 'Mozilla/5.0', 'Accept': 'application/json',
                  'X-Lab-Profile': 'stage-m', 'Connection': 'keep-alive', **extra_headers}
        if body is not None:headers['Content-Length'] = str(len(body))
        head = f'{method} {path} HTTP/1.1\r\n' + ''.join(f'{name}: {value}\r\n' for name, value in headers.items())
        try:
            conn.sendall(head.encode() + b'\r\n' + (body or b''))
            answered = ex['server_think'] is not None
            got = _recv_http(conn, time.monotonic() + 45) if answered else None
        except (OSError, ssl.SSLError):
            if s['closer'] != 'server':raise
            server_closed = True; break
        if answered and (got is None or not got[0].startswith(b'HTTP/1.1 200')):
            if s['closer'] != 'server':raise RuntimeError(f'exchange {k} failed')
            server_closed = True
        journal.append({'k': k, 'sent_rel': round(time.monotonic() - t0, 6), 'answered': bool(answered and got),
                        'request_sha256': hashlib.sha256(path.encode() + (body or b'')).hexdigest()})
        if server_closed:break
    if s['closer'] == 'client':
        time.sleep(max(0.0, t0 + s['close_at'] - time.monotonic()))
        _close(conn, s['close_kind'])
    else:
        # Wait for the server's close, then answer it as a normal client does.
        try:
            conn.settimeout(max(1.0, t0 + s['close_at'] + 10 - time.monotonic())); conn.recv(1)
        except (socket.timeout, ssl.SSLError, OSError):pass
        _close(conn, 'fin')
    (root / 'client.json').write_text(json.dumps({'requests': journal, 'server_closed_early': server_closed}) + '\n')


def client_httpx(spec):
    """Same exchange as client(), but sent by the real httpx library (stage_m.py's
    own reusable-client implementation profile) instead of this module's
    hand-rolled HTTP/1.1 protocol. serve() is untouched: it speaks standard
    HTTP/1.1 regardless of which client sent the request.

    httpx resolves the URL's hostname itself; the isolated namespace has no
    resolver (no default route, by design), so realclients.patch_dns_to
    overrides socket.getaddrinfo for `.test` names to the synthetic server IP,
    in this process only -- see its docstring for what it does and does not touch.
    """
    from . import realclients
    s = spec['skeleton']; root = Path(spec['dir']); tech = TECHNIQUES[spec['technique']]
    realclients.patch_dns_to(SERVER_IP)
    scheme = 'https' if tech.get('tls', True) else 'http'
    conn = realclients.httpx_client(f'{scheme}://{tech["sni"]}:{PORT}', http2=tech.get('http2', False))
    journal = []; server_closed = False; t0 = time.monotonic()
    for k, ex in enumerate(s['exchanges']):
        if k:time.sleep(max(0.0, t0 + ex['at'] - time.monotonic()))
        method, path, body, extra_headers = application_request(spec, k, len(s['exchanges']))
        headers = {'User-Agent': 'Mozilla/5.0', 'Accept': 'application/json', 'X-Lab-Profile': 'stage-m', **extra_headers}
        answered = ex['server_think'] is not None
        try:
            resp = conn.request(method, path, headers=headers, content=body)
            if answered:resp.read()
        except Exception:
            if s['closer'] != 'server':raise
            server_closed = True; break
        if answered and resp.status_code != 200:
            if s['closer'] != 'server':raise RuntimeError(f'exchange {k} failed: {resp.status_code}')
            server_closed = True
        journal.append({'k': k, 'sent_rel': round(time.monotonic() - t0, 6), 'answered': bool(answered),
                        'request_sha256': hashlib.sha256(path.encode() + (body or b'')).hexdigest()})
        if server_closed:break
    # httpx exposes no RST-vs-FIN control (see TECHNIQUES's comment): a
    # closer='client' skeleton is always closed via a normal FIN teardown here,
    # whatever its recorded close_kind was.
    if s['closer'] == 'client':
        time.sleep(max(0.0, t0 + s['close_at'] - time.monotonic()))
    elif not server_closed:
        # closer='server': hang up only after the server does, as client() and client_ws() do.
        # Returning right after the last request made the still-running server outlive
        # run_session()'s 30 s wait (8 of the 11 pairs lost in the 2026-09-29 x60 run).
        realclients.wait_for_server_close(conn, t0 + s['close_at'] + 10)
    conn.close()
    (root / 'client.json').write_text(json.dumps({'requests': journal, 'server_closed_early': server_closed}) + '\n')


def serve_ws(spec):
    """Real websockets library server, paired with client_ws(). websockets.serve()
    is a long-running multi-connection server; this session needs exactly one
    connection handled once, so serve_forever() runs in a background thread and
    is shut down as soon as that one handler returns."""
    from . import realclients
    s = spec['skeleton']; root = Path(spec['dir']); tech = TECHNIQUES[spec['technique']]
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER); ctx.load_cert_chain(root / 'cert.pem', root / 'key.pem')
    thinks = [e['server_think'] or 0.0 for e in s['exchanges']]
    events = []; done = threading.Event()

    def handler(websocket):
        t0 = time.monotonic()
        time.sleep(min(thinks[0], 5.0))
        close_at = t0 + s['close_at'] if s['closer'] == 'server' else None
        k = 0
        try:
            while True:
                deadline = close_at if close_at else t0 + s['close_at'] + 10
                try:message = websocket.recv(timeout=max(0.05, deadline - time.monotonic()))
                except Exception:break
                answered = k < len(s['exchanges']) and s['exchanges'][k]['server_think'] is not None
                if not answered:
                    events.append({'k': k, 'rel': time.monotonic() - t0, 'answered': False}); k += 1; continue
                think = 0.0 if k == 0 else min(thinks[k] if k < len(thinks) else 0.0, 30.0)
                time.sleep(think)
                try:websocket.send(tech['ws_response'](message))
                except Exception:break
                events.append({'k': k, 'rel': time.monotonic() - t0, 'think': think}); k += 1
            if close_at:time.sleep(max(0.0, close_at - time.monotonic()))
        finally:
            try:websocket.close()
            except Exception:pass
            done.set()

    server = realclients.ws_serve(SERVER_IP, PORT, handler, ctx)
    with server:
        (root / 'server.ready').write_text('1')
        t = threading.Thread(target=server.serve_forever, daemon=True); t.start()
        if not done.wait(timeout=s['close_at'] + 60):raise TimeoutError('WSS server never saw a completed session')
        server.shutdown(); t.join(timeout=5)
    (root / 'server.json').write_text(json.dumps({'responses': events}) + '\n')


def client_ws(spec):
    """Real websockets library client, matching stage_m.py's _python_wss:
    one persistent WSS connection, one JSON text message per skeleton exchange."""
    from . import realclients
    s = spec['skeleton']; root = Path(spec['dir']); tech = TECHNIQUES[spec['technique']]
    realclients.patch_dns_to(SERVER_IP)
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT); ctx.check_hostname = False; ctx.verify_mode = ssl.CERT_NONE
    conn = realclients.ws_connect(f'wss://{tech["sni"]}:{PORT}/ws', ctx)
    journal = []; server_closed = False; t0 = time.monotonic()
    try:
        for k, ex in enumerate(s['exchanges']):
            if k:time.sleep(max(0.0, t0 + ex['at'] - time.monotonic()))
            message = application_message(spec, k, len(s['exchanges']))
            answered = ex['server_think'] is not None
            try:
                conn.send(message)
                if answered:conn.recv(timeout=45)
            except Exception:
                if s['closer'] != 'server':raise
                server_closed = True; break
            journal.append({'k': k, 'sent_rel': round(time.monotonic() - t0, 6), 'answered': bool(answered),
                            'request_sha256': hashlib.sha256(message.encode()).hexdigest()})
            if server_closed:break
        # websockets exposes only a clean RFC 6455 close handshake, no RST:
        # same disclosed gap as client_httpx() for closer='client', close_kind='rst'.
        if s['closer'] == 'client':
            time.sleep(max(0.0, t0 + s['close_at'] - time.monotonic()))
        elif not server_closed:
            # closer='server': wait passively for the server's own close instead
            # of hanging up right after the last scheduled exchange -- otherwise
            # a long-idle-then-server-closes skeleton (M-WSS-LONG's whole point)
            # has the client disconnect far too early, and the server subprocess
            # (still legitimately running out close_at) trips run_session()'s own
            # wait timeout. Same pattern as client()'s else branch.
            try:conn.recv(timeout=max(1.0, t0 + s['close_at'] + 10 - time.monotonic()))
            except Exception:pass
    finally:
        try:conn.close()
        except Exception:pass
    (root / 'client.json').write_text(json.dumps({'requests': journal, 'server_closed_early': server_closed}) + '\n')


# ---------------------------------------------------------------- orchestration on .18
def _sudo(*args, check=True, **kw):
    return subprocess.run(['sudo', '-n', *map(str, args)], check=check, capture_output=True, text=True, timeout=30, **kw)


def pad_to_wire(src, dst):
    """Ethernet minimum frame: a tap on a real link sees 60 bytes, not 54."""
    from .source import write_pcap
    frames = [(ts, f if len(f) >= 60 else f + b'\x00' * (60 - len(f))) for ts, f in read_pcap(src)]
    write_pcap(dst, frames)
    return len(frames)


# The concrete mechanic of each technique, in plain terms: WHERE the hidden
# value sits and what it looks like, read off stage_m.py's own request code.
# Independent of *who* produced the traffic (see source_kind/c2_framework in
# describe_mechanic): the same mechanic could later come from a real captured
# C2 framework (Mythic, Adaptix, Sliver) and would then be a different row of
# that other axis, not a different mechanic.
MECHANICS = {
    'M-HTTPS-LOWENT': {'code': 'http_query_param_low_entropy', 'carrier': 'http_query_param', 'covert_field': 'q',
        'payload_class': 'low_entropy',
        'description': 'Скрытое значение — короткие низкоэнтропийные коды (id=do, status=ok, cmd=1, GUID) в query-параметре q '
                       'у HTTPS POST /stage-m/status; тело запроса постоянное'},
    'M-HTTPS-BEACON': {'code': 'http_body_high_entropy_beacon', 'carrier': 'http_body', 'covert_field': 'body',
        'payload_class': 'high_entropy',
        'description': 'Скрытое значение — высокоэнтропийные данные (base64url, 32–104 байта) в теле HTTPS POST /stage-m/beacon'},
    'M-HTTPS-FRONT': {'code': 'http_body_high_entropy_fronted', 'carrier': 'http_body', 'covert_field': 'body',
        'payload_class': 'high_entropy',
        'description': 'То же тело, что у beacon, но запрос уходит на фронтовый хост (SNI/Host edge-front.test) — доменный фронтинг'},
    'M-HTTPS-FRAG': {'code': 'http_query_param_fragment', 'carrier': 'http_query_param', 'covert_field': 'id',
        'payload_class': 'fragment_2_6',
        'description': 'Скрытое значение — фрагменты по 2–6 hex-символов в параметре id у HTTPS GET /stage-m/item; тела нет'},
    'M-HTTP-443': {'code': 'http_plaintext_body_low_entropy', 'carrier': 'http_body', 'covert_field': 'body',
        'payload_class': 'low_entropy',
        'description': 'Обычный HTTP без TLS на порту 443: POST /fakeurl.htm, скрытое значение — низкоэнтропийный код в теле status=…'},
    'M-RMM-SHAPE': {'code': 'http_poll_then_interactive_body', 'carrier': 'http_body', 'covert_field': 'body',
        'payload_class': 'high_entropy',
        'description': 'Форма удалённого управления: первая половина сессии — GET-опросы /stage-m/poll?cursor=N, вторая — POST '
                       '/stage-m/interactive с высокоэнтропийными телами 96–864 байта'},
    'M-CLOUD-API': {'code': 'http_cloud_api_mimic_body', 'carrier': 'http_body', 'covert_field': 'body',
        'payload_class': 'high_entropy',
        'description': 'Имитация REST облачного хранилища (пути drive/sheets/storage/blob, методы GET/PUT/POST); скрытое значение — '
                       'высокоэнтропийное тело PUT/POST, заголовок X-Client-Request-Id служебный'},
    'M-DOH': {'code': 'doh_dns_qname_label', 'carrier': 'dns_qname', 'covert_field': 'qname_label',
        'payload_class': 'low_entropy',
        'description': 'DNS поверх HTTPS: скрытое значение — метка имени запроса (base32 от низкоэнтропийного кода) внутри DoH-запроса '
                       '(GET ?dns= или POST application/dns-message)'},
    'M-WSS-LONG': {'code': 'wss_json_container_field', 'carrier': 'ws_json_field', 'covert_field': 'container',
        'payload_class': 'high_entropy',
        'description': 'Долгая WebSocket-сессия: JSON-сообщения {action, container, target, message}, скрытое значение — поле container'},
    'M-TUNNEL': {'code': 'wss_json_socks_data_base64', 'carrier': 'ws_json_base64_field', 'covert_field': 'data',
        'payload_class': 'high_entropy',
        'description': 'WebSocket-туннель: сообщения socks_data с base64-данными в поле data, четыре логических соединения m0–m3'},
}
MECHANIC_KEYS = ('client_lib', 'transport', 'technique_source', 'code', 'carrier', 'covert_field', 'payload_class',
                 'description', 'source_kind', 'c2_framework', 'timing_source')


def describe_mechanic(technique):
    """Everything about how one technique reached the wire, recorded on each
    campaign at generation time so a table can group by it instead of guessing
    from the family name.

    Three independent axes, deliberately not merged:
      * WHO produced the traffic  -- source_kind / c2_framework. Here always
        'stage_m_shape_reimplementation' with no named framework: these sessions
        reimplement Stage M's request shapes; they are NOT Mythic/Adaptix/Sliver.
        That name is set only for a real captured framework session (Stage M's
        own EXTERNAL_FRAMEWORK campaigns carry it in client_impl), never for a lookalike.
      * WHAT the mechanic is      -- code / carrier / covert_field / payload_class / description.
      * WHAT carried it           -- client_lib / transport.
    timing_source says whose clock drove the pauses: the borrowed office
    skeleton, not the technique's own cadence."""
    tech = TECHNIQUES[technique]
    lib = tech.get('client_lib') or 'own_socket'
    if lib == 'websockets':transport = 'tcp+tls+websocket_rfc6455'
    elif tech.get('tls', True) is False:transport = 'tcp+http1_plaintext'
    else:transport = 'tcp+tls+http1'
    return {'client_lib': lib, 'transport': transport, 'technique_source': tech['source'], **MECHANICS[technique],
            'source_kind': 'stage_m_shape_reimplementation', 'c2_framework': None,
            'timing_source': 'office_skeleton_borrowed'}


def mtu_for(s, default_mtu):
    return s['frame_max'] - 14 if s['frame_max'] >= 1200 else default_mtu


def run_session(job, runtime):
    ident = job['session_id']; d = Path(job['dir']); d.mkdir(parents=True)
    s = job['skeleton']; tag = uuid.uuid4().hex[:6]
    cns, sns, cif, sif = f'gen{tag}c', f'gen{tag}s', f'g{tag}c', f'g{tag}s'
    for name in ('cert.pem', 'key.pem'):(d / name).symlink_to(Path(job['pki']) / name)
    (d / 'spec.json').write_text(json.dumps(job, indent=2) + '\n')
    procs = []
    try:
        _sudo('ip', 'netns', 'add', cns); _sudo('ip', 'netns', 'add', sns)
        _sudo('ip', 'link', 'add', cif, 'netns', cns, 'type', 'veth', 'peer', 'name', sif, 'netns', sns)
        mtu = job['environment']['mtu']
        for ns, iface, mine, peer in ((cns, cif, CLIENT_IP, SERVER_IP), (sns, sif, SERVER_IP, CLIENT_IP)):
            _sudo('ip', 'netns', 'exec', ns, 'sysctl', '-q', '-w', 'net.ipv6.conf.all.disable_ipv6=1')
            _sudo('ip', '-n', ns, 'link', 'set', iface, 'mtu', mtu, 'up'); _sudo('ip', '-n', ns, 'link', 'set', 'lo', 'up')
            _sudo('ip', '-n', ns, 'addr', 'add', f'{mine}/32', 'peer', f'{peer}/32', 'dev', iface)
            _sudo('ip', 'netns', 'exec', ns, 'ethtool', '-K', iface, 'tso', 'off', 'gso', 'off', 'gro', 'off')
        _sudo('ip', 'netns', 'exec', cns, 'sysctl', '-q', '-w',
              f'net.ipv4.tcp_timestamps={int(job["environment"]["client_tcp_timestamps"])}')
        rtt_ms = s['rtt'] * 1000; jitter = job['environment']['jitter_ms']
        netem = ['delay', f'{rtt_ms:.3f}ms'] + ([f'{jitter:.3f}ms', 'distribution', 'normal'] if jitter > 0 else [])
        _sudo('ip', 'netns', 'exec', sns, 'tc', 'qdisc', 'add', 'dev', sif, 'root', 'netem', *netem)
        if _sudo('ip', 'netns', 'exec', cns, 'ip', 'route', 'show', 'default', check=False).stdout.strip():
            raise RuntimeError('client namespace unexpectedly has a default route')
        _sudo('ip', 'netns', 'exec', sns, 'sysctl', '-q', '-w', 'net.ipv4.ip_unprivileged_port_start=0')
        # Real client_lib techniques (httpx, dnspython, ...) live only in the
        # isolated .venv_realclients -- never in the venv the live office
        # pipeline uses. Everything else keeps this orchestrator's own python.
        tech = TECHNIQUES[job['technique']]
        role_python = sys.executable
        if tech.get('client_lib'):
            candidate = runtime / '.venv_realclients' / 'bin' / 'python'
            if not candidate.exists():
                raise RuntimeError(f'.venv_realclients missing for client_lib={tech["client_lib"]!r}; '
                                   'create it once with: python3 -m venv .venv_realclients (see realclients.py)')
            role_python = str(candidate)
        env = f'PYTHONPATH={runtime}'
        user = ['runuser', '-u', getpass.getuser(), '--', 'env', env, role_python, '-m', 'office_injection.shaped']
        log = (d / 'roles.log').open('w')
        srv = subprocess.Popen(['sudo', '-n', 'ip', 'netns', 'exec', sns, *user, '--role', 'server', '--spec', str(d / 'spec.json')],
                               stdout=log, stderr=log); procs.append(srv)
        cap_log = d / 'capture.log'
        cap = subprocess.Popen(['sudo', '-n', 'ip', 'netns', 'exec', cns, 'tcpdump', '-i', cif, '-s', '0',
                                '--immediate-mode', '-U', '-Z', getpass.getuser(), '-w', str(d / 'raw.pcap'),
                                f'tcp port {PORT}'], stdout=cap_log.open('w'), stderr=subprocess.STDOUT); procs.append(cap)
        deadline = time.monotonic() + 10
        while not ((d / 'server.ready').exists() and 'listening on' in cap_log.read_text()):
            if time.monotonic() > deadline or srv.poll() is not None or cap.poll() is not None:
                raise RuntimeError('server or capture did not start; see roles.log/capture.log')
            time.sleep(0.05)
        limit = s['close_at'] + 60
        subprocess.run(['sudo', '-n', 'ip', 'netns', 'exec', cns, *user, '--role', 'client', '--spec', str(d / 'spec.json')],
                       stdout=log, stderr=log, check=True, timeout=limit)
        srv.wait(timeout=30)
        time.sleep(max(0.5, 3 * s['rtt']))
        for pid in _sudo('ip', 'netns', 'pids', cns).stdout.split():
            if Path('/proc', pid, 'comm').read_text().strip() == 'tcpdump':_sudo('kill', '-INT', pid)
        cap.wait(timeout=10)
        pad_to_wire(d / 'raw.pcap', d / 'session.pcap')
        return verify(job, d)
    finally:
        for p in procs:
            if p.poll() is None:
                try:p.terminate(); p.wait(timeout=5)
                except Exception:pass
        for ns in (cns, sns):
            for pid in _sudo('ip', 'netns', 'pids', ns, check=False).stdout.split():
                _sudo('kill', '-TERM', pid, check=False)
            _sudo('ip', 'netns', 'del', ns, check=False)


def verify(job, d):
    frames = list(read_pcap(d / 'session.pcap'))
    flows = Counter(transport(f)['key'] for _, f in frames if transport(f))
    if len(flows) != 1:raise RuntimeError(f'expected one transport session, saw {len(flows)}')
    parsed = [transport(f) for _, f in frames]
    if not parsed[0]['flags'] & 2:raise RuntimeError('capture does not start with SYN')
    if not any(p['flags'] & 5 for p in parsed):raise RuntimeError('connection close not captured')
    journal = json.loads((d / 'client.json').read_text()); requests = journal['requests']
    # Only a server that closes on its own schedule may cut the exchange list short.
    if len(requests) != len(job['skeleton']['exchanges']) and not (
            journal['server_closed_early'] and job['skeleton']['closer'] == 'server'):
        raise RuntimeError('not every skeleton exchange ran')
    synack = next(ts for (ts, _), p in zip(frames, parsed) if p['flags'] & 18 == 18)
    measured_rtt = synack - frames[0][0]
    return {**{k: job[k] for k in ('session_id', 'arm', 'technique', 'template_id', 'pair_id')},
            'path': str(d / 'session.pcap'), 'sha256': sha256(d / 'session.pcap'),
            'packets': len(frames), 'duration': frames[-1][0] - frames[0][0], 'source_start': frames[0][0],
            'max_frame': max(len(f) for _, f in frames), 'measured_rtt': measured_rtt,
            'template_rtt': job['skeleton']['rtt'], 'exchanges': len(requests),
            'template_exchanges': len(job['skeleton']['exchanges']), 'server_closed_early': journal['server_closed_early']}


def replayable(tech):
    """Which office skeletons this technique's client can actually replay.

    A real httpx client waits for every response, so it cannot reproduce an office
    session in which the server never answered (35% of the hour-12 pool: a client
    retrying against a silent server, closed by its own RST). The hand-rolled
    socket client and the websockets client handle those, so they keep every skeleton.
    A response slower than httpx's own 10 s read timeout would fail the same way.
    """
    if tech.get('client_lib') != 'httpx':return None
    def keep(s):
        ex = s['exchanges']
        return all(e['server_think'] is not None for e in ex) and all(e['server_think'] <= 9.0 for e in ex[1:])
    return keep


def generate(store, out, hours, per_hour, seed, technique='M-HTTPS-LOWENT', parallel=8,
             exclude=(), before=None, days=7, jitter_fraction=0.05, max_jitter_ms=5.0,
             control_kind='benign_application'):
    tech = TECHNIQUES[technique]
    if tech['timing_owned_by_technique']:raise ValueError('technique owns its timing; skeleton timing would overwrite the mechanism')
    if control_kind not in ('benign_application','equal_length_ablation'):raise ValueError('unknown control kind')
    out = Path(out).resolve(); out.mkdir(parents=True, exist_ok=False)
    runtime = Path(__file__).resolve().parents[1]
    picked = tpl.sample(store, hours, per_hour, seed, exclude, before, days, keep=replayable(tech))
    big = Counter(s['frame_max'] for s in picked if s['frame_max'] >= 1200)
    default_mtu = (big.most_common(1)[0][0] - 14) if big else 1500
    pki = out / 'pki'; pki.mkdir()
    subprocess.run(['openssl', 'req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-keyout', pki / 'key.pem',
                    '-out', pki / 'cert.pem', '-days', '2', '-subj', f'/CN={tech["sni"]}'], check=True, capture_output=True)
    jobs = []
    for s in picked:
        pair = f'{s["template_id"]}'
        environment = {'mtu': mtu_for(s, default_mtu), 'client_tcp_timestamps': s['client_tcp_timestamps'],
                       'jitter_ms': min(max_jitter_ms, jitter_fraction * s['rtt'] * 1000),
                       'netem_side': 'server_egress', 'capture_point': 'client_interface',
                       'wire_min_frame_padding': 60}
        for arm in ('scenario', 'control'):
            ident = f'{pair}-{arm}'
            jobs.append({'session_id': ident, 'pair_id': pair, 'arm': arm, 'technique': technique, 'control_kind':control_kind,
                         'template_id': s['template_id'], 'skeleton': s, 'environment': environment,
                         'dir': str(out / 'sessions' / ident), 'pki': str(pki)})
    results, failures = [], []
    lock = threading.Lock()
    def one(job):
        try:r = run_session(job, runtime)
        except Exception as exc:
            with lock:failures.append({'session_id': job['session_id'], 'error': str(exc)})
            return
        with lock:results.append(r)
    with ThreadPoolExecutor(parallel) as pool:list(pool.map(one, jobs))
    # A pair is admitted only whole: an unmatched arm would reintroduce origin imbalance.
    arms = Counter(r['pair_id'] for r in results)
    admitted = [r for r in results if arms[r['pair_id']] == 2]
    by_pair = {s['template_id']: s for s in picked}
    campaigns = []
    for r in sorted(admitted, key=lambda r: r['session_id']):
        s = by_pair[r['pair_id']]
        campaigns.append({'campaign_id': r['session_id'], 'technique': technique, 'arm': r['arm'],
                          'path': r['path'], 'sha256': r['sha256'], 'duration': r['duration'],
                          'source_start': r['source_start'], 'packets': r['packets'],
                          'parent_campaign_id': r['pair_id'], 'template_id': r['template_id'],
                          'ancestor_group_id':r['template_id'], 'control_kind':control_kind,
                          'behavior_policy':'office_skeleton_fixed', 'semantic_scope':'application_message_fixture',
                          'moscow_hour': s['moscow_hour'], 'template_moscow_date': s['moscow_date'],
                          'mechanic': describe_mechanic(technique),
                          'generated': True, 'training_eligible': False, 'timing_training_eligible': False,
                          'label_scope': 'transport_session_generated_on_office_skeleton',
                          'membership': 'whole_generated_transport_session'})
    catalog = {'campaigns': campaigns, 'role': 'office_skeleton_generated', 'technique': technique,
               'technique_source': tech['source'], 'seed': seed, 'hours': sorted(hours), 'control_kind':control_kind,
               'template_policy': {'store': str(Path(store).resolve()), 'exclude_windows': list(exclude),
                                   'before_date': before, 'days': days, 'per_hour': per_hour},
               'default_mtu': default_mtu, 'sessions_attempted': len(jobs), 'failures': failures,
               'unpaired_dropped': len(results) - len(admitted),
               'fidelity': {'rtt_abs_error_p50': sorted(abs(r['measured_rtt'] - r['template_rtt']) for r in results)[len(results) // 2] if results else None}}
    (out / 'results.json').write_text(json.dumps({'results': results, 'failures': failures}, indent=2) + '\n')
    (out / 'catalog.json').write_text(json.dumps(catalog, indent=2) + '\n')
    return catalog


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--role', choices=('server', 'client'))
    p.add_argument('--spec', type=Path)
    p.add_argument('--store', type=Path); p.add_argument('--out', type=Path)
    p.add_argument('--hours', type=int, nargs='+'); p.add_argument('--per-hour', type=int, default=20)
    p.add_argument('--seed', type=int, default=1701); p.add_argument('--parallel', type=int, default=8)
    p.add_argument('--technique', default='M-HTTPS-LOWENT', choices=sorted(TECHNIQUES))
    p.add_argument('--exclude-from-inputs', type=Path, help='office_inputs JSON: their time spans (+-600 s) are not template sources')
    p.add_argument('--before', help='only template days strictly before YYYY-MM-DD (previous-days policy)')
    p.add_argument('--days', type=int, default=7)
    p.add_argument('--control-kind', choices=('benign_application','equal_length_ablation'), default='benign_application')
    a = p.parse_args()
    if a.role:
        spec = json.loads(a.spec.read_text())
        lib = TECHNIQUES[spec['technique']].get('client_lib')
        if a.role == 'server':
            return serve_ws(spec) if lib == 'websockets' else serve(spec)
        if lib == 'httpx':return client_httpx(spec)
        if lib == 'websockets':return client_ws(spec)
        return client(spec)
    exclude = []
    if a.exclude_from_inputs:
        from .records import iter_rows
        for path in json.loads(a.exclude_from_inputs.read_text()):
            first = last = None
            for x, _ in iter_rows(path):
                first = x[0] if first is None else first; last = x[0]
            if first is not None:exclude.append((first - 600, last + 600))
        merged = []
        for a_, b_ in sorted(exclude):
            if merged and a_ <= merged[-1][1]:merged[-1] = (merged[-1][0], max(merged[-1][1], b_))
            else:merged.append((a_, b_))
        exclude = merged
    catalog = generate(a.store, a.out, a.hours, a.per_hour, a.seed, a.technique, a.parallel, exclude, a.before, a.days,
                       control_kind=a.control_kind)
    print(json.dumps({k: v for k, v in catalog.items() if k != 'campaigns'} | {'campaigns': len(catalog['campaigns'])}, indent=2))


if __name__ == '__main__':raise SystemExit(main())
