"""Real reference client libraries for the isolated namespace pair in shaped.py.

Scope decision 2026-09-28: the full Stage M lab (cover-channel-lab/scripts/
setup_netns.sh + start_services.sh) needs system-wide changes on .18 while a
30-hour office collection is live there -- a new bridge, six namespaces,
machine-wide /etc/hosts edits for ~30 hostnames, and apt installs (nginx,
mosquitto, a JVM, a Rust toolchain, Node, Chromium). None of that is done
here. What ships in this module is the subset that needs neither: real
httpx/dnspython/websockets, pip-installed into a venv of their own
(`.venv_realclients`, untouched `../.venv` used by the live pipeline),
running inside the existing two-namespace/netem/office-skeleton architecture
shaped.py already has. The server this talks to is still ours, not nginx or
Mosquitto -- the office SPAN only ever sees the client's wire behaviour, and
that is what these libraries make genuine.

DNS: the isolated client namespace has no resolver (deliberately -- no
default route). httpx resolves the URL's hostname itself, so
`patch_dns_to` overrides socket.getaddrinfo for `.test` names to the
synthetic server IP, in this one process only. It never touches the host's
real /etc/hosts or DNS, and never affects any other process.
"""
from __future__ import annotations
import socket


def patch_dns_to(server_ip):
    """Route every `*.test` lookup in THIS process to server_ip. Process-local:
    does not write /etc/hosts, does not touch any other process or namespace."""
    real_getaddrinfo = socket.getaddrinfo

    def fake_getaddrinfo(host, port, *args, **kwargs):
        if isinstance(host, str) and host.endswith('.test'):
            return real_getaddrinfo(server_ip, port, *args, **kwargs)
        return real_getaddrinfo(host, port, *args, **kwargs)

    socket.getaddrinfo = fake_getaddrinfo


def httpx_client(base_url, http2=False):
    """One persistent httpx.Client -- the `_reuse` implementation profile in
    stage_m.py's own client catalog, matching this architecture's one
    skeleton = one connection model. Settings copied verbatim from
    stage_m.py's execute_http()/`_http_events` reusable-client branch:
    verify=False (self-signed lab cert), timeout=10, follow_redirects=False,
    trust_env=False (no system/proxy env influence)."""
    import httpx
    # keepalive_expiry=None: replay of an office skeleton is ONE persistent connection, however
    # long it idles. httpx's default (5 s) silently opens a second connection after a longer
    # pause, which the one-accept server never serves (2026-09-29: 3 of 11 lost pairs).
    return httpx.Client(base_url=base_url, verify=False, http2=http2, timeout=10,
                        follow_redirects=False, trust_env=False,
                        limits=httpx.Limits(keepalive_expiry=None))


def wait_for_server_close(client, deadline, poll=0.05):
    """Block until the server closes the pooled connection, or `deadline` (monotonic).

    A closer='server' skeleton ends when the SERVER hangs up, possibly a minute after
    the last request. httpx has no public 'wait for EOF' call, so this asks httpcore's
    own pool whether any connection is no longer usable (has_expired: the peer has
    closed it / it is readable while idle). Returns True if the server closed first.
    """
    import time
    pool = client._transport._pool
    while time.monotonic() < deadline:
        conns = list(pool.connections)
        if not conns or any(c.has_expired() for c in conns):return True
        time.sleep(poll)
    return False


def dns_wire_query(qname, qtype):
    """dnspython's real wire encoder -- stage_m.py's own _dns_wire_query."""
    import dns.message, dns.name, dns.rdatatype
    return dns.message.make_query(dns.name.from_text(qname), dns.rdatatype.from_text(qtype)).to_wire()


def dns_wire_answer(qname, qtype, ip='10.20.0.99', ttl=60):
    """A well-formed dnspython answer message. Content is never decoded
    downstream (sampled only for length/entropy over TLS ciphertext for DOH,
    or as opaque bytes for a plain DNS response) -- this need not be the
    resolver's real answer, only a genuine wire-format one of plausible size."""
    import dns.message, dns.name, dns.rdataset, dns.rdatatype, dns.rrset
    query = dns.message.make_query(dns.name.from_text(qname), dns.rdatatype.from_text(qtype))
    response = dns.message.make_response(query)
    if qtype == 'A':
        response.answer.append(dns.rrset.from_text(qname, ttl, 'IN', 'A', ip))
    return response.to_wire()


def ws_connect(url, ssl_context):
    """The real websockets sync client -- stage_m.py's _python_wss client path."""
    from websockets.sync.client import connect
    return connect(url, ssl=ssl_context, open_timeout=20, close_timeout=2, proxy=None, compression=None)


def ws_serve(host, port, handler, ssl_context):
    """The real websockets sync server, paired with ws_connect above."""
    from websockets.sync.server import serve
    return serve(handler, host, port, ssl=ssl_context)
