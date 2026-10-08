from __future__ import annotations

from .scenarios import Scenario, _s


EXTRA_SCENARIOS: tuple[Scenario, ...] = (
    # Real HTTP/3 / QUIC challenge corpus, local aioquic endpoint only.
    _s("CC_H3_01", "http3", "h3", "h3_request", "web_c2_plain", "c2", "browser_h3", "HTTP/3 GET/POST streams", "T1071.001"),
    _s("CC_H3_02", "http3", "h3", "h3_parallel", "covert_storage", "exfil", "browser_h3", "parallel H3 stream fragments", "T1071.001", "T1041"),
    _s("CC_H3_03", "http3", "h3", "h3_order", "covert_storage", "c2", "browser_h3", "stream ordering channel", "T1071.001"),
    _s("CC_H3_04", "http3", "h3", "h3_header", "covert_storage", "c2", "browser_h3", "H3 header value carrier", "T1071.001"),
    _s("CC_H3_05", "http3", "h3", "h3_data_size", "covert_storage", "c2", "media_h3", "H3 DATA size classes", "T1071.001"),
    _s("CC_H3_06", "http3", "h3", "h3_sparse", "web_c2_mimicry", "c2", "browser_h3", "sparse H3 streams", "T1071.001", "T1001.003"),
    _s("CC_H3_07", "http3", "h3", "h3_reconnect", "web_c2_plain", "c2", "browser_h3", "QUIC reconnect/NAT-rebinding-like profile", "T1071.001"),
    _s("CC_H3_08", "http3", "h3", "h3_fallback", "web_c2_mimicry", "c2", "browser_h3", "H3 to H2 to H1 fallback campaign", "T1071.001", "T1001.003"),
    # Tunnel / privacy challenge. Targets are synthetic and never Internet-routed.
    _s("CC_CONNECT_01", "connect", "http", "http_connect", "web_tunnel", "tunnel", "authorized_proxy", "HTTP CONNECT-like local echo fixture", "T1071.001", "T1572", "T1090"),
    _s("CC_CONNECT_02", "connect", "h2", "extended_connect", "web_tunnel", "tunnel", "authorized_proxy", "H2 Extended CONNECT semantic fixture", "T1071.001", "T1572", "T1090"),
    _s("CC_CONNECT_03", "connect", "h2", "websocket_h2", "web_tunnel", "tunnel", "collaboration", "WebSocket-over-H2 semantic fixture", "T1071.001", "T1572"),
    _s("CC_MASQUE_01", "masque", "h3", "connect_udp", "web_tunnel", "tunnel", "authorized_masque", "real H3 datagram CONNECT-UDP-like fixture", "T1071.001", "T1572", "T1090"),
    _s("CC_MASQUE_02", "masque", "h3", "connect_ip", "web_tunnel", "tunnel", "authorized_masque", "CONNECT-IP-like isolated synthetic datagram fixture", "T1071.001", "T1572", "T1090"),
    _s("CC_WEBTRANS_01", "webtransport", "h3", "webtransport_stream", "web_tunnel", "tunnel", "browser_realtime", "real WebTransport bidirectional stream fixture", "T1071.001", "T1572"),
    _s("CC_OHTTP_01", "privacy", "https", "ohttp_binary", "web_c2_plain", "unknown", "privacy_relay", "OHTTP-like encrypted binary benign hard-negative", "T1071.001"),
)
