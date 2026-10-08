from __future__ import annotations

from dataclasses import dataclass, asdict
from typing import Iterable


@dataclass(frozen=True)
class Scenario:
    scenario_id: str
    family: str
    transport: str
    carrier: str
    label_family: str
    label_intent: str
    attack_mapping: tuple[str, ...]
    benign_semantic_type: str
    description: str

    def to_dict(self) -> dict:
        d = asdict(self)
        d["attack_mapping"] = list(self.attack_mapping)
        return d


def _s(sid: str, family: str, transport: str, carrier: str, label_family: str,
       intent: str, benign: str, desc: str, *attack: str) -> Scenario:
    return Scenario(sid, family, transport, carrier, label_family, intent,
                    tuple(attack or ("T1071.001",)), benign, desc)


# IDs mirror the source plan. All implementations are benign-safe simulations: no command
# execution, persistence, credential access, Internet C2, or arbitrary proxying is present.
SCENARIOS: tuple[Scenario, ...] = (
    # URI / request target
    _s("CC_URI_01","uri","http","query_value","covert_storage","c2","search","message in id query","T1071.001","T1001.003"),
    _s("CC_URI_02","uri","http","query_values","covert_storage","c2","pagination","message split over query values","T1071.001","T1001.001"),
    _s("CC_URI_03","uri","http","path_segment","covert_storage","c2","resource_id","fragment in path segment","T1071.001"),
    _s("CC_URI_04","uri","http","multi_request_query","covert_storage","c2","spa_polling","small fragments over requests","T1071.001"),
    _s("CC_URI_05","uri","http","filename","web_c2_mimicry","c2","cache_busting","payload-like filename extension","T1071.001","T1001.003"),
    _s("CC_URI_06","uri","http","matrix_path","web_c2_mimicry","c2","api_path","matrix-like path params","T1071.001","T1001.003"),
    _s("CC_URI_07","uri","http","query_key","covert_storage","c2","analytics","symbols in query key names","T1071.001"),
    _s("CC_URI_08","uri","http","uri_length","covert_storage","c2","image_resize","URI length modulation","T1071.001","T1001.001"),
    # Standard headers
    _s("CC_HDR_01","header","https","cookie","covert_storage","c2","auth","registration in Cookie","T1071.001"),
    _s("CC_HDR_02","header","https","cookie","covert_storage","c2","session_rotation","fragments in Cookie","T1071.001"),
    _s("CC_HDR_03","header","https","authorization","covert_storage","c2","auth","synthetic payload disguised as bearer","T1071.001","T1001.003"),
    _s("CC_HDR_04","header","https","user_agent","web_c2_mimicry","c2","custom_sdk","ID suffix in User-Agent","T1071.001","T1001.003"),
    _s("CC_HDR_05","header","https","referer","covert_storage","exfil","navigation","encoded result in Referer","T1071.001","T1041"),
    _s("CC_HDR_06","header","https","origin","covert_storage","c2","cors","low bandwidth marker in Origin","T1071.001"),
    _s("CC_HDR_07","header","https","accept_language","covert_storage","c2","localization","Accept-Language order modulation","T1071.001"),
    _s("CC_HDR_08","header","https","accept_encoding","covert_storage","c2","content_negotiation","Accept-Encoding order modulation","T1071.001"),
    _s("CC_HDR_09","header","https","if_none_match","covert_storage","c2","cache","synthetic victim ID in If-None-Match","T1071.001"),
    _s("CC_HDR_10","header","https","if_modified_since","covert_timing","c2","cache","timestamp modulation","T1071.001"),
    _s("CC_HDR_11","header","https","range","covert_storage","c2","video_range","Range offsets encode symbols","T1071.001"),
    _s("CC_HDR_12","header","https","content_type_param","covert_storage","exfil","multipart","boundary/charset fragment","T1071.001","T1041"),
    # Custom headers
    _s("CC_XHDR_01","custom_header","https","x_session_id","covert_storage","c2","tracing","X-Session-Id value stream","T1071.001"),
    _s("CC_XHDR_02","custom_header","https","x_request_id","covert_storage","c2","tracing","X-Request-Id value stream","T1071.001"),
    _s("CC_XHDR_03","custom_header","https","x_correlation_id","covert_storage","c2","tracing","correlation ID stream","T1071.001"),
    _s("CC_XHDR_04","custom_header","https","x_telemetry","covert_storage","exfil","telemetry","encoded telemetry-like result","T1071.001","T1041"),
    # Body
    _s("CC_BODY_01","body","https","json","web_c2_plain","c2","telemetry","direct synthetic command/result JSON","T1071.001"),
    _s("CC_BODY_02","body","https","json_junk","web_c2_mimicry","c2","telemetry","payload among junk JSON fields","T1071.001","T1001.001"),
    _s("CC_BODY_03","body","http","form","covert_storage","exfil","form","fragments in form values","T1071.001","T1041"),
    _s("CC_BODY_04","body","https","multipart","web_c2_plain","exfil","file_upload","synthetic file-like result","T1071.001","T1041"),
    _s("CC_BODY_05","body","https","multipart_filename","covert_storage","exfil","file_upload","data in multipart filename/boundary","T1071.001","T1041"),
    _s("CC_BODY_06","body","https","octet_stream","web_c2_plain","exfil","crash_report","encrypted-like bytes","T1071.001","T1573","T1041"),
    _s("CC_BODY_07","body","h2","protobuf_like","web_c2_plain","c2","rpc","opaque protobuf-like bytes","T1071.001"),
    _s("CC_BODY_08","body","http","xml_attributes","stego_content","c2","xml_manifest","payload in XML attributes","T1071.001","T1001.002"),
    _s("CC_BODY_09","body","https","graphql_variables","web_c2_mimicry","c2","graphql","command disguised as variables","T1071.001","T1001.003"),
    _s("CC_BODY_10","body","http","chunked","covert_storage","exfil","resumable_upload","fragmented HTTP body","T1071.001","T1041"),
    # Response channels
    _s("CC_RESP_01","response","http","response_body","web_c2_plain","c2","api_response","plain task in response","T1071.001"),
    _s("CC_RESP_02","response","https","response_json","web_c2_mimicry","c2","api_response","task in noisy object","T1071.001","T1001.001"),
    _s("CC_RESP_03","response","http","response_xml","stego_content","c2","xml_manifest","GUID/hex steganography","T1071.001","T1001.002"),
    _s("CC_RESP_04","response","http","response_html","stego_content","c2","static_content","HTML comment/attribute carrier","T1071.001","T1001.002"),
    _s("CC_RESP_05","response","http","response_css","stego_content","c2","static_content","CSS value carrier","T1071.001","T1001.002"),
    _s("CC_RESP_06","response","http","response_image_meta","stego_content","c2","image_metadata","synthetic image metadata carrier","T1071.001","T1001.002"),
    _s("CC_RESP_07","response","https","set_cookie","covert_storage","c2","ab_testing","downstream command in Set-Cookie","T1071.001"),
    _s("CC_RESP_08","response","https","etag","covert_storage","c2","cache","downstream ETag fragment","T1071.001"),
    _s("CC_RESP_09","response","http","status_code","covert_storage","c2","healthcheck","status-code alphabet","T1071.001"),
    _s("CC_RESP_10","response","http","redirect","covert_storage","c2","redirect","Location carries task","T1071.001"),
    _s("CC_RESP_11","response","http","response_size","covert_storage","c2","content_variant","response length modulation","T1071.001"),
    _s("CC_RESP_12","response","http","response_chunks","covert_storage","c2","streaming","chunk-size modulation","T1071.001"),
    # Syntax / timing
    _s("CC_SYN_01","syntax","http","header_order","covert_storage","c2","runtime_variation","header order channel","T1071.001"),
    _s("CC_SYN_02","syntax","http","header_case","covert_storage","c2","runtime_variation","header case channel","T1071.001"),
    _s("CC_SYN_03","syntax","http","whitespace","covert_storage","c2","runtime_variation","OWS modulation","T1071.001"),
    _s("CC_SYN_04","syntax","http","duplicate_headers","covert_storage","c2","proxy","duplicate header order","T1071.001"),
    _s("CC_SYN_05","syntax","http","method","covert_storage","c2","api","method selection channel","T1071.001"),
    _s("CC_SYN_06","syntax","http","connection_reuse","covert_storage","c2","api","reuse/close modulation","T1071.001"),
    _s("CC_SYN_07","syntax","http","content_length_parity","covert_storage","c2","api","body length parity","T1071.001"),
    _s("CC_SYN_08","syntax","http","request_count","covert_storage","c2","api","request count symbols","T1071.001"),
    _s("CC_TIME_01","timing","https","fixed_beacon","covert_timing","c2","healthcheck","fixed beacon","T1071.001"),
    _s("CC_TIME_02","timing","https","low_jitter","covert_timing","c2","monitoring","low jitter beacon","T1071.001"),
    _s("CC_TIME_03","timing","https","medium_jitter","covert_timing","c2","background_sync","medium jitter beacon","T1071.001"),
    _s("CC_TIME_04","timing","https","high_jitter","covert_timing","c2","background_sync","lognormal jitter","T1071.001"),
    _s("CC_TIME_05","timing","https","burst","covert_timing","c2","telemetry","burst then pause","T1071.001"),
    _s("CC_TIME_06","timing","https","work_hours","web_c2_mimicry","c2","office_automation","work-hours schedule","T1071.001","T1001.003"),
    _s("CC_TIME_07","timing","https","backoff","covert_timing","c2","retry","exponential backoff","T1071.001"),
    _s("CC_TIME_08","timing","http","binary_timing","covert_timing","c2","polling","short/long interval bits","T1071.001"),
    _s("CC_TIME_09","timing","https","low_slow","web_c2_mimicry","c2","background_sync","accelerated low-and-slow fixture","T1071.001","T1001.003"),
    _s("CC_TIME_10","timing","https","event_driven","covert_timing","c2","notification","event-driven callback","T1071.001"),
    # WebSocket/WSS
    _s("CC_WS_01","websocket","wss","ws_registration","web_c2_plain","c2","chat","UUID + synthetic system profile","T1071.001"),
    _s("CC_WS_02","websocket","wss","ws_json_recv","web_c2_plain","c2","market_data","JSON recv polling","T1071.001"),
    _s("CC_WS_03","websocket","wss","ws_json_send","web_c2_plain","exfil","chat","JSON result send","T1071.001","T1041"),
    _s("CC_WS_04","websocket","wss","ws_b64_envelope","web_c2_mimicry","c2","market_data","Base64 JSON envelope","T1071.001","T1573"),
    _s("CC_WS_05","websocket","wss","ws_binary","web_c2_plain","exfil","game_telemetry","binary frames","T1071.001","T1041"),
    _s("CC_WS_06","websocket","wss","ws_ping","covert_timing","c2","notification","ping timing/payload","T1071.001"),
    _s("CC_WS_07","websocket","wss","ws_fragmentation","covert_storage","exfil","collaboration","fragmented messages","T1071.001"),
    _s("CC_WS_08","websocket","wss","ws_idle","web_c2_mimicry","c2","notification","long-lived sparse messages","T1071.001","T1001.003"),
    _s("CC_WS_09","websocket","wss","ws_reconnect","web_c2_plain","c2","dashboard","reconnect continuity","T1071.001"),
    _s("CC_WS_10","websocket","wss","ws_multipersona","web_c2_plain","c2","chat","multiple personas same endpoint","T1071.001"),
    _s("CC_WS_11","websocket","wss","ws_browser_headers","web_c2_mimicry","c2","browser_app","browser mimicry","T1071.001","T1001.003"),
    _s("CC_WS_12","websocket","wss","ws_appliance","web_c2_mimicry","c2","management","appliance-like WSS","T1071.001","T1001.003"),
    # HTTP/2
    _s("CC_H2_01","http2","h2","h2_request","web_c2_plain","c2","browser_h2","GET/POST streams","T1071.001"),
    _s("CC_H2_02","http2","h2","h2_parallel","covert_storage","exfil","browser_h2","parallel stream fragments","T1071.001","T1041"),
    _s("CC_H2_03","http2","h2","h2_order","covert_storage","c2","browser_h2","stream ordering channel","T1071.001"),
    _s("CC_H2_04","http2","h2","h2_header","covert_storage","c2","browser_h2","header value carrier","T1071.001"),
    _s("CC_H2_05","http2","h2","h2_data_size","covert_storage","c2","browser_h2","DATA size classes","T1071.001"),
    _s("CC_H2_06","http2","h2","h2_reset","covert_storage","c2","browser_h2","selective resets fixture","T1071.001"),
    _s("CC_H2_07","http2","h2","h2_sparse","web_c2_mimicry","c2","browser_h2","sparse streams on long connection","T1071.001","T1001.003"),
    _s("CC_H2_08","http2","h2","h2_client_mismatch","web_c2_mimicry","c2","service_rpc","browser-like headers from script stack","T1071.001","T1001.003"),
    # Browser primitives (wire-realistic browser build is run by optional browser job)
    _s("CC_BROWSER_01","browser","https","extension_registration","web_c2_mimicry","c2","extension_update","extension registration","T1071.001","T1001.003"),
    _s("CC_BROWSER_02","browser","https","service_worker_alarm","covert_timing","c2","background_sync","Service Worker alarm","T1071.001"),
    _s("CC_BROWSER_03","browser","https","push_wakeup","covert_timing","c2","web_push","push-like wake-up","T1071.001"),
    _s("CC_BROWSER_04","browser","https","keepalive_tab","web_c2_mimicry","c2","background_sync","hidden helper fetch","T1071.001","T1001.003"),
    _s("CC_BROWSER_05","browser","https","native_echo","web_c2_plain","c2","extension_update","safe local echo bridge","T1071.001"),
    _s("CC_BROWSER_06","browser","wss","browser_wss","web_c2_mimicry","c2","collaboration","WSS from browser-like context","T1071.001","T1001.003"),
    _s("CC_BROWSER_07","browser","https","headless","web_c2_mimicry","c2","headless_monitoring","headless browser timing","T1071.001","T1001.003"),
    _s("CC_BROWSER_08","browser","https","fetch_stream","web_c2_plain","exfil","browser_upload","synthetic blob fetch stream","T1071.001","T1041"),
    _s("CC_BROWSER_09","browser","https","send_beacon","covert_storage","exfil","analytics","sendBeacon-like exfil","T1071.001","T1041"),
    _s("CC_BROWSER_10","browser","https","csp_report","covert_storage","exfil","csp_reporting","CSP report carrier","T1071.001","T1041"),
    _s("CC_BROWSER_11","browser","https","prefetch","covert_storage","exfil","resource_hints","resource hint subdomain symbols","T1071.001","T1041"),
    # SSE / long polling / gRPC-like H2 fixtures
    _s("CC_SSE_01","sse","http","sse_command","web_c2_plain","c2","deployment_logs","command event stream","T1071.001"),
    _s("CC_SSE_02","sse","http","sse_encoded","covert_storage","c2","deployment_logs","encoded events","T1071.001"),
    _s("CC_SSE_03","sse","http","sse_comment_timing","covert_timing","c2","deployment_logs","comment timing","T1071.001"),
    _s("CC_SSE_04","sse","http","last_event_id","covert_storage","c2","notification","Last-Event-ID carrier","T1071.001"),
    _s("CC_SSE_05","sse","http","sse_sparse","web_c2_mimicry","c2","observability","sparse long-lived SSE","T1071.001","T1001.003"),
    _s("CC_LP_01","longpoll","https","long_poll_recv","web_c2_plain","c2","chat_polling","long polling receive","T1071.001"),
    _s("CC_LP_02","longpoll","https","rotating_poll","covert_storage","c2","chat_polling","rotating poll ID","T1071.001"),
    _s("CC_LP_03","longpoll","https","poll_upload","web_c2_plain","c2","chat_polling","poll + result upload","T1071.001"),
    _s("CC_GRPC_01","grpc","h2","grpc_unary","web_c2_plain","c2","service_rpc","gRPC wire-format unary fixture","T1071.001"),
    _s("CC_GRPC_02","grpc","h2","grpc_server_stream","web_c2_plain","c2","service_rpc","server stream fixture","T1071.001"),
    _s("CC_GRPC_03","grpc","h2","grpc_client_stream","web_c2_plain","exfil","otlp","client stream fixture","T1071.001","T1041"),
    _s("CC_GRPC_04","grpc","h2","grpc_bidi","web_tunnel","c2","otlp","bidi stream fixture","T1071.001","T1572"),
    _s("CC_GRPC_05","grpc","h2","grpc_metadata","covert_storage","c2","service_rpc","metadata carrier","T1071.001"),
    _s("CC_GRPC_06","grpc","h2","grpc_trailers","covert_storage","c2","service_rpc","status/trailer signal","T1071.001"),
    _s("CC_GRPC_07","grpc","h2","grpc_compressed","web_c2_mimicry","c2","otlp","compressed messages","T1071.001","T1001.003"),
    _s("CC_GRPC_08","grpc","h2","grpc_multiplex","web_tunnel","c2","service_rpc","multiplexed methods","T1071.001","T1572"),
    # Safe WSS tunnel grammar; no arbitrary forwarding
    _s("CC_TUN_01","tunnel","wss","fixed_echo_relay","web_tunnel","tunnel","remote_support","fixed local echo service","T1071.001","T1572","T1090"),
    _s("CC_TUN_02","tunnel","wss","allowlisted_connect","web_tunnel","proxy","remote_support","SOCKS-like grammar to synthetic target only","T1071.001","T1572","T1090"),
    _s("CC_TUN_03","tunnel","wss","multiplex_conn_id","web_tunnel","proxy","browser_ide","2-16 logical synthetic streams","T1071.001","T1572","T1090"),
    _s("CC_TUN_04","tunnel","wss","mixed_inner","web_tunnel","tunnel","browser_ide","synthetic inner protocol labels","T1071.001","T1572"),
    _s("CC_TUN_05","tunnel","wss","backpressure","web_tunnel","tunnel","collaboration","safe window/update-like controls","T1071.001","T1572"),
    _s("CC_TUN_06","tunnel","wss","stream_lifecycle","web_tunnel","tunnel","collaboration","half-close/reset grammar","T1071.001","T1572"),
    _s("CC_TUN_07","tunnel","wss","interactive","web_tunnel","tunnel","game_relay","small bidirectional messages","T1071.001","T1572"),
    _s("CC_TUN_08","tunnel","wss","bulk","web_tunnel","tunnel","backup","larger one-way synthetic phase","T1071.001","T1572"),
    _s("CC_TUN_09","tunnel","wss","keepalive","web_tunnel","tunnel","notification","idle + sparse ping/pong","T1071.001","T1572"),
    _s("CC_TUN_10","tunnel","wss","endpoint_migration","web_tunnel","tunnel","developer_tunnel","same campaign second local hostname","T1071.001","T1572"),
    # TLS / visibility challenges; safe traffic only
    _s("CC_TLS_01","tls","https","script_default","web_c2_plain","c2","api","default script TLS","T1071.001"),
    _s("CC_TLS_02","tls","https","browser_like","web_c2_mimicry","c2","browser_app","browser-like headers/TLS challenge","T1071.001","T1001.003"),
    _s("CC_TLS_03","tls","https","clienthello_variation","web_c2_mimicry","c2","browser_app","TLS stack diversity challenge","T1071.001","T1001.003"),
    _s("CC_TLS_04","tls","https","resumption","web_c2_plain","c2","browser_app","session resumption","T1071.001"),
    _s("CC_TLS_05","tls","https","zero_rtt_marker","web_c2_plain","c2","browser_app","0-RTT capability marker fixture","T1071.001"),
    _s("CC_TLS_06","tls","https","sni_loss_fixture","web_c2_plain","c2","privacy","visibility-loss fixture","T1071.001"),
    _s("CC_TLS_07","tls","h2","fallback","web_c2_plain","c2","browser_app","H3/H2/H1 metadata fallback fixture","T1071.001"),
    _s("CC_TLS_08","tls","https","shared_edge","web_c2_mimicry","c2","cdn","shared-edge hostname categories","T1071.001","T1001.003"),
    _s("CC_TLS_09","tls","https","cert_rotation","web_c2_plain","c2","cdn","certificate/destination rotation fixture","T1071.001"),
    _s("CC_TLS_10","tls","https","inspection_bypass","web_c2_plain","c2","management","pinning-like inspection outcome label","T1071.001"),
    # Commodity LOTS fixtures are LOCAL analogues only
    _s("CC_LOTS_01","lots","https","chatops_poll","lots_web_api","c2","ci_notification","local getUpdates-like polling","T1102","T1071.001"),
    _s("CC_LOTS_02","lots","https","chatops_push","lots_web_api","c2","ci_notification","local sendMessage-like request","T1102","T1071.001"),
    _s("CC_LOTS_03","lots","https","chatops_document","lots_web_api","exfil","ci_artifact","local sendDocument-like multipart","T1102","T1071.001","T1567"),
    _s("CC_LOTS_04","lots","https","webhook","lots_web_api","exfil","monitoring_notification","local webhook-like one-way POST","T1102","T1071.001","T1567"),
    _s("CC_LOTS_05","lots","wss","ephemeral_relay","web_tunnel","tunnel","developer_tunnel","local ephemeral relay analogue","T1071.001","T1572"),
    _s("CC_LOTS_06","lots","wss","paas_endpoint","web_c2_mimicry","c2","developer_tunnel","local PaaS-style endpoint","T1071.001","T1001.003"),
    _s("CC_LOTS_07","lots","wss","dyndns_endpoint","web_c2_mimicry","c2","self_hosting","local dynamic-DNS-style endpoint","T1071.001","T1001.003"),
    _s("CC_LOTS_08","lots","https","bucket_dead_drop","lots_web_api","c2","backup_sync","local S3-like time-slot object name","T1102","T1071.001"),
    # MQTT-over-WebSocket boundary
    _s("CC_MQTT_01","mqtt_ws","wss","mqtt_topic","web_tunnel","c2","iot_telemetry","MQTT-like CONNECT/PUBLISH frames over WSS","T1071.005","T1071.001"),
    _s("CC_MQTT_02","mqtt_ws","wss","mqtt_payload","web_tunnel","c2","iot_telemetry","MQTT-like topic/payload carrier","T1071.005","T1071.001"),
    _s("CC_MQTT_03","mqtt_ws","wss","mqtt_timing","covert_timing","c2","iot_telemetry","MQTT-over-WSS timing fixture","T1071.005","T1071.001"),
    # DoH boundary; only synthetic .test names
    _s("CC_DOH_01","doh","https","dns_message","web_c2_mimicry","c2","legitimate_doh","DNS wire-format in local /dns-query","T1071.001","T1071.004"),
)


BY_ID = {s.scenario_id: s for s in SCENARIOS}


def select(stage: str, shard: int = 0, shards: int = 1) -> list[Scenario]:
    """Select deterministic scenario subsets for CI stages."""
    if stage == "parser":
        base = list(SCENARIOS[:60])
    elif stage == "core":
        base = [s for s in SCENARIOS if s.family in {"uri","header","custom_header","body","response","syntax","timing"}]
    elif stage == "web":
        base = [s for s in SCENARIOS if s.family in {"websocket","http2","sse","longpoll","grpc"}]
    elif stage == "challenge":
        base = [s for s in SCENARIOS if s.family in {"browser","tunnel","tls","lots","mqtt_ws","doh"}]
    elif stage == "all":
        base = list(SCENARIOS)
    else:
        raise ValueError(f"unknown stage: {stage}")
    return [s for i, s in enumerate(base) if i % shards == shard]


def iter_pairs(items: Iterable[Scenario]):
    for scenario in items:
        yield scenario, True
        yield scenario, False
