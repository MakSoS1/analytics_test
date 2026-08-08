import json
from pathlib import Path

from fastapi.testclient import TestClient

from coverlab.scenarios import BY_ID, SCENARIOS, select
import coverlab.server as server


def test_scenario_ids_unique_and_parser_stage_has_60():
    assert len(BY_ID) == len(SCENARIOS)
    assert len(select("parser")) == 60
    required={"CC_HDR_09","CC_WS_01","CC_TUN_03","CC_LOTS_04","CC_MQTT_01","CC_DOH_01","CC_BROWSER_09"}
    assert required.issubset(BY_ID)


def test_tunnel_allowlist_is_not_general_proxy(tmp_path: Path):
    server.STATE=tmp_path/"state.json"
    server.TRACE=tmp_path/"trace.jsonl"
    server.STATE.write_text(json.dumps({"default":{"scenario_id":"CC_TUN_02","suspicious":True,"seed":23}}))
    client=TestClient(server.app)
    with client.websocket_connect("/ws") as ws:
        ws.send_text(json.dumps({"type":"socks_connect","conn_id":"1","target_host":"synthetic-api.test","target_port":8081}))
        assert json.loads(ws.receive_text())["allowed"] is True
        ws.send_text(json.dumps({"type":"socks_connect","conn_id":"2","target_host":"example.com","target_port":443}))
        assert json.loads(ws.receive_text())["allowed"] is False


def test_response_fixture_and_doh_stay_local(tmp_path: Path):
    server.STATE=tmp_path/"state.json"; server.TRACE=tmp_path/"trace.jsonl"
    server.STATE.write_text(json.dumps({"default":{"scenario_id":"CC_RESP_03","suspicious":True,"seed":23}}))
    client=TestClient(server.app)
    r=client.get("/assets/status.xml")
    assert r.status_code==200 and "<manifest>" in r.text
    q=b"\x00\x17\x01\x00"
    r=client.post("/dns-query",content=q,headers={"Content-Type":"application/dns-message"})
    assert r.content==q


def test_packet_features_are_campaign_scoped(tmp_path: Path):
    import pandas as pd
    import pytest
    scapy=pytest.importorskip("scapy.all")
    Ether,IP,TCP,wrpcap=scapy.Ether,scapy.IP,scapy.TCP,scapy.wrpcap
    from coverlab.pipeline import campaign_packet_features

    pcap=tmp_path/"two-campaigns.pcap"
    packets=[]
    for t,src in [(1000.1,"10.20.0.10"),(1000.2,"10.20.0.20"),(1001.1,"10.20.0.11"),(1001.2,"10.20.0.20")]:
        dst="10.20.0.20" if src!="10.20.0.20" else ("10.20.0.10" if t<1001 else "10.20.0.11")
        pkt=Ether()/IP(src=src,dst=dst)/TCP(sport=40000,dport=8080)
        pkt.time=t; packets.append(pkt)
    wrpcap(str(pcap),packets)
    df=pd.DataFrame([
        {"campaign_id":"c1","source_ip":"10.20.0.10","started_at":"1970-01-01T00:16:40.000Z","ended_at":"1970-01-01T00:16:40.500Z"},
        {"campaign_id":"c2","source_ip":"10.20.0.11","started_at":"1970-01-01T00:16:41.000Z","ended_at":"1970-01-01T00:16:41.500Z"},
    ])
    out=campaign_packet_features(pcap,df).set_index("campaign_id")
    assert out.loc["c1","packet_count"]==2
    assert out.loc["c2","packet_count"]==2
    assert out.loc["c1","up_packets"]==1 and out.loc["c1","down_packets"]==1
