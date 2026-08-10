from __future__ import annotations

import argparse
import hashlib
import json
from collections import Counter,defaultdict
from pathlib import Path

from .research_contract_v3 import CLIENT_STACKS, NETWORK_EVIDENCE_TYPES, SERVER_STACKS


def sha256(path:Path)->str:
    h=hashlib.sha256()
    with path.open('rb') as f:
        for chunk in iter(lambda:f.read(1024*1024),b''):h.update(chunk)
    return h.hexdigest()


CLIENT_MIN_SESSIONS={'windows_winhttp_schannel':500,'dotnet_httpclient_schannel':500,'edge_schannel':200,'firefox':200,'java_httpclient':200,'rust_reqwest':200,'chromium':200}
SERVER_MIN_SESSIONS={x:100 for x in {'nginx','envoy','caddy','apache','haproxy','iis'}}
SERVER_MIN_CAPTURES={x:3 for x in SERVER_MIN_SESSIONS}
NETWORK_MIN_SESSIONS={x:200 for x in {'nat','forward_proxy','tls_inspection','tls_bypass','partial_capture','capture_loss','connection_migration'}}
NETWORK_MIN_CAPTURES={x:3 for x in NETWORK_MIN_SESSIONS}


def validate(root:Path)->dict:
    manifest=root/'environment_evidence.jsonl'
    if not manifest.exists():return {'validated':False,'records':0,'client_stacks':[],'server_stacks':[],'network_evidence':[],'reason':'environment_evidence.jsonl missing'}
    rows=[json.loads(x) for x in manifest.read_text().splitlines() if x.strip()];errors=[];clients=set();servers=set();networks=set();client_sessions=Counter();server_sessions=Counter();network_sessions=Counter();server_pcaps=defaultdict(set);network_pcaps=defaultdict(set)
    for i,r in enumerate(rows):
        client=str(r.get('client_stack',''));server=str(r.get('server_stack',''));net=str(r.get('network_evidence',''));sessions=int(r.get('session_count',0) or 0)
        if sessions<=0:errors.append(f'row {i}: positive session_count required')
        if client and client not in CLIENT_STACKS:errors.append(f'row {i}: unknown client_stack={client}')
        if server and server not in SERVER_STACKS:errors.append(f'row {i}: unknown server_stack={server}')
        if net and net not in NETWORK_EVIDENCE_TYPES:errors.append(f'row {i}: unknown network_evidence={net}')
        if r.get('wire_real') is not True:errors.append(f'row {i}: evidence is not wire-real')
        if r.get('isolated_lab') is not True:errors.append(f'row {i}: evidence is not isolated-lab')
        rel=str(r.get('pcap_file',''));p=root/rel
        if not rel or not p.is_file():errors.append(f'row {i}: pcap missing')
        elif sha256(p)!=r.get('pcap_sha256'):errors.append(f'row {i}: pcap sha mismatch')
        if client:clients.add(client);client_sessions[client]+=sessions
        if server:servers.add(server);server_sessions[server]+=sessions;server_pcaps[server].add(rel)
        if net:networks.add(net);network_sessions[net]+=sessions;network_pcaps[net].add(rel)
    client_ready=all(client_sessions[k]>=v for k,v in CLIENT_MIN_SESSIONS.items())
    server_ready=all(server_sessions[k]>=SERVER_MIN_SESSIONS[k] and len(server_pcaps[k])>=SERVER_MIN_CAPTURES[k] for k in SERVER_MIN_SESSIONS)
    network_ready=all(network_sessions[k]>=NETWORK_MIN_SESSIONS[k] and len(network_pcaps[k])>=NETWORK_MIN_CAPTURES[k] for k in NETWORK_MIN_SESSIONS)
    return {'validated':bool(rows) and not errors,'records':len(rows),'errors':errors,'client_stacks':sorted(clients),'server_stacks':sorted(servers),'network_evidence':sorted(networks),'client_session_counts':dict(client_sessions),'server_session_counts':dict(server_sessions),'network_session_counts':dict(network_sessions),'server_capture_counts':{k:len(v) for k,v in server_pcaps.items()},'network_capture_counts':{k:len(v) for k,v in network_pcaps.items()},'client_min_sessions':CLIENT_MIN_SESSIONS,'server_min_sessions':SERVER_MIN_SESSIONS,'server_min_captures':SERVER_MIN_CAPTURES,'network_min_sessions':NETWORK_MIN_SESSIONS,'network_min_captures':NETWORK_MIN_CAPTURES,'client_diversity_ready':client_ready,'server_diversity_ready':server_ready,'network_diversity_ready':network_ready,'missing_or_underfilled_clients':sorted(k for k,v in CLIENT_MIN_SESSIONS.items() if client_sessions[k]<v),'missing_or_underfilled_servers':sorted(k for k,v in SERVER_MIN_SESSIONS.items() if server_sessions[k]<v or len(server_pcaps[k])<SERVER_MIN_CAPTURES[k]),'missing_or_underfilled_network_evidence':sorted(k for k,v in NETWORK_MIN_SESSIONS.items() if network_sessions[k]<v or len(network_pcaps[k])<NETWORK_MIN_CAPTURES[k]),'training_eligible':False,'dataset_role':'environment_external_holdout'}


def main():
    ap=argparse.ArgumentParser();ap.add_argument('--root',required=True);ap.add_argument('--out',required=True);a=ap.parse_args();report=validate(Path(a.root));p=Path(a.out);p.parent.mkdir(parents=True,exist_ok=True);p.write_text(json.dumps(report,indent=2,sort_keys=True)+'\n');print(json.dumps(report,sort_keys=True))

if __name__=='__main__':main()
