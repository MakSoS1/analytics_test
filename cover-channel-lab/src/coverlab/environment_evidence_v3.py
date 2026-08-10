from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path

from .research_contract_v3 import CLIENT_STACKS, NETWORK_EVIDENCE_TYPES, SERVER_STACKS


def sha256(path: Path) -> str:
    h=hashlib.sha256()
    with path.open('rb') as f:
        for chunk in iter(lambda:f.read(1024*1024),b''): h.update(chunk)
    return h.hexdigest()


def validate(root: Path) -> dict:
    manifest=root/'environment_evidence.jsonl'
    if not manifest.exists():
        return {'validated':False,'records':0,'client_stacks':[],'server_stacks':[],'network_evidence':[],
                'reason':'environment_evidence.jsonl missing'}
    rows=[json.loads(x) for x in manifest.read_text().splitlines() if x.strip()]
    errors=[]; clients=set(); servers=set(); networks=set()
    for i,r in enumerate(rows):
        client=str(r.get('client_stack','')); server=str(r.get('server_stack','')); net=str(r.get('network_evidence',''))
        if client and client not in CLIENT_STACKS: errors.append(f'row {i}: unknown client_stack={client}')
        if server and server not in SERVER_STACKS: errors.append(f'row {i}: unknown server_stack={server}')
        if net and net not in NETWORK_EVIDENCE_TYPES: errors.append(f'row {i}: unknown network_evidence={net}')
        if r.get('wire_real') is not True: errors.append(f'row {i}: evidence is not wire-real')
        if r.get('isolated_lab') is not True: errors.append(f'row {i}: evidence is not isolated-lab')
        rel=str(r.get('pcap_file','')); p=root/rel
        if not rel or not p.is_file(): errors.append(f'row {i}: pcap missing')
        elif sha256(p)!=r.get('pcap_sha256'): errors.append(f'row {i}: pcap sha mismatch')
        if client: clients.add(client)
        if server: servers.add(server)
        if net: networks.add(net)
    required_clients={'windows_winhttp_schannel','dotnet_httpclient_schannel','edge_schannel','java_httpclient','rust_reqwest','chromium','firefox'}
    required_servers={'nginx','envoy','caddy','apache','haproxy','iis'}
    required_networks={'nat','forward_proxy','tls_inspection','tls_bypass','partial_capture','capture_loss','connection_migration'}
    return {
        'validated':bool(rows) and not errors,'records':len(rows),'errors':errors,
        'client_stacks':sorted(clients),'server_stacks':sorted(servers),'network_evidence':sorted(networks),
        'client_diversity_ready':required_clients.issubset(clients),
        'server_diversity_ready':required_servers.issubset(servers),
        'network_diversity_ready':required_networks.issubset(networks),
        'missing_clients':sorted(required_clients-clients),'missing_servers':sorted(required_servers-servers),
        'missing_network_evidence':sorted(required_networks-networks),
        'training_eligible':False,'dataset_role':'environment_external_holdout',
    }


def main():
    ap=argparse.ArgumentParser(); ap.add_argument('--root',required=True); ap.add_argument('--out',required=True); a=ap.parse_args()
    report=validate(Path(a.root)); p=Path(a.out); p.parent.mkdir(parents=True,exist_ok=True); p.write_text(json.dumps(report,indent=2,sort_keys=True)+'\n'); print(json.dumps(report,sort_keys=True))

if __name__=='__main__': main()
