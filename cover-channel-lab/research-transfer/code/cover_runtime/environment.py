"""Container-only path variation, chosen before observing class or model results.

The activity (what the application sends and when) is never touched here. This
module only sets the *environment* the isolated client sits in: link delay, the
client interface MTU and whether the client stack negotiates TCP timestamps.
`office_path_v1` takes those parameters from measurements of the retained
office captures, not from any detector or origin-classifier result.
"""
import hashlib
import json
import math
from pathlib import Path
import subprocess

# Measured on retained office captures (read-only, aggregates only):
#  * client SYNs from private sources to public destinations (outbound
#    Internet): MSS 1250 in 100% of 10 273 SYNs on 2026-09-22 and 100% of
#    3 321 SYNs on 2026-09-23. 1250+20+20+14 = 1304 is the dominant office frame
#    size. Internal-to-internal SYNs are a mixture (1460 present) and are not
#    modelled here: the generated activities reach Internet-style servers.
#  * TCP timestamps in those SYNs: 62.7% (09-22) and 85.6% (09-23), pooled 68.3%.
#  * handshake RTT: 132 207 office sessions with a measured RTT (09-22 and
#    09-28), 20 mid-quantile points of the pooled distribution.
# The office TCP option *order* (Windows, Apple, Android layouts) and window
# scale are not reproduced: a Linux client cannot emit them. Recorded as a
# known unmatched dimension, see office_path_report in the audit output.
OFFICE_PATH_V1 = {
    'id': 'office_path_v1',
    'client_mtu': 1290,
    'timestamps_share': 0.683,
    'rtt_grid_ms': [1.1, 2.1, 3.1, 4.0, 4.9, 5.2, 5.3, 5.5, 5.6, 5.8,
                    8.4, 18.8, 26.2, 36.8, 42.0, 45.3, 52.6, 98.8, 144.6, 243.4],
    'evidence': {
        'syn_mss_1250_share_internet_outbound': {'2026-09-22': [10273, 1.0], '2026-09-23': [3321, 1.0]},
        'syn_timestamps_share_internet_outbound': {'2026-09-22': 0.627, '2026-09-23': 0.856},
        'rtt_source_rows': 132207,
        'rtt_source_table_sha256': '21cced84d78b32535362e3fcba68cfae23b52bb8c6d640c9398f3b767aa2ab97',
    },
}
# The earlier predeclared lab range. Kept so old runs stay reproducible.
LAB_FIXED_V1 = {'id': 'lab_fixed_v1', 'rtt_grid_ms': [8., 20., 36., 70., 120.]}
PATH_PROFILES = {p['id']: p for p in (OFFICE_PATH_V1, LAB_FIXED_V1)}
CLIENT_LINKS = (('v-dev', None), ('eth0', 'cc-dev'))


def commands(rtt_ms):
    if not math.isfinite(rtt_ms) or not 0 <= rtt_ms <= 500:
        raise ValueError('bounded RTT in [0,500] ms required')
    delay=str(float(rtt_ms)/2)+'ms'
    result=[]
    for ns,device in (('cc-c2','v-c2'),('cc-dns','v-dns')):
        result.append(['tc','qdisc','replace','dev',device,'root','netem','delay',delay])
        result.append(['ip','netns','exec',ns,'tc','qdisc','replace','dev','eth0','root','netem','delay',delay])
    return result


def client_commands(mtu,timestamps):
    """MTU on both ends of the isolated client veth plus the client TCP timestamp sysctl."""
    if not isinstance(mtu,int) or not 576 <= mtu <= 1500:
        raise ValueError('client MTU must be an integer in [576,1500]')
    result=[]
    for device,ns in CLIENT_LINKS:
        prefix=['ip','netns','exec',ns] if ns else []
        result.append(prefix+['ip','link','set','dev',device,'mtu',str(mtu)])
    result.append(['ip','netns','exec','cc-dev','sysctl','-w','net.ipv4.tcp_timestamps='+('1' if timestamps else '0')])
    return result


def _pick(entry_id,profile_id,seed,salt,n):
    """Deterministic and independent of the arm: a pair shares one environment."""
    return int(hashlib.sha256(f'{seed}:{entry_id}:{profile_id}:{salt}'.encode()).hexdigest(),16)%n


def office_path(entry_id,profile_id,seed,profile=OFFICE_PATH_V1):
    grid=profile['rtt_grid_ms']
    rtt=grid[_pick(entry_id,profile_id,seed,'rtt',len(grid))]
    timestamps=_pick(entry_id,profile_id,seed,'ts',1000)<round(profile['timestamps_share']*1000)
    return {'path_profile':profile['id'],'path_rtt_ms':rtt,'client_mtu':profile['client_mtu'],'client_tcp_timestamps':timestamps}


def profile_config(entry_id,profile_id,seed,family=None,path_profile='office_path_v1'):
    if path_profile not in PATH_PROFILES:raise ValueError('unknown path profile: '+str(path_profile))
    burst=entry_id in ('M-DEAD-DROP','M-FALLBACK','M-GRPC-BIDI','M-PUBSUB-MQTT') or entry_id=='M-H3-QUIC' and profile_id=='h3-aioquic-parallel'
    interval=None if burst or not entry_id.startswith('M-') else 50 if entry_id=='M-WSS-LONG' else 5 if entry_id in ('M-HTTPS-BEACON','M-RMM-SHAPE','M-TIMING-XCARRIER') else 1
    if path_profile=='lab_fixed_v1':
        # Fixed predeclared range, not an office template and no claim that
        # netem closes the known laboratory/office domain gap.
        grid=LAB_FIXED_V1['rtt_grid_ms']
        path={'path_profile':'lab_fixed_v1','path_rtt_ms':grid[int(hashlib.sha256(f'{seed}:{entry_id}:{profile_id}'.encode()).hexdigest(),16)%5]}
    else:
        path=office_path(entry_id,profile_id,seed)
    return {**path,'runtime_events':6,'native_interval':interval}


def _link(prefix,device):
    return json.loads(subprocess.check_output(prefix+['ip','-j','link','show','dev',device],text=True))[0]


def apply_client(mtu,timestamps):
    """Apply and read back. Always explicit, so one job never inherits the previous job's state."""
    issued=client_commands(mtu,timestamps);actual=[]
    for c in issued[:-1]:subprocess.run(c,check=True,stdout=subprocess.DEVNULL)
    # Docker mounts /proc/sys read-only and `sysctl -w` then prints "ignoring"
    # yet exits 0 (measured on 2026-10-05), so the write needs a short remount
    # and the read-back below is the real check. Only this fixed namespaced
    # key is written, inside cc-dev; the remount is undone even on failure.
    subprocess.run(['mount','-o','remount,rw','/proc/sys'],check=True,stdout=subprocess.DEVNULL)
    try:subprocess.run(issued[-1],check=True,stdout=subprocess.DEVNULL)
    finally:subprocess.run(['mount','-o','remount,ro','/proc/sys'],check=True,stdout=subprocess.DEVNULL)
    for device,ns in CLIENT_LINKS:
        link=_link(['ip','netns','exec',ns] if ns else [],device)
        if link['mtu']!=mtu:raise RuntimeError(f'client MTU readback mismatch on {device}: {link["mtu"]}')
        actual.append({'device':device,'namespace':ns,'mtu':link['mtu']})
    value=subprocess.check_output(['ip','netns','exec','cc-dev','sysctl','-n','net.ipv4.tcp_timestamps'],text=True).strip()
    if value!=('1' if timestamps else '0'):raise RuntimeError('tcp_timestamps readback mismatch: '+value)
    return {'commands':issued,'links':actual,'tcp_timestamps':value=='1'}


def apply(rtt_ms,out,client_mtu=None,client_tcp_timestamps=None,path_profile=None):
    issued=commands(float(rtt_ms))
    for c in issued:subprocess.run(c,check=True,stdout=subprocess.DEVNULL)
    checks=[]
    for ns,device in (('cc-c2','v-c2'),('cc-dns','v-dns')):
        for prefix,link in (([],device),(['ip','netns','exec',ns],'eth0')):
            actual=json.loads(subprocess.check_output(prefix+['tc','-j','qdisc','show','dev',link],text=True))
            if not any(q['kind']=='netem' for q in actual):raise RuntimeError('netem readback failed')
            checks.append({'namespace':ns if prefix else None,'link':link,'qdisc':actual})
    # Jobs without a declared client environment get the plain default back.
    client=apply_client(1500 if client_mtu is None else client_mtu,True if client_tcp_timestamps is None else client_tcp_timestamps)
    ping=subprocess.run(['ip','netns','exec','cc-dev','ping','-n','-c','2','-i','.05','-W','2','10.20.0.20'],text=True,stdout=subprocess.PIPE,stderr=subprocess.STDOUT)
    if ping.returncode:raise RuntimeError('isolated path ping failed: '+ping.stdout)
    report={'requested_rtt_ms':rtt_ms,'path_profile':path_profile,'commands':issued,'readback':checks,'client':client,'ping':ping.stdout,
            'selection':'predeclared; same for both arms',
            'office_equivalence_claim':False,'unmatched_dimensions':['tcp_option_order','window_scale','client_tls_stack']}
    (Path(out)/'path_environment.json').write_text(json.dumps(report,indent=2)+'\n')
    return report

WIRE_CORE_IP = '100.64.0.20'
WIRE_WSS_IP = '100.64.0.21'
WIRE_OUT_CHAIN = 'COVERLAB_WIRE_OUT'
WIRE_IN_CHAIN = 'COVERLAB_WIRE_IN'


def office_wire_translation_plan():
    """Pre-capture isolated NAT: preserve app endpoints but expose office-like wire tuples.

    The application still connects to the lab fixture addresses.  DNAT happens
    inside the client namespace before the packet reaches v-dev, so the capture
    sees an internal client talking to an external-like RFC6598 address on 443.
    The server namespace reverses that mapping back to the local fixture.  No
    default route or Internet path is created and captured bytes are never
    rewritten after the fact.
    """
    commands = [
        ['ip','netns','exec','cc-c2','ip','addr','replace',WIRE_CORE_IP+'/32','dev','eth0'],
        ['ip','netns','exec','cc-c2','ip','addr','replace',WIRE_WSS_IP+'/32','dev','eth0'],
        ['ip','netns','exec','cc-dev','ip','route','replace',WIRE_CORE_IP+'/32','dev','eth0'],
        ['ip','netns','exec','cc-dev','ip','route','replace',WIRE_WSS_IP+'/32','dev','eth0'],
        ['ip','netns','exec','cc-dev','iptables','-t','nat','-A',WIRE_OUT_CHAIN,
         '-p','tcp','-d','10.20.0.20','--dport','8443','-j','DNAT','--to-destination',WIRE_CORE_IP+':443'],
        ['ip','netns','exec','cc-dev','iptables','-t','nat','-A',WIRE_OUT_CHAIN,
         '-p','tcp','-d','10.20.0.21','--dport','8443','-j','DNAT','--to-destination',WIRE_WSS_IP+':443'],
        ['ip','netns','exec','cc-c2','iptables','-t','nat','-A',WIRE_IN_CHAIN,
         '-p','tcp','-d',WIRE_CORE_IP,'--dport','443','-j','DNAT','--to-destination','10.20.0.20:8443'],
        ['ip','netns','exec','cc-c2','iptables','-t','nat','-A',WIRE_IN_CHAIN,
         '-p','tcp','-d',WIRE_WSS_IP,'--dport','443','-j','DNAT','--to-destination','10.20.0.21:8443'],
    ]
    return {
        'version': 'office-wire-v1',
        'wire_core_ip': WIRE_CORE_IP,
        'wire_wss_ip': WIRE_WSS_IP,
        'commands': commands,
        'default_route_added': False,
        'post_capture_rewrite': False,
    }


def _ensure_nat_chain(namespace, builtin, chain):
    prefix=['ip','netns','exec',namespace,'iptables','-t','nat']
    subprocess.run(prefix+['-N',chain],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
    subprocess.run(prefix+['-F',chain],check=True,stdout=subprocess.DEVNULL)
    check=subprocess.run(prefix+['-C',builtin,'-j',chain],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
    if check.returncode:
        subprocess.run(prefix+['-A',builtin,'-j',chain],check=True,stdout=subprocess.DEVNULL)


def apply_office_wire_translation(out='/out'):
    plan=office_wire_translation_plan()
    _ensure_nat_chain('cc-dev','OUTPUT',WIRE_OUT_CHAIN)
    _ensure_nat_chain('cc-c2','PREROUTING',WIRE_IN_CHAIN)
    for command in plan['commands']:
        subprocess.run(command,check=True,stdout=subprocess.DEVNULL)
    dev_rules=subprocess.check_output(
        ['ip','netns','exec','cc-dev','iptables','-t','nat','-S',WIRE_OUT_CHAIN],text=True)
    c2_rules=subprocess.check_output(
        ['ip','netns','exec','cc-c2','iptables','-t','nat','-S',WIRE_IN_CHAIN],text=True)
    routes=subprocess.check_output(['ip','netns','exec','cc-dev','ip','route'],text=True)
    if 'default' in routes:
        raise RuntimeError('office wire translation must not add a default route')
    for token in (WIRE_CORE_IP, WIRE_WSS_IP):
        if token not in dev_rules or token not in c2_rules or token not in routes:
            raise RuntimeError('office wire translation readback missing '+token)
    report={**plan,'client_nat_rules':dev_rules,'server_nat_rules':c2_rules,'client_routes':routes}
    target=Path(out)/'wire_translation.json'
    target.parent.mkdir(parents=True,exist_ok=True)
    target.write_text(json.dumps(report,indent=2)+'\n')
    return report
