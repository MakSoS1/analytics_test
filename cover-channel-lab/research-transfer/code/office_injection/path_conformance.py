"""Check that an isolated capture really carries the declared office path.

Generator-independent: it reads only the capture. A new scenario must pass this
before its capture is imported, so a changed generator cannot silently bring
back a laboratory-only path (MSS 1460, frames up to 1514 bytes).

What it can prove: the client SYN options and the largest frame on the wire.
What it cannot: that the TCP option order, window scale or TLS stack look like
an office client. Those stay listed as unmatched dimensions.
"""
import argparse
import json
from pathlib import Path
import struct
from .source import read_pcap, sha256

# Mirrors cover_runtime/environment.py OFFICE_PATH_V1 (a test keeps them equal).
OFFICE_PATH_V1_MTU = 1290
ETHERNET_HEADER = 14
UNMATCHED_DIMENSIONS = ['tcp_option_order', 'window_scale', 'client_tls_stack']


def _ipv4_tcp(frame):
    """(src, dst, ip_header, tcp_header_offset) for an unfragmented IPv4 TCP frame, else None."""
    if len(frame) < 34 or struct.unpack_from('!H', frame, 12)[0] != 0x0800:
        return None
    ihl = (frame[14] & 15) * 4
    if ihl < 20 or frame[23] != 6 or len(frame) < 14 + ihl + 20:
        return None
    return '.'.join(map(str, frame[26:30])), '.'.join(map(str, frame[30:34])), ihl, 14 + ihl


def parse_options(options):
    out = {'mss': None, 'timestamps': False, 'window_scale': None, 'sack_permitted': False}
    i = 0
    while i < len(options):
        kind = options[i]
        if kind == 0:
            break
        if kind == 1:
            i += 1
            continue
        if i + 2 > len(options) or options[i + 1] < 2 or i + options[i + 1] > len(options):
            raise ValueError('malformed TCP options')
        length = options[i + 1]
        if kind == 2 and length == 4:
            out['mss'] = struct.unpack_from('!H', options, i + 2)[0]
        elif kind == 3 and length == 3:
            out['window_scale'] = options[i + 2]
        elif kind == 4 and length == 2:
            out['sack_permitted'] = True
        elif kind == 8 and length == 10:
            out['timestamps'] = True
        i += length
    return out


def observe(pcap, client_ip):
    syns, largest, oversize_1514, frames, ties, previous = [], 0, 0, 0, 0, None
    # Same tolerance as the importer: tcpdump --immediate-mode can write
    # frames up to 100 us out of order; larger regressions are still rejected.
    for stamp, frame in read_pcap(pcap, max_regression=.0001):
        frames += 1
        largest = max(largest, len(frame))
        oversize_1514 += len(frame) > 1514
        tick = round(stamp * 1e6)
        ties += previous == tick
        previous = tick
        parsed = _ipv4_tcp(frame)
        if parsed is None:
            continue
        src, dst, ihl, tcp = parsed
        header = (frame[tcp + 12] >> 4) * 4
        if frame[tcp + 13] & 0x12 == 2 and src == client_ip and tcp + header <= len(frame):
            syns.append(parse_options(frame[tcp + 20:tcp + header]))
    return {'frames': frames, 'frame_length_max': largest, 'frames_over_1514': oversize_1514,
            'adjacent_timestamp_ties': ties, 'client_syns': syns}


def check_capture(pcap, client_ip, mtu=OFFICE_PATH_V1_MTU, timestamps=None, waive_syn=False):
    """Findings are failures; an empty list means the declared path is on the wire.

    `waive_syn` is for mechanics that hand-craft their own SYN (raw packets): the
    client stack never builds it, so its options cannot be set by the environment.
    The SYN findings are then reported under `waived`, never dropped, and the frame
    size limits stay enforced.
    """
    seen = observe(pcap, client_ip)
    findings, mss = [], mtu - 40
    if seen['frames_over_1514']:
        findings.append('frames above the Ethernet MTU: transport offload artifact')
    if seen['frame_length_max'] > mtu + ETHERNET_HEADER:
        findings.append(f'frame {seen["frame_length_max"]} B exceeds the declared path MTU {mtu} (+14 Ethernet)')
    syn_findings = []
    for syn in seen['client_syns']:
        if syn['mss'] != mss:
            syn_findings.append(f'client SYN advertises MSS {syn["mss"]}, declared path needs {mss}')
            break
    if timestamps is not None:
        for syn in seen['client_syns']:
            if syn['timestamps'] != timestamps:
                syn_findings.append(f'client SYN timestamps={syn["timestamps"]}, declared {timestamps}')
                break
    waived = syn_findings if waive_syn else []
    findings += [] if waive_syn else syn_findings
    return {'ok': not findings, 'findings': findings, 'waived': waived, 'declared': {'client_mtu': mtu, 'client_tcp_timestamps': timestamps},
            'observed': {**seen, 'client_syns': len(seen['client_syns']),
                         'client_syn_mss_values': sorted({s['mss'] for s in seen['client_syns'] if s['mss'] is not None}),
                         'client_syn_timestamps': sorted({s['timestamps'] for s in seen['client_syns']})},
            'tcp_flows_observed': bool(seen['client_syns']), 'unmatched_dimensions': UNMATCHED_DIMENSIONS,
            'capture_sha256': sha256(pcap)}


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--pcap', type=Path, required=True)
    p.add_argument('--client-ip', required=True)
    p.add_argument('--client-mtu', type=int, default=OFFICE_PATH_V1_MTU)
    p.add_argument('--timestamps', choices=('on', 'off'))
    a = p.parse_args()
    result = check_capture(a.pcap, a.client_ip, a.client_mtu, None if a.timestamps is None else a.timestamps == 'on')
    print(json.dumps(result, indent=2))
    raise SystemExit(0 if result['ok'] else 1)


if __name__ == '__main__':
    main()
