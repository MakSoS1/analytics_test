"""Contract every generator must satisfy before its captures can enter the injection pipeline.

New scenarios do not need their own naturalness code: they declare
`path_profile` and these checks decide whether the capture really carries the
measured office path. Nothing here uses a detector, an origin classifier or a
held-out score.
"""
import importlib.util
import inspect
import json
import struct
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from demo.prepare_research_registry import prepare
from office_injection import path_conformance
from office_injection.activity import prepare_activity
from office_injection.path_conformance import check_capture, parse_options
from office_injection.source import sha256, write_pcap

RUNTIME = Path(__file__).resolve().parents[1] / 'cover_runtime'
spec = importlib.util.spec_from_file_location('environment', RUNTIME / 'environment.py')
environment = importlib.util.module_from_spec(spec)
spec.loader.exec_module(environment)
CLIENT, SERVER = '10.20.0.11', '10.20.0.20'


def tcp_frame(src, dst, flags, payload=0, options=b'', sport=40000, dport=443):
    options += b'\x00' * (-len(options) % 4)
    header = 20 + len(options)
    tcp = struct.pack('!HHIIBBHHH', sport, dport, 1, 1, header // 4 << 4, flags, 65535, 0, 0) + options
    ip_len = 20 + header + payload
    ip = struct.pack('!BBHHHBBH4s4s', 0x45, 0, ip_len, 1, 0, 64, 6, 0,
                     bytes(map(int, src.split('.'))), bytes(map(int, dst.split('.'))))
    return b'\x02' * 6 + b'\x04' * 6 + b'\x08\x00' + ip + tcp + b'x' * payload


def syn_options(mss, timestamps=True):
    options = struct.pack('!BBH', 2, 4, mss) + b'\x04\x02'
    if timestamps:
        options += b'\x08\x0a' + bytes(8)
    return options + b'\x01\x03\x03\x07'


def flow(mss=1250, timestamps=True, data=1238, extra=()):
    """SYN, SYN-ACK, one full-size server segment: the shape of a short TLS fetch."""
    syn = tcp_frame(CLIENT, SERVER, 0x02, options=syn_options(mss, timestamps))
    synack = tcp_frame(SERVER, CLIENT, 0x12, options=syn_options(1460, timestamps), sport=443, dport=40000)
    body = tcp_frame(SERVER, CLIENT, 0x18, payload=data, sport=443, dport=40000,
                     options=b'\x01\x01\x08\x0a' + bytes(8) if timestamps else b'')
    return [(10 + i * .001, f) for i, f in enumerate([syn, synack, body, *extra])]


def pcap(root, frames, name='c.pcap'):
    path = Path(root) / name
    write_pcap(path, frames)
    return path


class EnvironmentContractTests(unittest.TestCase):
    def test_environment_cannot_depend_on_the_arm(self):
        params = inspect.signature(environment.profile_config).parameters
        self.assertNotIn('arm', params)
        self.assertEqual(environment.profile_config('X', 'p', 7), environment.profile_config('X', 'p', 7))

    def test_office_path_values_come_from_the_measured_profile(self):
        grid = environment.OFFICE_PATH_V1['rtt_grid_ms']
        rows = [environment.profile_config(f'E{i}', 'p', 1) for i in range(3000)]
        self.assertEqual({r['client_mtu'] for r in rows}, {1290})
        self.assertEqual({r['path_profile'] for r in rows}, {'office_path_v1'})
        self.assertTrue(all(r['path_rtt_ms'] in grid for r in rows))
        share = sum(r['client_tcp_timestamps'] for r in rows) / len(rows)
        self.assertAlmostEqual(share, environment.OFFICE_PATH_V1['timestamps_share'], delta=.04)

    def test_mirrored_conformance_constant_matches_runtime_profile(self):
        self.assertEqual(path_conformance.OFFICE_PATH_V1_MTU, environment.OFFICE_PATH_V1['client_mtu'])

    def test_office_path_rtt_grid_is_ordered_and_bounded(self):
        grid = environment.OFFICE_PATH_V1['rtt_grid_ms']
        self.assertEqual(grid, sorted(grid))
        self.assertTrue(0 < grid[0] and grid[-1] <= 500)

    def test_legacy_lab_profile_is_still_reproducible(self):
        row = environment.profile_config('X', 'p', 7, path_profile='lab_fixed_v1')
        self.assertIn(row['path_rtt_ms'], (8., 20., 36., 70., 120.))
        self.assertNotIn('client_mtu', row)
        with self.assertRaises(ValueError):
            environment.profile_config('X', 'p', 7, path_profile='nope')

    def test_client_commands_touch_only_the_isolated_client_link(self):
        commands = environment.client_commands(1290, False)
        flat = [' '.join(c) for c in commands]
        self.assertTrue(any('v-dev' in c and 'mtu 1290' in c for c in flat))
        self.assertTrue(any('cc-dev' in c and 'eth0' in c and 'mtu 1290' in c for c in flat))
        self.assertIn('net.ipv4.tcp_timestamps=0', flat[-1])
        for c in flat:
            self.assertNotIn('enp0s', c)
        for bad in (575, 1501, '1290', None, 1290.0):
            with self.assertRaises(ValueError):
                environment.client_commands(bad, True)

    def test_apply_client_resets_state_and_verifies_readback(self):
        calls = []
        links = iter([{'mtu': 1290}, {'mtu': 1290}])

        def fake_output(command, **kw):
            calls.append(command)
            return json.dumps([next(links)]) if 'link' in command and 'show' in command else '0\n'
        with mock.patch.object(subprocess, 'run'), mock.patch.object(subprocess, 'check_output', fake_output):
            result = environment.apply_client(1290, False)
        self.assertEqual(result['tcp_timestamps'], False)
        self.assertEqual([l['mtu'] for l in result['links']], [1290, 1290])
        links = iter([{'mtu': 1500}, {'mtu': 1290}])
        with mock.patch.object(subprocess, 'run'), mock.patch.object(subprocess, 'check_output', fake_output):
            with self.assertRaises(RuntimeError):
                environment.apply_client(1290, True)

    def test_proc_sys_is_remounted_read_only_even_when_the_write_fails(self):
        order = []

        def fake_run(command, **kw):
            order.append(' '.join(command))
            if 'sysctl' in command:
                raise subprocess.CalledProcessError(1, command)
        with mock.patch.object(subprocess, 'run', fake_run):
            with self.assertRaises(subprocess.CalledProcessError):
                environment.apply_client(1290, False)
        self.assertTrue(any('remount,rw /proc/sys' in c for c in order))
        self.assertEqual(order[-1], 'mount -o remount,ro /proc/sys')

    def test_silent_sysctl_ignore_is_caught_by_readback(self):
        # sysctl exits 0 but the key stays 1 (read-only /proc/sys): must not pass.
        def fake_output(command, **kw):
            return json.dumps([{'mtu': 1290}]) if 'show' in command else '1\n'
        with mock.patch.object(subprocess, 'run'), mock.patch.object(subprocess, 'check_output', fake_output):
            with self.assertRaises(RuntimeError):
                environment.apply_client(1290, False)

    def test_jobs_without_a_declared_client_environment_get_the_default_back(self):
        seen = {}
        with mock.patch.object(environment, 'apply_client', lambda mtu, ts: seen.update(mtu=mtu, ts=ts) or {}), \
             mock.patch.object(environment, 'commands', lambda r: []), \
             mock.patch.object(subprocess, 'run', lambda *a, **k: mock.Mock(returncode=0, stdout='')), \
             mock.patch.object(subprocess, 'check_output', lambda *a, **k: '[{"kind":"netem"}]'), \
             tempfile.TemporaryDirectory() as out:
            environment.apply(8.0, out)
        self.assertEqual(seen, {'mtu': 1500, 'ts': True})


class RegistryContractTests(unittest.TestCase):
    def test_every_profile_of_every_registry_gets_the_same_path_for_both_arms(self):
        for name in ('registry.json', 'supplemental_registry.json', 'native_registry.json'):
            base = json.loads((RUNTIME / name).read_text())
            first, second = prepare(base), prepare(base)
            self.assertEqual(first['sha256'], second['sha256'], name)
            self.assertEqual(first['path_profile'], 'office_path_v1')
            for entry in first['entries']:
                for profile in entry['profiles']:
                    self.assertEqual(profile['client_mtu'], 1290, name)
                    self.assertIn(profile['path_rtt_ms'], environment.OFFICE_PATH_V1['rtt_grid_ms'])
                    self.assertIsInstance(profile['client_tcp_timestamps'], bool)

    def test_path_profile_changes_registry_identity(self):
        base = json.loads((RUNTIME / 'native_registry.json').read_text())
        self.assertNotEqual(prepare(base)['sha256'], prepare(base, path_profile='lab_fixed_v1')['sha256'])


class PathConformanceTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)

    def check(self, frames, **kw):
        return check_capture(pcap(self.root, frames), CLIENT, **kw)

    def test_office_path_on_the_wire_passes(self):
        result = self.check(flow(), timestamps=True)
        self.assertTrue(result['ok'], result['findings'])
        self.assertEqual(result['observed']['client_syn_mss_values'], [1250])
        self.assertEqual(result['observed']['frame_length_max'], 14 + 20 + 32 + 1238)

    def test_laboratory_mss_is_rejected(self):
        result = self.check(flow(mss=1460, data=1448))
        self.assertFalse(result['ok'])
        self.assertTrue(any('MSS 1460' in f for f in result['findings']))
        self.assertTrue(any('exceeds the declared path MTU' in f for f in result['findings']))

    def test_correct_syn_but_oversized_frames_are_rejected(self):
        result = self.check(flow(mss=1250, data=1448))
        self.assertFalse(result['ok'])

    def test_offload_artifact_above_ethernet_mtu_is_flagged(self):
        result = self.check(flow(data=2800))
        self.assertTrue(any('transport offload' in f for f in result['findings']))

    def test_declared_timestamp_state_must_match_the_syn(self):
        self.assertTrue(self.check(flow(timestamps=False, data=1250), timestamps=False)['ok'])
        self.assertFalse(self.check(flow(timestamps=True), timestamps=False)['ok'])

    def test_udp_only_capture_has_no_syn_to_judge_and_passes_size_check(self):
        udp = bytes(12) + b'\x08\x00' + struct.pack('!BBHHHBBH4s4s', 0x45, 0, 28 + 40, 1, 0, 64, 17, 0,
                                                   bytes([10, 20, 0, 11]), bytes([10, 20, 0, 20])) + bytes(8 + 40)
        result = self.check([(1, udp), (2, udp)])
        self.assertTrue(result['ok'])
        self.assertFalse(result['tcp_flows_observed'])

    def test_capture_writer_jitter_is_tolerated_but_real_regression_is_not(self):
        frames = flow()
        t = [x for x, _ in frames]
        small = [(t[0], frames[0][1]), (t[1], frames[1][1]), (t[2] - .00005 + .00002, frames[2][1]), (t[2] - .00005, frames[2][1])]
        self.assertTrue(self.check(small)['ok'])
        large = [(t[0] + 1, frames[0][1]), (t[1], frames[1][1])]
        with self.assertRaises(ValueError):
            self.check(large)

    def test_raw_mechanic_syn_can_be_waived_but_frame_limits_stay_enforced(self):
        raw = self.check(flow(mss=1460, timestamps=False, data=1250), waive_syn=True)
        self.assertTrue(raw['ok'])
        self.assertTrue(any('MSS 1460' in w for w in raw['waived']))
        too_big = self.check(flow(mss=1460, data=1448), waive_syn=True)
        self.assertFalse(too_big['ok'])
        self.assertTrue(any('exceeds the declared path MTU' in f for f in too_big['findings']))
        self.assertEqual(self.check(flow())['waived'], [])

    def test_option_parser_keeps_absent_mss_absent(self):
        self.assertIsNone(parse_options(b'\x04\x02\x01\x01')['mss'])
        self.assertTrue(parse_options(syn_options(1250))['timestamps'])
        with self.assertRaises(ValueError):
            parse_options(b'\x02\x09')

    def test_command_line_exit_status(self):
        good = pcap(self.root, flow(), 'good.pcap')
        bad = pcap(self.root, flow(mss=1460, data=1448), 'bad.pcap')
        run = lambda p: subprocess.run(['python3', '-m', 'office_injection.path_conformance', '--pcap', str(p), '--client-ip', CLIENT],
                                       cwd=Path(__file__).resolve().parents[1], capture_output=True, text=True)
        self.assertEqual(run(good).returncode, 0)
        self.assertEqual(run(bad).returncode, 1)


class ActivityPathDeclarationTests(unittest.TestCase):
    """A new scenario declares the path; the adapter refuses captures that do not carry it."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        (self.root / 'receipt.json').write_text('{"observed": true}')

    def spec(self, mss, declared='office_path_v1'):
        arms = {}
        for arm in ('scenario', 'control'):
            path = pcap(self.root, flow(mss=mss, data=mss - 12), arm + '.pcap')
            arms[arm] = {'pcap': path.name, 'sha256': sha256(path), 'source_ip': CLIENT, 'description': arm,
                         'evidence': [{'path': 'receipt.json', 'sha256': sha256(self.root / 'receipt.json')}]}
        body = {'activity_id': 'new_tls', 'pair_id': 'p1', 'capture_environment': 'isolated', 'arms': arms}
        if declared:
            body['path_profile'] = declared
        (self.root / 'activity.json').write_text(json.dumps(body))
        return self.root / 'activity.json'

    def test_declared_profile_is_verified_and_recorded(self):
        result = prepare_activity(self.spec(1250), self.root / 'ok')
        self.assertEqual({c['path_conformance']['status'] for c in result['campaigns']}, {'verified'})

    def test_declared_profile_rejects_a_laboratory_path(self):
        with self.assertRaises(ValueError) as caught:
            prepare_activity(self.spec(1460), self.root / 'rejected')
        self.assertIn('path profile', str(caught.exception))
        self.assertFalse((self.root / 'rejected').exists())

    def test_undeclared_profile_is_recorded_as_such_not_as_verified(self):
        result = prepare_activity(self.spec(1460, declared=None), self.root / 'plain')
        self.assertEqual({c['path_conformance']['status'] for c in result['campaigns']}, {'not_declared'})

    def test_malformed_declaration_is_rejected(self):
        with self.assertRaises(ValueError):
            prepare_activity(self.spec(1250, declared='something_else'), self.root / 'bad')


if __name__ == '__main__':
    unittest.main()
