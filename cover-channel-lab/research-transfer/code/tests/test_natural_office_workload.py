"""Black-box checks for authorized, fixture-only office actions."""

import json
import os
from pathlib import Path
import socket
import struct
from tempfile import TemporaryDirectory
import unittest

from natural_traffic.office_workload import (
    _wait_for_capture_ready,
    _wait_for_wire_coverage,
    audit_client_handshakes,
    run_benign_office_workload,
)
from office_injection.source import write_pcap


def _tcp_packet(src_port: int, dst_port: int, flags: int) -> bytes:
    src = socket.inet_aton("127.0.0.1")
    dst = socket.inet_aton("127.0.0.1")
    ip = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 40, 0, 0, 64, 6, 0, src, dst)
    tcp = struct.pack("!HHIIHHHH", src_port, dst_port, 0, 0,
                      (5 << 12) | flags, 65535, 0, 0)
    return b"\0" * 12 + b"\x08\x00" + ip + tcp


class BenignOfficeWorkloadTests(unittest.TestCase):
    def test_capture_fails_on_missing_handshake(self):
        with TemporaryDirectory() as tmp:
            path = Path(tmp) / "missing.pcap"
            write_pcap(path, [(1.0, _tcp_packet(44001, 9090, 0x02))])
            with self.assertRaisesRegex(RuntimeError, "incomplete"):
                _wait_for_wire_coverage(path, server_port=9090,
                                        expected_sessions=1, timeout_seconds=.02)

    def test_capture_waits_for_initialized_pcap_header(self):
        with TemporaryDirectory() as tmp:
            path = Path(tmp) / "recording.pcap"

            class Process:
                def __init__(self, code=None):
                    self.code = code

                def poll(self):
                    return self.code

            path.write_bytes(b"\xd4\xc3\xb2\xa1" + b"\0" * 20)
            _wait_for_capture_ready(Process(), path, timeout_seconds=.1)
            path.write_bytes(b"\xd4\xc3")
            with self.assertRaisesRegex(RuntimeError, "not ready"):
                _wait_for_capture_ready(Process(), path, timeout_seconds=.02)
            with self.assertRaisesRegex(RuntimeError, "exited before"):
                _wait_for_capture_ready(Process(1), path, timeout_seconds=.02)

            read_fd, write_fd = os.pipe()
            try:
                class ReadyProcess(Process):
                    stderr = None

                with os.fdopen(read_fd, "rb", buffering=0) as reader:
                    proc = ReadyProcess()
                    proc.stderr = reader
                    os.write(write_fd, b"listening on lo, link-type EN10MB\n")
                    _wait_for_capture_ready(proc, path, timeout_seconds=.1)
            finally:
                os.close(write_fd)

    def test_tcp_handshakes_are_accounted_for_independently_of_actions(self):
        with TemporaryDirectory() as tmp:
            path = Path(tmp) / "sample.pcap"
            frames = []
            for i in range(3):
                src_port = 44001 + i
                frames.extend([
                    (1.0 + i, _tcp_packet(src_port, 9090, 0x02)),
                    (1.1 + i, _tcp_packet(9090, src_port, 0x12)),
                    (1.2 + i, _tcp_packet(src_port, 9090, 0x10)),
                ])
            write_pcap(path, frames)
            counts = audit_client_handshakes(path, server_port=9090)
            self.assertEqual(counts["client_syn_flows"], 3)
            self.assertEqual(counts["completed_tcp_handshakes"], 3)
            self.assertEqual(counts["server_synack_flows"], 3)

            write_pcap(path, frames[:-3])
            partial = audit_client_handshakes(path, server_port=9090)
            self.assertEqual(partial["client_syn_flows"], 2)
            self.assertEqual(partial["completed_tcp_handshakes"], 2)
            with self.assertRaisesRegex(RuntimeError, "incomplete"):
                _wait_for_wire_coverage(path, server_port=9090,
                                        expected_sessions=3, timeout_seconds=.02)
            write_pcap(path, frames)
            counted = _wait_for_wire_coverage(
                path, server_port=9090, expected_sessions=3, timeout_seconds=.1,
            )
            self.assertEqual(counted["completed_tcp_handshakes"], 3)

    def test_real_tls_tasks_preserve_application_causality(self):
        with TemporaryDirectory() as tmp:
            out = Path(tmp) / "run"
            report = run_benign_office_workload(
                out, sessions=2, seed=13, action_pause_seconds=0,
            )
            self.assertEqual(report["sessions_completed"], 2)
            self.assertEqual(report["tasks_completed"], 8)
            self.assertEqual(report["actions_completed"], 16)
            self.assertTrue(report["tls_peer_verified"])
            self.assertTrue(report["document_versions_verified"])
            self.assertTrue(report["download_integrity_verified"])
            self.assertEqual(report["capture_status"], "not_requested")
            self.assertEqual(report["naturalness_status"], "not_passed")
            self.assertFalse(report["production_ready"])
            self.assertEqual(report["client_stack"], "python_stdlib_https")
            receipt = json.loads((out / "workload_receipt.json").read_text())
            self.assertEqual(receipt, report)
            self.assertFalse(any(
                name.endswith((".pem", ".key", ".crt")) for name in
                (p.name for p in out.rglob("*"))
            ))

    def test_refuses_unbounded_or_invalid_sessions(self):
        with TemporaryDirectory() as tmp:
            for count in (0, -1, 10001):
                with self.subTest(count=count):
                    with self.assertRaisesRegex(ValueError, "sessions"):
                        run_benign_office_workload(Path(tmp) / "bad", sessions=count)

    def test_refuses_overwrite_of_existing_corpus(self):
        with TemporaryDirectory() as tmp:
            out = Path(tmp) / "existing"
            out.mkdir()
            (out / "workload_receipt.json").write_text("untouched")
            with self.assertRaises(FileExistsError):
                run_benign_office_workload(out)
            self.assertEqual((out / "workload_receipt.json").read_text(), "untouched")


if __name__ == "__main__":
    unittest.main()
