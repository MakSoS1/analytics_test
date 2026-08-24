from __future__ import annotations

import argparse
import json
from pathlib import Path
import socket
import ssl
import time
from typing import Any


def probe_https(
    host: str,
    *,
    connect_host: str | None = None,
    port: int = 443,
    path: str = '/',
    timeout_s: float = 8.0,
    verify_tls: bool = True,
    max_body_bytes: int = 65536,
    user_agent: str = 'LOTS-v5-real-observation/1.0',
) -> dict[str, Any]:
    host = host.strip().lower().rstrip('.')
    target = connect_host or host
    capture_wall_start = time.time()
    result: dict[str, Any] = {
        'action_id': f'real-{int(capture_wall_start * 1_000_000)}',
        'attempt': 1,
        'accepted_attempt': False,
        'label': 'reference',
        'phase': 'read',
        'capture_wall_start': capture_wall_start,
        'wall_start': capture_wall_start,
        'virtual_wall_start': capture_wall_start,
        'monotonic_start': time.monotonic(),
        'src_ip': '', 'src_port': 0,
        'dst_ip': '', 'dst_port': int(port),
        'proto': 'tcp',
        'expected_sni': host,
        'intended_outcome': 'observe',
        'actual_outcome': 'error',
        'http_status': None,
        'tls_version': '',
        'tls_cipher': '',
        'app_bytes_up': 0,
        'app_bytes_down': 0,
    }

    raw: socket.socket | None = None
    try:
        raw = socket.create_connection((target, int(port)), timeout=timeout_s)
        raw.settimeout(timeout_s)
        src_ip, src_port = raw.getsockname()[:2]
        dst_ip, dst_port = raw.getpeername()[:2]

        if verify_tls:
            context = ssl.create_default_context()
        else:
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
        context.minimum_version = ssl.TLSVersion.TLSv1_2

        with context.wrap_socket(raw, server_hostname=host) as tls:
            raw = None
            tls.settimeout(timeout_s)
            negotiated_version = tls.version() or ''
            negotiated_cipher = tls.cipher()
            request = (
                f'GET {path or "/"} HTTP/1.1\r\n'
                f'Host: {host}\r\n'
                f'User-Agent: {user_agent}\r\n'
                'Accept: */*\r\n'
                f'Range: bytes=0-{max(0, int(max_body_bytes) - 1)}\r\n'
                'Connection: close\r\n\r\n'
            ).encode('ascii', errors='strict')
            tls.sendall(request)

            buf = bytearray()
            while b'\r\n\r\n' not in buf and len(buf) < 256 * 1024:
                chunk = tls.recv(16384)
                if not chunk:
                    break
                buf.extend(chunk)
            head, sep, rest = bytes(buf).partition(b'\r\n\r\n')
            if not sep:
                raise OSError('HTTP response headers not received')
            status_line = head.split(b'\r\n', 1)[0].decode('latin1', errors='replace')
            parts = status_line.split()
            if len(parts) < 2 or not parts[1].isdigit():
                raise OSError(f'invalid HTTP status line: {status_line!r}')
            status = int(parts[1])

            body_read = min(len(rest), max_body_bytes)
            while body_read < max_body_bytes:
                chunk = tls.recv(min(16384, max_body_bytes - body_read))
                if not chunk:
                    break
                body_read += len(chunk)

            result.update({
                'accepted_attempt': True,
                'actual_outcome': 'success',
                'src_ip': str(src_ip),
                'src_port': int(src_port),
                'dst_ip': str(dst_ip),
                'dst_port': int(dst_port),
                'http_status': status,
                'tls_version': negotiated_version,
                'tls_cipher': negotiated_cipher[0] if negotiated_cipher else '',
                'app_bytes_up': len(request),
                'app_bytes_down': int(body_read),
                'http_response_header_bytes': len(head) + 4,
            })
    except Exception as exc:
        if raw is not None:
            try:
                raw.close()
            except OSError:
                pass
        result['error'] = f'{type(exc).__name__}: {exc}'
    return result


def main() -> int:
    ap = argparse.ArgumentParser(description='Safe read-only HTTPS observation probe')
    ap.add_argument('--host', required=True)
    ap.add_argument('--path', default='/')
    ap.add_argument('--timeout-s', type=float, default=8.0)
    ap.add_argument('--max-body-bytes', type=int, default=65536)
    ap.add_argument('--out', required=True)
    args = ap.parse_args()
    result = probe_https(args.host, path=args.path, timeout_s=args.timeout_s, max_body_bytes=args.max_body_bytes)
    out = Path(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(result, indent=2, sort_keys=True) + '\n', encoding='utf-8')
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0 if result.get('accepted_attempt') else 2


if __name__ == '__main__':
    raise SystemExit(main())
