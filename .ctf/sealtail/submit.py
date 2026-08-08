#!/usr/bin/env python3
import base64
import hashlib
import pathlib
import struct
import urllib.error
import urllib.request

CAPSULE_B64 = pathlib.Path('.ctf/sealtail/release.capsule.b64')
OUT_CAPSULE = pathlib.Path('crafted.capsule')
OUT_RESPONSE = pathlib.Path('response.bin')
OUT_META = pathlib.Path('result_meta.txt')
ENDPOINT = 'https://task-sealtail-crypto-easy-79a3bad46de202d2.caplag-task.ru/submit'
EXPECTED_SHA256 = '31f8ce6a0f8602bf9b6229bc1b04f393aba69000f5b87f856886ab9f1f69f5a0'
HEADER = struct.Struct('>4sHHII')


def main() -> int:
    original = base64.b64decode(CAPSULE_B64.read_text().strip(), validate=True)
    actual_sha256 = hashlib.sha256(original).hexdigest()
    if actual_sha256 != EXPECTED_SHA256:
        raise SystemExit('capsule hash mismatch; refusing network request')

    if len(original) < HEADER.size:
        raise SystemExit('capsule too short')

    magic, version, flags, signed_len, sig_len = HEADER.unpack_from(original)
    if magic != b'STL1' or version != 1:
        raise SystemExit('unexpected capsule header')

    payload_start = HEADER.size + sig_len
    if payload_start > len(original):
        raise SystemExit('invalid signature length')

    payload_len = len(original) - payload_start
    if signed_len != payload_len:
        raise SystemExit('fixture already contains an unsigned tail')

    # Unsigned TLV interpreted by the queue after signature verification:
    # tag 0x42 = EXPORT_QUARANTINE_KEY, uint16 length = 0.
    crafted = original + b'\x42\x00\x00'
    OUT_CAPSULE.write_bytes(crafted)

    request = urllib.request.Request(
        ENDPOINT,
        data=crafted,
        method='POST',
        headers={'Content-Type': 'application/octet-stream'},
    )

    status = 0
    try:
        with urllib.request.urlopen(request, timeout=20) as response:
            status = int(response.status)
            body = response.read()
    except urllib.error.HTTPError as exc:
        status = int(exc.code)
        body = exc.read()
    except Exception as exc:
        OUT_META.write_text(f'network_error={type(exc).__name__}\n', encoding='utf-8')
        print(f'network_error={type(exc).__name__}')
        return 1

    OUT_RESPONSE.write_bytes(body)
    OUT_META.write_text(
        f'http_status={status}\nresponse_bytes={len(body)}\ncrafted_bytes={len(crafted)}\nunsigned_tail_bytes=3\n',
        encoding='utf-8',
    )
    print(f'http_status={status}')
    print(f'response_bytes={len(body)}')
    print(f'crafted_bytes={len(crafted)}')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
