#!/usr/bin/env python3
"""Read the TLS hello out of a QUIC Initial packet.

QUIC encrypts even its first packets, but with keys anyone can derive: RFC 9001
section 5.2 builds them from the Destination Connection ID the client picked and
a published salt. A passive observer can therefore read the ClientHello -- tshark
does exactly this -- and the sensor has to as well if QUIC sessions are to carry
the TLS features TCP sessions do. Measured on a 10-second office capture: 48 of
676 ClientHellos were inside QUIC, and all 48 were invisible to the pipeline.

The AES work is done by the `cryptography` package (OpenSSL underneath), which
Ubuntu ships as a system package on both the sensor and the processing VM. A
pure-python AES-128/GCM is kept below only as a fallback for a host without it
-- a developer laptop running the tests, say -- and `BACKEND` says which one is
in use, so a silent switch shows up in the export statistics.

Either way the GCM tag is always checked, and a packet whose tag does not verify
is dropped, never parsed: a wrong key yields nothing rather than a plausible
wrong fingerprint.

Both backends are held to the FIPS-197 AES vector, the McGrew-Viega GCM vectors
and the worked example in RFC 9001 appendix A, and to each other
(tests/test_quic_initial.py); end to end, against tshark's own QUIC decryption
on real traffic.
"""
from __future__ import annotations

import hashlib
import hmac

try:
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    from cryptography.exceptions import InvalidTag
    BACKEND = "cryptography"
except ImportError:                                   # pragma: no cover - host dependent
    BACKEND = "pure-python"

# --------------------------------------------------------------------- AES-128


def _rotl8(x: int, s: int) -> int:
    return ((x << s) | (x >> (8 - s))) & 0xFF


def _build_sbox() -> bytes:
    """The AES S-box, generated rather than typed in: a transcription error in
    256 hex bytes is invisible to the eye and fatal to every result."""
    sbox = [0] * 256
    p = q = 1
    while True:
        p = (p ^ (p << 1) ^ (0x1B if p & 0x80 else 0)) & 0xFF
        q = (q ^ (q << 1)) & 0xFF
        q = (q ^ (q << 2)) & 0xFF
        q = (q ^ (q << 4)) & 0xFF
        if q & 0x80:
            q ^= 0x09
        x = q ^ _rotl8(q, 1) ^ _rotl8(q, 2) ^ _rotl8(q, 3) ^ _rotl8(q, 4)
        sbox[p] = (x ^ 0x63) & 0xFF
        if p == 1:
            break
    sbox[0] = 0x63
    return bytes(sbox)


SBOX = _build_sbox()
_RCON = (0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1B, 0x36)


def _xtime(a: int) -> int:
    return ((a << 1) ^ 0x1B) & 0xFF if a & 0x80 else a << 1


def expand_key(key: bytes) -> list[bytes]:
    """AES-128 key schedule: eleven 16-byte round keys."""
    if len(key) != 16:
        raise ValueError("AES-128 needs a 16-byte key")
    w = [list(key[i:i + 4]) for i in range(0, 16, 4)]
    for i in range(4, 44):
        t = list(w[i - 1])
        if i % 4 == 0:
            t = t[1:] + t[:1]
            t = [SBOX[b] for b in t]
            t[0] ^= _RCON[i // 4 - 1]
        w.append([w[i - 4][j] ^ t[j] for j in range(4)])
    return [bytes(sum(w[4 * r:4 * r + 4], [])) for r in range(11)]


def _shift_rows(s: list[int]) -> list[int]:
    # State is column-major (byte r + 4c); row r moves left by r columns.
    return [s[(i + 4 * (i % 4)) % 16] for i in range(16)]


def _mix_columns(s: list[int]) -> list[int]:
    out = list(s)
    for c in range(0, 16, 4):
        a0, a1, a2, a3 = s[c:c + 4]
        t = a0 ^ a1 ^ a2 ^ a3
        out[c] = a0 ^ t ^ _xtime(a0 ^ a1)
        out[c + 1] = a1 ^ t ^ _xtime(a1 ^ a2)
        out[c + 2] = a2 ^ t ^ _xtime(a2 ^ a3)
        out[c + 3] = a3 ^ t ^ _xtime(a3 ^ a0)
    return out


def encrypt_block(round_keys: list[bytes], block: bytes) -> bytes:
    s = [b ^ k for b, k in zip(block, round_keys[0])]
    for rnd in range(1, 10):
        s = _mix_columns(_shift_rows([SBOX[b] for b in s]))
        s = [b ^ k for b, k in zip(s, round_keys[rnd])]
    s = _shift_rows([SBOX[b] for b in s])
    return bytes(b ^ k for b, k in zip(s, round_keys[10]))


# ------------------------------------------------------------------------- GCM

_R = 0xE1 << 120


def _gf_mult(x: int, y: int) -> int:
    """Multiply in GF(2^128) with GCM's bit order (bit 0 is the MSB)."""
    z, v = 0, y
    for i in range(127, -1, -1):
        if (x >> i) & 1:
            z ^= v
        v = (v >> 1) ^ _R if v & 1 else v >> 1
    return z


def _ghash(h: int, aad: bytes, ct: bytes) -> int:
    x = 0
    for data in (aad, ct):
        for i in range(0, len(data), 16):
            x = _gf_mult(x ^ int.from_bytes(data[i:i + 16].ljust(16, b"\0"), "big"), h)
    lengths = ((len(aad) * 8) << 64) | (len(ct) * 8)
    return _gf_mult(x ^ lengths, h)


def _ctr(round_keys: list[bytes], nonce: bytes, data: bytes) -> bytes:
    out = bytearray()
    counter = 1
    for i in range(0, len(data), 16):
        counter = (counter + 1) & 0xFFFFFFFF
        stream = encrypt_block(round_keys, nonce + counter.to_bytes(4, "big"))
        out += bytes(a ^ b for a, b in zip(data[i:i + 16], stream))
    return bytes(out)


def _tag(round_keys: list[bytes], nonce: bytes, aad: bytes, ct: bytes) -> bytes:
    h = int.from_bytes(encrypt_block(round_keys, b"\0" * 16), "big")
    j0 = int.from_bytes(encrypt_block(round_keys, nonce + b"\x00\x00\x00\x01"), "big")
    return (j0 ^ _ghash(h, aad, ct)).to_bytes(16, "big")


def py_gcm_encrypt(key: bytes, nonce: bytes, plaintext: bytes, aad: bytes) -> bytes:
    rk = expand_key(key)
    ct = _ctr(rk, nonce, plaintext)
    return ct + _tag(rk, nonce, aad, ct)


def py_gcm_decrypt(key: bytes, nonce: bytes, sealed: bytes, aad: bytes) -> bytes | None:
    if len(sealed) < 16 or len(nonce) != 12:
        return None
    rk = expand_key(key)
    ct, tag = sealed[:-16], sealed[-16:]
    if not hmac.compare_digest(_tag(rk, nonce, aad, ct), tag):
        return None
    return _ctr(rk, nonce, ct)


def py_ecb_block(key: bytes, block: bytes) -> bytes:
    return encrypt_block(expand_key(key), block)


def gcm_encrypt(key: bytes, nonce: bytes, plaintext: bytes, aad: bytes) -> bytes:
    """Ciphertext followed by the 16-byte tag. Used by the tests to build
    packets; the sensor itself only ever decrypts."""
    if BACKEND == "cryptography":
        return AESGCM(key).encrypt(nonce, plaintext, aad)
    return py_gcm_encrypt(key, nonce, plaintext, aad)


def gcm_decrypt(key: bytes, nonce: bytes, sealed: bytes, aad: bytes) -> bytes | None:
    """Plaintext, or None when the tag does not verify."""
    if len(sealed) < 16 or len(nonce) != 12:
        return None
    if BACKEND == "cryptography":
        try:
            return AESGCM(key).decrypt(nonce, sealed, aad)
        except InvalidTag:
            return None
    return py_gcm_decrypt(key, nonce, sealed, aad)


def ecb_block(key: bytes, block: bytes) -> bytes:
    """One AES block, as header protection needs (RFC 9001 section 5.4.3)."""
    if BACKEND == "cryptography":
        enc = Cipher(algorithms.AES(key), modes.ECB()).encryptor()
        return enc.update(block) + enc.finalize()
    return py_ecb_block(key, block)


# ------------------------------------------------------------------ QUIC keys

QUIC_V1 = 0x00000001
QUIC_V2 = 0x6B3343CF
_SALT = {
    QUIC_V1: bytes.fromhex("38762cf7f55934b34d179ae6a4c80cadccbb7f0a"),  # RFC 9001
    QUIC_V2: bytes.fromhex("0dede3def700a6db819381be6e269dcbf9bd2ed9"),  # RFC 9369
}
_LABELS = {
    QUIC_V1: (b"quic key", b"quic iv", b"quic hp"),
    QUIC_V2: (b"quicv2 key", b"quicv2 iv", b"quicv2 hp"),
}
# Long-header packet type that means Initial differs between the versions.
_INITIAL_TYPE = {QUIC_V1: 0, QUIC_V2: 1}
_RETRY_TYPE = {QUIC_V1: 3, QUIC_V2: 0}
VERSIONS = frozenset(_SALT)


def hkdf_extract(salt: bytes, ikm: bytes) -> bytes:
    return hmac.new(salt, ikm, hashlib.sha256).digest()


def hkdf_expand_label(secret: bytes, label: bytes, length: int) -> bytes:
    full = b"tls13 " + label
    info = length.to_bytes(2, "big") + bytes([len(full)]) + full + b"\x00"
    out, block, i = b"", b"", 1
    while len(out) < length:
        block = hmac.new(secret, block + info + bytes([i]), hashlib.sha256).digest()
        out += block
        i += 1
    return out[:length]


def initial_secret(version: int, dcid: bytes, is_client: bool) -> bytes:
    secret = hkdf_extract(_SALT[version], dcid)
    return hkdf_expand_label(secret, b"client in" if is_client else b"server in", 32)


def initial_keys(version: int, dcid: bytes, is_client: bool) -> tuple[bytes, bytes, bytes]:
    """(key, iv, hp) for one side of the Initial packet space."""
    side = initial_secret(version, dcid, is_client)
    k, iv, hp = _LABELS[version]
    return (hkdf_expand_label(side, k, 16), hkdf_expand_label(side, iv, 12),
            hkdf_expand_label(side, hp, 16))


# -------------------------------------------------------------- packet parsing


def varint(b: bytes, p: int) -> tuple[int, int]:
    """(value, bytes used) of a QUIC variable-length integer."""
    first = b[p]
    n = 1 << (first >> 6)
    if p + n > len(b):
        raise IndexError("truncated varint")
    v = first & 0x3F
    for i in range(1, n):
        v = (v << 8) | b[p + i]
    return v, n


def long_header(dgram: bytes, pos: int = 0):
    """Fields of the long-header packet at `pos`, or None if it is not one we read.

    Returns (version, packet_type, dcid, pn_offset, end) where `end` is where the
    next coalesced packet in the datagram starts.
    """
    if pos + 7 > len(dgram) or not dgram[pos] & 0x80:
        return None
    version = int.from_bytes(dgram[pos + 1:pos + 5], "big")
    if version not in _SALT:
        return None
    ptype = (dgram[pos] >> 4) & 0x03
    if ptype == _RETRY_TYPE[version]:
        return None                       # Retry carries no Length field
    # A mirror carries malformed and cut datagrams too; a header that runs past
    # the datagram is "not one we read", never an exception that would lose the
    # whole capture interval it sits in.
    try:
        p = pos + 5
        dl = dgram[p]
        p += 1
        dcid = bytes(dgram[p:p + dl])
        p += dl
        sl = dgram[p]
        p += 1 + sl
        if ptype == _INITIAL_TYPE[version]:
            tl, n = varint(dgram, p)
            p += n + tl
        length, n = varint(dgram, p)
    except IndexError:
        return None
    p += n
    if p + length > len(dgram):
        return None
    return version, ptype, dcid, p, p + length


def open_initial(dgram: bytes, pos: int, dcid_for_keys: bytes | None, is_client: bool,
                 keys: tuple | None = None):
    """Decrypt the Initial packet at `pos`.

    Returns (plaintext or None, end of this packet, the header fields). A packet
    that is not an Initial, or whose tag fails, gives None plaintext but still
    reports its end so coalesced packets after it can be read.
    """
    hdr = long_header(dgram, pos)
    if hdr is None:
        return None, len(dgram), None
    version, ptype, dcid, pn_offset, end = hdr
    if ptype != _INITIAL_TYPE[version] or end > len(dgram):
        return None, min(end, len(dgram)), hdr
    key, iv, hp = keys or initial_keys(version, dcid_for_keys or dcid, is_client)
    sample = dgram[pn_offset + 4:pn_offset + 20]
    if len(sample) < 16:
        return None, end, hdr
    mask = ecb_block(hp, bytes(sample))
    first = dgram[pos] ^ (mask[0] & 0x0F)
    pn_len = (first & 0x03) + 1
    pn_bytes = bytes(x ^ m for x, m in zip(dgram[pn_offset:pn_offset + pn_len],
                                           mask[1:1 + pn_len]))
    header = bytes([first]) + bytes(dgram[pos + 1:pn_offset]) + pn_bytes
    nonce = bytes(a ^ b for a, b in zip(iv, int.from_bytes(pn_bytes, "big").to_bytes(12, "big")))
    plaintext = gcm_decrypt(key, nonce, bytes(dgram[pn_offset + pn_len:end]), header)
    return plaintext, end, hdr


def crypto_frames(plaintext: bytes) -> list[tuple[int, bytes]]:
    """(offset, data) of every CRYPTO frame in a decrypted Initial payload.

    An Initial may hold only PADDING, PING, ACK, CRYPTO and CONNECTION_CLOSE.
    Chrome's "chaos protection" scatters the ClientHello over many CRYPTO frames
    in random order between PINGs and PADDING, so offsets are kept, not order.
    """
    out = []
    p = 0
    try:
        while p < len(plaintext):
            t = plaintext[p]
            if t in (0x00, 0x01):                      # PADDING, PING
                p += 1
                continue
            if t in (0x02, 0x03):                      # ACK, ACK with ECN
                p += 1
                for _ in range(2):                     # largest, delay
                    p += varint(plaintext, p)[1]
                count, n = varint(plaintext, p)
                p += n
                p += varint(plaintext, p)[1]           # first range
                for _ in range(count):
                    p += varint(plaintext, p)[1]
                    p += varint(plaintext, p)[1]
                if t == 0x03:
                    for _ in range(3):
                        p += varint(plaintext, p)[1]
                continue
            if t == 0x06:                              # CRYPTO
                p += 1
                off, n = varint(plaintext, p)
                p += n
                ln, n = varint(plaintext, p)
                p += n
                out.append((off, bytes(plaintext[p:p + ln])))
                p += ln
                continue
            break                                      # CONNECTION_CLOSE or unknown
    except IndexError:
        pass
    return out


def assemble(pieces: dict[int, bytes]) -> bytes:
    """The contiguous crypto stream from offset 0, as far as it has arrived."""
    buf = bytearray()
    end = 0
    for off in sorted(pieces):
        data = pieces[off]
        if off > end:
            break
        if off + len(data) > end:
            buf += data[end - off:]
            end = off + len(data)
    return bytes(buf)


def complete_handshake(stream: bytes) -> bytes | None:
    """The first handshake message in the stream once all of it has arrived."""
    if len(stream) < 4:
        return None
    need = 4 + int.from_bytes(stream[1:4], "big")
    return stream[:need] if len(stream) >= need else None
