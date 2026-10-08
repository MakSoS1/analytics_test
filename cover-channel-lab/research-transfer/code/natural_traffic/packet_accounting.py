"""Read-only accounting of captured Ethernet frames and extractor output.

A large physical Ethernet frame may represent several virtual MTU segments.
The office feature extractor calls split_coalesced_frames before assigning
pkt_count and seq arrays, so a physical frame count need not equal pkt_count.
"""
from __future__ import annotations

import math
from collections.abc import Mapping, Sequence


def reconcile(
    lengths: Sequence[int],
    counts: Sequence[int],
    sequences: Mapping[str, Sequence[int]],
    mtu: int = 1514,
) -> dict[str, object]:
    if mtu < 100 or not lengths:
        raise ValueError("invalid MTU or empty physical capture")
    if any(not isinstance(n, int) or n <= 0 for n in lengths):
        raise ValueError("nonpositive or noninteger Ethernet frame length")
    if any(not isinstance(n, int) or n < 0 for n in counts):
        raise ValueError("invalid extracted packet count")
    expected = sum(math.ceil(n / mtu) for n in lengths)
    extracted = sum(counts)
    names = ("seq_signed_len", "seq_iat_us", "seq_flags")
    aligned = all(
        name in sequences
        and len(sequences[name]) == len(counts)
        and all(int(v) == n for v, n in zip(sequences[name], counts))
        for name in names
    )
    return {
        "version": "physical-vs-normalized-packets-v1",
        "physical_frames": len(lengths),
        "oversized_frames": sum(n > mtu for n in lengths),
        "virtual_segments": expected,
        "added_segments": expected - len(lengths),
        "extractor_packet_count": extracted,
        "sequence_arrays_aligned": bool(aligned),
        "passed": bool(aligned and expected == extracted),
        "production_ready": False,
    }
