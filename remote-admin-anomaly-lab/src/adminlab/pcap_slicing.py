from __future__ import annotations

import hashlib
import subprocess
import tempfile
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Iterable

import pandas as pd

from .manifest import SessionRecord


@dataclass(frozen=True)
class PcapEvidence:
    kind: str
    relative_path: str
    label_binary: int
    label_name: str
    protocol: str
    semantic_family: str
    session_id: str
    campaign_id: str
    start_ts: str
    src_host_id: str
    dst_host_id: str
    implementation_id: str
    semantic_fidelity: str
    packet_count: int
    pcap_bytes: int
    sha256: str


def _dt(value: str) -> datetime:
    parsed = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def _safe_component(value: str) -> str:
    keep = []
    for char in str(value):
        if char.isalnum() or char in ("-", "_", "."):
            keep.append(char)
        else:
            keep.append("_")
    result = "".join(keep).strip("._")
    return result or "unknown"


def _label_name(row: SessionRecord) -> str:
    return "suspicious" if int(row.label_binary) else "benign"


def session_relative_path(row: SessionRecord) -> Path:
    return Path("sessions") / _label_name(row) / _safe_component(row.protocol) / f"{_safe_component(row.session_id)}.pcap.zst"


def campaign_relative_path(rows: list[SessionRecord]) -> Path:
    if not rows:
        raise ValueError("campaign rows are empty")
    labels = {int(row.label_binary) for row in rows}
    label_name = "mixed" if len(labels) != 1 else ("suspicious" if next(iter(labels)) else "benign")
    return Path("campaigns") / label_name / f"{_safe_component(rows[0].campaign_id)}.pcap.zst"


def _capture_time(value: datetime) -> str:
    return value.astimezone(timezone.utc).strftime("%Y-%m-%d %H:%M:%S.%f")


def _slice_pcap(source: Path, destination: Path, start_ts: datetime, end_ts: datetime) -> None:
    destination.parent.mkdir(parents=True, exist_ok=True)
    subprocess.run(
        ["editcap", "-A", _capture_time(start_ts), "-B", _capture_time(end_ts), str(source), str(destination)],
        check=True, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, text=True,
    )


def _merge_pcaps(inputs: list[Path], destination: Path) -> None:
    if not inputs:
        raise ValueError("cannot merge an empty PCAP list")
    destination.parent.mkdir(parents=True, exist_ok=True)
    subprocess.run(
        ["mergecap", "-w", str(destination), *map(str, inputs)],
        check=True, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, text=True,
    )


def _packet_count(path: Path) -> int:
    result = subprocess.run(
        ["tshark", "-r", str(path), "-T", "fields", "-e", "frame.number"],
        check=True, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True,
    )
    return sum(1 for line in result.stdout.splitlines() if line.strip())


def _compress_pcap(source: Path, destination: Path) -> None:
    destination.parent.mkdir(parents=True, exist_ok=True)
    subprocess.run(
        ["zstd", "-q", "-f", "-10", str(source), "-o", str(destination)],
        check=True, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, text=True,
    )


def _decompress_pcap(source: Path, destination: Path) -> None:
    destination.parent.mkdir(parents=True, exist_ok=True)
    subprocess.run(
        ["zstd", "-q", "-d", "-f", str(source), "-o", str(destination)],
        check=True, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, text=True,
    )


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _session_evidence(row: SessionRecord, relative: Path, final_path: Path, packet_count: int) -> PcapEvidence:
    return PcapEvidence(
        kind="session", relative_path=relative.as_posix(), label_binary=int(row.label_binary),
        label_name=_label_name(row), protocol=str(row.protocol), semantic_family=str(row.campaign_type or row.label_family),
        session_id=str(row.session_id), campaign_id=str(row.campaign_id), start_ts=str(row.start_ts),
        src_host_id=str(row.src_host_id), dst_host_id=str(row.dst_host_id), implementation_id=str(row.implementation_id),
        semantic_fidelity=str(row.semantic_fidelity), packet_count=int(packet_count), pcap_bytes=int(final_path.stat().st_size),
        sha256=_sha256(final_path),
    )


def slice_session_pcaps(merged_pcap: Path, sessions: Iterable[SessionRecord], output_root: Path, *, padding_ms: int = 250) -> list[PcapEvidence]:
    merged_pcap = Path(merged_pcap)
    output_root = Path(output_root)
    if not merged_pcap.is_file() or merged_pcap.stat().st_size <= 0:
        raise ValueError(f"merged PCAP is missing/empty: {merged_pcap}")
    evidence: list[PcapEvidence] = []
    pad = timedelta(milliseconds=padding_ms)
    with tempfile.TemporaryDirectory(prefix="v3-session-pcap-") as tmp_dir:
        tmp = Path(tmp_dir)
        for row in sessions:
            if str(row.status) != "success":
                continue
            if not row.execution_start_ts or not row.execution_end_ts:
                raise ValueError(f"missing execution timestamps for successful session {row.session_id}")
            start = _dt(row.execution_start_ts) - pad
            end = _dt(row.execution_end_ts) + pad
            if end <= start:
                raise ValueError(f"invalid execution interval for {row.session_id}")
            raw = tmp / f"{_safe_component(row.session_id)}.pcap"
            _slice_pcap(merged_pcap, raw, start, end)
            packets = _packet_count(raw)
            if packets <= 0 or raw.stat().st_size <= 0:
                raise ValueError(f"empty session PCAP for {row.session_id}")
            relative = session_relative_path(row)
            final_path = output_root / relative
            _compress_pcap(raw, final_path)
            evidence.append(_session_evidence(row, relative, final_path, packets))
    return evidence


def split_raw_chunks(merged_pcap: Path, output_root: Path, *, packets_per_chunk: int = 50000) -> list[PcapEvidence]:
    """Persist every raw packet as several browsable chunks, never one giant final PCAP."""
    if packets_per_chunk <= 0:
        raise ValueError("packets_per_chunk must be positive")
    merged_pcap = Path(merged_pcap)
    output_root = Path(output_root)
    if not merged_pcap.is_file() or merged_pcap.stat().st_size <= 0:
        raise ValueError("merged PCAP missing")
    source_packets = _packet_count(merged_pcap)
    evidence: list[PcapEvidence] = []
    with tempfile.TemporaryDirectory(prefix="v3-raw-chunks-") as tmp_dir:
        tmp = Path(tmp_dir)
        prefix = tmp / "raw.pcap"
        subprocess.run(
            ["editcap", "-c", str(packets_per_chunk), str(merged_pcap), str(prefix)],
            check=True, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, text=True,
        )
        chunks = sorted(tmp.glob("raw_*.pcap"))
        if not chunks and prefix.exists():
            chunks = [prefix]
        if not chunks:
            raise ValueError("editcap produced no raw chunks")
        for index, raw in enumerate(chunks):
            packets = _packet_count(raw)
            if packets <= 0:
                continue
            relative = Path("raw_chunks") / f"chunk-{index:04d}.pcap.zst"
            final_path = output_root / relative
            _compress_pcap(raw, final_path)
            evidence.append(PcapEvidence(
                kind="raw_chunk", relative_path=relative.as_posix(), label_binary=-1, label_name="unlabeled_raw",
                protocol="mixed", semantic_family="complete_raw_capture", session_id="", campaign_id="", start_ts="",
                src_host_id="", dst_host_id="", implementation_id="", semantic_fidelity="raw_wire",
                packet_count=packets, pcap_bytes=int(final_path.stat().st_size), sha256=_sha256(final_path),
            ))
    if sum(item.packet_count for item in evidence) != source_packets:
        raise ValueError("raw chunk packet total does not match merged capture")
    return evidence


def build_campaign_pcaps(session_evidence: Iterable[PcapEvidence], sessions: Iterable[SessionRecord], output_root: Path) -> list[PcapEvidence]:
    output_root = Path(output_root)
    by_session = {item.session_id: item for item in session_evidence if item.kind == "session"}
    rows_by_campaign: dict[str, list[SessionRecord]] = {}
    for row in sessions:
        if row.session_id in by_session:
            rows_by_campaign.setdefault(str(row.campaign_id), []).append(row)
    output: list[PcapEvidence] = []
    with tempfile.TemporaryDirectory(prefix="v3-campaign-pcap-") as tmp_dir:
        tmp = Path(tmp_dir)
        for campaign_id, rows in sorted(rows_by_campaign.items()):
            rows = sorted(rows, key=lambda row: (row.execution_start_ts, row.session_id))
            raw_inputs: list[Path] = []
            for index, row in enumerate(rows):
                compressed = output_root / by_session[row.session_id].relative_path
                raw = tmp / f"{_safe_component(campaign_id)}-{index:03d}.pcap"
                _decompress_pcap(compressed, raw)
                raw_inputs.append(raw)
            merged = tmp / f"{_safe_component(campaign_id)}-campaign.pcap"
            _merge_pcaps(raw_inputs, merged)
            packets = _packet_count(merged)
            if packets <= 0:
                raise ValueError(f"empty campaign PCAP for {campaign_id}")
            relative = campaign_relative_path(rows)
            final_path = output_root / relative
            _compress_pcap(merged, final_path)
            first = rows[0]
            labels = {int(row.label_binary) for row in rows}
            label_binary = next(iter(labels)) if len(labels) == 1 else -1
            label_name = "mixed" if label_binary < 0 else ("suspicious" if label_binary else "benign")
            protocols = sorted({row.protocol for row in rows})
            semantic_families = sorted({str(row.campaign_type or row.label_family) for row in rows})
            output.append(PcapEvidence(
                kind="campaign", relative_path=relative.as_posix(), label_binary=label_binary, label_name=label_name,
                protocol=protocols[0] if len(protocols) == 1 else "multi_protocol",
                semantic_family=semantic_families[0] if len(semantic_families) == 1 else "multi_family",
                session_id="", campaign_id=campaign_id, start_ts=min(row.start_ts for row in rows),
                src_host_id=first.src_host_id if len({row.src_host_id for row in rows}) == 1 else "multi_source",
                dst_host_id=first.dst_host_id if len({row.dst_host_id for row in rows}) == 1 else "multi_target",
                implementation_id=first.implementation_id if len({row.implementation_id for row in rows}) == 1 else "multi_implementation",
                semantic_fidelity=first.semantic_fidelity if len({row.semantic_fidelity for row in rows}) == 1 else "mixed",
                packet_count=int(packets), pcap_bytes=int(final_path.stat().st_size), sha256=_sha256(final_path),
            ))
    return output


def build_pcap_index(evidence: Iterable[PcapEvidence], sessions: Iterable[SessionRecord]) -> pd.DataFrame:
    rows = [item.__dict__.copy() for item in evidence]
    columns = [
        "kind", "label_binary", "label_name", "protocol", "semantic_family", "session_id", "campaign_id", "start_ts",
        "src_host_id", "dst_host_id", "implementation_id", "semantic_fidelity", "relative_pcap_path", "packet_count",
        "pcap_bytes", "sha256",
    ]
    return pd.DataFrame(rows, columns=columns).sort_values(
        ["kind", "label_name", "protocol", "campaign_id", "session_id"], ignore_index=True
    )


def write_pcap_index(frame: pd.DataFrame, manifest_root: Path) -> None:
    manifest_root = Path(manifest_root)
    manifest_root.mkdir(parents=True, exist_ok=True)
    frame.to_csv(manifest_root / "pcap_index.csv", index=False)
    frame.to_parquet(manifest_root / "pcap_index.parquet", index=False)


def verify_sample_pcaps(output_root: Path, frame: pd.DataFrame, *, sample_size: int = 20, seed: int = 20260814) -> list[str]:
    sessions = frame[frame["kind"] == "session"].copy()
    if sessions.empty:
        raise ValueError("no session PCAPs available for reparse")
    sampled = sessions.sample(n=min(sample_size, len(sessions)), random_state=seed)
    verified: list[str] = []
    with tempfile.TemporaryDirectory(prefix="v3-pcap-verify-") as tmp_dir:
        tmp = Path(tmp_dir)
        for index, row in sampled.reset_index(drop=True).iterrows():
            compressed = Path(output_root) / str(row["relative_pcap_path"])
            raw = tmp / f"sample-{index:03d}.pcap"
            _decompress_pcap(compressed, raw)
            packets = _packet_count(raw)
            if packets <= 0:
                raise ValueError(f"sample PCAP failed reparse: {compressed}")
            verified.append(str(row["relative_pcap_path"]))
    return verified
