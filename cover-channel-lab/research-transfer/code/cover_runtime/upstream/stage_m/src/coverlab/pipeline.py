from __future__ import annotations

import argparse
import base64
import bisect
import hashlib
import json
import math
import re
import statistics
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any

import pandas as pd
from scapy.all import PcapReader, IP, IPv6, TCP, UDP


JA4_FIELDS = ("ja4", "ja4s", "ja4h", "ja4t", "ja4l")
HOLDOUT_CLIENTS = {"node_fetch", "python_stdlib", "browser_chromium"}
HOLDOUT_TRANSFORMS = {"semantic_uuid"}
HOLDOUT_CARRIERS = {"query_key", "response_chunks"}


def read_jsonl(path: Path) -> list[dict]:
    if not path.exists():
        return []
    out = []
    with path.open(errors="replace") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                out.append(json.loads(line))
            except json.JSONDecodeError:
                continue
    return out


def safe_int(path: Path, default: int = -1) -> int:
    try:
        return int(path.read_text().strip())
    except Exception:
        return default


def sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def shannon_entropy(data: bytes) -> float:
    if not data:
        return 0.0
    counts = Counter(data)
    n = len(data)
    return -sum((c / n) * math.log2(c / n) for c in counts.values())


def printable_ratio(data: bytes) -> float:
    if not data:
        return 0.0
    return sum(32 <= b <= 126 for b in data) / len(data)


def alphabet_ratios(text: str) -> dict[str, float]:
    n = max(1, len(text))
    return {
        "digit_ratio": sum(c.isdigit() for c in text) / n,
        "alpha_ratio": sum(c.isalpha() for c in text) / n,
        "hex_ratio": sum(c in "0123456789abcdefABCDEF" for c in text) / n,
        "b64_ratio": sum(c.isalnum() or c in "+/=" for c in text) / n,
        "b64url_ratio": sum(c.isalnum() or c in "-_=" for c in text) / n,
        "delimiter_ratio": sum(c in ":;,.|/_-=+&?%" for c in text) / n,
    }


def grammar_scores(text: str) -> dict[str, int]:
    uuid_like = int(bool(re.fullmatch(r"[0-9a-fA-F]{8}-[0-9a-fA-F-]{27,36}", text)))
    jwt_like = int(text.count(".") == 2 and all(part for part in text.split(".")))
    etag_like = int(bool(re.fullmatch(r'W/".*"|".*"', text)))
    b64_like = int(bool(re.fullmatch(r"[A-Za-z0-9+/=_-]{16,}", text)))
    return {
        "uuid_like": uuid_like,
        "jwt_like": jwt_like,
        "etag_like": etag_like,
        "encoded_token_like": b64_like,
    }


def campaign_intervals(df: pd.DataFrame) -> dict[str, tuple[list[float], list[tuple[float, float, str]]]]:
    by_src: dict[str, list[tuple[float, float, str]]] = defaultdict(list)
    for r in df.itertuples(index=False):
        try:
            start = pd.Timestamp(r.started_at).timestamp()
            end = pd.Timestamp(r.ended_at).timestamp()
            by_src[str(r.source_ip)].append((start, end, str(r.campaign_id)))
        except Exception:
            continue
    out = {}
    for src, rows in by_src.items():
        rows.sort(key=lambda x: x[0])
        out[src] = ([x[0] for x in rows], rows)
    return out


def lookup_campaign(index: dict, src_ip: str, ts: float) -> str | None:
    item = index.get(src_ip)
    if not item:
        return None
    starts, rows = item
    pos = bisect.bisect_right(starts, ts) - 1
    for candidate in (pos, pos + 1):
        if 0 <= candidate < len(rows):
            start, end, cid = rows[candidate]
            if start - 0.100 <= ts <= end + 0.100:
                return cid
    return None


def parser_root(stage_dir: Path) -> Path:
    return stage_dir / "parser"


def normalize(stage_dir: Path, silver: Path) -> list[dict]:
    silver.mkdir(parents=True, exist_ok=True)
    campaigns = read_jsonl(stage_dir / "campaigns.jsonl")
    events = read_jsonl(stage_dir / "events.jsonl")
    if campaigns:
        pd.DataFrame(campaigns).to_parquet(silver / "campaigns.parquet", index=False)
    if events:
        pd.DataFrame(events).to_parquet(silver / "events.parquet", index=False)
    decrypted = read_jsonl(stage_dir / "manifests" / "decrypted_transactions.jsonl")
    if decrypted:
        pd.json_normalize(decrypted, sep=".").to_parquet(silver / "decrypted_transactions.parquet", index=False)

    p_root = parser_root(stage_dir)
    eve = read_jsonl(p_root / "suricata" / "eve.json")
    if eve:
        pd.json_normalize(eve, sep=".").to_parquet(silver / "suricata_eve.parquet", index=False)

    for name in ("conn", "http", "ssl", "websocket", "quic", "dns"):
        rows = read_jsonl(p_root / "zeek" / f"{name}.log")
        if rows:
            pd.json_normalize(rows, sep=".").to_parquet(silver / f"zeek_{name}.parquet", index=False)
    return campaigns


def campaign_packet_features(pcap: Path, df: pd.DataFrame) -> pd.DataFrame:
    index = campaign_intervals(df)
    acc: dict[str, dict[str, Any]] = defaultdict(
        lambda: {
            "sizes": [], "times": [], "up_bytes": 0, "down_bytes": 0,
            "up_packets": 0, "down_packets": 0, "tcp_packets": 0,
            "udp_packets": 0, "tcp_flags": Counter(),
        }
    )
    if pcap.exists():
        with PcapReader(str(pcap)) as rd:
            for pkt in rd:
                try:
                    ts = float(pkt.time); n = len(pkt)
                    if IP in pkt:
                        src, dst = pkt[IP].src, pkt[IP].dst
                    elif IPv6 in pkt:
                        src, dst = pkt[IPv6].src, pkt[IPv6].dst
                    else:
                        continue
                    persona_ip = src if src in index else dst if dst in index else None
                    if not persona_ip:
                        continue
                    cid = lookup_campaign(index, persona_ip, ts)
                    if not cid:
                        continue
                    a = acc[cid]; a["sizes"].append(n); a["times"].append(ts)
                    if src == persona_ip:
                        a["up_bytes"] += n; a["up_packets"] += 1
                    else:
                        a["down_bytes"] += n; a["down_packets"] += 1
                    if TCP in pkt:
                        a["tcp_packets"] += 1; a["tcp_flags"][str(pkt[TCP].flags)] += 1
                    if UDP in pkt:
                        a["udp_packets"] += 1
                except Exception:
                    continue
    rows = []
    for cid in df.campaign_id.astype(str):
        a = acc.get(cid, {"sizes": [], "times": [], "up_bytes": 0, "down_bytes": 0,
                          "up_packets": 0, "down_packets": 0, "tcp_packets": 0,
                          "udp_packets": 0, "tcp_flags": Counter()})
        sizes = a["sizes"]; times = sorted(a["times"])
        inter = [b - a0 for a0, b in zip(times, times[1:])]
        rows.append({
            "campaign_id": cid, "packet_count": len(sizes), "byte_count": sum(sizes),
            "wire_duration_s": (times[-1] - times[0]) if len(times) > 1 else 0.0,
            "packet_size_mean": statistics.fmean(sizes) if sizes else 0.0,
            "packet_size_std": statistics.pstdev(sizes) if len(sizes) > 1 else 0.0,
            "packet_size_p95": sorted(sizes)[max(0, math.ceil(.95 * len(sizes)) - 1)] if sizes else 0,
            "interarrival_mean": statistics.fmean(inter) if inter else 0.0,
            "interarrival_std": statistics.pstdev(inter) if len(inter) > 1 else 0.0,
            "interarrival_cv": (statistics.pstdev(inter) / statistics.fmean(inter)) if len(inter) > 1 and statistics.fmean(inter) > 0 else 0.0,
            "up_bytes": a["up_bytes"], "down_bytes": a["down_bytes"],
            "up_packets": a["up_packets"], "down_packets": a["down_packets"],
            "up_down_byte_ratio": a["up_bytes"] / max(1, a["down_bytes"]),
            "tcp_packets": a["tcp_packets"], "udp_packets": a["udp_packets"],
            "syn_packets": sum(v for k, v in a["tcp_flags"].items() if "S" in k),
            "rst_packets": sum(v for k, v in a["tcp_flags"].items() if "R" in k),
        })
    return pd.DataFrame(rows)


def _event_ts(row: dict, source: str) -> float | None:
    try:
        return pd.Timestamp(row.get("timestamp")).timestamp() if source == "suricata" else float(row.get("ts"))
    except Exception:
        return None


def _event_src(row: dict, source: str) -> str:
    if source == "suricata":
        return str(row.get("src_ip") or "")
    return str(row.get("id.orig_h") or row.get("id", {}).get("orig_h") or "")


def _flatten(row: dict, prefix: str = "") -> dict[str, Any]:
    out: dict[str, Any] = {}
    for k, v in row.items():
        key = f"{prefix}.{k}" if prefix else str(k)
        if isinstance(v, dict):
            out.update(_flatten(v, key))
        else:
            out[key] = v
    return out


def parser_session_features(stage_dir: Path, df: pd.DataFrame, gold: Path) -> tuple[pd.DataFrame, dict]:
    index = campaign_intervals(df)
    acc: dict[str, dict[str, Any]] = defaultdict(lambda: {
        "suricata_events": 0, "zeek_events": 0, "suricata_alerts": 0,
        "http_events": 0, "tls_events": 0, "dns_events": 0, "quic_events": 0,
        "websocket_events": 0, "flow_events": 0, "app_proto": Counter(),
        "services": Counter(), "sni": set(), "hosts": set(), "status_codes": Counter(),
        "ja4": defaultdict(set), "suricata_flow_ids": set(), "zeek_uids": set(),
    })
    parser_rows = 0; mapped_rows = 0
    sources: list[tuple[str, list[dict]]] = [("suricata", read_jsonl(parser_root(stage_dir) / "suricata" / "eve.json"))]
    for name in ("conn", "http", "ssl", "websocket", "quic", "dns"):
        sources.append((f"zeek:{name}", read_jsonl(parser_root(stage_dir) / "zeek" / f"{name}.log")))

    for source_name, rows in sources:
        base_source = "suricata" if source_name == "suricata" else "zeek"
        log_name = source_name.split(":", 1)[1] if ":" in source_name else ""
        for raw in rows:
            parser_rows += 1
            ts = _event_ts(raw, base_source); src = _event_src(raw, base_source)
            if ts is None or not src:
                continue
            cid = lookup_campaign(index, src, ts)
            if not cid:
                continue
            mapped_rows += 1; a = acc[cid]; flat = _flatten(raw)
            if base_source == "suricata":
                a["suricata_events"] += 1
                et = str(raw.get("event_type") or "")
                if et == "alert": a["suricata_alerts"] += 1
                if et == "http": a["http_events"] += 1
                elif et == "tls": a["tls_events"] += 1
                elif et == "dns": a["dns_events"] += 1
                elif et == "quic": a["quic_events"] += 1
                elif et == "flow": a["flow_events"] += 1
                proto = raw.get("app_proto")
                if proto: a["app_proto"][str(proto)] += 1
                flow_id = raw.get("flow_id")
                if flow_id is not None: a["suricata_flow_ids"].add(str(flow_id))
                for key in ("tls.sni", "http.hostname", "dns.rrname"):
                    val = flat.get(key)
                    if val: (a["sni"] if key == "tls.sni" else a["hosts"]).add(str(val))
                status = flat.get("http.status")
                if status is not None: a["status_codes"][str(status)] += 1
            else:
                a["zeek_events"] += 1
                if log_name == "http": a["http_events"] += 1
                elif log_name == "ssl": a["tls_events"] += 1
                elif log_name == "dns": a["dns_events"] += 1
                elif log_name == "quic": a["quic_events"] += 1
                elif log_name == "websocket": a["websocket_events"] += 1
                elif log_name == "conn": a["flow_events"] += 1
                svc = raw.get("service")
                if svc: a["services"][str(svc)] += 1
                uid = raw.get("uid")
                if uid: a["zeek_uids"].add(str(uid))
                for key in ("server_name", "host", "query"):
                    val = raw.get(key)
                    if val: (a["sni"] if key == "server_name" else a["hosts"]).add(str(val))
                status = raw.get("status_code")
                if status is not None: a["status_codes"][str(status)] += 1
            for key, val in flat.items():
                lower = key.lower()
                for ja in JA4_FIELDS:
                    if lower == ja or lower.endswith("." + ja):
                        if val not in (None, "", "-"): a["ja4"][ja].add(str(val))

    rows_out = []
    for cid in df.campaign_id.astype(str):
        a = acc[cid]
        row = {
            "campaign_id": cid, "suricata_events": a["suricata_events"], "zeek_events": a["zeek_events"],
            "suricata_alerts": a["suricata_alerts"], "http_parser_events": a["http_events"],
            "tls_parser_events": a["tls_events"], "dns_parser_events": a["dns_events"],
            "quic_parser_events": a["quic_events"], "websocket_parser_events": a["websocket_events"],
            "flow_parser_events": a["flow_events"], "app_proto_unique": len(a["app_proto"]),
            "service_unique": len(a["services"]), "sni_unique": len(a["sni"]), "host_unique": len(a["hosts"]),
            "http_status_unique": len(a["status_codes"]), "suricata_flow_id_unique": len(a["suricata_flow_ids"]),
            "zeek_uid_unique": len(a["zeek_uids"]),
        }
        for ja in JA4_FIELDS:
            row[f"{ja}_unique"] = len(a["ja4"][ja]); row[f"{ja}_present"] = int(bool(a["ja4"][ja]))
        rows_out.append(row)
    out_df = pd.DataFrame(rows_out); out_df.to_parquet(gold / "parser_session_features.parquet", index=False)
    meta = {"parser_rows_total": parser_rows, "parser_rows_mapped": mapped_rows,
            "parser_mapping_coverage": mapped_rows / parser_rows if parser_rows else 0.0}
    return out_df, meta


def transaction_and_field_features(stage_dir: Path, df: pd.DataFrame, gold: Path) -> None:
    traces = read_jsonl(stage_dir / "manifests" / "decrypted_transactions.jsonl")
    if not traces: return
    index = campaign_intervals(df); tx_rows = []; field_rows = []
    def add_field(cid: str, ts: float, field_name: str, value: str, field_role: str) -> None:
        raw = value.encode(errors="replace")
        field_rows.append({
            "campaign_id": cid, "ts": ts, "field_name": field_name.lower(), "field_role": field_role,
            "raw_length": len(value), "byte_length": len(raw), "entropy": shannon_entropy(raw),
            "printable_ratio": printable_ratio(raw), "unique_char_ratio": len(set(value)) / max(1, len(value)),
            "prefix8_hash": hashlib.sha256(value[:8].encode()).hexdigest()[:12] if value else "",
            **alphabet_ratios(value), **grammar_scores(value),
        })
    for t in traces:
        src = str(t.get("client_ip") or "")
        try: ts = float(t.get("ts"))
        except Exception: continue
        cid = lookup_campaign(index, src, ts)
        if not cid: continue
        headers = t.get("request_headers") or {}; req = t.get("request") or {}; resp = t.get("response") or {}
        body = b""
        try: body = base64.b64decode(req.get("body_b64") or "", validate=False)
        except Exception: pass
        header_blob = "\n".join(f"{k}:{v}" for k, v in headers.items()).encode(errors="replace")
        path = str(t.get("path") or ""); query = str(t.get("query") or "")
        tx_rows.append({
            "campaign_id": cid, "ts": ts, "kind": t.get("kind"), "method": t.get("method"),
            "path_length": len(path), "query_length": len(query), "header_count": len(headers),
            "header_bytes": len(header_blob), "header_entropy": shannon_entropy(header_blob),
            "request_body_length": int(req.get("body_length") or 0), "request_body_entropy": shannon_entropy(body),
            "request_body_truncated": bool(req.get("body_truncated") or False),
            "response_status": t.get("response_status"), "response_body_length": int(resp.get("body_length") or 0),
        })
        add_field(cid, ts, ":path", path, "request_target")
        if query: add_field(cid, ts, ":query", query, "request_target")
        for k, v in headers.items(): add_field(cid, ts, str(k), str(v), "request_header")
        if body: add_field(cid, ts, ":body", body[:16384].decode("latin1", errors="replace"), "request_body")
    if tx_rows: pd.DataFrame(tx_rows).to_parquet(gold / "transaction_features.parquet", index=False)
    if field_rows: pd.DataFrame(field_rows).to_parquet(gold / "field_features.parquet", index=False)


def assign_split(row: pd.Series) -> str:
    stage = str(row.get("experiment_stage", "")).lower(); client = str(row.get("client_impl", "")); carrier = str(row.get("carrier", ""))
    transform = row.get("transform_chain", [])
    transforms = {transform} if isinstance(transform, str) else {str(x) for x in transform} if isinstance(transform, (list, tuple)) else set()
    if "challenge" in stage or "commodity" in stage: return "challenge"
    if client == "browser_chromium" or carrier in HOLDOUT_CARRIERS: return "challenge"
    if client in HOLDOUT_CLIENTS or transforms & HOLDOUT_TRANSFORMS: return "test"
    cid = str(row.get("campaign_id", "")); x = int(hashlib.sha256(cid.encode()).hexdigest()[:8], 16) % 100
    return "train" if x < 85 else "validation"


def build_splits(df: pd.DataFrame, gold: Path) -> dict[str, int]:
    split = df.apply(assign_split, axis=1); result = {}
    for name in ("train", "validation", "test", "challenge"):
        ids = df.loc[split == name, "campaign_id"].astype(str).tolist()
        (gold / f"{name}_campaigns.txt").write_text("\n".join(ids) + ("\n" if ids else "")); result[name] = len(ids)
    pd.DataFrame({"campaign_id": df.campaign_id.astype(str), "split": split}).to_parquet(gold / "campaign_splits.parquet", index=False)
    return result


def leakage_audit(df: pd.DataFrame, split_counts: dict[str, int]) -> dict[str, Any]:
    if df.empty: return {"passed": False, "reason": "empty"}
    seen = defaultdict(set); split_series = df.apply(assign_split, axis=1)
    for (_, r), sp in zip(df.iterrows(), split_series):
        for key, value in (("seed", str(r.get("seed", ""))), ("payload", str(r.get("plaintext_sha256", "")))):
            if value: seen[(key, value)].add(sp)
    crossing = {f"{k[0]}:{k[1]}": sorted(v) for k, v in seen.items() if len(v) > 1}
    train_clients = set(df.loc[split_series == "train", "client_impl"].astype(str)) if "client_impl" in df else set()
    bad_clients = sorted(train_clients & HOLDOUT_CLIENTS)
    duplicate = bool(df.campaign_id.astype(str).duplicated().any())
    return {"duplicate_campaign_ids": duplicate, "cross_split_seed_or_payload": crossing,
            "holdout_clients_in_train": bad_clients, "split_counts": split_counts,
            "passed": not duplicate and not crossing and not bad_clients}


def build_gold(stage_dir: Path, silver: Path, gold: Path, pcap: Path) -> tuple[float, dict, dict]:
    gold.mkdir(parents=True, exist_ok=True); cpath = silver / "campaigns.parquet"
    if not cpath.exists(): return 0.0, {}, {}
    df = pd.read_parquet(cpath)
    feat = pd.DataFrame({
        "campaign_id": df.campaign_id, "label_binary": df.label_binary, "label_family": df.label_family,
        "protocol": df.protocol, "persona": df.persona,
        "client_impl": df.get("client_impl", pd.Series(["unknown"] * len(df))),
        "visibility_mode": df.visibility_mode, "expected_events": df.expected_events,
        "inspection_policy": df.inspection_policy, "sni_visibility": df.sni_visibility,
    })
    net = campaign_packet_features(pcap, df); parser_feat, parser_meta = parser_session_features(stage_dir, df, gold)
    feat = feat.merge(net, on="campaign_id", how="left").merge(parser_feat, on="campaign_id", how="left")
    feat.to_parquet(gold / "session_features.parquet", index=False); transaction_and_field_features(stage_dir, df, gold)
    mapping_coverage = float((feat.packet_count.fillna(0) > 0).mean()) if len(feat) else 0.0
    split_counts = build_splits(df, gold); leak = leakage_audit(df, split_counts)
    return mapping_coverage, parser_meta, leak


def quality(stage_dir: Path, pcap: Path, out: Path, mapping_coverage: float, parser_meta: dict, leak: dict):
    out.mkdir(parents=True, exist_ok=True); campaigns = read_jsonl(stage_dir / "campaigns.jsonl"); events = read_jsonl(stage_dir / "events.jsonl")
    sroot = parser_root(stage_dir) / "suricata"; zroot = parser_root(stage_dir) / "zeek"
    suri_rc = safe_int(sroot / "exit_code.txt"); zeek_rc = safe_int(zroot / "exit_code.txt"); eve = sroot / "eve.json"; conn = zroot / "conn.log"
    checks = {
        "pcap_exists": pcap.exists(), "pcap_nonempty": pcap.exists() and pcap.stat().st_size > 24,
        "campaign_count": len(campaigns), "event_count": len(events),
        "unique_campaign_ids": len({c.get('campaign_id') for c in campaigns}) == len(campaigns),
        "all_success": all(c.get("status") == "success" for c in campaigns),
        "external_dependencies_false": all(c.get("external_dependency") is False for c in campaigns),
        "event_to_packet_mapping_coverage": round(mapping_coverage, 6),
        "mapping_coverage_ge_0_95": mapping_coverage >= .95 if campaigns else False,
        "suricata_exit_zero": suri_rc == 0, "zeek_exit_zero": zeek_rc == 0,
        "suricata_eve_nonempty": eve.exists() and eve.stat().st_size > 0,
        "zeek_conn_nonempty": conn.exists() and conn.stat().st_size > 0,
        "parser_rows_total": int(parser_meta.get("parser_rows_total", 0)),
        "parser_rows_mapped": int(parser_meta.get("parser_rows_mapped", 0)),
        "leakage_audit_passed": bool(leak.get("passed", False)),
    }
    bool_checks = [v for v in checks.values() if isinstance(v, bool)]; checks["passed"] = bool(bool_checks) and all(bool_checks)
    (out / "capture_health.json").write_text(json.dumps(checks, indent=2)); (out / "leakage_checks.json").write_text(json.dumps(leak, indent=2))
    checksum = {}
    for p in stage_dir.rglob("*"):
        if p.is_file(): checksum[str(p.relative_to(stage_dir))] = sha256(p)
    if pcap.exists(): checksum[str(pcap.name)] = sha256(pcap)
    (out / "checksums.json").write_text(json.dumps(checksum, indent=2, sort_keys=True))
    if not checks["passed"]: raise SystemExit("quality gates failed: " + json.dumps(checks, sort_keys=True))
    return checks


def main():
    p = argparse.ArgumentParser(); p.add_argument("--stage-dir", required=True); p.add_argument("--pcap", required=True)
    p.add_argument("--silver", required=True); p.add_argument("--gold", required=True); p.add_argument("--quality", required=True)
    a = p.parse_args(); stage = Path(a.stage_dir); silver = Path(a.silver); gold = Path(a.gold); pcap = Path(a.pcap)
    normalize(stage, silver); mapping, parser_meta, leak = build_gold(stage, silver, gold, pcap)
    result = quality(stage, pcap, Path(a.quality), mapping, parser_meta, leak); print(json.dumps(result))


if __name__ == "__main__": main()
