#!/usr/bin/env python3
"""Process an office capture in batches WHILE it runs, and throw away what is done.

A week of the office mirror is about 1.2 TB of packet rows; the processing VM
has a small fraction of that. So nothing waits for the capture to end: every
`--batch-seconds` of traffic is turned into tables as soon as all of it has
arrived, its tables go to Jupyter, and then its packet rows are deleted here.

What makes that safe is that a batch boundary is invisible in the result:

* **Sessions.** Open sessions are carried to the next batch on a checkpoint and
  written when they really end, however many batches later. A session too long
  to hold is written in numbered segments; `summarize` regroups them.
* **Payload.** A session carried across the boundary can close in the next
  batch with all of its payload recorded in earlier ones. Keeping the sidecar
  files for it would pin a month of them behind one tunnel open since the first
  hour, so the records themselves are carried instead: those no written row can
  take yet, and only while their flow is still open. Every record is read
  exactly once, and a batch's sidecars go with its packet rows.
* **LoTS connections.** A connection is written once, by the batch its last
  segment is in; unfinished ones are carried.
* **LoTS windows** are a function of every connection that started in a window,
  and a connection can end a week later. They are built once, at the end, from
  every batch's connections, split by host to bound memory.

`compare_batch_runs.py` is how this is proven rather than argued: the same rows
processed as one batch and as many must give the same tables.

Deletion follows verification, never the other way round:
  packet rows       after the batch verified (they are not published)
  payload sidecars  same; what open sessions still need travels in the checkpoint
  batch tables      after Spark on Jupyter counted every row into parquet
  staged shards     same, on both sides

Two guards keep a long run from breaking something: if this disk runs low the
capture on the sensor is stopped (the run then finishes what it has), and a
batch is not uploaded while Jupyter lacks room for it -- it waits and retries.
"""
from __future__ import annotations

import argparse
import gzip
import json
import os
import re
import shutil
import subprocess
import sys
import threading
import time
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parent
NAME = re.compile(r"^chunk-(\d{8}T\d{6})Z\.(pkts|pay)$")
STAMP = re.compile(r"(\d{8}T\d{6})Z")
INTERMEDIATE = ("_sessions_raw-*.csv", "_payload.csv", "_lots_conns_raw-*.csv",
                "_session_index-*.csv")


def stamp_epoch(text: str) -> float | None:
    m = STAMP.search(text)
    if not m:
        return None
    return datetime.strptime(m.group(1), "%Y%m%dT%H%M%S").replace(
        tzinfo=timezone.utc).timestamp()


def epoch_name(t: float) -> str:
    return datetime.fromtimestamp(t, timezone.utc).strftime("%Y%m%dT%H%M%SZ")


def batch_start(t: float, batch_seconds: int) -> float:
    return float(int(t // batch_seconds) * batch_seconds)


def log(msg: str, fh=None) -> None:
    line = f"{datetime.now(timezone.utc):%H:%M:%S}  {msg}"
    print(line, flush=True)
    if fh is not None:
        fh.write(line + "\n")
        fh.flush()


# --------------------------------------------------------------------------
# What is where
# --------------------------------------------------------------------------

def local_files(rows_dir: Path) -> dict[float, dict[str, Path]]:
    """stamp -> {"pkts": path, "pay": path} for complete files only."""
    out: dict[float, dict[str, Path]] = {}
    for p in rows_dir.iterdir():
        m = NAME.match(p.name)
        if m:
            out.setdefault(stamp_epoch(p.name), {})[m.group(2)] = p
    return out


def read_journal(path: Path) -> dict[float, dict]:
    out = {}
    if not path.exists():
        return out
    for line in path.read_text().splitlines():
        if line.strip():
            e = json.loads(line)
            t = stamp_epoch(e.get("pcap", "") or e.get("rows_file", ""))
            if t is not None:
                out[t] = e
    return out


def decide(next_start: float, batch_seconds: int, local: dict, journal: dict,
           pending: set[float], capture_finished: bool) -> str:
    """'wait', 'skip' (nothing here, the capture moved on), 'process' or 'final'.

    A batch is ready when nothing of it is still on the sensor, every interval
    the sensor converted has both files here, and the capture has provably moved
    past its end -- or has ended.
    """
    end = next_start + batch_seconds
    if any(t < end for t in pending):
        return "wait"
    seen = set(local) | set(journal) | pending
    moved_on = capture_finished or any(t >= end for t in seen)
    if not moved_on:
        return "wait"
    for t, e in journal.items():
        if next_start <= t < end and e.get("status") == "ok":
            have = local.get(t, {})
            if "pkts" not in have or "pay" not in have:
                return "wait"                      # still in transit
    later = any(t >= end for t in seen)
    mine = [t for t in local if next_start <= t < end]
    if capture_finished and not later:
        return "final"
    return "process" if mine else "skip"


# --------------------------------------------------------------------------
# Sensor
# --------------------------------------------------------------------------

class Sensor:
    def __init__(self, host: str, key: str, run_dir: str, rows_dir: str, journal: Path,
                 until_file: Path | None = None):
        self.host, self.key = host, key
        self.run_dir, self.rows_dir, self.journal = run_dir, rows_dir, journal
        # Consecutive capture runs share the sensor's rows directory. Once a later
        # run has started, its stamp is written here: files from then on are the
        # successor's, and waiting for them would hold this run open for ever.
        self.until_file = until_file

    def ssh(self, cmd: str, timeout: int = 60) -> str:
        r = subprocess.run(["ssh", "-o", "BatchMode=yes", "-o", "ConnectTimeout=15",
                            "-i", self.key, self.host, cmd],
                           capture_output=True, text=True, timeout=timeout)
        if r.returncode:
            raise RuntimeError(f"ssh: {r.stderr.strip()[:300]}")
        return r.stdout

    def status(self) -> tuple[bool, set[float]]:
        out = self.ssh(
            f"cat {self.run_dir}/capture.rc 2>/dev/null || echo RUNNING; "
            f"ls {self.run_dir} {self.rows_dir} 2>/dev/null | grep -E '^chunk-' || true")
        lines = out.split()
        finished = bool(lines) and lines[0] != "RUNNING"
        pending = {t for name in lines[1:] if (t := stamp_epoch(name)) is not None}
        until = (stamp_epoch(self.until_file.read_text().strip())
                 if self.until_file and self.until_file.exists() else None)
        if until is not None:
            pending = {t for t in pending if t < until}
        tmp = self.journal.with_suffix(".tmp")
        subprocess.run(["scp", "-q", "-o", "BatchMode=yes", "-i", self.key,
                        f"{self.host}:{self.run_dir}/consumed.jsonl", str(tmp)],
                       check=True, timeout=300)
        os.replace(tmp, self.journal)
        return finished, pending

    def stop_capture(self) -> None:
        # The same signal the sensor's own disk guard sends: tcpdump closes the
        # current file cleanly and the converter finishes what is on disk.
        self.ssh(f"ps -eo pid=,comm=,args= | awk -v run={self.run_dir} "
                 "'$2 == \"tcpdump\" && index($0, \"-i enp0s4\") && index($0, run) {print $1}' "
                 "| xargs -r sudo -n kill -INT")


# --------------------------------------------------------------------------
# One batch
# --------------------------------------------------------------------------

def run(cmd: list, logf, **kw) -> dict:
    """Run a step; its last JSON line is its report."""
    logf.write("$ " + " ".join(str(c) for c in cmd) + "\n")
    r = subprocess.run([str(c) for c in cmd], capture_output=True, text=True, **kw)
    logf.write(r.stdout[-20000:] + r.stderr[-20000:])
    logf.flush()
    if r.returncode:
        raise RuntimeError(f"{Path(str(cmd[1])).name} failed: {(r.stdout + r.stderr)[-800:]}")
    for line in reversed(r.stdout.strip().splitlines()):
        if line.startswith("{"):
            try:
                return json.loads(line)
            except ValueError:
                break
    return {}


class Batches:
    def __init__(self, args):
        self.a = args
        self.work: Path = args.work
        self.bdir = self.work / "batches"
        self.bdir.mkdir(parents=True, exist_ok=True)
        (self.work / "lots_conns").mkdir(exist_ok=True)
        self.logf = (self.work / "batches.log").open("a")
        self.stop = threading.Event()
        self.failed: str | None = None
        self.capture_stopped_for_disk = False

    # -- bookkeeping -------------------------------------------------------
    def dirs(self, marker: str) -> list[Path]:
        """Batch directories (named by their start) that carry this marker."""
        return sorted(p.parent for p in self.bdir.glob(f"*/{marker}")
                      if stamp_epoch(p.parent.name) is not None)

    def last_processed(self) -> Path | None:
        done = self.dirs("verified.json")
        return done[-1] if done else None

    def next_start(self, local: dict, journal: dict) -> float | None:
        last = self.last_processed()
        skipped = sorted(self.bdir.glob("*/skipped"))
        marks = [stamp_epoch(p.name) for p in ([last] if last else [])]
        marks += [stamp_epoch(p.parent.name) for p in skipped]
        if marks:
            return max(marks) + self.a.batch_seconds
        known = set(local) | set(journal)
        return batch_start(min(known), self.a.batch_seconds) if known else None

    # -- processing --------------------------------------------------------
    def process(self, start: float, final: bool, local: dict) -> None:
        a = self.a
        name = epoch_name(start)
        out = self.bdir / name
        if out.exists():
            shutil.rmtree(out)                       # an earlier attempt that failed
        out.mkdir()
        logf = (out / "steps.log").open("w")
        prev = self.last_processed()
        end = start + a.batch_seconds
        stamps = sorted(t for t in local if start <= t < end)
        staging = out / "_rows"
        staging.mkdir()
        for t in stamps:
            for kind in ("pkts", "pay"):
                p = local[t][kind]
                (staging / p.name).symlink_to(p.resolve())
        py = sys.executable
        t0 = time.time()

        report: dict = {"batch": name, "final": final, "intervals": len(stamps)}
        if stamps:
            audit = run([py, ROOT / "audit_row_series.py", "--rows-dir", staging,
                         "--journal", a.journal, "--rotate-seconds", a.interval_seconds,
                         "--out-json", out / "rows_audit.json"], logf)
            report["missing_intervals"] = audit.get("missing_minutes", [])
            # A gap at the boundary with the previous batch is invisible to an
            # audit that only sees this batch, so it is checked here.
            if prev is not None:
                prev_last = json.loads((prev / "batch.json").read_text()).get("last_stamp")
                if prev_last is not None:
                    gap = stamps[0] - prev_last
                    if gap > a.interval_seconds:
                        report["missing_intervals"] = [
                            epoch_name(prev_last + k * a.interval_seconds)
                            for k in range(1, int(gap // a.interval_seconds))
                        ] + report["missing_intervals"]
            report["conversion_errors"] = json.loads(
                (out / "rows_audit.json").read_text()).get("conversion_errors", [])

        # The session pass runs as N workers, each on the flows of its shard:
        # a session's features depend on its own packets only, so the split
        # changes nothing but the wall time. Each worker keeps its own
        # checkpoint, and the split may not change between batches.
        n = a.shards
        procs = []
        for k in range(n):
            state = ["--state-in", prev / f"session_state-{k}.pkl"] if prev else []
            state += ["--finalize"] if final else [
                "--state-out", out / f"session_state-{k}.pkl",
                "--live-out", out / f"live_flows-{k}.csv"]
            cmd = [py, ROOT / "extract_office_sessions.py", "--pcap-dir", staging,
                   "--glob", "*.pkts", "--min-packets", a.min_packets,
                   "--shard-index", k, "--shard-count", n,
                   "--out-sessions", out / f"_sessions_raw-{k}.csv",
                   "--out-lots-conns", out / f"_lots_conns_raw-{k}.csv",
                   "--session-index", out / f"_session_index-{k}.csv",
                   "--stats-json", out / f"sessions.stats-{k}.json", *state]
            logf.write("$ " + " ".join(str(c) for c in cmd) + "\n")
            logf.flush()
            procs.append(subprocess.Popen([str(c) for c in cmd], stdout=logf,
                                          stderr=subprocess.STDOUT))
        codes = [p.wait() for p in procs]
        if any(codes):
            raise RuntimeError(f"extract_office_sessions.py failed in shards "
                               f"{[k for k, c in enumerate(codes) if c]}")
        parts = [json.loads((out / f"sessions.stats-{k}.json").read_text()) for k in range(n)]
        sessions = {key: sum(p.get(key, 0) for p in parts)
                    for key in ("packets", "rows_written", "pending_at_end",
                                "pending_packets_held", "segments_emitted")}
        sessions["seconds"] = max(p.get("seconds", 0) for p in parts)
        (out / "sessions.stats.json").write_text(json.dumps({"shards": parts, **sessions}, indent=2))
        if stamps:
            audit = json.loads((out / "rows_audit.json").read_text())
            if audit["unaccounted"]:
                raise RuntimeError("frames unaccounted for in the capture journal")
            if sessions["packets"] != audit["rows_on_disk"]:
                raise RuntimeError("session pass did not read every row on disk")
            report["packets"] = sessions["packets"]
            report["frames"] = audit["frames_total"]
        # Minute-by-minute volume of every internal host, from the rows while
        # they are still here: the time-true volume a burst needs (sessions
        # stamp all their bytes at their start).
        if stamps:
            vol = run([a.parquet_python, ROOT / "host_minutes.py", "--rows-dir", staging,
                       "--out-csv", out / "office_host_minutes.csv"], logf)
            if vol.get("packets") != sessions["packets"]:
                raise RuntimeError("host_minutes did not read every row on disk")
            report["host_minutes"] = vol.get("host_minutes", 0)
        report["sessions_written"] = sessions.get("rows_written", 0)
        report["open_sessions_carried"] = sessions.get("pending_at_end", 0)
        report["open_packets_carried"] = sessions.get("pending_packets_held", 0)
        live = [out / f"live_flows-{k}.csv" for k in range(n)]
        if final:
            for f in live:
                f.write_text("ip_a,port_a,ip_b,port_b,proto,seg_start\n")
        pending_in = ["--pending-in", prev / "pending_records.pkl"] if prev else []
        payload = run([py, ROOT / "merge_payload_sidecars.py", "--sidecar-dir", staging,
                       "--interval-seconds", a.interval_seconds,
                       "--session-index", *[out / f"_session_index-{k}.csv" for k in range(n)],
                       "--out-csv", out / "_payload.csv",
                       "--stats-json", out / "payload.stats.json",
                       "--live", *live,
                       "--pending-out", out / "pending_records.pkl", *pending_in], logf)
        report["payload_records_waiting"] = payload.get("records_pending_out")

        conns_carry = ["--conns-carry-in", prev / "conns_carry.json"] if prev and (prev / "conns_carry.json").exists() else []
        if not final:
            conns_carry += ["--conns-carry-out", out / "conns_carry.json"]
        if prev and (prev / "facts_carry.json").exists():
            conns_carry += ["--facts-carry-in", prev / "facts_carry.json"]
        if not final:
            conns_carry += ["--facts-carry-out", out / "facts_carry.json"]
        join = run([py, ROOT / "finalize_tables.py",
                    "--sessions", *[out / f"_sessions_raw-{k}.csv" for k in range(n)],
                    "--payload", out / "_payload.csv",
                    "--lots-conns-in", *[out / f"_lots_conns_raw-{k}.csv" for k in range(n)],
                    "--out-sessions", out / "office_sessions.csv",
                    "--out-lots-conns", out / "office_lots_conns.csv",
                    "--stats-json", out / "join.stats.json", *conns_carry], logf)
        if a.extra_tables:
            run([py, ROOT / "build_host20_windows.py", "--sessions", out / "office_sessions.csv",
                 "--out-csv", out / "office_host20_windows.csv",
                 "--stats-json", out / "host20.stats.json", "--include-partial"], logf)

        # The payload gate: a session can end up without payload facts only
        # through a record shared with another instance of its flow. The two
        # sides of that can fall in different batches -- the record is read,
        # and counted as contested, where it lies; the instance it could not
        # reach is written when it ends, possibly batches later -- so the gate
        # holds on running totals, not per batch.
        pay = json.loads((out / "payload.stats.json").read_text())
        missing = join["sessions_without_payload"]
        ceiling = pay.get("sessions_possibly_starved", 0)
        before = json.loads((prev / "batch.json").read_text()) if prev else {}
        cum_missing = before.get("cum_sessions_without_payload", 0) + missing
        cum_ceiling = before.get("cum_payload_ceiling", 0) + ceiling
        report.update(sessions_without_payload=missing, payload_ceiling=ceiling,
                      cum_sessions_without_payload=cum_missing, cum_payload_ceiling=cum_ceiling,
                      lots_conns_written=join["lots_conns_written"],
                      lots_conns_carried_out=join.get("lots_conns_carried_out"))
        if cum_missing > cum_ceiling:
            raise RuntimeError(f"{cum_missing} sessions without payload so far, "
                               f"only {cum_ceiling} explainable")

        # One table leaves this host unless the model-specific ones are asked
        # for: the sessions, every feature in one row per session (segment).
        # The LoTS connections are still assembled -- the carry across batches
        # needs them -- but not published.
        if not a.extra_tables:
            (out / "office_lots_conns.csv").unlink(missing_ok=True)
        tables = {}
        for path in sorted(out.glob("office_*.csv")):
            with path.open("rb") as fh:
                tables[path.name] = {"rows": max(sum(1 for _ in fh) - 1, 0)}
        # Rows are counted as lines here and as CSV records by the stager;
        # arrays are space-separated and no field holds a newline, so the two agree.
        report["tables"] = tables
        report["last_stamp"] = stamps[-1] if stamps else (
            json.loads((prev / "batch.json").read_text()).get("last_stamp") if prev else None)
        report["seconds"] = round(time.time() - t0, 1)

        # The LoTS connections stay here, small and compressed, for the windows
        # that can only be built at the end.
        if a.extra_tables:
            with (out / "office_lots_conns.csv").open("rb") as src, \
                 gzip.open(self.work / "lots_conns" / f"{name}.csv.gz", "wb") as dst:
                shutil.copyfileobj(src, dst)

        (out / "batch.json").write_text(json.dumps(report, indent=2) + "\n")
        (out / "verified.json").write_text(json.dumps({"status": "verified", "tables": tables}) + "\n")
        logf.close()

        # ---- what this batch no longer needs --------------------------------
        for pattern in INTERMEDIATE:
            for f in out.glob(pattern):
                f.unlink()
        shutil.rmtree(staging)
        if prev is not None:
            for pattern in ("session_state-*.pkl", "conns_carry.json", "facts_carry.json",
                            "pending_records.pkl",
                            "live_flows-*.csv"):
                for f in prev.glob(pattern):
                    f.unlink()
        if not a.keep_rows:
            for t in stamps:
                local[t]["pkts"].unlink()
                local[t]["pay"].unlink()
        if final:
            (self.work / "processing.done").write_text(name + "\n")
        log(f"пакет {name}: {report.get('packets', 0)} пакетов, "
            f"{report['sessions_written']} строк, открытых перенесено "
            f"{report['open_sessions_carried']}, {report['seconds']} с"
            + (" — ПОСЛЕДНИЙ" if final else ""), self.logf)

    def free_gb(self) -> float:
        return shutil.disk_usage(self.work).free / 2**30

    def processing_loop(self, sensor: Sensor | None) -> None:
        a = self.a
        while not self.stop.is_set():
            if (self.work / "processing.done").exists():
                return
            if sensor is not None:
                try:
                    finished, pending = sensor.status()
                except Exception as exc:                          # noqa: BLE001
                    log(f"сенсор не ответил: {exc}; повтор", self.logf)
                    time.sleep(60)
                    continue
                if (not finished and not self.capture_stopped_for_disk
                        and self.free_gb() < a.min_free_gb):
                    log(f"СВОБОДНО {self.free_gb():.0f} ГиБ < {a.min_free_gb}: "
                        "останавливаю захват на сенсоре", self.logf)
                    sensor.stop_capture()
                    self.capture_stopped_for_disk = True
            else:
                finished, pending = True, set()
            local = local_files(a.rows_dir)
            journal = read_journal(a.journal)
            # A pcap whose conversion failed stays on the sensor to be looked
            # at; it is a named loss in its batch, not something to wait for.
            pending -= {t for t, e in journal.items() if e.get("status") != "ok"}
            # A pcap that failed once and was converted again later stays on the
            # sensor too; once both of its files are here it is done, not pending.
            pending -= {t for t, e in journal.items() if e.get("status") == "ok"
                        and {"pkts", "pay"} <= set(local.get(t, {}))}
            start = self.next_start(local, journal)
            if start is None:
                if finished and sensor is not None:
                    log("захват кончился, а данных нет", self.logf)
                    self.failed = "no data"
                    return
                time.sleep(a.poll_seconds)
                continue
            # A pcap left on the sensor whose interval lies before the next
            # batch belongs to a batch already verified (its rows were used and
            # then deleted here), so it cannot hold up the batches after it.
            pending = {t for t in pending if t >= start}
            verdict = decide(start, a.batch_seconds, local, journal, pending, finished)
            if verdict == "wait":
                time.sleep(a.poll_seconds)
                continue
            if verdict == "skip":
                d = self.bdir / epoch_name(start)
                d.mkdir(exist_ok=True)
                (d / "skipped").write_text("no intervals; the capture moved on\n")
                continue
            try:
                self.process(start, verdict == "final", local)
            except Exception as exc:                              # noqa: BLE001
                self.failed = f"пакет {epoch_name(start)}: {exc}"
                log("ОШИБКА " + self.failed, self.logf)
                self.stop.set()
                return

    # -- publishing ----------------------------------------------------------
    def jrun(self, code: str, timeout: int = 3600) -> str:
        env = dict(os.environ, PYTHONPATH=str(self.a.pylibs), JRUN_TIMEOUT=str(timeout))
        for line in self.a.jupyter_env.read_text().splitlines():
            if "=" in line and not line.lstrip().startswith("#"):
                k, v = line.split("=", 1)
                env[k.strip()] = v.strip()
        r = subprocess.run([sys.executable, ROOT / "jrun.py"], input=code, text=True,
                           capture_output=True, env=env, timeout=timeout + 300)
        if r.returncode:
            raise RuntimeError(f"jupyter: {(r.stdout + r.stderr)[-800:]}")
        return r.stdout

    def jupyter_free_gb(self) -> float:
        out = self.jrun("import os, shutil\nprint(shutil.disk_usage(os.path.expanduser('~')).free / 2**30)", 300)
        return float(out.strip().splitlines()[-1])

    def publish(self, d: Path, batch_id: str | None = None) -> None:
        a = self.a
        batch_id = batch_id or d.name
        staged = self.work / "staged" / batch_id
        if staged.exists():
            shutil.rmtree(staged)
        run([sys.executable, ROOT / "stage_for_cosmolake.py", "--hour-dir", d,
             "--out-dir", staged], self.logf)
        size_gb = sum(p.stat().st_size for p in staged.rglob("*") if p.is_file()) / 2**30
        # Room for the shards, the parquet made from them, and a margin.
        while True:
            free = self.jupyter_free_gb()
            if free >= 2.5 * size_gb + a.jupyter_margin_gb:
                break
            log(f"в Jupyter свободно {free:.1f} ГиБ, пакету {batch_id} нужно "
                f"{2.5 * size_gb + a.jupyter_margin_gb:.1f}; жду", self.logf)
            if self.stop.wait(600):
                return
        remote = f"{a.remote_dir}/staged/{batch_id}"
        run([sys.executable, ROOT / "upload_to_jupyter.py", "--config", a.jupyter_env,
             "--local-dir", staged, "--remote-dir", remote, "--verify"], self.logf)
        out = self.jrun(f"""
import json, os, shutil, subprocess, sys
home = os.path.expanduser("~")
run = f"{{home}}/{a.remote_dir}"
b = f"{{run}}/staged/{batch_id}"
r = subprocess.run([sys.executable, f"{{home}}/{a.remote_bin}/spark_office_tables.py", "convert",
                    "--batch-dir", b, "--batch-id", "{batch_id}", "--out-root", f"{{run}}/parquet",
                    "--summary-json", f"{{run}}/summaries/{batch_id}.json",
                    "--cores", "4", "--driver-memory", "5g"], capture_output=True, text=True)
if r.returncode:
    print(json.dumps({{"status": "spark_failed", "stderr": r.stderr[-1500:]}}))
else:
    s = json.load(open(f"{{run}}/summaries/{batch_id}.json"))
    ok = s["converted"]["all_rows_accounted_for"]
    if ok:
        shutil.copy(f"{{b}}/manifest.json", f"{{run}}/summaries/{batch_id}.manifest.json")
        shutil.rmtree(b)          # the shards; the parquet holds every row
    print(json.dumps({{"status": "ok" if ok else "rows_mismatch", "tables": s["tables"]}}))
""")
        report = json.loads(out[out.index("{"):out.rindex("}") + 1])
        if report.get("status") != "ok":
            raise RuntimeError(f"Spark по пакету {batch_id}: {json.dumps(report)[:800]}")
        if a.session_store_root and batch_id != "lots-windows":
            # Optional second publication. Keep local staged files and leave
            # published.json absent until the session store verifies its copy.
            # A retry is safe: the store checks an existing batch instead of
            # appending another copy of it.
            store_root = a.session_store_root
            if not store_root.startswith("/"):
                store_root = f"{{home}}/{store_root}"
            out = self.jrun(f"""
import json, os, subprocess, sys
home = os.path.expanduser("~")
source = f"{{home}}/{a.remote_dir}/parquet/office_sessions.parquet"
manifest = f"{{home}}/{a.remote_dir}/summaries/{batch_id}.manifest.json"
root = {json.dumps(store_root)}.replace("{{home}}", home)
r = subprocess.run([sys.executable,
                    f"{{home}}/{a.remote_bin}/office_session_store.py",
                    "--cores", "2", "publish", "--source", source,
                    "--root", root, "--run-id", {json.dumps(a.session_store_run_id)},
                    "--batch-id", {json.dumps(batch_id)},
                    "--source-manifest", manifest],
                   capture_output=True, text=True)
print(json.dumps({{"status": "ok" if r.returncode == 0 else "store_failed",
                  "stdout": r.stdout[-1000:], "stderr": r.stderr[-1200:]}}))
""")
            store_report = json.loads(out[out.index("{"):out.rindex("}") + 1])
            if store_report.get("status") != "ok":
                raise RuntimeError(f"session store по пакету {batch_id}: {json.dumps(store_report)[:800]}")
        shutil.rmtree(staged)
        (d / "published.json").write_text(json.dumps(report, indent=2) + "\n")
        self.drop_tables_if_done(d)
        log(f"пакет {batch_id} в parquet, строки сошлись", self.logf)

    def drop_tables_if_done(self, d: Path) -> None:
        """A batch's CSV tables go once every enabled sink has its copy."""
        a = self.a
        if a.keep_tables:
            return
        if a.publish and not (d / "published.json").exists():
            return
        if a.cosmolake and not (d / "cosmolake.json").exists():
            return
        for p in d.glob("office_*.csv"):
            p.unlink()

    # -- Cosmolake: parquet here, Bronze through the API, Silver/Gold on the cluster
    def cosmolake_bronze(self, d: Path) -> None:
        """Parquet and Bronze: needs only the API, never waits for Jupyter."""
        a = self.a
        batch_id = d.name
        cdir = self.work / "cosmolake" / batch_id
        if not (cdir / "manifest.json").exists():
            run([a.parquet_python, ROOT / "office_to_parquet.py", "--batch-dir", d,
                 "--out-dir", cdir, "--run-id", a.run_id, "--batch-id", batch_id,
                 "--journal", a.journal, "--rotate-seconds", a.interval_seconds,
                 "--batch-seconds", a.batch_seconds], self.logf)
        if not (cdir / "bronze.json").exists():
            run([sys.executable, ROOT / "cosmolake_bronze.py", "--parquet-dir", cdir,
                 "--env-file", a.cosmolake_env,
                 *(["--supersede"] if a.cosmolake_supersede else [])], self.logf)
            log(f"пакет {batch_id} в Bronze", self.logf)

    def cosmolake_publish(self, d: Path) -> None:
        """Silver and Gold on the cluster, through Jupyter."""
        a = self.a
        batch_id = d.name
        cdir = self.work / "cosmolake" / batch_id
        self.cosmolake_bronze(d)
        if not self.lake_scripts_uploaded:
            for pattern in ("cosmolake_gold.py", "office_features.py", "office_dictionary.py",
                            "office_feature_sets.toml"):
                run([sys.executable, ROOT / "upload_to_jupyter.py", "--config", a.jupyter_env,
                     "--local-dir", ROOT, "--remote-dir", a.remote_bin,
                     "--glob", pattern, "--verify"], self.logf)
            self.lake_scripts_uploaded = True
        manifest = (cdir / "manifest.json").read_text()
        bronze = (cdir / "bronze.json").read_text()
        out = self.jrun(f"""
import json, os, subprocess, sys, tempfile
home = os.path.expanduser("~")
tmp = tempfile.mkdtemp()
open(f"{{tmp}}/manifest.json", "w").write({json.dumps(manifest)})
open(f"{{tmp}}/bronze.json", "w").write({json.dumps(bronze)})
bin_ = f"{{home}}/{a.remote_bin}"
env = dict(os.environ, PYTHONPATH=bin_)
steps = [["load", "--bronze-json", f"{{tmp}}/bronze.json", "--manifest", f"{{tmp}}/manifest.json",
          "--bucket", {json.dumps(a.cosmolake_bucket)}],
         ["gold", "--batch", {json.dumps(a.run_id)}, {json.dumps(batch_id)}]]
report = {{"status": "ok"}}
for step in steps:
    r = subprocess.run([sys.executable, f"{{bin_}}/cosmolake_gold.py", "--root", {json.dumps(a.cosmolake_root)}, *step],
                       capture_output=True, text=True, env=env)
    if r.returncode:
        report = {{"status": step[0] + "_failed", "stderr": r.stderr[-1500:]}}
        break
    report[step[0]] = json.loads(r.stdout.strip().splitlines()[-1])
print(json.dumps(report))
""", 7200)
        report = json.loads(out[out.index("{"):out.rindex("}") + 1])
        if report.get("status") != "ok":
            raise RuntimeError(f"Cosmolake по пакету {batch_id}: {json.dumps(report)[:900]}")
        report["bronze"] = json.loads(bronze)
        (d / "cosmolake.json").write_text(json.dumps(report, indent=2, ensure_ascii=False) + "\n")
        shutil.rmtree(cdir)
        self.drop_tables_if_done(d)
        loaded = report["load"]["tables"]["office_sessions"]
        log(f"пакет {batch_id} в Cosmolake: {loaded['rows']} строк, "
            f"{loaded['packets']} пакетов, Silver и Gold обновлены", self.logf)

    def cosmolake_loop(self) -> None:
        # Two speeds. Parquet and Bronze follow every verified batch at once --
        # they need only the Cosmolake API. Silver and Gold need Jupyter, which
        # can be asleep for hours; they catch up, oldest batch first, when it
        # answers, and a batch's CSV tables stay here until they have.
        self.lake_scripts_uploaded = False
        jupyter_retry_at = 0.0
        while True:
            todo = [d for d in self.dirs("verified.json")
                    if not (d / "cosmolake.json").exists() and (d / "office_sessions.csv").exists()]
            if not todo:
                if (self.work / "processing.done").exists() or self.stop.is_set():
                    return
                self.stop.wait(30)
                continue
            for d in todo:
                if not (self.work / "cosmolake" / d.name / "bronze.json").exists():
                    try:
                        self.cosmolake_bronze(d)
                    except Exception as exc:                      # noqa: BLE001
                        log(f"Bronze: {d.name} не выгружен: {str(exc)[-400:]}; повтор", self.logf)
            if time.time() >= jupyter_retry_at:
                try:
                    self.cosmolake_publish(todo[0])
                    continue
                except Exception as exc:                          # noqa: BLE001
                    log(f"Silver/Gold: {todo[0].name} не обновлён ({str(exc)[-300:]}); "
                        "повтор через 10 мин, Bronze идёт дальше", self.logf)
                    jupyter_retry_at = time.time() + 600
            if self.stop.wait(30):
                return

    def publish_loop(self) -> None:
        a = self.a
        # Jupyter being unreachable -- an expired token, a restarted pod -- must
        # never stop the processing: batches keep being made and verified here,
        # and are published once it answers again.
        while True:
            try:
                run([sys.executable, ROOT / "upload_to_jupyter.py", "--config", a.jupyter_env,
                     "--local-dir", ROOT, "--remote-dir", a.remote_bin,
                     "--glob", "spark_office_tables.py", "--verify"], self.logf)
                if a.session_store_root:
                    run([sys.executable, ROOT / "upload_to_jupyter.py", "--config", a.jupyter_env,
                         "--local-dir", ROOT, "--remote-dir", a.remote_bin,
                         "--glob", "office_session_store.py", "--verify"], self.logf)
                break
            except Exception as exc:                              # noqa: BLE001
                log(f"Jupyter недоступен ({str(exc)[-160:]}); обработка идёт, "
                    "выгрузка повторится через 10 мин", self.logf)
                if self.stop.wait(600):
                    return
        while True:
            todo = [d for d in self.dirs("verified.json") if not (d / "published.json").exists()]
            if not todo:
                if (self.work / "processing.done").exists() or self.stop.is_set():
                    return
                self.stop.wait(30)
                continue
            try:
                self.publish(todo[0])
            except Exception as exc:                              # noqa: BLE001
                log(f"выгрузка {todo[0].name} не удалась: {exc}; повтор через 10 мин", self.logf)
                if self.stop.wait(600):
                    return

    # -- the end ---------------------------------------------------------------
    def windows(self) -> Path:
        d = self.bdir / "lots-windows"
        d.mkdir(exist_ok=True)
        files = sorted((self.work / "lots_conns").glob("*.csv.gz"))
        run([sys.executable, ROOT / "build_lots_windows.py", "--conns", *files,
             "--shards", self.a.window_shards,
             "--out-csv", d / "office_lots_windows.csv",
             "--stats-json", d / "lots_windows.stats.json"], self.logf)
        (d / "verified.json").write_text(json.dumps({"status": "verified"}) + "\n")
        return d

    def summarize(self) -> dict:
        a = self.a
        out = self.jrun(f"""
import json, os, subprocess, sys
home = os.path.expanduser("~")
run = f"{{home}}/{a.remote_dir}"
r = subprocess.run([sys.executable, f"{{home}}/{a.remote_bin}/spark_office_tables.py", "summarize",
                    "--out-root", f"{{run}}/parquet", "--summary-json", f"{{run}}/summary.json",
                    "--cores", "4", "--driver-memory", "5g"], capture_output=True, text=True)
print(json.dumps({{"status": "spark_failed", "stderr": r.stderr[-1500:]}}) if r.returncode
      else open(f"{{run}}/summary.json").read().replace("\\n", " "))
""")
        return json.loads(out[out.index("{"):out.rindex("}") + 1])


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--rows-dir", type=Path, required=True,
                    help="where packet rows and sidecars arrive")
    ap.add_argument("--journal", type=Path, required=True,
                    help="the sensor's conversion journal (refreshed from the sensor in --sensor mode)")
    ap.add_argument("--work", type=Path, required=True)
    ap.add_argument("--batch-seconds", type=int, default=3 * 3600)
    ap.add_argument("--interval-seconds", type=int, default=20)
    ap.add_argument("--min-packets", type=int, default=int(os.environ.get("OFFICE_MIN_PACKETS", "1")))
    ap.add_argument("--poll-seconds", type=int, default=60)
    ap.add_argument("--min-free-gb", type=float, default=40.0)
    ap.add_argument("--keep-rows", action="store_true",
                    help="do not delete packet rows and sidecars (for a comparison run)")
    ap.add_argument("--keep-tables", action="store_true",
                    help="keep batch tables here after they are in parquet")
    ap.add_argument("--extra-tables", action="store_true",
                    help="also build and publish the LoTS connections/windows and host20 windows")
    ap.add_argument("--window-shards", type=int, default=32)
    ap.add_argument("--shards", type=int, default=3,
                    help="session-pass workers; fixed for the whole run (checkpoints are per shard)")
    sensor = ap.add_argument_group("live capture")
    sensor.add_argument("--sensor", help="user@host; without it the rows are taken as complete")
    sensor.add_argument("--sensor-key")
    sensor.add_argument("--sensor-run-dir")
    sensor.add_argument("--sensor-rows-dir")
    pub = ap.add_argument_group("publishing")
    pub.add_argument("--publish", action="store_true")
    pub.add_argument("--jupyter-env", type=Path)
    pub.add_argument("--pylibs", type=Path)
    pub.add_argument("--remote-dir", help="under the Jupyter home, e.g. work/office_iter/run-X")
    pub.add_argument("--remote-bin", default="work/office_iter/bin")
    pub.add_argument("--session-store-root",
                     help="optional Jupyter path for a global time-addressable session dataset")
    pub.add_argument("--session-store-run-id",
                     help="globally unique run id for --session-store-root")
    pub.add_argument("--jupyter-margin-gb", type=float, default=5.0)
    cl = ap.add_argument_group("Cosmolake (parquet -> Bronze API -> Silver/Gold via Jupyter Spark)")
    cl.add_argument("--cosmolake", action="store_true")
    cl.add_argument("--cosmolake-env", type=Path,
                    help="COSMOLAKE_API_URL, COSMOLAKE_TOKEN, COSMOLAKE_AUTH_SCHEME, COSMOLAKE_SOURCE_NAME")
    cl.add_argument("--cosmolake-root", help="s3a:// prefix of Silver and Gold")
    cl.add_argument("--cosmolake-bucket", help="S3 bucket that holds Bronze")
    cl.add_argument("--parquet-python", default=sys.executable,
                    help="python with pyarrow and pandas, for office_to_parquet.py")
    cl.add_argument("--run-id", help="globally unique run id (default: from --work run-<id>)")
    cl.add_argument("--cosmolake-supersede", action="store_true",
                    help="batches were re-processed on purpose: replace what Bronze holds for them")
    args = ap.parse_args()
    if args.publish and not (args.jupyter_env and args.pylibs and args.remote_dir):
        ap.error("--publish needs --jupyter-env, --pylibs and --remote-dir")
    if args.cosmolake:
        if not (args.cosmolake_env and args.cosmolake_root and args.cosmolake_bucket
                and args.jupyter_env and args.pylibs):
            ap.error("--cosmolake needs --cosmolake-env, --cosmolake-root, --cosmolake-bucket, "
                     "--jupyter-env and --pylibs")
        if not args.run_id:
            m = re.fullmatch(r"run-(.+)", args.work.resolve().name)
            if not m:
                ap.error("--cosmolake needs --run-id (the work directory is not run-<id>)")
            args.run_id = m.group(1)
    if bool(args.session_store_root) != bool(args.session_store_run_id):
        ap.error("--session-store-root and --session-store-run-id must be given together")
    args.work.mkdir(parents=True, exist_ok=True)

    b = Batches(args)
    sensor = None
    if args.sensor:
        sensor = Sensor(args.sensor, args.sensor_key, args.sensor_run_dir,
                        args.sensor_rows_dir, args.journal, args.work / "pull_until")
    publisher = None
    if args.publish:
        publisher = threading.Thread(target=b.publish_loop, daemon=True)
        publisher.start()
    lake = None
    if args.cosmolake:
        lake = threading.Thread(target=b.cosmolake_loop, daemon=True)
        lake.start()
    b.processing_loop(sensor)
    if publisher is not None:
        publisher.join()
    if lake is not None:
        lake.join()
    if b.failed:
        log(f"ОСТАНОВЛЕНО: {b.failed}", b.logf)
        return 1

    if args.extra_tables:
        if not (args.work / "windows.done").exists():
            b.windows()
            (args.work / "windows.done").write_text("ok\n")
        wd = b.bdir / "lots-windows"
        if args.publish and not (wd / "published.json").exists():
            b.publish(wd, "lots-windows")
    report = {"batches": [json.loads((d / "batch.json").read_text())
                          for d in b.dirs("batch.json")]}
    if args.publish:
        report["summary"] = b.summarize()
    (args.work / "run_report.json").write_text(json.dumps(report, indent=2) + "\n")
    log("всё готово", b.logf)
    return 0


if __name__ == "__main__":
    sys.path.insert(0, str(ROOT))
    raise SystemExit(main())
