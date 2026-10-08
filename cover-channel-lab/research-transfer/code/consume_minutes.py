#!/usr/bin/env python3
"""Turn closed minute pcaps into packet rows on the sensor, then delete them.

The sensor cannot keep its pcaps and cannot ship them. Measured on this mirror:
169 MB/s and 173k packets/s at peak, against roughly 72 MB/s on the two fast SSH
paths and 1.6x compression on this traffic. A minute of capture is gigabytes and
the disk holds a handful of minutes. So each minute file is read here, once,
into the packed rows `export_full_packets.py` writes -- from which sessions and
every behavioural feature are rebuilt downstream, proven equal to the pcap path
by `tests/test_packet_rows_equivalence.py` -- and only then removed.

Two things make this safe to run unattended for a month.

**A file is converted only once it cannot still be growing.** `tcpdump -G 60`
has an older file closed by the time a newer one exists, and the run is over
once `capture.rc` is written. Anything else is left alone until the next sweep,
so a file being written is never half-read and then deleted.

**Deleting is conditional and the condition is counted.** The pcap goes only
after its rows are written and fsynced and the pass reported zero truncated
frames. Every minute appends a line to `consumed.jsonl` with its frame and row
counts, so the capture's own totals can be reconciled against the rows later
instead of being taken on trust.

Work is done by a pool of processes because one is not enough: a single python
pass does not keep up with the mirror at peak, while minute files are entirely
independent of each other. Session assembly stays sequential and cheap -- it
reads 35-byte rows, not packets off a wire.

  python3 consume_minutes.py --run-dir /var/tmp/office-month --rows-dir rows \\
      --salt-file ~/.office_packet_salt --workers 4 --follow
"""
from __future__ import annotations

import argparse
import json
import os
import sys
import time
from concurrent.futures import FIRST_COMPLETED, ProcessPoolExecutor, wait
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from export_full_packets import export_with_payload  # noqa: E402


def closed_pcaps(run_dir: Path, glob: str) -> list[Path]:
    """Minute files that cannot still be written to, oldest first."""
    files = sorted(run_dir.glob(glob))
    if not files:
        return []
    # The last file is only closed once the capture itself has finished.
    if (run_dir / "capture.rc").exists():
        return files
    return files[:-1]


def convert(args: tuple[str, str, str, str]) -> dict:
    """Read one pcap into rows and delete it, or leave it and say why."""
    pcap_s, rows_s, salt_s, names_s = args
    pcap, rows_dir = Path(pcap_s), Path(rows_s)
    names_dir = Path(names_s) if names_s else None
    started = time.time()
    out = rows_dir / (pcap.stem + ".pkts")
    pay = rows_dir / (pcap.stem + ".pay")
    partial = out.with_suffix(".pkts.partial")
    pay_partial = pay.with_suffix(".pay.partial")
    try:
        salt = Path(salt_s).read_bytes().strip()
        addresses: dict | None = {} if names_dir else None
        names: dict | None = {} if names_dir else None
        with partial.open("wb") as fh, pay_partial.open("wb") as pfh:
            # One read of the pcap produces both files. The payload facts have
            # to be taken here: a second pass would need the pcap, and the pcap
            # is about to be deleted.
            stats = export_with_payload(pcap, fh, pfh, salt, names, addresses)
            for handle in (fh, pfh):
                handle.flush()
                os.fsync(handle.fileno())
        # Rename only after the bytes are on the disk: a row file that exists
        # but is short would look finished to the next step.
        partial.rename(out)
        pay_partial.rename(pay)
        if names_dir is not None:
            # Deliberately NOT in the rows directory: the puller drains that one
            # to the processing VM, and this file is the one thing that must
            # stay here. Written before the pcap is removed.
            names_dir.mkdir(parents=True, exist_ok=True)
            tmp = names_dir / (pcap.stem + ".keys.json.partial")
            final = names_dir / (pcap.stem + ".keys.json")
            with tmp.open("w") as nfh:
                json.dump({"addresses": addresses, "sni": names}, nfh)
                nfh.flush()
                os.fsync(nfh.fileno())
            os.chmod(tmp, 0o600)
            tmp.rename(final)
            stats["addresses_learned"] = len(addresses or {})
        size = pcap.stat().st_size
        pcap.unlink()
        return {"pcap": pcap.name, "rows_file": out.name,
                "payload_file": pay.name, "status": "ok",
                "pcap_bytes": size, "rows_bytes": out.stat().st_size,
                "payload_bytes": pay.stat().st_size,
                "seconds": round(time.time() - started, 2), **stats}
    except Exception as exc:                       # noqa: BLE001
        partial.unlink(missing_ok=True)
        pay_partial.unlink(missing_ok=True)
        # The pcap is deliberately NOT removed: whatever went wrong, the only
        # copy of these packets is still on the disk and can be looked at.
        return {"pcap": pcap.name, "status": "error",
                "error": f"{type(exc).__name__}: {exc}",
                "seconds": round(time.time() - started, 2)}


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--run-dir", type=Path, required=True,
                    help="directory capture_office_minutes.sh writes into")
    ap.add_argument("--rows-dir", type=Path, required=True)
    ap.add_argument("--salt-file", type=Path, required=True)
    ap.add_argument("--names-dir", type=Path,
                    help="куда писать словарь ключ->адрес; остаётся на сенсоре, "
                         "не кладите его в --rows-dir")
    ap.add_argument("--glob", default="chunk-*.pcap")
    ap.add_argument("--workers", type=int, default=max(1, (os.cpu_count() or 2) - 1))
    ap.add_argument("--follow", action="store_true",
                    help="keep sweeping until the capture has finished and nothing is left")
    ap.add_argument("--poll-seconds", type=float, default=5.0)
    args = ap.parse_args()

    if not args.salt_file.exists():
        args.salt_file.write_bytes(os.urandom(32))
        args.salt_file.chmod(0o600)
    args.rows_dir.mkdir(parents=True, exist_ok=True)
    if args.names_dir:
        if args.names_dir.resolve() == args.rows_dir.resolve():
            raise SystemExit("--names-dir не должен совпадать с --rows-dir: "
                             "словарь уехал бы вместе со строками")
        args.names_dir.mkdir(parents=True, exist_ok=True)
        args.names_dir.chmod(0o700)
    journal = args.run_dir / "consumed.jsonl"

    totals = {"files": 0, "frames": 0, "packets": 0, "errors": 0,
              "pcap_bytes": 0, "rows_bytes": 0, "payload_bytes": 0}
    # Files are submitted the moment they close and collected as they finish,
    # rather than a batch at a time. Converting one file takes about as long as
    # capturing one, so a loop that waited for a whole batch before looking for
    # new work left workers idle and fell behind by seconds per file -- on a
    # sensor whose disk holds a handful of files, that ends with the capture
    # being killed by its own disk guard.
    def collect(done):
        for future in done:
            result = future.result()
            with journal.open("a") as fh:
                fh.write(json.dumps(result) + "\n")
            if result["status"] == "ok":
                totals["files"] += 1
                totals["frames"] += result["frames"]
                totals["packets"] += result["packets"]
                totals["pcap_bytes"] += result["pcap_bytes"]
                totals["rows_bytes"] += result["rows_bytes"]
                totals["payload_bytes"] += result["payload_bytes"]
            else:
                totals["errors"] += 1
                print(json.dumps(result), file=sys.stderr)

    with ProcessPoolExecutor(max_workers=args.workers) as pool:
        pending: dict = {}
        submitted: set[str] = set()

        def fresh() -> list[Path]:
            """Closed files not yet handed to a worker.

            A file whose conversion failed is deliberately left on the disk, so
            "is anything closed" is not the same question as "is there work":
            asking the first one would spin on that file forever.
            """
            return [p for p in closed_pcaps(args.run_dir, args.glob)
                    if p.name not in submitted]

        while True:
            for path in fresh():
                submitted.add(path.name)
                pending[pool.submit(
                    convert, (str(path), str(args.rows_dir), str(args.salt_file),
                              str(args.names_dir) if args.names_dir else "")
                )] = path.name
            if pending:
                # Oldest first is what keeps the disk falling: a file is only
                # deleted when its own conversion finishes.
                done, _ = wait(list(pending), timeout=args.poll_seconds,
                               return_when=FIRST_COMPLETED)
                for future in done:
                    pending.pop(future, None)
                collect(done)
            if not args.follow:
                if not pending and not fresh():
                    break
                continue
            if ((args.run_dir / "capture.rc").exists() and not pending
                    and not fresh()):
                break
            if not pending:
                time.sleep(args.poll_seconds)

    kept = totals["rows_bytes"] + totals["payload_bytes"]
    totals["shrink_vs_pcap"] = (
        round(totals["pcap_bytes"] / kept, 1) if kept else None)
    totals["status"] = "ok" if not totals["errors"] else "errors"
    totals["journal"] = str(journal)
    print(json.dumps(totals))
    return 1 if totals["errors"] else 0


if __name__ == "__main__":
    raise SystemExit(main())
