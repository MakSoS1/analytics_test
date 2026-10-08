#!/usr/bin/env python3
"""Follow the exporter's JSONL across restarts and rotations, losing nothing.

`iter_jsonl` opens a file, reads to EOF and returns. On a sensor that file is
appended to continuously, rotated underneath the reader, and the process that
reads it gets restarted. Each of those silently costs decisions, and a lost
decision is not a benign verdict — so each is counted here rather than absorbed.

The ordering that makes a crash safe: read, process, **then** commit. A
checkpoint written before the records were acted on turns a crash into a gap;
written after, it turns a crash into a repeat, and a repeat is what the alert
dedup already handles.
"""
from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any, Iterator


class CheckpointedTail:
    """A resumable reader for a file that is appended to and rotated."""

    def __init__(self, path: str | Path, checkpoint: str | Path) -> None:
        self.path = Path(path)
        self.checkpoint = Path(checkpoint)
        self.counters: dict[str, int] = {"records": 0, "malformed": 0, "rotations": 0,
                                         "truncations": 0, "bytes": 0}
        self._offset, self._inode = self._load()
        self._pending_offset = self._offset
        self._pending_inode = self._inode
        self._carry = ""

    # ---- checkpoint ------------------------------------------------------
    def _load(self) -> tuple[int, int | None]:
        try:
            d = json.loads(self.checkpoint.read_text())
            return int(d["offset"]), d.get("inode")
        except (OSError, ValueError, KeyError, TypeError):
            # A checkpoint we cannot read is not a position we may guess at.
            # Starting over repeats work; inventing an offset skips records.
            return 0, None

    def commit(self) -> None:
        """Persist the position, atomically, only after the caller is done."""
        tmp = self.checkpoint.with_suffix(self.checkpoint.suffix + ".part")
        tmp.write_text(json.dumps({"offset": self._pending_offset,
                                   "inode": self._pending_inode}))
        os.replace(tmp, self.checkpoint)
        self._offset, self._inode = self._pending_offset, self._pending_inode

    # ---- reading ---------------------------------------------------------
    def read_available(self) -> Iterator[dict[str, Any]]:
        try:
            st = self.path.stat()
        except OSError:
            return                      # the exporter has not created it yet

        offset = self._offset
        if self._inode is not None and st.st_ino != self._inode:
            # Rotated: this is a different file, and it starts at zero.
            self.counters["rotations"] += 1
            offset = 0
        elif st.st_size < offset:
            # Truncated in place — same inode, fewer bytes than we had read.
            self.counters["truncations"] += 1
            offset = 0
        if offset == 0:
            self._carry = ""

        with self.path.open("r", errors="replace") as fh:
            fh.seek(offset)
            chunk = fh.read()
            consumed = fh.tell()

        data = self._carry + chunk
        lines = data.split("\n")
        # The last element is whatever follows the final newline: either empty,
        # or a record the exporter has not finished writing.
        self._carry = lines.pop()
        # Only bytes belonging to complete lines may be checkpointed.
        self._pending_offset = consumed - len(self._carry.encode(errors="replace"))
        self._pending_inode = st.st_ino
        self.counters["bytes"] += consumed - offset

        for line in lines:
            line = line.strip()
            if not line:
                continue
            try:
                rec = json.loads(line)
            except ValueError:
                self.counters["malformed"] += 1
                continue
            self.counters["records"] += 1
            yield rec
