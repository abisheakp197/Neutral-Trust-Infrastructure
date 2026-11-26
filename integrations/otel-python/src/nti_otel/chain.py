"""Hash-chained record log.

Each entry carries the hash of the entry before it. Removing an entry, editing
one, or reordering two breaks every hash after the edit point, so the question
"was this record altered after the fact" becomes a single recomputation instead
of an argument.
"""

from __future__ import annotations

import json
import os
import threading
from typing import Iterable, Iterator

from .records import canonical_json, sha256_hex


class ReceiptChain:
    """Appends records to a JSONL log with a `prev_hash` link.

    The chain is intentionally local and append-only: no network call, no
    server to trust, and the file can be shipped to a customer or an auditor
    as-is.
    """

    def __init__(self, path: str | None = None, prev_hash: str | None = None, signer=None):
        self.path = path
        self._prev_hash = prev_hash
        # signer(record_hash: str) -> hex signature. Kept outside the hashed
        # body: a signature over the hash cannot itself be inside the hash.
        self._signer = signer
        self._lock = threading.Lock()
        self._count = 0
        if path:
            self._prev_hash = _tail_hash(path) or prev_hash

    @property
    def prev_hash(self) -> str | None:
        return self._prev_hash

    @property
    def count(self) -> int:
        return self._count

    def append(self, record: dict) -> dict:
        with self._lock:
            entry = dict(record)
            entry["prev_hash"] = self._prev_hash
            entry["record_hash"] = sha256_hex(canonical_json(entry))
            if self._signer is not None:
                entry["signature"] = self._signer(entry["record_hash"])
            self._prev_hash = entry["record_hash"]
            self._count += 1
            if self.path:
                _append_line(self.path, canonical_json(entry).decode("utf-8"))
            return entry


def _append_line(path: str, line: str) -> None:
    with open(path, "a", encoding="utf-8") as f:
        f.write(line)
        f.write("\n")
        f.flush()
        os.fsync(f.fileno())


def _tail_hash(path: str) -> str | None:
    if not os.path.exists(path) or os.path.getsize(path) == 0:
        return None
    with open(path, "rb") as f:
        f.seek(0, os.SEEK_END)
        size = f.tell()
        block = min(size, 65536)
        f.seek(size - block)
        tail = f.read().splitlines()
    for raw in reversed(tail):
        if raw.strip():
            return json.loads(raw)["record_hash"]
    return None


def read_entries(path: str) -> Iterator[dict]:
    with open(path, "r", encoding="utf-8") as f:
        for lineno, raw in enumerate(f, start=1):
            if not raw.strip():
                continue
            try:
                yield json.loads(raw)
            except json.JSONDecodeError as exc:
                raise ValueError(f"{path}:{lineno}: invalid JSON: {exc}") from exc


def verify(entries: Iterable[dict], prev_hash: str | None = None) -> list[str]:
    """Return the problems found in a chain. An empty list means it verifies."""
    problems: list[str] = []
    expected_prev = prev_hash
    count = 0
    for index, entry in enumerate(entries):
        count += 1
        claimed = entry.get("record_hash")
        body = {k: v for k, v in entry.items() if k not in ("record_hash", "signature")}
        recomputed = sha256_hex(canonical_json(body))
        if claimed != recomputed:
            problems.append(
                f"entry {index}: record_hash mismatch (claimed {claimed}, computed {recomputed})"
            )
        if entry.get("prev_hash") != expected_prev:
            problems.append(
                f"entry {index}: prev_hash {entry.get('prev_hash')!r} does not follow "
                f"{expected_prev!r}; an entry was removed, inserted or reordered"
            )
        expected_prev = claimed
    if count == 0:
        problems.append("chain is empty")
    return problems
