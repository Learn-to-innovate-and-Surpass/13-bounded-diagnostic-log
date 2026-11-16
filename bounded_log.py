"""Separate a bounded diagnostic tail from an append-only critical-feedback ledger."""
from __future__ import annotations

import hashlib
import json
import math
import os
from pathlib import Path
import tempfile
import threading
from uuid import uuid4


class CorruptLog(ValueError):
    pass


class CriticalConflict(ValueError):
    pass


def encode(record: dict) -> bytes:
    return (json.dumps(record, ensure_ascii=False, sort_keys=True, separators=(",", ":"),
                       allow_nan=False) + "\n").encode("utf-8")


def _strict_loads(data: bytes):
    def finite_float(token):
        value = float(token)
        if not math.isfinite(value):
            raise ValueError("nonfinite JSON number")
        return value

    def reject_constant(token):
        raise ValueError(f"nonfinite JSON constant: {token}")

    def unique_object(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise ValueError(f"duplicate JSON key: {key}")
            result[key] = value
        return result

    return json.loads(data.decode("utf-8"), parse_float=finite_float,
                      parse_constant=reject_constant, object_pairs_hook=unique_object)


def _valid_identity(value):
    return isinstance(value, str) and bool(value.strip()) and value == value.strip()


def _valid_digest(value):
    return (isinstance(value, str) and len(value) == 64
            and all(char in "0123456789abcdef" for char in value))


def read_records(path: Path) -> list[dict]:
    if not path.exists():
        return []
    raw = path.read_bytes()
    if raw and not raw.endswith(b"\n"):
        raise CorruptLog(f"{path.name}: incomplete final record")
    records = []
    for number, line in enumerate(raw.splitlines(), 1):
        try:
            value = _strict_loads(line)
        except (ValueError, UnicodeError) as exc:
            raise CorruptLog(f"{path.name}: invalid record at line {number}") from exc
        if not isinstance(value, dict):
            raise CorruptLog(f"{path.name}: line {number} is not an object")
        records.append(value)
    return records


class BoundedLog:
    """A single writer; per-instance threads are serialized, processes are not.

    max_bytes/max_entries apply only to diagnostics.jsonl. Critical feedback has
    independent persistence and no automatic deletion or capacity limit.
    """

    def __init__(self, directory: str | Path, *, max_bytes: int = 8192,
                 max_entries: int = 32, max_event_bytes: int = 2048):
        for name, value in (("max_bytes", max_bytes), ("max_entries", max_entries),
                            ("max_event_bytes", max_event_bytes)):
            if type(value) is not int or value <= 0:
                raise ValueError(f"{name} must be a positive integer")
        if not 256 <= max_event_bytes <= max_bytes:
            raise ValueError("require 256 <= max_event_bytes <= max_bytes")
        self.directory = Path(directory)
        self.directory.mkdir(parents=True, exist_ok=True)
        self.diagnostic_path = self.directory / "diagnostics.jsonl"
        self.critical_path = self.directory / "critical-feedback.jsonl"
        self.max_bytes = max_bytes
        self.max_entries = max_entries
        self.max_event_bytes = max_event_bytes
        self._lock = threading.RLock()
        records = self._read_diagnostics()  # Refuse corrupt history instead of silently discarding it.
        self._read_critical()
        if self.diagnostic_path.exists():
            bounded = self._bounded_lines(records)
            if b"".join(bounded) != self.diagnostic_path.read_bytes():
                self._replace_diagnostics(b"".join(bounded))

    def _read_diagnostics(self):
        records = read_records(self.diagnostic_path)
        seen = set()
        for record in records:
            if not _valid_identity(record.get("event_id")):
                raise CorruptLog("invalid diagnostic record schema")
            if record["event_id"] in seen:
                raise CorruptLog("duplicate diagnostic event identity on disk")
            seen.add(record["event_id"])
            if record.get("kind") == "event":
                if (set(record) != {"event_id", "kind", "payload"}
                        or not isinstance(record["payload"], dict)):
                    raise CorruptLog("invalid diagnostic event schema")
            elif record.get("kind") == "oversize-summary":
                if (set(record) != {"event_id", "kind", "original_utf8_bytes", "sha256"}
                        or type(record["original_utf8_bytes"]) is not int
                        or record["original_utf8_bytes"] <= 0
                        or not _valid_digest(record["sha256"])):
                    raise CorruptLog("invalid diagnostic summary schema")
            else:
                raise CorruptLog("unknown diagnostic record kind")
        return records

    def _read_critical(self):
        records = read_records(self.critical_path)
        seen = set()
        for record in records:
            if (set(record) != {"event_id", "payload"}
                    or not _valid_identity(record["event_id"])
                    or not isinstance(record["payload"], dict)):
                raise CorruptLog("invalid critical record schema")
            if record["event_id"] in seen:
                raise CorruptLog("duplicate critical event identity on disk")
            seen.add(record["event_id"])
        return records

    def _replace_diagnostics(self, data: bytes):
        fd, temporary = tempfile.mkstemp(prefix=".diagnostic-", suffix=".tmp",
                                         dir=self.directory)
        try:
            with os.fdopen(fd, "wb") as stream:
                stream.write(data)
                stream.flush()
                os.fsync(stream.fileno())
            os.replace(temporary, self.diagnostic_path)
        finally:
            if os.path.exists(temporary):
                os.unlink(temporary)

    def _bounded_lines(self, records):
        lines = [encode(row) for row in records]
        # Reconfiguration may have reduced the individual record budget.
        lines = [line for line in lines if len(line) <= self.max_event_bytes]
        total = sum(map(len, lines))
        while len(lines) > self.max_entries or total > self.max_bytes:
            total -= len(lines.pop(0))
        return lines

    def append_diagnostic(self, event: dict) -> dict:
        """Roll whole records, counting serialized UTF-8 bytes including newlines."""
        if not isinstance(event, dict):
            raise ValueError("diagnostic event must be a JSON object")
        # Serialize before mutation, rejecting invalid/nonfinite inputs.
        original = encode(event)
        event_id = uuid4().hex
        record = {"event_id": event_id, "kind": "event",
                  "payload": _strict_loads(original)}
        serialized = encode(record)
        if len(serialized) > self.max_event_bytes:
            record = {"event_id": event_id, "kind": "oversize-summary",
                      "original_utf8_bytes": len(original),
                      "sha256": hashlib.sha256(original).hexdigest()}
            serialized = encode(record)
            if len(serialized) > self.max_event_bytes:
                raise ValueError("configured event budget cannot hold an oversize summary")
        with self._lock:
            records = self._read_diagnostics()
            lines = self._bounded_lines([*records, record])
            self._replace_diagnostics(b"".join(lines))
        return record

    def append_critical(self, event_id: str, payload: dict) -> str:
        """Persist an essential feedback independently; same ID+payload is idempotent.

        Failed or partial writes are reported. A damaged tail requires deliberate
        external recovery; later writes never erase evidence to make parsing succeed.
        """
        if not isinstance(event_id, str) or not event_id.strip() or event_id != event_id.strip():
            raise ValueError("critical event_id must be a nonempty, trimmed string")
        if not isinstance(payload, dict):
            raise ValueError("critical payload must be a JSON object")
        record = {"event_id": event_id, "payload": payload}
        serialized = encode(record)
        with self._lock:
            for previous in self._read_critical():
                if previous["event_id"] == event_id:
                    if encode(previous) != serialized:
                        raise CriticalConflict("same critical event_id has a different payload")
                    # A previous call may have written bytes but failed during fsync.
                    # Re-sync before reporting that the retry is safely idempotent.
                    with self.critical_path.open("ab") as stream:
                        stream.flush()
                        os.fsync(stream.fileno())
                    return "DUPLICATE"
            # This file is never passed to diagnostic trimming/replacement.
            with self.critical_path.open("ab") as stream:
                written = stream.write(serialized)
                if written != len(serialized):
                    raise OSError("short critical-ledger write")
                stream.flush()
                os.fsync(stream.fileno())
        return "APPLIED"

    def diagnostics(self) -> tuple[dict, ...]:
        with self._lock:
            return tuple(self._read_diagnostics())

    def critical_feedback(self) -> tuple[dict, ...]:
        with self._lock:
            return tuple(self._read_critical())

    def diagnostic_stats(self) -> dict:
        with self._lock:
            records = self._read_diagnostics()
            size = self.diagnostic_path.stat().st_size if self.diagnostic_path.exists() else 0
            return {"entries": len(records), "utf8_bytes": size,
                    "max_entries": self.max_entries, "max_bytes": self.max_bytes}
