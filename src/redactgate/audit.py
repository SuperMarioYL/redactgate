"""JSONL audit log — the third leg of the redaction triple.

Every time RedactGate masks (or blocks) a field on the way out, it appends one
line to an append-only JSONL audit file: *who* (file), *where* (line / col),
*what type* (id_card / phone / …), *whether the checksum validated*, *what the
egress would have looked like* (the masked preview — never the raw PII), and
*what action* was taken (mask / block). This is what a compliance reviewer reads
to prove "no real 身份证 left the machine" — the value of the product is as much
the audit trail as the masking itself.

RedactGate **owns** this schema; there is deliberately no external schema
dependency. The contract is the small set of fields below, versioned by
:data:`AUDIT_SCHEMA_VERSION` so a future field addition is detectable by readers.
One JSON object per line keeps the log greppable (`grep id_card audit.jsonl`),
streamable, and safe to tail while it is being written.

Public surface:

- :data:`AUDIT_SCHEMA_VERSION` — bump on a breaking field change.
- :class:`AuditEntry`          — one structured record (+ ``to_dict`` / ``to_json``).
- :func:`build_entry`          — turn a :class:`~redactgate.redactor.Redaction`
                                 (for a given source) into an :class:`AuditEntry`.
- :class:`AuditLog`            — append entries to a JSONL file (or any stream).
- :func:`read_entries`         — parse a JSONL audit file back into entries.
"""

from __future__ import annotations

import json
import os
import threading
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import IO, Iterable, Iterator

from .redactor import Redaction
from .rules import Policy

__all__ = [
    "AUDIT_SCHEMA_VERSION",
    "DEFAULT_AUDIT_PATH",
    "AuditEntry",
    "AuditLog",
    "build_entry",
    "read_entries",
]

#: Audit schema version. Bump on any breaking change to the field set so old
#: readers can detect (and refuse / migrate) a newer log.
AUDIT_SCHEMA_VERSION = 1

#: Default audit file written by the CLI / proxy when no path is given.
DEFAULT_AUDIT_PATH = "audit.jsonl"


def _utc_now_iso() -> str:
    """Current time as an RFC 3339 / ISO 8601 UTC timestamp (second precision)."""
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


# --------------------------------------------------------------------------- #
# The AuditEntry schema (mvp_plan.md §2 — RedactGate owns it)
# --------------------------------------------------------------------------- #


@dataclass(frozen=True)
class AuditEntry:
    """One append-only audit record describing a single masked/blocked field.

    Field contract (also the JSONL key set):

    ======================  ===================================================
    key                     meaning
    ======================  ===================================================
    ``schema``              :data:`AUDIT_SCHEMA_VERSION` (int)
    ``ts``                  ISO 8601 UTC timestamp of the egress event
    ``type``                detector type — id_card / phone / bank_card / uscc /
                            intranet_domain
    ``action``              ``mask`` or ``block``
    ``checksum_valid``      whether a checksum (GB 11643 / Luhn / mod-31)
                            confirmed the value
    ``file``                source path / stream label the field came from
    ``line``                1-based line (``None`` when streaming without lines)
    ``col``                 1-based column (``None`` when unknown)
    ``rule_id``             the rule/detector id that fired (== ``type`` for the
                            built-ins; a custom pattern's label otherwise)
    ``masked_preview``      the *masked* rendering (NEVER the raw PII)
    ======================  ===================================================

    Note that the raw value is intentionally absent: the audit log must be safe
    to ship to a compliance reviewer, so it records only the masked preview.
    """

    schema: int
    ts: str
    type: str
    action: str
    checksum_valid: bool
    file: str
    rule_id: str
    masked_preview: str
    line: int | None = None
    col: int | None = None

    def to_dict(self) -> dict[str, object]:
        """Return the entry as a plain dict (JSONL key set, stable order)."""
        data = asdict(self)
        # Emit a deterministic key order so logs diff cleanly.
        ordered_keys = (
            "schema",
            "ts",
            "type",
            "action",
            "checksum_valid",
            "file",
            "line",
            "col",
            "rule_id",
            "masked_preview",
        )
        return {key: data[key] for key in ordered_keys}

    def to_json(self) -> str:
        """Serialize to a single-line JSON string (no trailing newline)."""
        return json.dumps(self.to_dict(), ensure_ascii=False, separators=(",", ":"))

    @classmethod
    def from_dict(cls, data: dict[str, object]) -> "AuditEntry":
        """Rebuild an entry from a parsed JSONL object (tolerant of extras)."""
        return cls(
            schema=int(data.get("schema", AUDIT_SCHEMA_VERSION)),
            ts=str(data.get("ts", "")),
            type=str(data.get("type", "")),
            action=str(data.get("action", "mask")),
            checksum_valid=bool(data.get("checksum_valid", False)),
            file=str(data.get("file", "")),
            rule_id=str(data.get("rule_id", data.get("type", ""))),
            masked_preview=str(data.get("masked_preview", "")),
            line=_opt_int(data.get("line")),
            col=_opt_int(data.get("col")),
        )


def _opt_int(value: object) -> int | None:
    if value is None:
        return None
    try:
        return int(value)  # type: ignore[arg-type]
    except (TypeError, ValueError):
        return None


def build_entry(
    redaction: Redaction,
    *,
    file: str,
    ts: str | None = None,
    rule_id: str | None = None,
) -> AuditEntry:
    """Turn a :class:`~redactgate.redactor.Redaction` into an :class:`AuditEntry`.

    Args:
        redaction: the masked/blocked field.
        file: the source path or stream label the field came from
            (e.g. ``examples/demo-repo/leaky.py`` or ``<stdin>``).
        ts: ISO 8601 timestamp; defaults to "now" in UTC.
        rule_id: the rule id; defaults to the detector type (the built-in rule).

    Returns:
        A populated, immutable :class:`AuditEntry`.
    """
    action = "block" if redaction.policy is Policy.BLOCK else "mask"
    return AuditEntry(
        schema=AUDIT_SCHEMA_VERSION,
        ts=ts or _utc_now_iso(),
        type=redaction.type,
        action=action,
        checksum_valid=redaction.detection.checksum_valid,
        file=file,
        line=redaction.line,
        col=redaction.col,
        rule_id=rule_id or redaction.type,
        masked_preview=redaction.masked_preview(),
    )


# --------------------------------------------------------------------------- #
# Append-only JSONL writer
# --------------------------------------------------------------------------- #


@dataclass
class AuditLog:
    """An append-only JSONL audit sink.

    Open it on a path (the file is created / appended to) or hand it an existing
    writable stream. Each :meth:`append` writes exactly one line and flushes, so
    a reader tailing the file always sees whole records.

    Example::

        with AuditLog("audit.jsonl") as log:
            for redaction in result.redactions:
                log.append(build_entry(redaction, file="leaky.py"))
    """

    path: str | os.PathLike[str] | None = None
    stream: IO[str] | None = None
    _own_stream: bool = field(default=False, init=False, repr=False)
    count: int = field(default=0, init=False)
    _lock: threading.RLock = field(default_factory=threading.RLock, init=False, repr=False)

    def __post_init__(self) -> None:
        if self.stream is None:
            if self.path is None:
                raise ValueError("AuditLog needs either a path or a stream")
            target = Path(self.path)
            if target.parent and not target.parent.exists():
                target.parent.mkdir(parents=True, exist_ok=True)
            self.stream = open(target, "a", encoding="utf-8")
            self._own_stream = True

    # -- writing -----------------------------------------------------------

    def append(self, entry: AuditEntry) -> None:
        """Append one entry as a JSON line and flush (thread-safe).

        The local HTTP forward proxy (:class:`~redactgate.proxy.RedactingProxyServer`)
        serves concurrent agent requests on a threaded server, so several threads
        can call this at once. The lock keeps the write + flush + count atomic so
        two threads can never interleave half a JSON line into the compliance
        trail — the audit log's integrity is the product's headline guarantee.
        """
        assert self.stream is not None  # set in __post_init__
        with self._lock:
            self.stream.write(entry.to_json())
            self.stream.write("\n")
            self.stream.flush()
            self.count += 1

    def append_redactions(
        self, redactions: Iterable[Redaction], *, file: str, ts: str | None = None
    ) -> int:
        """Append an audit entry for each redaction; return how many were written."""
        written = 0
        for redaction in redactions:
            self.append(build_entry(redaction, file=file, ts=ts))
            written += 1
        return written

    # -- lifecycle ---------------------------------------------------------

    def close(self) -> None:
        """Close the underlying stream if this log opened it."""
        if self._own_stream and self.stream is not None:
            self.stream.close()
            self.stream = None

    def __enter__(self) -> "AuditLog":
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()


def read_entries(path: str | os.PathLike[str]) -> Iterator[AuditEntry]:
    """Yield every :class:`AuditEntry` parsed from a JSONL audit ``path``.

    Blank lines are skipped; a malformed (non-JSON) line is skipped rather than
    aborting the whole report, so a compliance log that accreted a corrupt line
    (a partial write, an editor save race) still yields its clean entries.

    Args:
        path: the JSONL audit file to read.

    Yields:
        One :class:`AuditEntry` per non-blank, JSON-valid line, in file order.
    """
    file_path = Path(path)
    with open(file_path, "r", encoding="utf-8") as handle:
        for line in handle:
            line = line.strip()
            if not line:
                continue
            try:
                data = json.loads(line)
            except json.JSONDecodeError:
                continue
            yield AuditEntry.from_dict(data)
