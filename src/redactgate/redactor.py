"""Field-level masking — the m2 redaction primitive.

The detection layer (:mod:`redactgate.detectors`) tells us *where* the PII is;
this module decides *what the masked text looks like* and rewrites the buffer in
place without disturbing the surrounding business logic. The unit of work is a
single outbound text chunk (a whole source file, or — for the proxy — one diff
hunk / request body), so masking is **field-level, not file-level**: only the
matched span of each confirmed detection is replaced, every other byte (the
logic the agent actually needs to read) passes through untouched.

The default style is ``partial``: keep a short head and tail of the original and
replace the middle with the mask char, preserving the *length and shape* of the
value (``110101199003078515`` -> ``1101**********8515``). That shape hint is
deliberate — a reviewer eyeballing the diff can still tell "this was an 18-digit
身份证" and confirm the redaction landed on the right field, while the actual
identifying digits never leave the machine. Two other styles are supported:
``full`` (replace the whole span with one run of mask chars) and ``label``
(replace with a typed tag such as ``[身份证-已脱敏]``).

The public surface is :class:`Redaction` (one masked hit), :class:`RedactResult`
(the rewritten text + every redaction + the bytes-saved tally) and
:func:`redact_text` / :func:`mask_value`. Nothing here does I/O or touches the
audit log; :mod:`redactgate.audit` and :mod:`redactgate.proxy` compose on top.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Iterable

from .detectors import Detection, detect
from .rules import (
    MaskingStyle,
    MaskStyleName,
    Policy,
    Ruleset,
    load_default_ruleset,
)

__all__ = [
    "Redaction",
    "RedactResult",
    "mask_value",
    "redact_text",
    "redact_detections",
]


# --------------------------------------------------------------------------- #
# The Redaction primitive (mvp_plan.md §2)
# --------------------------------------------------------------------------- #


@dataclass(frozen=True)
class Redaction:
    """A single masked hit: the detection plus the string that replaced it.

    Attributes:
        detection: the :class:`~redactgate.detectors.Detection` that fired.
        masked: the replacement string written into the output buffer.
        policy: the resolved policy — ``Policy.MASK`` (value replaced) or
            ``Policy.BLOCK`` (the whole request should be stopped by the proxy;
            the redactor still produces a masked rendering so the audit log and a
            ``--report`` preview can show what tripped the block).
    """

    detection: Detection
    masked: str
    policy: Policy

    @property
    def type(self) -> str:
        """Detector type of the underlying hit (e.g. ``id_card``)."""
        return self.detection.type

    @property
    def line(self) -> int | None:
        """1-based line of the hit when known (``redactgate scan`` path)."""
        return self.detection.line

    @property
    def col(self) -> int | None:
        """1-based column of the hit when known."""
        return self.detection.col

    def masked_preview(self, max_len: int = 64) -> str:
        """A short, log-safe preview of the masked value (never the raw value).

        The audit log records *what the egress would have looked like*, not the
        original PII — so this returns the masked rendering, truncated so a long
        bank-card group does not bloat a JSONL line.
        """
        preview = self.masked
        if len(preview) > max_len:
            preview = preview[: max_len - 1] + "…"
        return preview


@dataclass
class RedactResult:
    """The outcome of redacting one text buffer.

    Attributes:
        text: the rewritten buffer with every confirmed hit masked.
        redactions: one :class:`Redaction` per masked span, in document order.
        original_len: length (chars) of the input buffer.
        blocked: True if any redaction carried ``Policy.BLOCK`` — the proxy uses
            this to decide whether to forward or refuse the request.
    """

    text: str
    redactions: list[Redaction] = field(default_factory=list)
    original_len: int = 0
    blocked: bool = False

    @property
    def count(self) -> int:
        """Number of fields masked in this buffer."""
        return len(self.redactions)

    @property
    def changed(self) -> bool:
        """Whether the buffer was modified at all."""
        return bool(self.redactions)

    def counts_by_type(self) -> dict[str, int]:
        """Per-detector-type tally of how many fields were masked."""
        tally: dict[str, int] = {}
        for redaction in self.redactions:
            tally[redaction.type] = tally.get(redaction.type, 0) + 1
        return tally


# --------------------------------------------------------------------------- #
# Value masking — shape-preserving by default
# --------------------------------------------------------------------------- #


def _partial_mask(raw: str, style: MaskingStyle) -> str:
    """Keep ``keep_prefix`` head + ``keep_suffix`` tail; mask the middle.

    Length and shape are preserved: the masked string is the same length as the
    original, with separator characters (space / dash, as found in a grouped
    bank card) left in place so the diff still reads as "a card-shaped field".
    If the value is too short for the requested head+tail to leave any middle,
    the head/tail are shrunk proportionally so at least one char is masked.
    """
    n = len(raw)
    keep_prefix = max(0, style.keep_prefix)
    keep_suffix = max(0, style.keep_suffix)

    # Guarantee at least one masked char even for short values.
    if keep_prefix + keep_suffix >= n:
        # leave at most n-1 visible chars, split between head and tail.
        budget = max(0, n - 1)
        keep_prefix = min(keep_prefix, budget)
        keep_suffix = min(keep_suffix, max(0, budget - keep_prefix))

    out: list[str] = []
    for index, ch in enumerate(raw):
        in_head = index < keep_prefix
        in_tail = index >= n - keep_suffix
        if in_head or in_tail:
            out.append(ch)
        elif ch in " -":
            # preserve grouping separators so the field keeps its shape.
            out.append(ch)
        else:
            out.append(style.mask_char)
    return "".join(out)


def _full_mask(raw: str, style: MaskingStyle) -> str:
    """Replace every non-separator char with the mask char (length kept)."""
    return "".join(style.mask_char if ch not in " -" else ch for ch in raw)


def mask_value(raw: str, detector_type: str, style: MaskingStyle) -> str:
    """Return the masked rendering of ``raw`` for ``detector_type``.

    The rendering is chosen by ``style.style``:

    - ``partial`` — shape-preserving head/tail (``1101**********8515``);
    - ``full``    — whole span replaced with mask chars (length preserved);
    - ``label``   — span replaced with the typed tag (``[身份证-已脱敏]``).

    The raw value is *consumed* here but never returned or logged; only the
    masked form leaves this function.
    """
    if style.style is MaskStyleName.LABEL:
        return style.label_for(detector_type)
    if style.style is MaskStyleName.FULL:
        return _full_mask(raw, style)
    return _partial_mask(raw, style)


# --------------------------------------------------------------------------- #
# Buffer redaction
# --------------------------------------------------------------------------- #


def redact_detections(
    text: str,
    detections: Iterable[Detection],
    ruleset: Ruleset | None = None,
) -> RedactResult:
    """Mask the given ``detections`` inside ``text`` and return the result.

    Spans are applied right-to-left so earlier offsets stay valid as the buffer
    is rewritten (a ``label`` replacement changes length). Overlapping or
    duplicate detections at the same span are de-duplicated, keeping the
    highest-confidence one, so a value caught by two recognizers is masked once.

    Args:
        text: the buffer to rewrite.
        detections: detections located in ``text`` (offsets must index ``text``).
        ruleset: active ruleset (bundled default when ``None``) — supplies the
            masking style and the per-type mask/block policy.

    Returns:
        A :class:`RedactResult` with the rewritten text and one
        :class:`Redaction` per masked span (in document order).
    """
    rules = ruleset if ruleset is not None else load_default_ruleset()
    style = rules.masking

    ordered = _dedupe_spans(detections)
    redactions: list[Redaction] = []
    blocked = False
    buffer = text

    # Apply from the end so untouched offsets remain valid during rewrite.
    for detection in sorted(ordered, key=lambda d: d.start, reverse=True):
        masked = mask_value(detection.raw, detection.type, style)
        policy = rules.policy_for(detection.type)
        if policy is Policy.BLOCK:
            blocked = True
        buffer = buffer[: detection.start] + masked + buffer[detection.end :]
        redactions.append(Redaction(detection=detection, masked=masked, policy=policy))

    redactions.reverse()  # back to document order for stable output / audit
    return RedactResult(
        text=buffer,
        redactions=redactions,
        original_len=len(text),
        blocked=blocked,
    )


def redact_text(text: str, ruleset: Ruleset | None = None) -> RedactResult:
    """Detect + mask every confirmed PII hit in ``text`` in one call.

    This is the high-level entry the proxy and the ``--report`` path use: it runs
    :func:`~redactgate.detectors.detect` to find checksum-validated hits and then
    masks them field-level. Business logic outside the matched spans is preserved
    byte-for-byte.

    Args:
        text: an outbound buffer (a file, a diff hunk, a request body chunk).
        ruleset: active ruleset (bundled default when ``None``).

    Returns:
        A :class:`RedactResult`.
    """
    rules = ruleset if ruleset is not None else load_default_ruleset()
    detections = detect(text, rules)
    return redact_detections(text, detections, rules)


def _dedupe_spans(detections: Iterable[Detection]) -> list[Detection]:
    """Collapse detections sharing an identical ``(start, end)`` span.

    When two recognizers flag the same bytes (rare, but e.g. a value that is both
    Luhn- and length-plausible), keep the higher-confidence one so the span is
    masked exactly once.
    """
    best: dict[tuple[int, int], Detection] = {}
    for det in detections:
        key = (det.start, det.end)
        current = best.get(key)
        if current is None or det.confidence > current.confidence:
            best[key] = det
    return list(best.values())
