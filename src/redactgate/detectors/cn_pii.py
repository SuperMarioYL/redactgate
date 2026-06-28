"""China-PII recognizers — the core detection primitive.

This module turns a blob of outbound text into a list of :class:`Detection`
records. Each recognizer is a regex that *finds candidate spans*, paired with a
checksum validator from :mod:`redactgate.detectors.checksum` that *confirms*
them. A candidate that does not pass its checksum is reported with a lower
confidence (or dropped), which is exactly the property that separates RedactGate
from a naive ``\\d{18}`` scanner: only checksum-valid 身份证 / 银行卡 /
统一社会信用代码 are masked, so plain order ids and 18-digit counters survive
untouched.

Covered types (the five m1 recognizers):

==================  ==========================================================
type                signal
==================  ==========================================================
``id_card``         18-digit 居民身份证, GB 11643 (mod-11-2) check digit
``phone``           中国大陆手机号, ``1[3-9]\\d{9}`` (number-plan regex)
``bank_card``       13-19 digit 银行卡 PAN, Luhn (mod-10)
``uscc``            18-char 统一社会信用代码, GB 32100 (mod-31)
``intranet_domain`` internal hostnames by suffix list + RFC1918-ish IP literals
==================  ==========================================================

The public surface is :func:`detect` (a string -> ``list[Detection]``) and
:func:`scan_text` (the same, but each detection carries 1-based ``line`` /
``col`` for ``redactgate scan``). Both honour a :class:`~redactgate.rules.Ruleset`
so disabled types, the allowlist, and per-type confidence thresholds are applied
in one place. The recognizers are also importable individually for reuse.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Callable, Iterable, Iterator, Sequence

from ..rules import DETECTOR_TYPES, Ruleset, load_default_ruleset
from .checksum import is_valid_bank_card, is_valid_id_card, is_valid_uscc

__all__ = [
    "Detection",
    "Recognizer",
    "RECOGNIZERS",
    "detect",
    "scan_text",
]


# --------------------------------------------------------------------------- #
# The Detection primitive (mvp_plan.md §2)
# --------------------------------------------------------------------------- #


@dataclass(frozen=True)
class Detection:
    """A single PII hit located in a text buffer.

    Attributes:
        type: one of :data:`~redactgate.rules.DETECTOR_TYPES`.
        start: byte/char offset of the match start in the scanned buffer.
        end: offset one past the last matched char (so ``text[start:end]`` is raw).
        raw: the exact matched substring.
        checksum_valid: True if a checksum gate confirmed the value (always True
            for types whose only signal is a checksum; may be False for
            number-plan-only types like ``phone`` / ``intranet_domain`` where the
            regex itself is the signal).
        confidence: 0.0-1.0 strength of the hit (checksum-confirmed hits score
            higher than regex-only ones).
        line: 1-based line number, populated by :func:`scan_text` (else ``None``).
        col: 1-based column on that line, populated by :func:`scan_text`.
    """

    type: str
    start: int
    end: int
    raw: str
    checksum_valid: bool
    confidence: float
    line: int | None = None
    col: int | None = None

    def with_position(self, line: int, col: int) -> "Detection":
        """Return a copy carrying 1-based ``line`` / ``col`` coordinates."""
        return Detection(
            type=self.type,
            start=self.start,
            end=self.end,
            raw=self.raw,
            checksum_valid=self.checksum_valid,
            confidence=self.confidence,
            line=line,
            col=col,
        )


# --------------------------------------------------------------------------- #
# Recognizers: regex candidate finder + optional checksum gate
# --------------------------------------------------------------------------- #


def _identity(value: str) -> str:
    """Default cleaner: pass the matched text through unchanged."""
    return value


@dataclass(frozen=True)
class Recognizer:
    """A candidate-finding regex paired with an optional checksum validator.

    Attributes:
        type: the detector type produced.
        pattern: compiled regex whose group(0) (or named group ``v`` if present)
            is the candidate value span.
        validator: ``str -> bool`` checksum gate, or ``None`` when the regex is
            itself the signal (phone number plan, intranet domain).
        confidence_ok / confidence_bad: scores for a candidate that passes /
            fails the checksum. A failing-checksum candidate scores
            ``confidence_bad`` (often 0.0, i.e. dropped) so it is never masked.
        cleaner: maps the matched text to the canonical form fed to ``validator``
            (e.g. stripping spaces/dashes from a bank card).
    """

    type: str
    pattern: re.Pattern[str]
    validator: Callable[[str], bool] | None
    confidence_ok: float
    confidence_bad: float
    cleaner: Callable[[str], str] = _identity

    def find(self, text: str) -> Iterator[Detection]:
        """Yield every (checksum-gated) detection of this type in ``text``."""
        for match in self.pattern.finditer(text):
            raw = match.group("v") if "v" in match.groupdict() else match.group(0)
            start = match.start("v") if "v" in match.groupdict() else match.start()
            end = start + len(raw)
            if self.validator is None:
                yield Detection(
                    type=self.type,
                    start=start,
                    end=end,
                    raw=raw,
                    checksum_valid=False,
                    confidence=self.confidence_ok,
                )
                continue
            cleaned = self.cleaner(raw)
            ok = self.validator(cleaned)
            confidence = self.confidence_ok if ok else self.confidence_bad
            if confidence <= 0.0:
                # checksum failed and we don't surface bare candidates -> drop.
                continue
            yield Detection(
                type=self.type,
                start=start,
                end=end,
                raw=raw,
                checksum_valid=ok,
                confidence=confidence,
            )


# --- regex building blocks ------------------------------------------------- #

# 身份证: 17 digits + final digit-or-X. Bounded by non-alnum so it doesn't fire
# inside a longer number. We validate the checksum, so the regex stays simple.
_ID_CARD_RE = re.compile(r"(?<![0-9A-Za-z])(?P<v>\d{17}[0-9Xx])(?![0-9A-Za-z])")

# 手机号: the number plan itself is the signal (1, then 3-9, then 9 digits).
_PHONE_RE = re.compile(r"(?<!\d)(?P<v>1[3-9]\d{9})(?!\d)")

# 银行卡: 13-19 digits, optionally grouped by single spaces or dashes (e.g.
# "6222 0210 0011 2233 444"). We clean separators before the Luhn check.
_BANK_CARD_RE = re.compile(
    r"(?<![\d-])(?P<v>\d{13,19}|\d{4}(?:[ -]\d{4}){2,4}(?:[ -]\d{1,3})?)(?![\d-])"
)

# 统一社会信用代码: 18 chars from the GB 32100 base-31 alphabet (no I O S V Z).
_USCC_RE = re.compile(
    r"(?<![0-9A-Za-z])(?P<v>[0-9A-HJ-NP-RTUWXYa-hj-np-rtuwxy]{2}\d{6}"
    r"[0-9A-HJ-NP-RTUWXYa-hj-np-rtuwxy]{10})(?![0-9A-Za-z])"
)

#: Hostname suffixes that denote an internal/intranet zone. Lower-cased compare.
INTRANET_SUFFIXES: tuple[str, ...] = (
    ".internal",
    ".intranet",
    ".corp",
    ".local",
    ".lan",
    ".localdomain",
    ".test",
    ".example",
    ".home.arpa",
)

# A DNS-ish hostname (labels of letters/digits/hyphen separated by dots).
_HOSTNAME_RE = re.compile(
    r"(?<![\w.-])(?P<v>(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+"
    r"[A-Za-z]{2,})(?![\w.-])"
)

# RFC1918 / loopback / link-local IPv4 literals (the private ranges that, in
# code, almost always point at an internal host).
_PRIVATE_IP_RE = re.compile(
    r"(?<![\d.])(?P<v>"
    r"10\.\d{1,3}\.\d{1,3}\.\d{1,3}"
    r"|192\.168\.\d{1,3}\.\d{1,3}"
    r"|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}"
    r"|127\.\d{1,3}\.\d{1,3}\.\d{1,3}"
    r")(?![\d.])"
)


def _strip_separators(value: str) -> str:
    """Drop spaces and dashes so a grouped PAN can be Luhn-checked."""
    return value.replace(" ", "").replace("-", "")


def _is_intranet_host(value: str) -> bool:
    """True if ``value`` ends in a known internal suffix (case-insensitive)."""
    low = value.lower()
    return any(low.endswith(suffix) for suffix in INTRANET_SUFFIXES)


class _IntranetDomainRecognizer:
    """Composite recognizer: private IPs + internal-suffix hostnames.

    Kept as its own class because it draws on two regexes and a suffix filter
    rather than the single-regex + checksum shape of :class:`Recognizer`.
    """

    type = "intranet_domain"

    def find(self, text: str) -> Iterator[Detection]:
        for match in _PRIVATE_IP_RE.finditer(text):
            raw = match.group("v")
            # Reject octets > 255 — the regex is permissive for readability.
            if any(int(octet) > 255 for octet in raw.split(".")):
                continue
            yield Detection(
                type=self.type,
                start=match.start("v"),
                end=match.start("v") + len(raw),
                raw=raw,
                checksum_valid=False,
                confidence=0.9,
            )
        for match in _HOSTNAME_RE.finditer(text):
            raw = match.group("v")
            if not _is_intranet_host(raw):
                continue
            yield Detection(
                type=self.type,
                start=match.start("v"),
                end=match.start("v") + len(raw),
                raw=raw,
                checksum_valid=False,
                confidence=0.85,
            )


#: All built-in recognizers, keyed by detector type. ``detect`` iterates these in
#: :data:`~redactgate.rules.DETECTOR_TYPES` order so output is stable.
RECOGNIZERS: dict[str, "Recognizer | _IntranetDomainRecognizer"] = {
    "id_card": Recognizer(
        type="id_card",
        pattern=_ID_CARD_RE,
        validator=is_valid_id_card,
        confidence_ok=0.99,
        confidence_bad=0.0,  # failed GB 11643 -> not a real card, drop it
    ),
    "phone": Recognizer(
        type="phone",
        pattern=_PHONE_RE,
        validator=None,  # number plan is the signal; no checksum exists
        confidence_ok=0.8,
        confidence_bad=0.0,
    ),
    "bank_card": Recognizer(
        type="bank_card",
        pattern=_BANK_CARD_RE,
        validator=lambda v: is_valid_bank_card(_strip_separators(v)),
        confidence_ok=0.9,
        confidence_bad=0.0,  # failed Luhn -> not a PAN, drop it
        cleaner=_strip_separators,
    ),
    "uscc": Recognizer(
        type="uscc",
        pattern=_USCC_RE,
        validator=is_valid_uscc,
        confidence_ok=0.97,
        confidence_bad=0.0,  # failed mod-31 -> not a USCC, drop it
    ),
    "intranet_domain": _IntranetDomainRecognizer(),
}


# --------------------------------------------------------------------------- #
# Public detection entry points
# --------------------------------------------------------------------------- #


def _active_recognizers(
    ruleset: Ruleset,
) -> Iterable["Recognizer | _IntranetDomainRecognizer"]:
    """Yield recognizers enabled by ``ruleset`` in stable display order."""
    for type_name in DETECTOR_TYPES:
        if not ruleset.is_enabled(type_name):
            continue
        recognizer = RECOGNIZERS.get(type_name)
        if recognizer is not None:
            yield recognizer


def detect(text: str, ruleset: Ruleset | None = None) -> list[Detection]:
    """Find every enabled, above-threshold, non-allowlisted PII hit in ``text``.

    The ruleset gates each detection three ways: the type must be enabled, the
    confidence must clear the per-type threshold, and the raw value must not be
    allowlisted. Results are sorted by start offset so callers (the redactor, the
    scanner) get them in document order.

    Args:
        text: the buffer to scan (a source file, a diff hunk, an outbound chunk).
        ruleset: the active ruleset; the bundled default is used when ``None``.

    Returns:
        Detections in ascending ``start`` order.
    """
    rules = ruleset if ruleset is not None else load_default_ruleset()
    hits: list[Detection] = []
    for recognizer in _active_recognizers(rules):
        for detection in recognizer.find(text):
            if rules.is_allowlisted(detection.raw):
                continue
            if detection.confidence < rules.threshold_for(detection.type):
                continue
            hits.append(detection)
    hits.sort(key=lambda d: (d.start, d.end))
    return hits


def _line_starts(text: str) -> Sequence[int]:
    """Return the offset at which each line begins (offset 0 == line 1)."""
    starts = [0]
    for index, char in enumerate(text):
        if char == "\n":
            starts.append(index + 1)
    return starts


def _locate(offset: int, line_starts: Sequence[int]) -> tuple[int, int]:
    """Map a char ``offset`` to a 1-based ``(line, col)`` via binary search."""
    import bisect

    line_index = bisect.bisect_right(line_starts, offset) - 1
    col = offset - line_starts[line_index] + 1
    return line_index + 1, col


def scan_text(text: str, ruleset: Ruleset | None = None) -> list[Detection]:
    """Like :func:`detect`, but every detection carries 1-based line/col.

    This is what ``redactgate scan <file>`` renders: each hit's type, the line it
    sits on, the column, and whether its checksum validated. Coordinates are
    computed once from a precomputed line-start index, so a large file is still
    a single linear pass.

    Args:
        text: file contents to scan.
        ruleset: active ruleset (bundled default when ``None``).

    Returns:
        Positioned detections in document order.
    """
    line_starts = _line_starts(text)
    located: list[Detection] = []
    for detection in detect(text, ruleset):
        line, col = _locate(detection.start, line_starts)
        located.append(detection.with_position(line, col))
    return located
