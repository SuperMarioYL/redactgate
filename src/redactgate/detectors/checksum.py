"""Checksum validators for China-specific PII formats.

The whole point of RedactGate over a naive regex scanner is that it only acts on
strings that *pass a checksum*. A bare ``\\d{18}`` matches every 18-digit number;
a GB 11643 validator matches only the ones whose last digit is consistent with
the first 17. That single gate is what pushes the false-positive rate down to a
usable level — masking a random order number would corrupt the very business
logic the agent needs to see.

Each validator here is **pure and dependency-free**: it takes the already-cleaned
candidate string (digits, plus an ``X`` for 身份证 / letters for 统一社会信用代码)
and returns ``True`` / ``False``. Cleaning (stripping spaces, dashes) is the
recognizer's job in :mod:`redactgate.detectors.cn_pii`; this module never does
regex matching, so it stays trivially unit-testable.

Algorithms implemented:

- :func:`is_valid_id_card`  — 居民身份证 18 位, GB 11643 / ISO 7064 mod-11-2.
- :func:`luhn_valid`        — generic Luhn (mod-10); used for 银行卡.
- :func:`is_valid_bank_card`— 银行卡 13-19 位 via Luhn.
- :func:`is_valid_uscc`     — 统一社会信用代码 18 位, GB 32100 mod-31 (base-31).
"""

from __future__ import annotations

__all__ = [
    "is_valid_id_card",
    "luhn_valid",
    "is_valid_bank_card",
    "is_valid_uscc",
]


# --------------------------------------------------------------------------- #
# 居民身份证 (Resident Identity Card) — GB 11643 / ISO 7064 MOD 11-2
# --------------------------------------------------------------------------- #

#: Weight applied to each of the first 17 digits (高位在前).
_ID_CARD_WEIGHTS: tuple[int, ...] = (7, 9, 10, 5, 8, 4, 2, 1, 6, 3, 7, 9, 10, 5, 8, 4, 2)

#: Check-digit lookup indexed by ``sum(digit * weight) % 11``. Position 2 is "X".
_ID_CARD_CHECK_CODES: tuple[str, ...] = (
    "1", "0", "X", "9", "8", "7", "6", "5", "4", "3", "2",
)


def is_valid_id_card(value: str) -> bool:
    """Return True if ``value`` is a checksum-valid 18-digit 居民身份证.

    Validation follows the national standard GB 11643-1999 (ISO 7064 MOD 11-2):
    the first 17 characters are weighted digits and the 18th is a check
    character in ``0-9`` or ``X`` (upper or lower case accepted). Length-15
    legacy cards carry no check digit and are intentionally **not** accepted
    here — the recognizer treats them with a lower, non-checksummed confidence.

    Args:
        value: a candidate string already stripped of separators.

    Returns:
        True iff the trailing check character matches the mod-11-2 computation.
    """
    if len(value) != 18:
        return False
    body, check = value[:17], value[17].upper()
    if not body.isdigit():
        return False
    if check not in "0123456789X":
        return False
    total = sum(int(ch) * w for ch, w in zip(body, _ID_CARD_WEIGHTS))
    return _ID_CARD_CHECK_CODES[total % 11] == check


# --------------------------------------------------------------------------- #
# 银行卡 (Bank card / PAN) — Luhn / mod-10
# --------------------------------------------------------------------------- #


def luhn_valid(value: str) -> bool:
    """Return True if the all-digit ``value`` satisfies the Luhn (mod-10) check.

    The Luhn algorithm doubles every second digit from the right, subtracts 9
    from any product over 9, sums everything, and requires the total to be a
    multiple of 10. It is the standard checksum for payment-card PANs (ISO/IEC
    7812) and is what catches transposition / single-digit typos.

    Args:
        value: a string of decimal digits (no separators).

    Returns:
        True iff ``value`` is non-empty, all digits, and the mod-10 sum is 0.
    """
    if not value or not value.isdigit():
        return False
    total = 0
    # Walk right-to-left; double every second digit (the 2nd, 4th, ... from end).
    for index, ch in enumerate(reversed(value)):
        digit = ord(ch) - 48  # faster, branch-free int(ch) for a known-digit char
        if index % 2 == 1:
            digit *= 2
            if digit > 9:
                digit -= 9
        total += digit
    return total % 10 == 0


def is_valid_bank_card(value: str) -> bool:
    """Return True if ``value`` looks like a Luhn-valid 13-19 digit 银行卡 PAN.

    Length is bounded to the ISO/IEC 7812 PAN range (13-19 digits) so that, e.g.,
    an 18-digit 身份证 or a short order id does not get Luhn-tested by accident.

    Args:
        value: a candidate string already stripped of separators.

    Returns:
        True iff length is 13-19 and the Luhn checksum passes.
    """
    if not (13 <= len(value) <= 19) or not value.isdigit():
        return False
    return luhn_valid(value)


# --------------------------------------------------------------------------- #
# 统一社会信用代码 (Unified Social Credit Identifier) — GB 32100 mod-31, base-31
# --------------------------------------------------------------------------- #

#: The 31-character alphabet used by 统一社会信用代码. It deliberately omits
#: the letters I, O, S, V, Z (and the digit positions for them) to avoid visual
#: confusion. Index in this string == the character's numeric value.
_USCC_ALPHABET = "0123456789ABCDEFGHJKLMNPQRTUWXY"

#: Per-position weights (18 positions), powers of 3 modulo 31. Defined by GB 32100.
_USCC_WEIGHTS: tuple[int, ...] = (
    1, 3, 9, 27, 19, 26, 16, 17, 20, 29, 25, 13, 8, 24, 10, 30, 28,
)

#: Reverse lookup: character -> value. Built once at import.
_USCC_VALUES = {ch: i for i, ch in enumerate(_USCC_ALPHABET)}


def is_valid_uscc(value: str) -> bool:
    """Return True if ``value`` is a checksum-valid 18-char 统一社会信用代码.

    The Unified Social Credit Identifier (GB 32100-2015) is 18 base-31
    characters drawn from :data:`_USCC_ALPHABET`. The first 17 are weighted
    (:data:`_USCC_WEIGHTS`); the 18th is a check character such that the full
    weighted sum is ``0 (mod 31)``. Equivalently the check value is
    ``(31 - total % 31) % 31``.

    Args:
        value: an 18-character candidate (case-insensitive for letters).

    Returns:
        True iff every character is in the alphabet and the mod-31 check holds.
    """
    if len(value) != 18:
        return False
    upper = value.upper()
    if any(ch not in _USCC_VALUES for ch in upper):
        return False
    total = sum(_USCC_VALUES[ch] * w for ch, w in zip(upper[:17], _USCC_WEIGHTS))
    expected = (31 - total % 31) % 31
    return _USCC_VALUES[upper[17]] == expected
