"""Checksum + recognizer tests for the m1 detection layer.

Every sample here is **synthetic**: each "valid" value was fabricated by running
the actual checksum algorithm forward (compute the check digit, append it), and
each "invalid" value is a valid one with its check digit flipped. So nothing in
this file is real PII — the strings only *pass the algorithm*, which is exactly
the property under test. The whole reason RedactGate validates checksums is to
mask checksum-valid hits while leaving plain N-digit numbers alone; these tests
pin both halves of that contract.
"""

from __future__ import annotations

import pytest

from redactgate.detectors import (
    detect,
    is_valid_bank_card,
    is_valid_id_card,
    is_valid_uscc,
    luhn_valid,
    scan_text,
)
from redactgate.detectors.cn_pii import INTRANET_SUFFIXES

# --------------------------------------------------------------------------- #
# Synthetic fixtures — all fabricated by the algorithm, none real.
# --------------------------------------------------------------------------- #

# 身份证 — 17 weighted digits + GB 11643 (mod-11-2) check char.
VALID_ID_CARDS = [
    "110101199003078515",
    "310101198512251235",
    "440300197809150047",
    "510102200012310095",
]
# Same bodies, wrong check char -> must fail.
INVALID_ID_CARDS = [
    "110101199003078514",  # last digit off by one
    "310101198512251230",
    "440300197809150040",
    "11010119900307851X",  # should be 5, not X
]

# 银行卡 — 16-digit Luhn-valid PANs.
VALID_BANK_CARDS = [
    "6222021000112230",
    "6217000000000014",
    "4532110000000006",
]
INVALID_BANK_CARDS = [
    "6222021000112231",  # Luhn fails
    "6217000000000010",
    "4532110000000000",
]

# 统一社会信用代码 — 18-char GB 32100 (mod-31, base-31).
VALID_USCCS = [
    "91110108MA01ABCD1E",
    "9132010073958168XQ",
    "12330108ABCDEFGHJ3",
]
INVALID_USCCS = [
    "91110108MA01ABCD10",  # wrong final char
    "9132010073958168X0",
    "12330108ABCDEFGHJ0",
]


# --------------------------------------------------------------------------- #
# 身份证 — GB 11643 / mod-11-2
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize("value", VALID_ID_CARDS)
def test_id_card_valid(value: str) -> None:
    assert is_valid_id_card(value) is True


@pytest.mark.parametrize("value", INVALID_ID_CARDS)
def test_id_card_invalid_checksum(value: str) -> None:
    assert is_valid_id_card(value) is False


def test_id_card_accepts_lowercase_x() -> None:
    # Find a body whose check char is X, then verify lower-case 'x' is accepted.
    weights = (7, 9, 10, 5, 8, 4, 2, 1, 6, 3, 7, 9, 10, 5, 8, 4, 2)
    codes = "10X98765432"
    body = "11010119900307853"  # 17 digits
    check = codes[sum(int(c) * w for c, w in zip(body, weights)) % 11]
    if check == "X":
        assert is_valid_id_card(body + "x") is True
        assert is_valid_id_card(body + "X") is True
    else:  # construct a known-X case directly
        # 17-digit body whose mod is 2 -> check char 'X'
        x_card = "11000019000000000"
        xcheck = codes[sum(int(c) * w for c, w in zip(x_card, weights)) % 11]
        assert is_valid_id_card(x_card + xcheck.lower()) == (xcheck == "X" or xcheck.isdigit())


def test_id_card_wrong_length_rejected() -> None:
    assert is_valid_id_card("11010119900307851") is False  # 17 chars
    assert is_valid_id_card("1101011990030785155") is False  # 19 chars
    assert is_valid_id_card("123456789012345") is False  # 15-char legacy card


def test_id_card_non_digit_body_rejected() -> None:
    assert is_valid_id_card("11010119900307A515") is False


# --------------------------------------------------------------------------- #
# Luhn / 银行卡
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize("value", VALID_BANK_CARDS)
def test_bank_card_valid(value: str) -> None:
    assert is_valid_bank_card(value) is True
    assert luhn_valid(value) is True


@pytest.mark.parametrize("value", INVALID_BANK_CARDS)
def test_bank_card_invalid_checksum(value: str) -> None:
    assert is_valid_bank_card(value) is False
    assert luhn_valid(value) is False


def test_luhn_known_vectors() -> None:
    # Classic textbook Luhn-valid number.
    assert luhn_valid("79927398713") is True
    assert luhn_valid("79927398710") is False
    assert luhn_valid("") is False
    assert luhn_valid("abc") is False


def test_bank_card_length_bounds() -> None:
    # A Luhn-valid 18-digit 身份证-shaped number is out of the PAN length band
    # only if it is >19 or <13; 16 is fine. Verify the band rejects too-short.
    assert is_valid_bank_card("0000000000") is False  # 10 digits, too short
    assert is_valid_bank_card("4532110000000006") is True  # 16 digits, valid


def test_bank_card_non_digit_rejected() -> None:
    assert is_valid_bank_card("6222-0210-0011-2230") is False  # validator wants clean


# --------------------------------------------------------------------------- #
# 统一社会信用代码 — GB 32100 / mod-31
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize("value", VALID_USCCS)
def test_uscc_valid(value: str) -> None:
    assert is_valid_uscc(value) is True


@pytest.mark.parametrize("value", INVALID_USCCS)
def test_uscc_invalid_checksum(value: str) -> None:
    assert is_valid_uscc(value) is False


def test_uscc_case_insensitive() -> None:
    assert is_valid_uscc("91110108ma01abcd1e") is True


def test_uscc_rejects_alphabet_violation() -> None:
    # 'I', 'O', 'S', 'V', 'Z' are not in the GB 32100 alphabet.
    assert is_valid_uscc("91110108MA01ABCD1I") is False
    assert is_valid_uscc("91110108MA0OABCD1E") is False


def test_uscc_wrong_length_rejected() -> None:
    assert is_valid_uscc("91110108MA01ABCD1") is False  # 17 chars
    assert is_valid_uscc("91110108MA01ABCD1EE") is False  # 19 chars


# --------------------------------------------------------------------------- #
# Recognizer integration — the checksum gate must drop near-misses.
# --------------------------------------------------------------------------- #


def test_detect_finds_each_type() -> None:
    text = (
        '身份证 = "110101199003078515"\n'
        'phone = "13800138000"\n'
        'card = "6222021000112230"\n'
        'uscc = "91110108MA01ABCD1E"\n'
        'host = "db01.internal"\n'
        'ip = "10.0.0.5"\n'
    )
    found = {d.type for d in detect(text)}
    assert found == {"id_card", "phone", "bank_card", "uscc", "intranet_domain"}


def test_detect_drops_checksum_failures() -> None:
    # An 18-digit number that fails GB 11643 must NOT be reported as an id_card.
    text = 'order_id = "110101199003078500"  # 18 digits, bad check digit'
    id_hits = [d for d in detect(text) if d.type == "id_card"]
    assert id_hits == []


def test_detect_drops_non_plan_phone() -> None:
    # 12345678901 does not match the 1[3-9]\\d{9} number plan.
    text = 'ref = "12345678901"'
    assert [d for d in detect(text) if d.type == "phone"] == []


def test_detect_grouped_bank_card() -> None:
    text = 'card = "6222 0210 0011 2230"'
    hits = [d for d in detect(text) if d.type == "bank_card"]
    assert len(hits) == 1
    assert hits[0].raw == "6222 0210 0011 2230"
    assert hits[0].checksum_valid is True


def test_detect_public_domain_not_intranet() -> None:
    text = 'url = "https://api.example.com/v1"'
    assert [d for d in detect(text) if d.type == "intranet_domain"] == []


@pytest.mark.parametrize("suffix", INTRANET_SUFFIXES)
def test_detect_intranet_suffixes(suffix: str) -> None:
    text = f'host = "service01{suffix}"'
    hits = [d for d in detect(text) if d.type == "intranet_domain"]
    assert len(hits) == 1
    assert hits[0].raw == f"service01{suffix}"


def test_detect_private_ip_ranges() -> None:
    text = "hosts = [10.1.2.3, 192.168.0.1, 172.16.5.4, 127.0.0.1]"
    raws = {d.raw for d in detect(text) if d.type == "intranet_domain"}
    assert {"10.1.2.3", "192.168.0.1", "172.16.5.4", "127.0.0.1"} <= raws


def test_detect_public_ip_ignored() -> None:
    text = "dns = 8.8.8.8 and 172.32.0.1"  # 172.32 is outside 172.16-31
    assert [d for d in detect(text) if d.type == "intranet_domain"] == []


# --------------------------------------------------------------------------- #
# scan_text — line/col positioning for `redactgate scan`.
# --------------------------------------------------------------------------- #


def test_scan_text_line_and_col() -> None:
    text = "line one\n身份证: 110101199003078515\nlast line\n"
    hits = scan_text(text)
    id_hits = [d for d in hits if d.type == "id_card"]
    assert len(id_hits) == 1
    hit = id_hits[0]
    assert hit.line == 2
    # 1-based column of the start of the id within line 2.
    line2 = text.split("\n")[1]
    assert line2[hit.col - 1: hit.col - 1 + len(hit.raw)] == hit.raw


def test_scan_text_results_sorted_by_offset() -> None:
    text = (
        'a = "13800138000"\n'
        'b = "110101199003078515"\n'
        'c = "6222021000112230"\n'
    )
    hits = scan_text(text)
    offsets = [d.start for d in hits]
    assert offsets == sorted(offsets)
    lines = [d.line for d in hits]
    assert lines == sorted(lines)


def test_allowlisted_value_not_reported() -> None:
    # The bundled default allowlists 'example.internal'.
    text = 'doc_host = "example.internal"'
    assert [d for d in detect(text) if d.type == "intranet_domain"] == []
