"""Tests for the v0.2 custom-patterns extension surface (m1).

Pins that a user-supplied ``custom_patterns`` entry in a ruleset YAML is actually
honoured by ``detect`` / ``scan_text`` / ``redact_text``. In v0.1 the ruleset
parsed and documented the feature but ``detect`` never ran it (bug-hunter bh1);
these tests lock the fix.
"""

from __future__ import annotations

import pytest

from redactgate.detectors import detect, scan_text
from redactgate.redactor import redact_text
from redactgate.rules import RulesError, load_ruleset

ID_CARD = "110101199003078515"  # GB 11643 valid (synthetic)
BANK_CARD = "6222021000112230"  # Luhn valid (synthetic)

CUSTOM_YAML = r"""
custom_patterns:
  - type: employee_id
    pattern: 'EMP-\d{4,6}'
    confidence: 0.8
  - type: custom_card
    pattern: 'ID-(?P<v>\d{16})'
    checksum: bank_card
    confidence: 0.9
"""


@pytest.fixture()
def custom_ruleset(tmp_path):
    f = tmp_path / "custom.yaml"
    f.write_text(CUSTOM_YAML, encoding="utf-8")
    return load_ruleset(f)


def test_regex_only_custom_pattern_fires(custom_ruleset):
    hits = detect("see EMP-12345 here", custom_ruleset)
    types = [h.type for h in hits]
    assert "employee_id" in types
    emp = next(h for h in hits if h.type == "employee_id")
    assert emp.raw == "EMP-12345"
    assert emp.checksum_valid is False  # regex-only signal, no checksum gate


def test_checksum_gated_custom_drops_bad_candidates(custom_ruleset):
    # The 16-digit tail is Luhn-valid only for the real BANK_CARD body.
    good = detect(f"card=ID-{BANK_CARD}", custom_ruleset)
    assert any(h.type == "custom_card" and h.checksum_valid for h in good)
    bad = detect("card=ID-6222021000112231", custom_ruleset)  # last digit flipped
    assert not any(h.type == "custom_card" for h in bad)


def test_custom_pattern_is_masked_by_redact_text(custom_ruleset):
    result = redact_text(f"see EMP-12345 and ID-{BANK_CARD}", custom_ruleset)
    assert "EMP-12345" not in result.text
    assert BANK_CARD not in result.text
    counts = result.counts_by_type()
    assert counts.get("employee_id") == 1
    assert counts.get("custom_card") == 1


def test_custom_pattern_appears_in_scan_text(custom_ruleset):
    hits = scan_text("line EMP-12345 end", custom_ruleset)
    emp = next(h for h in hits if h.type == "employee_id")
    assert emp.line == 1
    assert emp.col is not None and emp.col > 0


def test_custom_pattern_respects_allowlist(custom_ruleset, tmp_path):
    # A custom value added to the allowlist is NOT masked.
    f = tmp_path / "allow.yaml"
    f.write_text(
        CUSTOM_YAML + "allowlist:\n  - 'EMP-12345'\n", encoding="utf-8"
    )
    rs = load_ruleset(f)
    result = redact_text("see EMP-12345 here", rs)
    assert "EMP-12345" in result.text  # allowlisted -> survived
    assert result.count == 0


def test_bad_custom_regex_raises_at_load(tmp_path):
    f = tmp_path / "bad.yaml"
    f.write_text(
        "custom_patterns:\n  - type: x\n    pattern: '['\n", encoding="utf-8"
    )
    with pytest.raises(RulesError):
        load_ruleset(f)


def test_custom_pattern_is_disabled_via_detectors(tmp_path):
    f = tmp_path / "disabled.yaml"
    f.write_text(
        CUSTOM_YAML + "detectors:\n  employee_id:\n    enabled: false\n",
        encoding="utf-8",
    )
    rs = load_ruleset(f)
    hits = detect("see EMP-12345 here", rs)
    assert not any(h.type == "employee_id" for h in hits)


# --------------------------------------------------------------------------- #
# v0.6.0 — honor an explicit confidence: 0.0 on a custom pattern.
#
#   fix-custom-pattern-confidence-zero-clobbered  (type:fix)
#       _coerce_custom_patterns defaulted confidence with `_opt_float(...) or
#       0.6`; because 0.0 is falsy, a custom pattern declared confidence: 0.0
#       was silently rewritten to 0.6 (clearing the default min_confidence 0.5
#       -> over-redaction). Default on None, not truthiness, so 0.0 survives.
# --------------------------------------------------------------------------- #


ZERO_CONF_YAML = (
    "custom_patterns:\n"
    "  - type: employee_id\n"
    "    pattern: 'EMP-\\d{4,6}'\n"
    "    confidence: 0.0\n"
)


def test_custom_pattern_confidence_zero_is_preserved(tmp_path):
    """A custom pattern declared confidence: 0.0 must survive, not be clobbered.

    Before the fix `_opt_float(entry.get('confidence')) or 0.6` rewrote a valid
    0.0 (falsy) to 0.6, so hits the user intended to drop below the default
    min_confidence (0.5) instead cleared the threshold and got masked — a
    surprising over-redaction on the user's own extensibility surface. Defaulting
    on None (not truthiness) lets 0.0 survive.
    """
    f = tmp_path / "zero_conf.yaml"
    f.write_text(ZERO_CONF_YAML, encoding="utf-8")
    rs = load_ruleset(f)
    pat = next(p for p in rs.custom_patterns if p.type == "employee_id")
    # The clobber fix: 0.0 is preserved, not rewritten to 0.6.
    assert pat.confidence == 0.0


def test_custom_pattern_confidence_zero_is_dropped_below_threshold(tmp_path):
    """A confidence: 0.0 custom pattern's hits are dropped (0.0 < 0.5), not masked.

    This is the user-facing impact of the clobber fix: before, 0.0 -> 0.6 cleared
    the default 0.5 min_confidence and the hit was masked (over-redaction); now
    0.0 survives and the hit is correctly dropped below threshold.
    """
    f = tmp_path / "zero_conf.yaml"
    f.write_text(ZERO_CONF_YAML, encoding="utf-8")
    rs = load_ruleset(f)
    hits = detect("see EMP-12345 here", rs)
    # 0.0 < default min_confidence (0.5) -> the employee_id hit is dropped, not
    # masked. Before the fix this would have contained an employee_id hit.
    assert not any(h.type == "employee_id" for h in hits)


def test_custom_pattern_confidence_defaults_to_0_6_when_absent(tmp_path):
    """Omitting confidence still applies the 0.6 default (the else branch)."""
    f = tmp_path / "no_conf.yaml"
    f.write_text(
        "custom_patterns:\n"
        "  - type: employee_id\n"
        "    pattern: 'EMP-\\d{4,6}'\n",
        encoding="utf-8",
    )
    rs = load_ruleset(f)
    pat = next(p for p in rs.custom_patterns if p.type == "employee_id")
    assert pat.confidence == 0.6

