"""Tests for the m2 redaction core: redactor + audit + proxy surfaces.

Pins the contract the demo relies on:

- a planted 身份证 / 手机号 in a code snippet is masked field-level,
- the surrounding business logic survives byte-for-byte,
- a checksum *failure* (a plain 18-digit number) is left alone,
- an audit entry is emitted per masked field — and never carries the raw value,
- both proxy surfaces (stdin filter, HTTP body redaction) go through the same
  masking so behaviour is identical.

Every PII string here is synthetic (fabricated by running the checksum forward),
matching the fixtures in ``test_checksum.py``.
"""

from __future__ import annotations

import io
import json

import pytest

from redactgate.audit import (
    AUDIT_SCHEMA_VERSION,
    AuditEntry,
    AuditLog,
    build_entry,
    read_entries,
)
from redactgate.proxy import (
    ProxyConfig,
    UpstreamResponse,
    make_handler,
    redact_chunk,
    redact_json_payload,
    run_stdin_filter,
)
from redactgate.redactor import (
    RedactResult,
    mask_value,
    redact_text,
)
from redactgate.rules import (
    MaskingStyle,
    MaskStyleName,
    Policy,
    load_default_ruleset,
)

# --------------------------------------------------------------------------- #
# A realistic code snippet: business logic + planted PII.
# --------------------------------------------------------------------------- #

ID_CARD = "110101199003078515"   # GB 11643 valid
PHONE = "13800138000"            # number plan
BANK_CARD = "6222021000112230"   # Luhn valid
BAD_ID = "110101199003078500"    # 18 digits, bad check digit -> must NOT mask

SNIPPET = (
    "def settle(amount):\n"
    "    fee = amount * 60 // 10000\n"
    f'    customer = {{"id_card": "{ID_CARD}", "phone": "{PHONE}"}}\n'
    f'    order_id = "{BAD_ID}"  # plain counter, not PII\n'
    "    return amount - fee\n"
)


# --------------------------------------------------------------------------- #
# mask_value — shape-preserving partial / full / label
# --------------------------------------------------------------------------- #


def test_partial_mask_preserves_length_and_shape() -> None:
    style = MaskingStyle()  # partial, keep 4/4
    masked = mask_value(ID_CARD, "id_card", style)
    assert masked == "1101**********8515"
    assert len(masked) == len(ID_CARD)
    assert masked[:4] == ID_CARD[:4]
    assert masked[-4:] == ID_CARD[-4:]


def test_partial_mask_keeps_grouping_separators() -> None:
    style = MaskingStyle()
    grouped = "6222 0210 0011 2230"
    masked = mask_value(grouped, "bank_card", style)
    # spaces survive so the field still reads as a card; digits in the middle go.
    assert len(masked) == len(grouped)
    assert masked[:4] == "6222"
    assert masked[-4:] == "2230"
    assert " " in masked


def test_full_mask_replaces_all_non_separators() -> None:
    style = MaskingStyle(style=MaskStyleName.FULL)
    masked = mask_value(PHONE, "phone", style)
    assert masked == "*" * len(PHONE)


def test_label_mask_uses_typed_tag() -> None:
    style = MaskingStyle(
        style=MaskStyleName.LABEL, labels={"id_card": "[身份证-已脱敏]"}
    )
    assert mask_value(ID_CARD, "id_card", style) == "[身份证-已脱敏]"


def test_partial_mask_short_value_still_masks_one_char() -> None:
    style = MaskingStyle(keep_prefix=4, keep_suffix=4)
    masked = mask_value("12345", "phone", style)
    assert masked != "12345"  # at least one char masked
    assert len(masked) == 5


# --------------------------------------------------------------------------- #
# redact_text — field-level masking, logic preserved, near-misses survive
# --------------------------------------------------------------------------- #


def test_redact_masks_planted_pii_field_level() -> None:
    result = redact_text(SNIPPET)
    # the planted id card + phone are gone from the output...
    assert ID_CARD not in result.text
    assert PHONE not in result.text
    # ...replaced by shape-preserving masks.
    assert "1101**********8515" in result.text
    # business logic survives byte-for-byte.
    assert "def settle(amount):" in result.text
    assert "fee = amount * 60 // 10000" in result.text
    assert "return amount - fee" in result.text


def test_redact_leaves_checksum_failures_untouched() -> None:
    result = redact_text(SNIPPET)
    # a plain 18-digit counter (bad check digit) is NOT a real id card -> survives.
    assert BAD_ID in result.text
    assert all(r.detection.raw != BAD_ID for r in result.redactions)


def test_redact_reports_each_redaction_in_order() -> None:
    result = redact_text(SNIPPET)
    types = [r.type for r in result.redactions]
    assert "id_card" in types
    assert "phone" in types
    # redactions are in document order (ascending start offset).
    starts = [r.detection.start for r in result.redactions]
    assert starts == sorted(starts)


def test_redact_counts_by_type() -> None:
    result = redact_text(SNIPPET)
    counts = result.counts_by_type()
    assert counts.get("id_card") == 1
    assert counts.get("phone") == 1


def test_redact_empty_text_is_noop() -> None:
    result = redact_text("just some logic, no pii here\n")
    assert result.changed is False
    assert result.count == 0
    assert result.text == "just some logic, no pii here\n"


def test_block_policy_sets_blocked_flag() -> None:
    # A ruleset whose default policy is block should flag the result.
    import redactgate.rules as rules_mod

    base = load_default_ruleset()
    blocking = rules_mod.Ruleset(
        version=base.version,
        default_policy=Policy.BLOCK,
        min_confidence=base.min_confidence,
        masking=base.masking,
        detectors=base.detectors,
        allowlist=base.allowlist,
        custom_patterns=base.custom_patterns,
    )
    result = redact_text(SNIPPET, blocking)
    assert result.blocked is True
    assert all(r.policy is Policy.BLOCK for r in result.redactions)


# --------------------------------------------------------------------------- #
# audit — entry per masked field, masked preview only (never raw), roundtrip
# --------------------------------------------------------------------------- #


def test_audit_entry_never_contains_raw_value() -> None:
    result = redact_text(SNIPPET)
    id_redaction = next(r for r in result.redactions if r.type == "id_card")
    entry = build_entry(id_redaction, file="leaky.py")
    blob = entry.to_json()
    assert ID_CARD not in blob               # raw PII must not be in the log
    assert entry.masked_preview == id_redaction.masked
    assert entry.schema == AUDIT_SCHEMA_VERSION
    assert entry.type == "id_card"
    assert entry.action == "mask"
    assert entry.checksum_valid is True
    assert entry.rule_id == "id_card"


def test_audit_log_appends_jsonl_and_reads_back(tmp_path) -> None:
    audit_file = tmp_path / "audit.jsonl"
    result = redact_text(SNIPPET)
    with AuditLog(audit_file) as log:
        written = log.append_redactions(result.redactions, file="leaky.py")
    assert written == result.count

    # one JSON object per line.
    lines = audit_file.read_text(encoding="utf-8").splitlines()
    assert len(lines) == result.count
    for line in lines:
        obj = json.loads(line)
        assert obj["schema"] == AUDIT_SCHEMA_VERSION
        assert obj["file"] == "leaky.py"

    entries = list(read_entries(audit_file))
    assert len(entries) == result.count
    assert {e.type for e in entries} >= {"id_card", "phone"}


def test_audit_entry_roundtrip_dict() -> None:
    entry = AuditEntry(
        schema=AUDIT_SCHEMA_VERSION,
        ts="2026-01-01T00:00:00+00:00",
        type="phone",
        action="mask",
        checksum_valid=False,
        file="x.py",
        rule_id="phone",
        masked_preview="138****8000",
        line=3,
        col=7,
    )
    again = AuditEntry.from_dict(json.loads(entry.to_json()))
    assert again == entry


# --------------------------------------------------------------------------- #
# proxy — stdin filter + JSON body redaction share the masking core
# --------------------------------------------------------------------------- #


def test_stdin_filter_masks_and_audits(tmp_path) -> None:
    audit_file = tmp_path / "audit.jsonl"
    with AuditLog(audit_file) as log:
        config = ProxyConfig.build(audit=log)
        stdin = io.StringIO(SNIPPET)
        stdout = io.StringIO()
        result = run_stdin_filter(config, stdin=stdin, stdout=stdout)

    out = stdout.getvalue()
    assert ID_CARD not in out
    assert PHONE not in out
    assert "def settle(amount):" in out
    assert result.count >= 2
    # audit captured the same number of fields.
    assert len(audit_file.read_text(encoding="utf-8").splitlines()) == result.count


def test_redact_json_payload_preserves_structure() -> None:
    config = ProxyConfig.build()
    payload = {
        "model": "demo",
        "messages": [
            {"role": "user", "content": f'fix this: id_card = "{ID_CARD}"'},
            {"role": "system", "content": "no pii here"},
        ],
        "max_tokens": 256,
    }
    masked = redact_json_payload(payload, config, source="<test>")
    # structure identical, scalars untouched.
    assert masked["model"] == "demo"
    assert masked["max_tokens"] == 256
    assert isinstance(masked["messages"], list)
    # PII inside a string leaf is gone; surrounding text preserved.
    user_content = masked["messages"][0]["content"]
    assert ID_CARD not in user_content
    assert "fix this:" in user_content
    assert masked["messages"][1]["content"] == "no pii here"


def test_redact_chunk_is_shared_choke_point() -> None:
    config = ProxyConfig.build()
    result = redact_chunk(SNIPPET, config, source="<unit>")
    assert isinstance(result, RedactResult)
    assert ID_CARD not in result.text


def test_http_handler_redacts_json_body_before_forwarding() -> None:
    # Capture what the proxy forwards upstream via a fake forward() — no socket.
    forwarded: dict[str, object] = {}

    def fake_forward(method, url, headers, body, timeout):
        forwarded["body"] = body
        return UpstreamResponse(
            status_code=200,
            headers={"Content-Type": "application/json"},
            content=b'{"ok": true}',
        )

    config = ProxyConfig.build()
    handler_cls = make_handler(config, fake_forward)

    body = json.dumps(
        {"messages": [{"role": "user", "content": f"see {ID_CARD}"}]}
    ).encode("utf-8")

    # Drive the handler's body-redaction path directly (no real HTTP needed).
    fake = handler_cls.__new__(handler_cls)
    fake.command = "POST"
    fake.path = "https://api.example.com/v1/chat"
    masked_body = handler_cls._redact_body(fake, body, "application/json")

    decoded = json.loads(masked_body.decode("utf-8"))
    content = decoded["messages"][0]["content"]
    assert ID_CARD not in content
    assert content.startswith("see ")


# --------------------------------------------------------------------------- #
# End-to-end on the shipped demo file.
# --------------------------------------------------------------------------- #


def test_demo_file_masks_all_planted_pii() -> None:
    from pathlib import Path

    repo_root = Path(__file__).resolve().parents[1]
    demo = repo_root / "examples" / "demo-repo" / "leaky.py"
    text = demo.read_text(encoding="utf-8")
    result = redact_text(text)

    # all planted checksum-valid PII is masked...
    assert "110101199003078515" not in result.text   # id_card
    assert "13800138000" not in result.text           # phone
    assert "6222021000112230" not in result.text      # bank_card
    assert "91110108MA01ABCD1E" not in result.text    # uscc
    # ...the bad-check-digit counter survives (not real PII)...
    assert "110101199003078500" in result.text
    # ...and the business logic is untouched.
    assert "def settle_order(amount_cents: int" in result.text
    assert "fee = (amount_cents * fee_bps) // 10_000" in result.text

    types = result.counts_by_type()
    assert types.get("id_card", 0) >= 1
    assert types.get("phone", 0) >= 2          # two planted phones
    assert types.get("bank_card", 0) >= 1
    assert types.get("uscc", 0) >= 1
    assert types.get("intranet_domain", 0) >= 1
