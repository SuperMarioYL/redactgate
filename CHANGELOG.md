# Changelog

All notable changes to RedactGate are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.1.0] - 2026-06-29

First public release.

### Added

- **Checksum-validated Chinese-PII detectors** (`redactgate.detectors`) covering
  five types: 身份证号 (GB 11643 校验位), 手机号, 银行卡 (Luhn), 统一社会信用代码
  (mod-11-2), and 内网域名. Only spans that pass their checksum are reported, so a
  plain 18-digit number is not flagged.
- **`redactgate scan <file>`** — lists every CN-PII hit with line, offset, type,
  and checksum status, zero-config.
- **`redactgate proxy`** — local outbound gateway that masks each hit field-level
  inside the diff hunk (business logic is preserved) before egress.
- **JSONL audit log** — every redaction appends a one-line entry recording what
  was masked, where, and the action taken.
- **`redactgate report`** — summary of the redactions in an audit log.
- **Bundled CN-PII ruleset** (`rules/default.yaml`) controlling which detectors
  are enabled, the masking style, and an allowlist; user rulesets merge on top.
- Bilingual README (中文 primary + English sibling), Apache 2.0 licensed.

[Unreleased]: https://github.com/SuperMarioYL/redactgate/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/SuperMarioYL/redactgate/releases/tag/v0.1.0
