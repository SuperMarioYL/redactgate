# Changelog

All notable changes to RedactGate are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.2.0] - 2026-08-02

### Added

- **`redactgate mask`** — first-class stdin→stdout egress filter, the canonical
  one-liner the demo sells (`cat file | redactgate mask`). Supports `--style`
  (partial/full/label) and `--report` (per-type summary to stderr). The existing
  `redactgate proxy --stdin` path is kept as a back-compat alias.
- **`redactgate scan` reads stdin (`-`) and multiple file paths**, aggregating
  hits across them with a CI-friendly exit code (1 if any PII is found), so a
  pre-commit hook or `git diff | redactgate scan -` gate is one invocation.

### Fixed

- **Custom recognizers now fire.** A `custom_patterns` entry in a ruleset YAML
  was parsed and documented in v0.1 but never executed by `detect` — it now
  builds a real recognizer (regex-only, or checksum-gated on `id_card` /
  `bank_card` / `uscc`) and is honoured by `detect`, `scan_text`, and
  `redact_text`. A malformed custom regex now fails fast at ruleset-load time.
- **Audit log is thread-safe.** The local HTTP forward proxy serves concurrent
  requests on a threaded server; `AuditLog.append` is now guarded by a lock so
  two threads can never interleave a half-JSON line into the compliance trail.
- **`read_entries` tolerates malformed lines.** A single corrupt line in an
  accreting audit log no longer aborts `redactgate report`; clean entries are
  still parsed and surfaced.

### Changed

- LICENSE copyright notice filled (`Copyright 2026 SuperMarioYL`); the README
  body and footer now consistently read Apache 2.0 (matching the badge).

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

[Unreleased]: https://github.com/SuperMarioYL/redactgate/compare/v0.2.0...HEAD
[0.2.0]: https://github.com/SuperMarioYL/redactgate/releases/tag/v0.2.0
[0.1.0]: https://github.com/SuperMarioYL/redactgate/releases/tag/v0.1.0
