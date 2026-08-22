# Changelog

All notable changes to RedactGate are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.6.0] - 2026-08-22

### Fixed

- **The gateway now actually closes the upstream httpx SSE stream when the
  client disconnects during response-header send.** The v0.5.0 fix relocated
  the `try/finally` so a `BrokenPipeError` from `end_headers()` still entered
  the finally and called `upstream_resp.stream.close()`. But on the real httpx
  path that stream was `_httpx_forward`'s `_stream()` generator, and the
  `for`-loop that would start it sits *after* `end_headers()`. So when
  `end_headers()` raised on a mid-SSE client disconnect (the exact scenario the
  v0.5.0 fix targeted), the generator was still in the CREATED state; calling
  `close()` on a never-started generator is a no-op and does not run its
  `finally`, so `response.close()` was never called — the httpx streaming
  `Response` (and owned `Client`) leaked, while the upstream model API could
  keep emitting tokens into a buffer with no consumer. The v0.5.0 regression
  test passed only because its fake stream was a class with a plain `.close()`,
  not a generator, so it never exercised the real path.
  `_stream()` is now `_UpstreamStream`, a non-generator iterator whose
  `.close()` unconditionally calls `response.close()` (+`client.close()` when
  owned), so the handler's finally releases the upstream stream whether or not
  iteration ever began. The regression test now uses a real SSE upstream +
  `_httpx_forward` and spies on `httpx.Response.close` / `httpx.Client.close`
  to assert both are called despite iteration never beginning.

- **A custom pattern declared `confidence: 0.0` is honored instead of being
  clobbered to 0.6.** `_coerce_custom_patterns` defaulted confidence with
  `_opt_float(...) or 0.6`; because `0.0` is falsy, a pattern declared with
  `confidence: 0.0` was silently rewritten to `0.6` — so hits the user intended
  to drop below the default `min_confidence` (0.5) instead cleared the threshold
  and got masked (over-redaction on the user's own extensibility surface).
  Confidence is now defaulted on `None` rather than truthiness, so a valid
  `0.0` survives.

## [0.5.0] - 2026-08-18

### Fixed

- **Gateway no longer leaks the upstream SSE stream when the response-header send fails.**
  In the streaming (`text/event-stream`) path the `try/finally` that closes the
  upstream stream began *after* `end_headers()`, which flushes the header buffer
  to the client socket. A client that disconnected before the first chunk (the
  common coding-agent cancel-mid-SSE pattern) made `end_headers()` raise
  `BrokenPipeError` *before* the `try` was entered, so the `finally` never ran:
  `upstream_resp.stream.close()` was never called and the open httpx streaming
  `Response` + `Client` (held by `_httpx_forward`'s `_stream()` generator) leaked
  until refcount/GC, while the upstream model API could keep generating tokens
  into a buffer with no consumer. The `try` now wraps the header send too, so a
  header-send failure still enters the `finally` and releases the stream; the
  terminating-chunk write is guarded so a second `BrokenPipeError` there does
  not mask the original.

### Changed

- **The gateway reuses one long-lived `httpx.Client` across requests** instead of
  constructing and destroying one per request. `_httpx_forward` previously built a
  fresh `httpx.Client` (full TLS handshake, no HTTP keepalive) on every gateway
  request — a real latency hit for the primary use case of a coding agent making
  many HTTPS model-API requests through the gateway. `RedactingProxyServer` now
  owns a single thread-safe `httpx.Client` (passed into `_httpx_forward`) so the
  TLS handshake is amortized and keepalive is enabled; only individual per-request
  `httpx.Response`s are closed, and the shared `Client` is closed on shutdown.
  Standalone `_httpx_forward` calls (tests) keep the per-call client behaviour.

## [0.4.0] - 2026-08-14

### Fixed

Three gateway-mode correctness fixes on the `_httpx_forward` / `_handle` path
introduced by the v0.3.0 `--upstream` gateway mode. Fix-only release, no scope
expansion.

- **Gateway no longer forwards the client's `Host` header to the HTTPS upstream.**
  In gateway mode the client points its model-SDK base URL at the local proxy,
  so its request carries `Host: 127.0.0.1:<port>`; httpx honoured the explicitly
  supplied Host over the URL-derived one, so model-API edges (Cloudflare/ALB/
  nginx) routed by the mismatched Host and returned 404/421/403 — the v0.3.0
  gateway HTTPS surface was broken for the primary use case. The client `Host`
  is now dropped from the forwarded headers so httpx derives it from the
  upstream URL.
- **Gateway no longer advertises `Content-Encoding: gzip` on an already-decompressed body.**
  httpx auto-decompresses, so the body the proxy holds is identity while the
  response headers still advertised `content-encoding: gzip` with the original
  compressed length — the client tried to gunzip plain bytes and failed, so
  every compressed model-API response (Anthropic/OpenAI gzip by default because
  the SDK's `Accept-Encoding` is forwarded) was undecodable. `content-encoding`
  is now dropped from the forwarded response headers.
- **Gateway streams SSE responses instead of buffering the whole body.**
  `text/event-stream` responses (the common `stream: true` model mode) are now
  forwarded chunk-by-chunk under `Transfer-Encoding: chunked` instead of being
  read into memory whole, so tokens reach the client as they arrive rather than
  after the upstream finishes (which also risked client-side read timeouts while
  the proxy blocked on the full body). Non-streamable content types keep the
  buffered path.

## [0.3.0] - 2026-08-06

### Fixed

- **Policy.BLOCK now stops egress on every surface** instead of
  masking-and-forwarding: the HTTP gateway returns a 403 without calling the
  upstream, and the stdin / `mask` commands write nothing to stdout and exit
  non-zero, while the audit log still records `action=block`.
- **Numeric JSON leaves carrying PII are redacted**, not leaked byte-for-byte: a
  request body like `{"id_card": 110101199003078515}` is masked the same as a
  string leaf (a non-PII number such as `max_tokens: 256` is left untouched).
- **The `--listen` proxy can actually intercept HTTPS model-API traffic** via an
  HTTP-gateway `--upstream` mode: the client points its model client base URL at
  the local proxy, which redacts the body and forwards it over HTTPS to the
  configured upstream. A blind `CONNECT` tunnel is deliberately not implemented
  because it could not redact encrypted bodies.

### Added

- Self-hosted product site as a distribution channel.

### Changed

- Reconciled the README footer license example MIT → Apache 2.0.

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

[Unreleased]: https://github.com/SuperMarioYL/redactgate/compare/v0.4.0...HEAD
[0.4.0]: https://github.com/SuperMarioYL/redactgate/releases/tag/v0.4.0
[0.3.0]: https://github.com/SuperMarioYL/redactgate/releases/tag/v0.3.0
[0.2.0]: https://github.com/SuperMarioYL/redactgate/releases/tag/v0.2.0
[0.1.0]: https://github.com/SuperMarioYL/redactgate/releases/tag/v0.1.0
