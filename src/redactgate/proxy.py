"""Outbound interception loop — the m2 proxy surface.

RedactGate's job is to sit on the path from a coding agent to a cloud model and
rewrite the bytes going *out* so checksum-validated Chinese PII is masked before
egress. This module provides two **explicit, non-MITM** ways to do that (per the
plan's scope: NOT transparent system-wide TLS interception):

1. **stdin -> stdout filter** (:func:`run_stdin_filter`). Pipe an agent's
   outbound text through ``redactgate proxy --stdin``: each line (or the whole
   stream) is redacted field-level and written to stdout, while an audit entry is
   appended per masked field. This is the zero-config way to wrap any tool whose
   egress you can pipe.

2. **A small local HTTP gateway** (:class:`RedactingProxyServer`). Pass
   ``--upstream https://api.anthropic.com`` and point an agent's model client
   *base URL* at ``http://127.0.0.1:8888`` (an explicit base-url override — *not*
   a transparent intercept): the proxy reads the request body, redacts it,
   forwards the masked body upstream over HTTPS with :mod:`httpx`, and streams
   the response straight back. JSON bodies are masked leaf-by-leaf (string and
   numeric) so the request structure the model expects is preserved; any other
   content type is masked as raw text. A ``Policy.BLOCK`` hit refuses the
   request with a 403 rather than forwarding masked bytes.

Both paths funnel through :func:`redact_chunk`, so the masking + audit behaviour
is identical no matter how the bytes arrive. Nothing here terminates arbitrary
TLS or rewrites system networking; the operator opts in by piping or by setting a
base-url override (gateway mode). A blind CONNECT tunnel is deliberately *not*
implemented — it could not redact encrypted HTTPS bodies, so the advertised HTTPS
surface is the gateway mode, not an HTTPS_PROXY forward proxy.
"""

from __future__ import annotations

import json
import sys
from dataclasses import dataclass
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import IO, Any, Callable
from urllib.parse import urljoin

from .audit import AuditLog, build_entry
from .redactor import RedactResult, redact_text
from .rules import Ruleset, load_default_ruleset

__all__ = [
    "ProxyConfig",
    "JsonRedaction",
    "RedactedBody",
    "redact_chunk",
    "redact_json_payload",
    "run_stdin_filter",
    "RedactingProxyServer",
    "make_handler",
]

#: Default listen address for the local HTTP forward proxy.
DEFAULT_HOST = "127.0.0.1"
DEFAULT_PORT = 8888


@dataclass
class ProxyConfig:
    """Runtime configuration shared by both proxy surfaces.

    Attributes:
        ruleset: the active :class:`~redactgate.rules.Ruleset`.
        audit: an open :class:`~redactgate.audit.AuditLog`, or ``None`` to skip
            audit logging (e.g. a dry preview).
        upstream_timeout: seconds to wait on the upstream model API (HTTP mode).
        upstream: optional HTTPS gateway base URL (e.g.
            ``https://api.anthropic.com``). When set, the HTTP proxy runs in
            *gateway* mode: a client points its model client's base URL at the
            local proxy and posts path-form requests (``/v1/messages``), which
            are redacted and then joined to this base and forwarded over HTTPS
            via httpx. Without it the proxy is a plain HTTP forward proxy
            (absolute-form ``self.path``); real HTTPS model APIs need gateway
            mode because a blind CONNECT tunnel cannot redact encrypted bodies.
    """

    ruleset: Ruleset
    audit: AuditLog | None = None
    upstream_timeout: float = 60.0
    upstream: str | None = None

    @classmethod
    def build(
        cls,
        ruleset: Ruleset | None = None,
        audit: AuditLog | None = None,
        upstream_timeout: float = 60.0,
        upstream: str | None = None,
    ) -> "ProxyConfig":
        """Construct a config, defaulting to the bundled ruleset."""
        return cls(
            ruleset=ruleset if ruleset is not None else load_default_ruleset(),
            audit=audit,
            upstream_timeout=upstream_timeout,
            upstream=upstream,
        )


# --------------------------------------------------------------------------- #
# Core: redact one outbound chunk + log it
# --------------------------------------------------------------------------- #


def redact_chunk(
    text: str,
    config: ProxyConfig,
    *,
    source: str,
) -> RedactResult:
    """Redact one outbound text chunk and append audit entries for each hit.

    This is the single choke point every proxy surface goes through, so masking
    and audit behaviour are identical for stdin, HTTP bodies, and tests.

    Args:
        text: the outbound buffer to rewrite.
        config: active :class:`ProxyConfig` (ruleset + optional audit log).
        source: a label recorded in the audit log (``<stdin>``, request path…).

    Returns:
        The :class:`~redactgate.redactor.RedactResult` (rewritten text + hits).
    """
    result = redact_text(text, config.ruleset)
    if config.audit is not None and result.redactions:
        for redaction in result.redactions:
            config.audit.append(build_entry(redaction, file=source))
    return result


@dataclass
class JsonRedaction:
    """The outcome of redacting a parsed JSON payload.

    Attributes:
        payload: a structurally-identical value with PII masked inside its
            string/numeric leaves (numeric PII like
            ``{"id_card": 110101199003078515}`` is masked as a string, since a
            redactor must not let a checksum-valid number round-trip
            byte-for-byte).
        blocked: True if any masked leaf carried ``Policy.BLOCK`` — the HTTP
            proxy uses this to refuse the request instead of forwarding.
    """

    payload: Any
    blocked: bool = False


def redact_json_payload(payload: Any, config: ProxyConfig, *, source: str) -> JsonRedaction:
    """Recursively redact every string/numeric leaf of a parsed JSON ``payload``.

    Model request bodies are JSON (messages, prompts, diffs embedded as strings).
    Masking value-by-value — rather than treating the serialized blob as one text
    span — keeps the JSON structure byte-identical so the upstream API still sees
    a well-formed request; only the leaf *values* change.

    Numeric leaves are redacted too: detectors run on ``str``, so a body like
    ``{"id_card": 110101199003078515}`` would otherwise round-trip the raw
    checksum-valid number byte-for-byte. We run the recognizers on
    ``str(value)`` and, when a hit fires, replace the leaf with its masked
    rendering (a masked string). A non-PII number (``max_tokens: 256``) is left
    as-is so its type and value survive untouched.

    Args:
        payload: a value decoded from JSON (dict / list / str / scalar).
        config: active proxy config.
        source: audit label.

    Returns:
        A :class:`JsonRedaction` with the masked payload and an aggregated
        ``blocked`` flag (True when any leaf carried ``Policy.BLOCK``).
    """
    if isinstance(payload, str):
        result = redact_chunk(payload, config, source=source)
        return JsonRedaction(result.text, result.blocked)
    if isinstance(payload, list):
        masked: list[Any] = []
        blocked = False
        for item in payload:
            sub = redact_json_payload(item, config, source=source)
            masked.append(sub.payload)
            blocked = blocked or sub.blocked
        return JsonRedaction(masked, blocked)
    if isinstance(payload, dict):
        out: dict[str, Any] = {}
        blocked = False
        for key, value in payload.items():
            sub = redact_json_payload(value, config, source=source)
            out[key] = sub.payload
            blocked = blocked or sub.blocked
        return JsonRedaction(out, blocked)
    # bool is a subclass of int — exclude it so True/False are never coerced.
    if isinstance(payload, (int, float)) and not isinstance(payload, bool):
        # A numeric leaf can carry PII (an id_card / bank account encoded as a
        # JSON number). Run the recognizers on its string form and mask it like
        # a string leaf when a hit fires; leave non-PII numbers untouched so
        # their type and value survive.
        result = redact_chunk(str(payload), config, source=source)
        if result.changed:
            return JsonRedaction(result.text, result.blocked)
        return JsonRedaction(payload, False)
    return JsonRedaction(payload, False)


# --------------------------------------------------------------------------- #
# Surface 1: stdin -> stdout filter
# --------------------------------------------------------------------------- #


def run_stdin_filter(
    config: ProxyConfig,
    *,
    stdin: IO[str] | None = None,
    stdout: IO[str] | None = None,
    source: str = "<stdin>",
) -> RedactResult:
    """Redact text streamed on stdin and write the masked text to stdout.

    Reads the whole input (a coding agent's outbound text piped in), masks every
    checksum-valid PII field, writes the result to stdout, and appends one audit
    entry per masked field. Returns the aggregate :class:`RedactResult` so the
    caller (the CLI) can print a one-line summary to stderr.

    Args:
        config: active proxy config.
        stdin / stdout: streams to read / write (default the process streams),
            injectable for tests.
        source: audit label for the stream.

    Returns:
        The :class:`RedactResult` over the whole input.
    """
    src = stdin if stdin is not None else sys.stdin
    dst = stdout if stdout is not None else sys.stdout
    data = src.read()
    result = redact_chunk(data, config, source=source)
    # Policy.BLOCK: the masked bytes must not egress — write nothing to stdout
    # and let the caller (the CLI) exit non-zero. The audit log still records
    # the block (action=block) inside redact_chunk above.
    if not result.blocked:
        dst.write(result.text)
        dst.flush()
    return result


# --------------------------------------------------------------------------- #
# Surface 2: local HTTP forward proxy
# --------------------------------------------------------------------------- #


@dataclass
class RedactedBody:
    """A redacted request body plus the aggregated Policy.BLOCK flag.

    The HTTP handler uses ``blocked`` to decide whether to forward the (masked)
    body upstream or refuse the request with a 403 — a BLOCK must actually stop
    egress, not just mask-and-forward.
    """

    body: bytes
    blocked: bool = False


def make_handler(
    config: ProxyConfig,
    forward: Callable[[str, str, dict[str, str], bytes, float], "UpstreamResponse"],
) -> type[BaseHTTPRequestHandler]:
    """Build a request-handler class bound to ``config`` and a ``forward`` fn.

    ``forward(method, url, headers, body, timeout) -> UpstreamResponse`` is
    injected so the HTTP transport (httpx) can be swapped for a fake in tests
    without opening a socket.
    """

    class _Handler(BaseHTTPRequestHandler):
        server_version = "RedactGate/0.1"
        protocol_version = "HTTP/1.1"

        # quiet by default; the CLI prints its own status line.
        def log_message(self, *_args: Any) -> None:  # noqa: N802 (stdlib name)
            return

        def _redact_body(self, raw: bytes, content_type: str) -> "RedactedBody":
            """Mask a request body, JSON-aware, returning the bytes + blocked flag."""
            text = raw.decode("utf-8", errors="replace")
            source = f"{self.command} {self.path}"
            if "application/json" in content_type.lower():
                try:
                    payload = json.loads(text)
                except json.JSONDecodeError:
                    payload = None
                if payload is not None:
                    jr = redact_json_payload(payload, config, source=source)
                    return RedactedBody(
                        json.dumps(jr.payload, ensure_ascii=False).encode("utf-8"),
                        jr.blocked,
                    )
            # Fall back to plain-text masking for any other content type.
            chunk = redact_chunk(text, config, source=source)
            return RedactedBody(chunk.text.encode("utf-8"), chunk.blocked)

        def _forward_url(self) -> str:
            """Resolve the upstream URL this request is forwarded to.

            In *gateway* mode (a ``--upstream`` base was configured) the client
            posts a relative path (``/v1/messages``); join it to the upstream
            base so the request leaves over HTTPS to the real model API. In plain
            forward-proxy mode (no ``--upstream``) ``self.path`` is the
            absolute-form request URI, used as-is (HTTP-only targets — a blind
            CONNECT tunnel cannot redact encrypted HTTPS bodies).
            """
            if config.upstream:
                return urljoin(config.upstream, self.path)
            return self.path

        def _handle(self) -> None:
            length = int(self.headers.get("Content-Length", "0") or "0")
            raw = self.rfile.read(length) if length else b""
            content_type = self.headers.get("Content-Type", "")
            redacted = (
                self._redact_body(raw, content_type)
                if raw
                else RedactedBody(b"", False)
            )

            # Policy.BLOCK tripped: refuse the request WITHOUT forwarding so the
            # (masked) bytes never egress. The audit log already recorded
            # action=block inside _redact_body; here we just stop the request.
            if redacted.blocked:
                self._send_simple(
                    403,
                    "blocked by redaction policy (pii present, policy=block)",
                )
                return

            masked = redacted.body
            url = self._forward_url()
            fwd_headers = {
                k: v
                for k, v in self.headers.items()
                if k.lower() not in ("content-length", "proxy-connection", "connection")
            }
            try:
                upstream_resp = forward(
                    self.command,
                    url,
                    fwd_headers,
                    masked,
                    config.upstream_timeout,
                )
            except Exception as exc:  # upstream unreachable -> 502
                self._send_simple(502, f"upstream error: {exc}")
                return

            self.send_response(upstream_resp.status_code)
            for key, value in upstream_resp.headers.items():
                if key.lower() in ("content-length", "transfer-encoding", "connection"):
                    continue
                self.send_header(key, value)
            self.send_header("Content-Length", str(len(upstream_resp.content)))
            self.end_headers()
            self.wfile.write(upstream_resp.content)

        def _send_simple(self, code: int, message: str) -> None:
            body = message.encode("utf-8")
            self.send_response(code)
            self.send_header("Content-Type", "text/plain; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        # All forwardable methods route through _handle.
        do_GET = _handle  # noqa: N815
        do_POST = _handle  # noqa: N815
        do_PUT = _handle  # noqa: N815
        do_PATCH = _handle  # noqa: N815
        do_DELETE = _handle  # noqa: N815

    return _Handler


@dataclass
class UpstreamResponse:
    """A minimal upstream HTTP response (status + headers + body)."""

    status_code: int
    headers: dict[str, str]
    content: bytes


def _httpx_forward(
    method: str,
    url: str,
    headers: dict[str, str],
    body: bytes,
    timeout: float,
) -> UpstreamResponse:
    """Forward a (redacted) request upstream with httpx and return the response.

    Imported lazily so importing :mod:`redactgate.proxy` (and running the stdin
    filter / tests) does not require httpx until the HTTP proxy is actually used.
    """
    import httpx

    with httpx.Client(timeout=timeout, follow_redirects=False) as client:
        response = client.request(
            method,
            url,
            headers=headers,
            content=body if body else None,
        )
        return UpstreamResponse(
            status_code=response.status_code,
            headers=dict(response.headers),
            content=response.content,
        )


class RedactingProxyServer:
    """A small, explicit local HTTP gateway that redacts request bodies.

    Start it with an ``--upstream`` HTTPS base and point your agent's model
    client *base URL* at it (a base-url override, not an HTTPS_PROXY forward
    proxy): every outbound request body is masked field-level before being
    forwarded upstream over HTTPS. This is an *opt-in* gateway, not a
    transparent system-wide TLS interceptor — a blind CONNECT tunnel is not
    implemented because it could not redact encrypted bodies.

    Example::

        config = ProxyConfig.build(
            audit=AuditLog("audit.jsonl"), upstream="https://api.anthropic.com"
        )
        server = RedactingProxyServer(config, host="127.0.0.1", port=8888)
        server.serve_forever()   # Ctrl-C to stop
    """

    def __init__(
        self,
        config: ProxyConfig,
        host: str = DEFAULT_HOST,
        port: int = DEFAULT_PORT,
        forward: Callable[..., UpstreamResponse] | None = None,
    ) -> None:
        self.config = config
        self.host = host
        self.port = port
        handler = make_handler(config, forward or _httpx_forward)
        self._httpd = ThreadingHTTPServer((host, port), handler)
        # If port 0 was requested, capture the OS-assigned port.
        self.port = self._httpd.server_address[1]

    @property
    def address(self) -> tuple[str, int]:
        """The ``(host, port)`` the server is bound to."""
        return self.host, self.port

    def serve_forever(self) -> None:
        """Block serving requests until :meth:`shutdown` (or Ctrl-C)."""
        try:
            self._httpd.serve_forever()
        finally:
            self._httpd.server_close()

    def shutdown(self) -> None:
        """Stop a running :meth:`serve_forever` loop."""
        self._httpd.shutdown()

    def server_close(self) -> None:
        """Release the listening socket."""
        self._httpd.server_close()
