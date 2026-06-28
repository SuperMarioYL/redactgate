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

2. **A small local HTTP forward proxy** (:class:`RedactingProxyServer`). Point an
   agent's model client at ``http://127.0.0.1:8888`` (an explicit ``HTTPS_PROXY``
   / base-url override — *not* a transparent intercept): the proxy reads the
   request body, redacts it, forwards the masked body upstream with
   :mod:`httpx`, and streams the response straight back. JSON bodies are masked
   value-by-value so the request structure the model expects is preserved; any
   other content type is masked as raw text.

Both paths funnel through :func:`redact_chunk`, so the masking + audit behaviour
is identical no matter how the bytes arrive. Nothing here terminates arbitrary
TLS or rewrites system networking; the operator opts in by piping or by setting a
proxy/base-url env var.
"""

from __future__ import annotations

import json
import sys
from dataclasses import dataclass
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import IO, Any, Callable

from .audit import AuditLog, build_entry
from .redactor import RedactResult, redact_text
from .rules import Ruleset, load_default_ruleset

__all__ = [
    "ProxyConfig",
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
    """

    ruleset: Ruleset
    audit: AuditLog | None = None
    upstream_timeout: float = 60.0

    @classmethod
    def build(
        cls,
        ruleset: Ruleset | None = None,
        audit: AuditLog | None = None,
        upstream_timeout: float = 60.0,
    ) -> "ProxyConfig":
        """Construct a config, defaulting to the bundled ruleset."""
        return cls(
            ruleset=ruleset if ruleset is not None else load_default_ruleset(),
            audit=audit,
            upstream_timeout=upstream_timeout,
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


def redact_json_payload(payload: Any, config: ProxyConfig, *, source: str) -> Any:
    """Recursively redact every string leaf of a parsed JSON ``payload``.

    Model request bodies are JSON (messages, prompts, diffs embedded as strings).
    Masking value-by-value — rather than treating the serialized blob as one text
    span — keeps the JSON structure byte-identical so the upstream API still sees
    a well-formed request; only the string *values* change.

    Args:
        payload: a value decoded from JSON (dict / list / str / scalar).
        config: active proxy config.
        source: audit label.

    Returns:
        A structurally-identical payload with PII masked inside string leaves.
    """
    if isinstance(payload, str):
        return redact_chunk(payload, config, source=source).text
    if isinstance(payload, list):
        return [redact_json_payload(item, config, source=source) for item in payload]
    if isinstance(payload, dict):
        return {
            key: redact_json_payload(value, config, source=source)
            for key, value in payload.items()
        }
    return payload


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
    dst.write(result.text)
    dst.flush()
    return result


# --------------------------------------------------------------------------- #
# Surface 2: local HTTP forward proxy
# --------------------------------------------------------------------------- #


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

        def _redact_body(self, raw: bytes, content_type: str) -> bytes:
            """Mask a request body, JSON-aware, returning the new bytes."""
            text = raw.decode("utf-8", errors="replace")
            source = f"{self.command} {self.path}"
            if "application/json" in content_type.lower():
                try:
                    payload = json.loads(text)
                except json.JSONDecodeError:
                    payload = None
                if payload is not None:
                    masked = redact_json_payload(payload, config, source=source)
                    return json.dumps(masked, ensure_ascii=False).encode("utf-8")
            # Fall back to plain-text masking for any other content type.
            return redact_chunk(text, config, source=source).text.encode("utf-8")

        def _handle(self) -> None:
            length = int(self.headers.get("Content-Length", "0") or "0")
            raw = self.rfile.read(length) if length else b""
            content_type = self.headers.get("Content-Type", "")
            masked = self._redact_body(raw, content_type) if raw else b""

            # The absolute-form request URI (forward-proxy style) is in self.path.
            url = self.path
            fwd_headers = {
                k: v
                for k, v in self.headers.items()
                if k.lower() not in ("content-length", "proxy-connection", "connection")
            }
            try:
                upstream = forward(
                    self.command,
                    url,
                    fwd_headers,
                    masked,
                    config.upstream_timeout,
                )
            except Exception as exc:  # upstream unreachable -> 502
                self._send_simple(502, f"upstream error: {exc}")
                return

            self.send_response(upstream.status_code)
            for key, value in upstream.headers.items():
                if key.lower() in ("content-length", "transfer-encoding", "connection"):
                    continue
                self.send_header(key, value)
            self.send_header("Content-Length", str(len(upstream.content)))
            self.end_headers()
            self.wfile.write(upstream.content)

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
    """A small, explicit local HTTP forward proxy that redacts request bodies.

    Start it, point your agent's model client at it via ``HTTPS_PROXY`` /
    ``HTTP_PROXY`` (or a base-url override), and every outbound request body is
    masked field-level before being forwarded upstream. This is an *opt-in*
    forward proxy, not a transparent system-wide TLS interceptor.

    Example::

        config = ProxyConfig.build(audit=AuditLog("audit.jsonl"))
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
