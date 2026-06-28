"""Command-line surface for RedactGate.

Three subcommands cover the v0.1 happy path:

- ``redactgate scan <file>`` — list every checksum-validated CN-PII hit in a
  file with its line / column / type / checksum status (the m1 demo step).
- ``redactgate proxy`` — start the outbound redaction surface: a stdin->stdout
  filter (``--stdin``) or a small local HTTP forward proxy (``--listen``), each
  masking PII field-level and appending JSONL audit entries.
- ``redactgate report`` — summarize an ``audit.jsonl`` (totals by type/action),
  the compliance-self-check view (``--report`` of an egress run).

Built on :mod:`click` (per the plan's stack). All rendering goes through
:mod:`rich` for readable tables / diffs. ``main()`` is the console-script entry
declared in ``pyproject.toml``.
"""

from __future__ import annotations

import sys
from pathlib import Path
from typing import Optional

import click
from rich.console import Console
from rich.table import Table
from rich.text import Text

from . import __version__
from .audit import AuditLog, read_entries
from .detectors import scan_text
from .proxy import ProxyConfig, RedactingProxyServer, run_stdin_filter
from .redactor import RedactResult, redact_text
from .rules import Ruleset, load_default_ruleset, load_ruleset

# stderr console for status / tables; stdout stays clean for piped output.
_err = Console(stderr=True)
_out = Console()

#: Short Chinese label per detector type, used in tables / summaries.
TYPE_LABELS = {
    "id_card": "身份证",
    "phone": "手机号",
    "bank_card": "银行卡",
    "uscc": "统一社会信用代码",
    "intranet_domain": "内网域名",
}


def _label(detector_type: str) -> str:
    return TYPE_LABELS.get(detector_type, detector_type)


def _load_rules(rules_path: Optional[str]) -> Ruleset:
    """Load the effective ruleset (bundled default merged with an optional file)."""
    if rules_path:
        return load_ruleset(rules_path)
    return load_default_ruleset()


# --------------------------------------------------------------------------- #
# Root group
# --------------------------------------------------------------------------- #


@click.group(
    context_settings={"help_option_names": ["-h", "--help"]},
    help=(
        "RedactGate — local outbound redaction gateway for coding agents.\n\n"
        "Mask checksum-validated Chinese PII (身份证/手机号/银行卡/统一社会信用代码/"
        "内网域名) before your Claude Code / Codex agent sends it offshore."
    ),
)
@click.version_option(__version__, "-V", "--version", prog_name="redactgate")
def cli() -> None:  # pragma: no cover - click dispatch
    pass


# --------------------------------------------------------------------------- #
# redactgate scan <file>
# --------------------------------------------------------------------------- #


@cli.command(help="Scan a file and list every CN-PII hit with line/column.")
@click.argument("file", type=click.Path(exists=True, dir_okay=False, path_type=Path))
@click.option(
    "--rules",
    "rules_path",
    type=click.Path(exists=True, dir_okay=False),
    default=None,
    help="User ruleset YAML merged on top of the bundled default.",
)
@click.option(
    "--json",
    "as_json",
    is_flag=True,
    help="Emit hits as JSON lines (for scripting) instead of a table.",
)
def scan(file: Path, rules_path: Optional[str], as_json: bool) -> None:
    """List every checksum-validated CN-PII hit in ``file``."""
    ruleset = _load_rules(rules_path)
    text = file.read_text(encoding="utf-8", errors="replace")
    hits = scan_text(text, ruleset)

    if as_json:
        import json

        for hit in hits:
            click.echo(
                json.dumps(
                    {
                        "type": hit.type,
                        "line": hit.line,
                        "col": hit.col,
                        "checksum_valid": hit.checksum_valid,
                        "confidence": round(hit.confidence, 3),
                    },
                    ensure_ascii=False,
                )
            )
        sys.exit(0 if not hits else 1)

    if not hits:
        _out.print(f"[green]✓[/green] {file}: no CN-PII detected.")
        sys.exit(0)

    table = Table(title=f"CN-PII in {file}", title_justify="left", show_lines=False)
    table.add_column("Line", justify="right", style="cyan", no_wrap=True)
    table.add_column("Col", justify="right", style="cyan", no_wrap=True)
    table.add_column("Type", style="magenta")
    table.add_column("类型", style="magenta")
    table.add_column("Checksum", justify="center")
    table.add_column("Confidence", justify="right")

    for hit in hits:
        check = (
            Text("✓", style="green") if hit.checksum_valid else Text("—", style="yellow")
        )
        table.add_row(
            str(hit.line),
            str(hit.col),
            hit.type,
            _label(hit.type),
            check,
            f"{hit.confidence:.2f}",
        )

    _out.print(table)
    _out.print(f"[bold]{len(hits)}[/bold] hit(s) — checksum-validated only.")
    # Non-zero exit when PII is present, so CI / pre-commit hooks can gate on it.
    sys.exit(1)


# --------------------------------------------------------------------------- #
# redactgate proxy
# --------------------------------------------------------------------------- #


@cli.command(help="Start the outbound redaction surface (stdin filter or HTTP proxy).")
@click.option(
    "--stdin",
    "use_stdin",
    is_flag=True,
    help="Filter mode: redact text on stdin, write masked text to stdout.",
)
@click.option(
    "--listen",
    default=None,
    metavar="HOST:PORT",
    help="HTTP proxy mode: bind a local forward proxy (e.g. 127.0.0.1:8888).",
)
@click.option(
    "--rules",
    "rules_path",
    type=click.Path(exists=True, dir_okay=False),
    default=None,
    help="User ruleset YAML merged on top of the bundled default.",
)
@click.option(
    "--audit",
    "audit_path",
    type=click.Path(dir_okay=False),
    default="audit.jsonl",
    show_default=True,
    help="JSONL audit log to append masked-field records to.",
)
@click.option(
    "--no-audit",
    is_flag=True,
    help="Disable audit logging (preview only).",
)
def proxy(
    use_stdin: bool,
    listen: Optional[str],
    rules_path: Optional[str],
    audit_path: str,
    no_audit: bool,
) -> None:
    """Run the stdin filter or the local HTTP forward proxy."""
    ruleset = _load_rules(rules_path)
    audit_log = None if no_audit else AuditLog(audit_path)
    config = ProxyConfig.build(ruleset=ruleset, audit=audit_log)

    try:
        if use_stdin:
            result = run_stdin_filter(config)
            _err.print(
                f"[green]redactgate[/green] masked "
                f"[bold]{result.count}[/bold] field(s) on stdin"
                + ("" if no_audit else f"; logged to {audit_path}")
            )
            sys.exit(0)

        host, port = _parse_listen(listen or "127.0.0.1:8888")
        server = RedactingProxyServer(config, host=host, port=port)
        bound_host, bound_port = server.address
        _err.print(
            f"[green]redactgate proxy[/green] listening on "
            f"http://{bound_host}:{bound_port}"
        )
        _err.print(
            "  Point your agent's model client at this address, e.g.\n"
            f"    export HTTPS_PROXY=http://{bound_host}:{bound_port}\n"
            "  Outbound request bodies are masked field-level before forwarding."
            + ("" if no_audit else f"\n  Audit log: {audit_path}")
        )
        _err.print("  Press Ctrl-C to stop.")
        try:
            server.serve_forever()
        except KeyboardInterrupt:  # pragma: no cover - interactive
            _err.print("\n[yellow]redactgate proxy stopped.[/yellow]")
            server.server_close()
    finally:
        if audit_log is not None:
            audit_log.close()


def _parse_listen(value: str) -> tuple[str, int]:
    """Parse a ``HOST:PORT`` string into ``(host, port)``."""
    if ":" not in value:
        raise click.BadParameter(
            f"--listen must be HOST:PORT (got {value!r})", param_hint="--listen"
        )
    host, _, port_str = value.rpartition(":")
    host = host or "127.0.0.1"
    try:
        port = int(port_str)
    except ValueError as exc:
        raise click.BadParameter(
            f"invalid port {port_str!r}", param_hint="--listen"
        ) from exc
    return host, port


# --------------------------------------------------------------------------- #
# redactgate report
# --------------------------------------------------------------------------- #


@cli.command(help="Summarize an audit log (the egress-redaction compliance view).")
@click.option(
    "--audit",
    "audit_path",
    type=click.Path(exists=True, dir_okay=False),
    default="audit.jsonl",
    show_default=True,
    help="JSONL audit log to summarize.",
)
def report(audit_path: str) -> None:
    """Print a per-type / per-action summary of an audit log."""
    entries = list(read_entries(audit_path))
    if not entries:
        _out.print(f"[yellow]No audit entries in {audit_path}.[/yellow]")
        sys.exit(0)

    by_type: dict[str, int] = {}
    by_action: dict[str, int] = {}
    files: set[str] = set()
    for entry in entries:
        by_type[entry.type] = by_type.get(entry.type, 0) + 1
        by_action[entry.action] = by_action.get(entry.action, 0) + 1
        files.add(entry.file)

    table = Table(title=f"Egress redaction report — {audit_path}", title_justify="left")
    table.add_column("Type", style="magenta")
    table.add_column("类型", style="magenta")
    table.add_column("Count", justify="right", style="cyan")
    for type_name in sorted(by_type, key=lambda t: (-by_type[t], t)):
        table.add_row(type_name, _label(type_name), str(by_type[type_name]))
    _out.print(table)

    action_summary = ", ".join(
        f"{action}={count}" for action, count in sorted(by_action.items())
    )
    _out.print(
        f"[bold]{len(entries)}[/bold] field(s) redacted across "
        f"[bold]{len(files)}[/bold] source(s) — {action_summary}"
    )
    sys.exit(0)


# --------------------------------------------------------------------------- #
# Programmatic helper (used by tests / examples) + entry point
# --------------------------------------------------------------------------- #


def redact_file(path: str | Path, ruleset: Ruleset | None = None) -> RedactResult:
    """Convenience: read ``path``, return its :class:`RedactResult` (no I/O side effects)."""
    text = Path(path).read_text(encoding="utf-8", errors="replace")
    return redact_text(text, ruleset)


def main() -> None:
    """Console-script entry point (``pyproject.toml [project.scripts]``)."""
    cli()


if __name__ == "__main__":  # pragma: no cover
    main()
