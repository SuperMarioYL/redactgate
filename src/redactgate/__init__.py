"""RedactGate — local outbound redaction gateway for coding agents.

RedactGate sits between a cloud coding agent (Claude Code / Codex) and the model
and masks checksum-validated Chinese PII — 身份证号 / 手机号 / 银行卡 /
统一社会信用代码 / 内网域名 — inside code and diffs before any byte leaves the
machine.

This package exposes a small, stable surface:

- :data:`__version__`        — the package version.
- :class:`Ruleset`           — a loaded, merged ruleset (which detectors are on,
                               masking style, allowlist, custom patterns).
- :func:`load_ruleset`       — load the bundled ``default.yaml`` and merge any
                               user ruleset on top of it.
"""

from __future__ import annotations

from .rules import (
    DEFAULT_RULES_RESOURCE,
    DetectorRule,
    MaskingStyle,
    Ruleset,
    load_default_ruleset,
    load_ruleset,
)

__version__ = "0.3.0"

__all__ = [
    "__version__",
    "DEFAULT_RULES_RESOURCE",
    "DetectorRule",
    "MaskingStyle",
    "Ruleset",
    "load_default_ruleset",
    "load_ruleset",
]
