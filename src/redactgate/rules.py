"""Ruleset loading and merging for RedactGate.

A *ruleset* decides three things every other module asks about:

1. **Which detectors run** (and per-type overrides) — consumed by
   ``redactgate.detectors``.
2. **How a confirmed hit is masked** (style, char, head/tail to keep, per-type
   labels) — consumed by ``redactgate.redactor``.
3. **What is never masked** (the allowlist) and **extra recognizers**
   (custom patterns).

The package ships a baseline ``rules/default.yaml``. A user ruleset is merged
*on top* of the default with :func:`load_ruleset`:

- scalar keys (``default_policy``, ``min_confidence``) override;
- the ``masking`` and ``detectors`` maps deep-merge per key;
- ``allowlist`` and ``custom_patterns`` are concatenated (default first).

Nothing here imports the detector or redactor modules, so this file stays a leaf
dependency that the rest of the package builds on.
"""

from __future__ import annotations

import importlib.resources as resources
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any, Mapping

import yaml

#: Built-in detector type identifiers, in a stable display order. Detectors
#: register against these names; rulesets toggle them by the same keys.
DETECTOR_TYPES: tuple[str, ...] = (
    "id_card",
    "phone",
    "bank_card",
    "uscc",
    "intranet_domain",
)

#: Resource name of the bundled default ruleset when installed as a package.
#: (At build time ``rules/default.yaml`` is force-included here; when running
#: from a source checkout we fall back to the repo-root ``rules/default.yaml``.)
DEFAULT_RULES_RESOURCE = "redactgate._bundled_rules"
_DEFAULT_RULES_FILENAME = "default.yaml"


class Policy(str, Enum):
    """What to do with a confirmed hit."""

    MASK = "mask"
    BLOCK = "block"


class MaskStyleName(str, Enum):
    """How a masked value is rendered."""

    PARTIAL = "partial"
    FULL = "full"
    LABEL = "label"


class RulesError(ValueError):
    """Raised when a ruleset file is malformed."""


@dataclass(frozen=True)
class MaskingStyle:
    """Resolved masking configuration."""

    style: MaskStyleName = MaskStyleName.PARTIAL
    mask_char: str = "*"
    keep_prefix: int = 4
    keep_suffix: int = 4
    labels: Mapping[str, str] = field(default_factory=dict)

    def label_for(self, detector_type: str) -> str:
        """Return the typed label for ``detector_type`` (or a generic one)."""
        return self.labels.get(detector_type, f"[{detector_type}-REDACTED]")


@dataclass(frozen=True)
class DetectorRule:
    """Per-detector configuration after merging."""

    type: str
    enabled: bool = True
    min_confidence: float | None = None
    policy: Policy | None = None


@dataclass(frozen=True)
class CustomPattern:
    """A user-supplied regex recognizer layered on top of the built-ins."""

    type: str
    pattern: str
    checksum: str | None = None
    confidence: float = 0.6


@dataclass(frozen=True)
class Ruleset:
    """A fully-resolved, immutable ruleset.

    This is the single object the detectors, redactor, and audit log consume.
    """

    version: int = 1
    default_policy: Policy = Policy.MASK
    min_confidence: float = 0.5
    masking: MaskingStyle = field(default_factory=MaskingStyle)
    detectors: Mapping[str, DetectorRule] = field(default_factory=dict)
    allowlist: tuple[str, ...] = ()
    custom_patterns: tuple[CustomPattern, ...] = ()

    # -- queries used across the package ---------------------------------

    def enabled_detectors(self) -> tuple[str, ...]:
        """Return detector type names that are enabled, in display order."""
        return tuple(
            t for t in DETECTOR_TYPES if self.detectors.get(t, DetectorRule(t)).enabled
        )

    def is_enabled(self, detector_type: str) -> bool:
        """Whether ``detector_type`` should run."""
        return self.detectors.get(detector_type, DetectorRule(detector_type)).enabled

    def threshold_for(self, detector_type: str) -> float:
        """Minimum confidence a hit of this type must reach to be acted on."""
        rule = self.detectors.get(detector_type)
        if rule is not None and rule.min_confidence is not None:
            return rule.min_confidence
        return self.min_confidence

    def policy_for(self, detector_type: str) -> Policy:
        """Resolved policy (mask/block) for this detector type."""
        rule = self.detectors.get(detector_type)
        if rule is not None and rule.policy is not None:
            return rule.policy
        return self.default_policy

    def is_allowlisted(self, raw_value: str) -> bool:
        """True if ``raw_value`` contains any allowlisted substring."""
        return any(allowed and allowed in raw_value for allowed in self.allowlist)


# --------------------------------------------------------------------------- #
# Loading & merging
# --------------------------------------------------------------------------- #


def _read_yaml(path: Path) -> dict[str, Any]:
    try:
        text = path.read_text(encoding="utf-8")
    except OSError as exc:  # pragma: no cover - filesystem error
        raise RulesError(f"cannot read ruleset {path}: {exc}") from exc
    return _parse_yaml(text, source=str(path))


def _parse_yaml(text: str, *, source: str) -> dict[str, Any]:
    try:
        data = yaml.safe_load(text)
    except yaml.YAMLError as exc:
        raise RulesError(f"invalid YAML in {source}: {exc}") from exc
    if data is None:
        return {}
    if not isinstance(data, dict):
        raise RulesError(f"ruleset {source} must be a mapping at the top level")
    return data


def _bundled_default_text() -> str:
    """Read the bundled default ruleset.

    Prefers the installed package resource; falls back to the repo-root
    ``rules/default.yaml`` for source checkouts and editable installs where the
    force-include path may not be present.
    """
    try:
        resource = resources.files(DEFAULT_RULES_RESOURCE).joinpath(
            _DEFAULT_RULES_FILENAME
        )
        if resource.is_file():
            return resource.read_text(encoding="utf-8")
    except (ModuleNotFoundError, FileNotFoundError):
        pass

    fallback = _repo_root_default()
    if fallback is not None and fallback.is_file():
        return fallback.read_text(encoding="utf-8")

    raise RulesError(
        "bundled default ruleset not found; expected package resource "
        f"{DEFAULT_RULES_RESOURCE}/{_DEFAULT_RULES_FILENAME} or a repo-root "
        "rules/default.yaml"
    )


def _repo_root_default() -> Path | None:
    """Locate ``rules/default.yaml`` relative to this source tree, if present.

    Layout: ``<repo>/src/redactgate/rules.py`` -> ``<repo>/rules/default.yaml``.
    """
    here = Path(__file__).resolve()
    for parent in here.parents:
        candidate = parent / "rules" / _DEFAULT_RULES_FILENAME
        if candidate.is_file():
            return candidate
    return None


def _coerce_masking(raw: Any) -> MaskingStyle:
    if raw is None:
        return MaskingStyle()
    if not isinstance(raw, dict):
        raise RulesError("`masking` must be a mapping")
    try:
        style = MaskStyleName(str(raw.get("style", "partial")))
    except ValueError as exc:
        raise RulesError(
            f"unknown masking.style {raw.get('style')!r}; "
            "expected partial|full|label"
        ) from exc
    labels_raw = raw.get("labels", {}) or {}
    if not isinstance(labels_raw, dict):
        raise RulesError("`masking.labels` must be a mapping")
    return MaskingStyle(
        style=style,
        mask_char=str(raw.get("mask_char", "*")) or "*",
        keep_prefix=_non_negative_int(raw.get("keep_prefix", 4), "masking.keep_prefix"),
        keep_suffix=_non_negative_int(raw.get("keep_suffix", 4), "masking.keep_suffix"),
        labels={str(k): str(v) for k, v in labels_raw.items()},
    )


def _coerce_detectors(raw: Any) -> dict[str, DetectorRule]:
    if raw is None:
        return {}
    if not isinstance(raw, dict):
        raise RulesError("`detectors` must be a mapping of type -> overrides")
    out: dict[str, DetectorRule] = {}
    for name, cfg in raw.items():
        name = str(name)
        cfg = cfg or {}
        if not isinstance(cfg, dict):
            raise RulesError(f"detector {name!r} config must be a mapping")
        policy = cfg.get("policy")
        out[name] = DetectorRule(
            type=name,
            enabled=bool(cfg.get("enabled", True)),
            min_confidence=_opt_float(cfg.get("min_confidence"), f"{name}.min_confidence"),
            policy=Policy(str(policy)) if policy is not None else None,
        )
    return out


def _coerce_custom_patterns(raw: Any) -> tuple[CustomPattern, ...]:
    if raw is None:
        return ()
    if not isinstance(raw, list):
        raise RulesError("`custom_patterns` must be a list")
    out: list[CustomPattern] = []
    for i, entry in enumerate(raw):
        if not isinstance(entry, dict):
            raise RulesError(f"custom_patterns[{i}] must be a mapping")
        if "type" not in entry or "pattern" not in entry:
            raise RulesError(
                f"custom_patterns[{i}] needs both `type` and `pattern`"
            )
        out.append(
            CustomPattern(
                type=str(entry["type"]),
                pattern=str(entry["pattern"]),
                checksum=(
                    str(entry["checksum"]) if entry.get("checksum") is not None else None
                ),
                confidence=_opt_float(
                    entry.get("confidence"), f"custom_patterns[{i}].confidence"
                )
                or 0.6,
            )
        )
    return tuple(out)


def _non_negative_int(value: Any, key: str) -> int:
    try:
        ivalue = int(value)
    except (TypeError, ValueError) as exc:
        raise RulesError(f"`{key}` must be an integer") from exc
    if ivalue < 0:
        raise RulesError(f"`{key}` must be >= 0")
    return ivalue


def _opt_float(value: Any, key: str) -> float | None:
    if value is None:
        return None
    try:
        return float(value)
    except (TypeError, ValueError) as exc:
        raise RulesError(f"`{key}` must be a number") from exc


def _deep_merge(base: dict[str, Any], overlay: dict[str, Any]) -> dict[str, Any]:
    """Merge ``overlay`` onto ``base`` (does not mutate either).

    - ``allowlist`` / ``custom_patterns`` lists are concatenated (base first).
    - other mappings deep-merge.
    - everything else: overlay wins.
    """
    merged: dict[str, Any] = dict(base)
    for key, value in overlay.items():
        if key in ("allowlist", "custom_patterns"):
            base_list = base.get(key) or []
            over_list = value or []
            if not isinstance(base_list, list) or not isinstance(over_list, list):
                raise RulesError(f"`{key}` must be a list in both rulesets")
            merged[key] = [*base_list, *over_list]
        elif (
            isinstance(value, dict)
            and isinstance(base.get(key), dict)
        ):
            merged[key] = _deep_merge(base[key], value)
        else:
            merged[key] = value
    return merged


def _build_ruleset(data: Mapping[str, Any]) -> Ruleset:
    policy_raw = data.get("default_policy", "mask")
    try:
        default_policy = Policy(str(policy_raw))
    except ValueError as exc:
        raise RulesError(
            f"unknown default_policy {policy_raw!r}; expected mask|block"
        ) from exc

    min_confidence = _opt_float(data.get("min_confidence", 0.5), "min_confidence")
    assert min_confidence is not None  # default supplied above

    return Ruleset(
        version=int(data.get("version", 1)),
        default_policy=default_policy,
        min_confidence=min_confidence,
        masking=_coerce_masking(data.get("masking")),
        detectors=_coerce_detectors(data.get("detectors")),
        allowlist=tuple(str(a) for a in (data.get("allowlist") or [])),
        custom_patterns=_coerce_custom_patterns(data.get("custom_patterns")),
    )


def load_default_ruleset() -> Ruleset:
    """Load the bundled ``rules/default.yaml`` with no user overrides."""
    data = _parse_yaml(_bundled_default_text(), source="<bundled default.yaml>")
    return _build_ruleset(data)


def load_ruleset(user_rules: str | Path | None = None) -> Ruleset:
    """Load the effective ruleset.

    With no argument, returns the bundled default. With a path, merges that user
    ruleset on top of the default (see module docstring for merge semantics).

    Args:
        user_rules: path to a user YAML ruleset, or ``None`` for the default.

    Returns:
        A resolved, immutable :class:`Ruleset`.

    Raises:
        RulesError: if a file is missing or malformed.
    """
    base = _parse_yaml(_bundled_default_text(), source="<bundled default.yaml>")
    if user_rules is None:
        return _build_ruleset(base)

    path = Path(user_rules)
    if not path.is_file():
        raise RulesError(f"user ruleset not found: {path}")
    overlay = _read_yaml(path)
    merged = _deep_merge(base, overlay)
    return _build_ruleset(merged)
