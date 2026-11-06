"""Version-consistency guard (regression for the v0.8.0 and v0.10.0 drift fixes).

At the shipped v0.7.0 the package surfaces (VERSION, pyproject.toml ``version``,
``redactgate.__version__``, ``redactgate --version``) all read 0.7.0, but
``web/site.json`` ``content_version`` was still ``v0.6.0`` — one release stale —
so the live site advertised v0.6.0 while the package shipped 0.7.0. The
CHANGELOG bottom link-reference block had drifted too (``[Unreleased]``
compared to ``v0.4.0...HEAD`` and the release links were missing).

The v0.8.0 guard still missed surfaces: at the shipped v0.9.0 both README
locales advertised ``v0.7.0`` and ``docs/demo-results.json`` (the recorded-demo
provenance the README links) recorded ``0.7.0``, while the suite stayed green —
and the guard itself hardcoded a fifth copy of the version in its own anchor.

This test reads the version from ``VERSION`` (the single source of truth) and
asserts every shipped surface agrees with it, so a bump that touches only one
surface re-fails here. Nothing in this file needs editing on a release bump.
"""

from __future__ import annotations

import json
import re
import tomllib
from pathlib import Path

import redactgate

_REPO_ROOT = Path(__file__).resolve().parents[1]


def _read_text(relative: str) -> str:
    return (_REPO_ROOT / relative).read_text(encoding="utf-8")


def test_version_surfaces_in_lockstep() -> None:
    """VERSION is the single source of truth; every other surface must agree."""
    expected = _read_text("VERSION").strip()
    assert re.fullmatch(r"\d+\.\d+\.\d+", expected), f"VERSION is not semver: {expected!r}"

    pyproject = tomllib.loads(_read_text("pyproject.toml"))
    assert pyproject["project"]["version"] == expected, (
        "pyproject.toml [project] version drifted from VERSION"
    )

    assert redactgate.__version__ == expected, (
        "redactgate.__version__ drifted from VERSION"
    )

    site = json.loads(_read_text("web/site.json"))
    # The top-level content_version is the canonical site version surface (it is
    # what the live product site renders). Newer site.json schemas also nest a
    # second content_version under `meta` (un-prefixed) and embed the version in
    # the footer `tag`; both are version surfaces that must stay in lockstep, so
    # guard them when present (the assertions are conditional so the test stays
    # valid against an older single-surface schema too).
    assert site["content_version"] == f"v{expected}", (
        "web/site.json top-level content_version drifted from VERSION"
    )
    meta = site.get("meta") or {}
    if "content_version" in meta:
        assert meta["content_version"] == expected, (
            "web/site.json meta.content_version drifted from VERSION"
        )
    footer = site.get("footer") or {}
    if "tag" in footer:
        assert footer["tag"].startswith(f"{expected} "), (
            "web/site.json footer.tag drifted from VERSION"
        )

    # Both README locales carry the release badge on line 12; the non-default
    # locale is the one that historically went stale (still v0.7.0 at the
    # v0.9.0 tag).
    for locale in ("README.md", "README.en.md"):
        assert f"`v{expected}`" in _read_text(locale), (
            f"{locale} release badge drifted from VERSION"
        )

    # The recorded-demo provenance the README links must name the shipped version.
    demo = json.loads(_read_text("docs/demo-results.json"))
    assert demo["version"] == expected, (
        "docs/demo-results.json version drifted from VERSION"
    )

    changelog = _read_text("CHANGELOG.md")
    # `## [Unreleased]` comes first; the newest RELEASE heading must be this one,
    # so an older heading plus a stale VERSION cannot both pass.
    headings = [
        heading
        for heading in re.findall(r"^## \[([^\]]+)\]", changelog, re.MULTILINE)
        if heading != "Unreleased"
    ]
    assert headings, "CHANGELOG has no release section headers"
    assert headings[0] == expected, (
        f"newest CHANGELOG section is [{headings[0]}], expected [{expected}]"
    )
    assert (
        f"[Unreleased]: https://github.com/SuperMarioYL/redactgate/compare/v{expected}...HEAD"
        in changelog
    ), "CHANGELOG [Unreleased] link does not compare to the current tag"
    assert (
        f"[{expected}]: https://github.com/SuperMarioYL/redactgate/releases/tag/v{expected}"
        in changelog
    ), f"CHANGELOG missing the [{expected}] release link reference"
