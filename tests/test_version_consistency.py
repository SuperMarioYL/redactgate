"""Version-consistency guard (regression for the v0.8.0 version-drift fix).

At the shipped v0.7.0 the package surfaces (VERSION, pyproject.toml ``version``,
``redactgate.__version__``, ``redactgate --version``) all read 0.7.0, but
``web/site.json`` ``content_version`` was still ``v0.6.0`` — one release stale
— so the live site advertised v0.6.0 while the package shipped 0.7.0. The
CHANGELOG bottom link-reference block had drifted too (``[Unreleased]``
compared to ``v0.4.0...HEAD`` and the ``[0.5.0]`` / ``[0.6.0]`` / ``[0.7.0]``
release links were missing).

This test treats the VERSION file as the single source of truth and asserts
every other version surface agrees with a canonical anchor value, so a future
bump that touches only one surface re-fails here. Bump the anchor together
with VERSION; the derived assertions then follow automatically.
"""

from __future__ import annotations

import json
import re
import tomllib
from pathlib import Path

import redactgate

_REPO_ROOT = Path(__file__).resolve().parents[1]


def test_version_surfaces_in_lockstep() -> None:
    """VERSION is the single source of truth; every other surface must agree."""
    expected = "0.8.0"  # canonical anchor; bump together with VERSION

    version_file = (_REPO_ROOT / "VERSION").read_text(encoding="utf-8").strip()
    assert version_file == expected, (
        f"VERSION file is {version_file!r}, expected {expected!r}"
    )

    pyproject = tomllib.loads((_REPO_ROOT / "pyproject.toml").read_text(encoding="utf-8"))
    assert pyproject["project"]["version"] == expected, (
        "pyproject.toml [project] version drifted from VERSION"
    )

    assert redactgate.__version__ == expected, (
        "redactgate.__version__ drifted from VERSION"
    )

    site = json.loads((_REPO_ROOT / "web" / "site.json").read_text(encoding="utf-8"))
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

    changelog = (_REPO_ROOT / "CHANGELOG.md").read_text(encoding="utf-8")
    assert re.search(rf"^## \[{re.escape(expected)}\]", changelog, re.MULTILINE), (
        f"CHANGELOG has no '## [{expected}]' section header"
    )
    assert (
        f"[Unreleased]: https://github.com/SuperMarioYL/redactgate/compare/v{expected}...HEAD"
        in changelog
    ), "CHANGELOG [Unreleased] link does not compare to the current tag"
    assert (
        f"[{expected}]: https://github.com/SuperMarioYL/redactgate/releases/tag/v{expected}"
        in changelog
    ), f"CHANGELOG missing the [{expected}] release link reference"
