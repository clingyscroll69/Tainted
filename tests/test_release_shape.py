"""One release, one number.

Seven files hardcoded `0.1.0`: the core, four surface manifests, the MCP server handshake and
the FastAPI/OpenAPI document. A release meant editing all seven and noticing none of them was
missed — and the two runtime ones are what a client and an API consumer are *told* the version
is, so a stale one there is a wrong answer rather than a cosmetic slip.

The two runtime numbers now read `tainted.__version__`. The manifests cannot (a build backend
reads them before anything is importable), so they are pinned here instead: bump the core and
the surfaces, and this test names any you forgot.
"""

from __future__ import annotations

import tomllib
from pathlib import Path

import pytest

import tainted

ROOT = Path(__file__).resolve().parents[1]
MANIFESTS = [ROOT / "pyproject.toml"] + [
    ROOT / "surfaces" / name / "pyproject.toml" for name in ("cli", "ci", "mcp", "website")
]


@pytest.mark.parametrize("manifest", MANIFESTS, ids=lambda p: p.parent.name)
def test_every_manifest_carries_the_engine_version(manifest):
    data = tomllib.loads(manifest.read_text(encoding="utf-8"))
    assert data["project"]["version"] == tainted.__version__, (
        f"{manifest.relative_to(ROOT)} says {data['project']['version']}, "
        f"the engine says {tainted.__version__}"
    )


@pytest.mark.parametrize("manifest", MANIFESTS, ids=lambda p: p.parent.name)
def test_every_manifest_is_publishable(manifest):
    """A wheel without a description or a readme is one nobody can tell apart on a release page."""
    project = tomllib.loads(manifest.read_text(encoding="utf-8"))["project"]
    assert project.get("name")
    assert project.get("description")
    assert project.get("requires-python")
    assert project.get("license"), "an unlicensed wheel is one nobody may lawfully install"


def test_the_surfaces_do_not_depend_on_each_other():
    """Each surface is independently deployable; a cross-import would make that false."""
    surfaces = {"tainted_cli", "tainted_ci", "tainted_mcp", "backend"}
    for name, package in (
        ("cli", "surfaces/cli/tainted_cli"),
        ("ci", "surfaces/ci/tainted_ci"),
        ("mcp", "surfaces/mcp/tainted_mcp"),
        ("website", "surfaces/website/backend"),
    ):
        own = package.rsplit("/", 1)[1]
        for path in (ROOT / package).rglob("*.py"):
            text = path.read_text(encoding="utf-8")
            for other in surfaces - {own}:
                assert f"import {other}" not in text, (
                    f"{path.relative_to(ROOT)} imports {other}; surfaces deploy separately"
                )
