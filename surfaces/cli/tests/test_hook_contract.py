"""The pre-commit hook has to be where pre-commit looks, and say what it can actually deliver.

Two placement rules, both of which the original arrangement broke at once: the manifest is read
from the top level of the cloned repository and nowhere else, and a `language: python` hook is
resolved inside a virtualenv built from that repository's root package — which here is the core
engine, with no `tainted-gate` script in it and none of the CLI's dependencies.

Nothing in the suite built a hook environment, so both failures were only reachable by a user
running `pre-commit install`.
"""

from __future__ import annotations

import tomllib
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[3]
MANIFEST = ROOT / ".pre-commit-hooks.yaml"


def _hooks() -> list[dict]:
    return yaml.safe_load(MANIFEST.read_text(encoding="utf-8"))


def test_the_manifest_is_at_the_repository_root():
    assert MANIFEST.is_file(), (
        "pre-commit reads .pre-commit-hooks.yaml from the top level of the cloned repo; "
        "anywhere else and `pre-commit install` fails before running anything"
    )


def test_no_stray_manifest_under_the_surface_folder():
    strays = [
        p for p in ROOT.rglob(".pre-commit-hooks.yaml")
        if p != MANIFEST and ".venv" not in p.parts and ".git" not in p.parts
    ]
    assert not strays, f"only the root manifest is reachable; found {strays}"


def test_the_entry_point_the_hook_names_is_one_this_surface_ships():
    entry = _hooks()[0]["entry"].split()[0]
    cli = tomllib.loads((ROOT / "surfaces" / "cli" / "pyproject.toml").read_text())
    assert entry in cli["project"]["scripts"], (
        f"the hook runs `{entry}`, which no surface declares as a console script"
    )


def test_the_hook_does_not_claim_an_environment_it_cannot_build():
    """`language: python` would install the ROOT package — the engine, which has no such script."""
    hook = _hooks()[0]
    if hook["language"] != "python":
        return
    root = tomllib.loads((ROOT / "pyproject.toml").read_text())
    assert hook["entry"].split()[0] in root.get("project", {}).get("scripts", {}), (
        "a language: python hook resolves `entry` inside a venv built from the root package"
    )


def test_the_gate_command_runs_and_gates():
    """The end the hook actually depends on: the command exists and exits on severity."""
    from typer.testing import CliRunner

    from tainted_cli.hooks import gate

    fixtures = ROOT / "tests" / "fixtures" / "vulnerable_routes"
    result = CliRunner().invoke(gate, [str(fixtures), "--fail-on", "high"])
    assert result.exit_code in (0, 1), result.stdout
    clean = CliRunner().invoke(gate, [str(fixtures), "--fail-on", "info"])
    assert clean.exit_code == 1, "a repo full of candidates must not pass an `info` threshold"
