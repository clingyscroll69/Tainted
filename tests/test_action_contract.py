"""The GitHub Action has to be buildable by GitHub, which is a stricter thing than buildable.

A Docker action is built with the directory holding `action.yml` as the build context, and a
published action is only found as `action.yml` at a repository root. Both were violated at once
by keeping the file in `surfaces/ci/`: every `COPY` in the Dockerfile named a path outside the
context, so the image never built and no consumer workflow ever reached Python.

Nothing in the test suite could catch that, because nothing in the test suite builds an image.
These tests read the two files against each other instead, which is enough to catch the whole
class: a COPY whose source is not in the context, and an action.yml that has drifted away from
the root.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
ACTION = ROOT / "action.yml"


def _action_text() -> str:
    return ACTION.read_text(encoding="utf-8")


def test_the_action_manifest_is_at_the_repository_root():
    assert ACTION.is_file(), (
        "action.yml must sit at the repository root: that is the only place GitHub looks when "
        "a workflow says `uses: owner/repo@ref`."
    )


def test_no_second_action_manifest_can_shadow_it():
    """A copy under a surface folder is an invitation to `uses: ./surfaces/ci`, which cannot build."""
    strays = [
        p for p in ROOT.rglob("action.yml")
        if p != ACTION and ".venv" not in p.parts and ".git" not in p.parts
    ]
    assert not strays, f"action.yml must exist only at the root; found {strays}"


def _dockerfile_for_action() -> Path:
    m = re.search(r'^\s*image:\s*"?([^"\n]+)"?\s*$', _action_text(), re.M)
    assert m, "the action declares no `image:`"
    image = m.group(1).strip()
    assert not image.startswith("docker://"), "this test covers the build-from-source form"
    return ROOT / image


def test_the_dockerfile_the_action_names_exists():
    assert _dockerfile_for_action().is_file()


def test_every_copy_source_exists_in_the_build_context():
    """The context is the root, because that is where action.yml is. Each COPY must resolve there."""
    dockerfile = _dockerfile_for_action()
    missing = []
    for line in dockerfile.read_text(encoding="utf-8").splitlines():
        stripped = line.strip()
        if not stripped.upper().startswith("COPY "):
            continue
        parts = [p for p in stripped.split()[1:] if not p.startswith("--")]
        for src in parts[:-1]:  # the last token is the destination inside the image
            if not (ROOT / src).exists():
                missing.append((src, stripped))
    assert not missing, (
        "these COPY sources do not exist in the action's build context (the repo root): "
        + "; ".join(f"{s!r} in {line!r}" for s, line in missing)
    )


@pytest.mark.parametrize(
    "env_var",
    [
        "TAINTED_REPO", "TAINTED_TARGET_URL", "TAINTED_FAIL_ON", "TAINTED_FIX", "GH_TOKEN",
        "TAINTED_ONLY", "TAINTED_SKIP",
    ],
)
def test_the_action_passes_through_the_environment_the_runner_reads(env_var):
    """An input the entrypoint reads and the manifest never sets is a documented dead feature."""
    assert env_var in _action_text()


def test_the_ci_image_carries_what_the_auto_fix_pr_shells_out_to():
    """`pull_request.py` runs `git` and `gh`. A slim base has neither."""
    dockerfile = (ROOT / "surfaces" / "ci" / "Dockerfile").read_text(encoding="utf-8")
    assert "git" in dockerfile and "gh" in dockerfile, (
        "TAINTED_FIX opens a PR by shelling out to `git` and `gh`; the image must install both "
        "or the feature fails at the first step every time."
    )
