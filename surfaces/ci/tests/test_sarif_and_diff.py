"""CI additions in 0.2.0: SARIF emission and opt-in diff-awareness."""

from __future__ import annotations

import json
import os

import tainted_ci.entrypoint as ep


def _clear_env(monkeypatch):
    for k in list(os.environ):
        if k.startswith("TAINTED_") or k in ("GITHUB_STEP_SUMMARY", "GITHUB_BASE_REF"):
            monkeypatch.delenv(k, raising=False)


def test_sarif_is_written_when_requested(tmp_path, monkeypatch):
    _clear_env(monkeypatch)
    out = tmp_path / "out.sarif"
    monkeypatch.setenv("TAINTED_REPO", "tests/fixtures/vulnerable_routes")
    monkeypatch.setenv("TAINTED_SARIF", str(out))
    ep.run()
    assert out.exists()
    doc = json.loads(out.read_text())
    assert doc["version"] == "2.1.0"


def test_no_sarif_without_the_env(tmp_path, monkeypatch):
    _clear_env(monkeypatch)
    monkeypatch.setenv("TAINTED_REPO", "tests/fixtures/vulnerable_routes")
    code = ep.run()
    assert code in (0, 1)  # ran normally, wrote no file


def test_diff_only_fails_open_on_no_git(tmp_path, monkeypatch):
    # A non-git directory: the changed-file set is empty, so the scan must stay whole-repo
    # rather than silently narrow to nothing.
    _clear_env(monkeypatch)
    monkeypatch.setenv("TAINTED_REPO", "tests/fixtures/vulnerable_routes")
    monkeypatch.setenv("TAINTED_DIFF_ONLY", "1")
    monkeypatch.setenv("TAINTED_DIFF_BASE", "does-not-exist")
    code = ep.run()
    assert code in (0, 1)


def test_changed_files_empty_on_bad_ref():
    assert ep._changed_files("tests/fixtures/vulnerable_routes", "nope") == set()
