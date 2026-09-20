"""MCP surface: the analyze `exclude` param and the prove missing-credentials prompt."""

from __future__ import annotations

import inspect
import textwrap

from tainted_mcp.server import tainted_analyze, tainted_prove_start


def _write(root, rel, text):
    p = root / rel
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(textwrap.dedent(text))


# --------------------------------------------------------------------------- #
# exclude
# --------------------------------------------------------------------------- #
def test_analyze_exclude_prunes_specimen_folders_and_echoes_the_list(tmp_path):
    _write(
        tmp_path,
        "src/handlers.py",
        """
        def unsafe_sql(cursor, uid):
            cursor.execute(f"select * from t where id = {uid}")
        """,
    )
    _write(
        tmp_path,
        "tests/fixtures/specimen.py",
        """
        def unsafe_sql(cursor, uid):
            cursor.execute(f"select * from t where id = {uid}")
        """,
    )

    baseline = tainted_analyze(repo_path=str(tmp_path), only="classic_injection")
    baseline_files = _files(baseline)
    assert any("fixtures" in f for f in baseline_files)
    assert "excluded" not in baseline  # not echoed when nothing was excluded

    pruned = tainted_analyze(
        repo_path=str(tmp_path), only="classic_injection", exclude="tests/fixtures"
    )
    pruned_files = _files(pruned)
    assert any("src/handlers.py" in f for f in pruned_files)
    assert not any("fixtures" in f for f in pruned_files)
    assert pruned["excluded"] == ["tests/fixtures"]


def test_analyze_exclude_takes_a_comma_separated_list(tmp_path):
    _write(tmp_path, "src/a.py", 'q = f"select {x}"')
    out = tainted_analyze(
        repo_path=str(tmp_path), only="classic_injection", exclude="demo, examples , tests"
    )
    assert out["excluded"] == ["demo", "examples", "tests"]


def _files(report: dict) -> set[str]:
    files = set()
    for key in ("findings", "unproven_candidates"):
        for row in report.get(key, []):
            cand = row.get("candidate", row)
            loc = cand.get("location") or {}
            if loc.get("file"):
                files.add(loc["file"])
    return files


# --------------------------------------------------------------------------- #
# credentials
# --------------------------------------------------------------------------- #
def test_logins_are_optional_in_the_signature():
    sig = inspect.signature(tainted_prove_start)
    assert sig.parameters["login_a"].default == ""
    assert sig.parameters["login_b"].default == ""


def test_missing_credentials_returns_an_ask_user_prompt_not_a_job():
    out = tainted_prove_start(repo_path="/repo", url="http://localhost:3000")
    assert out["job_id"] is None
    assert out["action_required"] == "ask_user"
    assert set(out["needs_credentials"]) == {"login_a", "login_b"}
    assert "invent" in out["message"].lower()


def test_one_missing_credential_still_prompts():
    out = tainted_prove_start(
        repo_path="/repo", url="http://localhost:3000", login_a="a@x.com:pw"
    )
    assert out["job_id"] is None
    assert out["needs_credentials"] == ["login_b"]


def test_blank_credential_strings_are_treated_as_missing():
    out = tainted_prove_start(
        repo_path="/repo", url="http://localhost:3000", login_a="   ", login_b="   "
    )
    assert out["job_id"] is None
    assert out["action_required"] == "ask_user"
