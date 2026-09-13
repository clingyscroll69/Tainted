"""The CI auto-fix PR: what it will propose unattended, and what it refuses to."""

from __future__ import annotations

import subprocess


from tainted.models import (
    Candidate,
    Check,
    FileEdit,
    Finding,
    FindingStatus,
    FixResult,
    ProbeResult,
    Exploit,
    ReverifyAssertion,
    Severity,
    SourceLocation,
)
from tainted_ci.pull_request import (
    apply_edits,
    eligible,
    open_pull_request,
    pr_body,
)


def finding(check=Check.RLS, status=FindingStatus.PROVEN, title="RLS off on `notes`") -> Finding:
    cand = Candidate(
        check=check,
        title=title,
        location=SourceLocation(file="src/data.ts", line=9),
        severity=Severity.CRITICAL,
        metadata={"table": "notes", "owner_column": "author"},
    )
    return Finding(
        candidate=cand,
        status=status,
        proof=ProbeResult(
            succeeded=status is FindingStatus.PROVEN,
            kind="unfiltered_rls",
            exploit=Exploit(
                description="B read A's rows",
                method="GET",
                url="http://localhost:54321/rest/v1/notes",
                headers={"apikey": "anon"},
                executed=True,
            ),
            notes="B pulled 5 rows owned by another account.",
        ),
    )


def fix_result(f: Finding, passed=(True, True)) -> FixResult:
    return FixResult(
        finding=f,
        edits=[FileEdit(file="supabase/migrations/0002_fix.sql", replacement="alter table …;\n")],
        assertions=[
            ReverifyAssertion(name="attack_now_fails", passed=passed[0], detail="B denied."),
            ReverifyAssertion(
                name="legitimate_access_survives", passed=passed[1], detail="A still reads."
            ),
        ],
        resulting_status=(
            FindingStatus.FIXED if all(passed) else FindingStatus.BROKE_IT_SAFELY
        ),
    )


# --------------------------------------------------------------------------- #
# Eligibility — the two restrictions
# --------------------------------------------------------------------------- #
def test_only_proven_findings_are_eligible():
    """A PR that changes a security boundary on a suspicion spends trust without evidence."""
    assert eligible([finding(status=FindingStatus.CANDIDATE)]) == []
    assert len(eligible([finding()])) == 1


def test_tool_plane_findings_are_never_auto_fixed():
    """An unattended pipeline cannot answer 'does this agent need both capabilities?'."""
    assert eligible([finding(check=Check.AGENT_INJECTION)]) == []


def test_no_eligible_finding_explains_itself_rather_than_failing(tmp_path):
    result = open_pull_request(
        str(tmp_path), [finding(check=Check.AGENT_INJECTION)], []
    )
    assert result.opened is False
    assert "interview" in result.note


# --------------------------------------------------------------------------- #
# Writing edits
# --------------------------------------------------------------------------- #
def test_additive_edits_are_written_whole(tmp_path):
    written = apply_edits(str(tmp_path), [fix_result(finding())])
    assert written == ["supabase/migrations/0002_fix.sql"]
    assert (tmp_path / written[0]).read_text().startswith("alter table")


def test_in_place_edits_are_written_beside_the_file_not_spliced_into_it(tmp_path):
    """A regex-guided splice into someone's handler looks right in a diff and breaks the build."""
    (tmp_path / "app").mkdir()
    (tmp_path / "app" / "route.ts").write_text("original contents\n")

    f = finding(check=Check.BOLA)
    fix = FixResult(
        finding=f,
        edits=[
            FileEdit(
                file="app/route.ts",
                original=".eq('id', params.id)",
                replacement=".eq('id', params.id).eq('user_id', user.id)",
            )
        ],
    )
    written = apply_edits(str(tmp_path), [fix])

    assert written == ["app/route.ts.tainted-fix"]
    assert (tmp_path / "app" / "route.ts").read_text() == "original contents\n"


# --------------------------------------------------------------------------- #
# The PR body carries the evidence
# --------------------------------------------------------------------------- #
def test_pr_body_shows_the_request_that_proved_it_and_both_assertions():
    f = finding()
    body = pr_body([f], [fix_result(f)])
    assert "GET http://localhost:54321/rest/v1/notes" in body
    assert "attack_now_fails" in body
    assert "legitimate_access_survives" in body
    assert "✅" in body


def test_pr_body_warns_loudly_when_the_fix_broke_legitimate_access():
    """'Fixed' and 'secure and broken' must never look the same to a reviewer."""
    f = finding()
    body = pr_body([f], [fix_result(f, passed=(True, False))])
    assert "Secure and broken" in body
    assert "Do not merge as-is" in body
    assert "❌" in body


# --------------------------------------------------------------------------- #
# Git orchestration
# --------------------------------------------------------------------------- #
def test_a_failing_git_step_reports_which_step_and_opens_nothing(tmp_path):
    calls = []

    def runner(cmd, cwd):
        calls.append(cmd)
        code = 1 if cmd[:2] == ["git", "push"] else 0
        return subprocess.CompletedProcess(cmd, code, stdout="", stderr="no upstream")

    f = finding()
    result = open_pull_request(str(tmp_path), [f], [fix_result(f)], runner=runner)

    assert result.opened is False
    assert "git push" in result.note
    assert not any(c[:3] == ["gh", "pr", "create"] for c in calls)


def test_successful_run_pushes_a_branch_and_opens_the_pr(tmp_path):
    calls = []

    def runner(cmd, cwd):
        calls.append(cmd)
        out = "https://github.com/o/r/pull/7" if cmd[:2] == ["gh", "pr"] else ""
        return subprocess.CompletedProcess(cmd, 0, stdout=out, stderr="")

    f = finding()
    result = open_pull_request(str(tmp_path), [f], [fix_result(f)], runner=runner, base="main")

    assert result.opened is True
    assert result.url == "https://github.com/o/r/pull/7"
    assert result.branch.startswith("tainted/fix-rls-")
    assert calls[0][:2] == ["git", "checkout"]
    assert any(c[:3] == ["gh", "pr", "create"] for c in calls)
