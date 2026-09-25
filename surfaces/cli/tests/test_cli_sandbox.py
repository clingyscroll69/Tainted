from typer.testing import CliRunner

from tainted_cli.main import app

runner = CliRunner()


def test_there_is_no_ownership_token_option_left_to_reach():
    """Spec test 4. CLI targets are always localhost, so the token path was dead."""
    result = runner.invoke(app, ["prove", "--help"])
    assert "--ownership-token" not in result.output


def test_a_non_local_target_is_refused_outright(tmp_path):
    result = runner.invoke(app, [
        "prove", str(tmp_path),
        "--url", "https://app.example.com",
        "--login-a", "a@example.com:pw",
        "--login-b", "b@example.com:pw",
    ])
    assert result.exit_code == 2
    assert "localhost" in result.output.lower()


def test_a_missing_docker_daemon_refuses_rather_than_running_in_process(tmp_path, monkeypatch):
    """The property the whole change exists for."""
    from tainted.execution.base import SandboxUnavailable

    def _boom(*a, **k):
        raise SandboxUnavailable("`prove` ... requires Docker to contain it")

    monkeypatch.setattr("tainted.execution.docker.DockerExecutor.prove", _boom)
    result = runner.invoke(app, [
        "prove", str(tmp_path),
        "--url", "http://localhost:3000",
        "--login-a", "a@example.com:pw",
        "--login-b", "b@example.com:pw",
    ])
    assert result.exit_code == 2
    assert "Docker" in result.output


def _proven_report(repo):
    from tainted.models import (
        AnalysisResult, Candidate, Check, Exploit, Finding, FindingStatus, ProbeResult,
        Severity, SourceLocation,
    )
    from tainted.report import build_report

    cand = Candidate(check=Check.BOLA, title="invoice leak", severity=Severity.LOW,
                     location=SourceLocation(file="app.py", line=1))
    finding = Finding(candidate=cand, status=FindingStatus.PROVEN, proof=ProbeResult(
        succeeded=True, kind="route_bola",
        exploit=Exploit(description="x", url="http://localhost:3000/api/invoices/42", executed=True),
    ))
    return build_report(AnalysisResult(repo_path=str(repo), candidates=[cand]), [finding])


def test_prove_writes_a_receipt_of_the_attacks_that_fired(tmp_path, monkeypatch):
    """`tainted receipt` fires nothing; the receipt that lists fired attacks comes from prove."""
    import json

    from tainted.execution.base import ProveOutcome

    report = _proven_report(tmp_path)
    monkeypatch.setattr(
        "tainted.execution.docker.DockerExecutor.prove",
        lambda *a, **k: ProveOutcome(report=report),
    )
    out = tmp_path / "receipt.json"
    result = runner.invoke(app, [
        "prove", str(tmp_path),
        "--url", "http://localhost:3000",
        "--login-a", "a@example.com:pw",
        "--login-b", "b@example.com:pw",
        "--receipt", str(out),
        "--receipt-secret", "k",
    ])
    assert result.exit_code == 0, result.output
    doc = json.loads(out.read_text())
    assert [r["status"] for r in doc["fired"]] == ["proven"]
    assert "signature" in doc
