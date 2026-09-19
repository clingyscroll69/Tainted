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
