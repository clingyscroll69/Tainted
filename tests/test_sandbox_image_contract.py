# tests/test_sandbox_image_contract.py
from pathlib import Path


DOCKERFILE = Path(__file__).resolve().parents[1] / "Dockerfile.sandbox"


def _text():
    return DOCKERFILE.read_text()


def test_the_image_installs_the_browser_and_not_just_its_client():
    """`pip install playwright` installs a client for a Chromium that is not there yet."""
    assert "playwright install --with-deps chromium" in _text()


def test_the_browsers_live_somewhere_an_unprivileged_process_can_read():
    """Left at the default they land in root's home, which the run user cannot see."""
    assert "PLAYWRIGHT_BROWSERS_PATH=/ms-playwright" in _text()
    assert "chmod -R a+rX /ms-playwright" in _text()


def test_the_run_does_not_happen_as_root():
    """A container escape and a process escape must not be the same event."""
    assert "USER tainted" in _text()
    assert "--uid 10001" in _text()


def test_the_entrypoint_is_the_container_main():
    assert "tainted.execution.container_main" in _text()


def test_the_build_context_is_not_the_whole_working_tree():
    ignore = DOCKERFILE.parent / ".dockerignore"
    assert ignore.exists(), ".dockerignore is what keeps .venv and .git out of the context"
    body = ignore.read_text()
    for noise in (".venv", ".git", "__pycache__"):
        assert noise in body
