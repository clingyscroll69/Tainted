"""What a request may name, and what it may not.

`repo` and `ref` are pasted into a GitHub API path. Unvalidated, a `..` segment normalises the
URL onto a different endpoint — so the server issued an authenticated request the caller never
named. These tests pin the shapes the fields accept, and that the ones which used to traverse
are refused before anything reaches the network.
"""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient
from pydantic import ValidationError

from backend.app import AnalyzeRequest, FixRequest, ProveRequest, app
from tainted.dynamic.target import Target

client = TestClient(app)


# --------------------------------------------------------------------------- #
# repo
# --------------------------------------------------------------------------- #
TRAVERSING = [
    "../../user",
    "owner/name/../../../user",
    "owner/../../user",
    "..%2f..%2fuser",
    "/etc/passwd",
    "owner/name?x=1",
    "owner/name#frag",
    "owner/na me",
    "owner",
    "owner/name/extra",
    "https://evil.example/x",
]


@pytest.mark.parametrize("bad", TRAVERSING)
def test_traversing_repo_names_are_refused(bad: str):
    with pytest.raises(ValidationError):
        AnalyzeRequest(repo=bad)


@pytest.mark.parametrize("good", ["owner/name", "My-Org/my_repo.js", "a/b", "demo/demo"])
def test_ordinary_repo_names_are_accepted(good: str):
    assert AnalyzeRequest(repo=good).repo == good


def test_repo_validation_applies_to_every_endpoint_model():
    """Prove and Fix inherit the same selector, so a new route cannot forget this."""
    for model, extra in (
        (ProveRequest, {"url": "https://example.com"}),
        (FixRequest, {}),
    ):
        with pytest.raises(ValidationError):
            model(repo="../../user", **extra)


def test_traversing_repo_is_a_422_not_a_fetch(monkeypatch):
    """The refusal happens at the model, before `_checkout` can reach GitHub."""
    import backend.github as gh

    def _explode(*a, **k):  # pragma: no cover - must never be called
        raise AssertionError("fetch_repo must not be reached for an invalid repo name")

    monkeypatch.setattr(gh, "fetch_repo", _explode)
    r = client.post("/api/analyze", json={"repo": "../../user"})
    assert r.status_code == 422


# --------------------------------------------------------------------------- #
# ref
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize("bad", ["../../../../user", "main/../../x", "..", "a/../b", "x y"])
def test_traversing_refs_are_refused(bad: str):
    with pytest.raises(ValidationError):
        AnalyzeRequest(repo="owner/name", ref=bad)


@pytest.mark.parametrize(
    "good", ["main", "release/1.2", "v1.0.0", "a" * 40, "feature/some-thing_2"]
)
def test_ordinary_refs_are_accepted(good: str):
    assert AnalyzeRequest(repo="owner/name", ref=good).ref == good


# --------------------------------------------------------------------------- #
# only / skip are gone
# --------------------------------------------------------------------------- #
def test_only_and_skip_are_no_longer_part_of_the_contract():
    """They were accepted and never read. Wiring them would have exposed test-integrity,
    the one check that executes a repository's own test suite."""
    assert "only" not in AnalyzeRequest.model_fields
    assert "skip" not in AnalyzeRequest.model_fields


# --------------------------------------------------------------------------- #
# every host a Target can reach
# --------------------------------------------------------------------------- #
def test_internal_supabase_url_is_refused_even_when_the_app_url_is_public():
    """Probes connect to `rest_base` — `supabase_url or url`. The gate has to judge both."""
    t = Target(url="https://app.example.com", supabase_url="http://127.0.0.1:54321")
    assert t.hosts == ["app.example.com", "127.0.0.1"]
    assert t.is_internal is True
    assert t.resolves_internal(lambda h: ["93.184.216.34"]) is True


def test_a_wholly_public_target_still_passes():
    t = Target(url="https://app.example.com", supabase_url="https://db.example.com")
    assert t.is_internal is False
    assert t.resolves_internal(lambda h: ["93.184.216.34"]) is False


def test_metadata_address_via_supabase_url_is_refused():
    t = Target(url="https://app.example.com", supabase_url="http://169.254.169.254")
    assert t.is_internal is True
