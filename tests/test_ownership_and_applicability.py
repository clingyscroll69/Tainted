"""Ownership verification and the applicability cascade."""

from __future__ import annotations

import httpx
import pytest

from tainted.applicability import BehavioralProbe, decide_plane
from tainted.dynamic.target import Target
from tainted.models import Plane, Register
from tainted.ownership import (
    OwnershipMethod,
    verify,
    verify_dns_txt,
    verify_oidc,
    verify_well_known,
)

TOKEN = "tainted-abc123"


# --------------------------------------------------------------------------- #
# Ownership
# --------------------------------------------------------------------------- #
def test_local_target_needs_nothing():
    assert verify(Target(url="http://localhost:3000")).verified
    assert verify(Target(url="http://127.0.0.1:54321")).method == OwnershipMethod.LOCAL


def test_well_known_file_matches_token():
    def handler(request):
        if request.url.path == "/.well-known/tainted-verify":
            return httpx.Response(200, text=TOKEN)
        return httpx.Response(404)

    client = httpx.Client(transport=httpx.MockTransport(handler))
    r = verify_well_known(Target(url="https://app.example.com"), TOKEN, client=client)
    assert r.verified

    r2 = verify_well_known(Target(url="https://app.example.com"), "wrong", client=client)
    assert not r2.verified


def test_dns_txt_with_injected_resolver():
    resolver = lambda host: [f"tainted-verify={TOKEN}", "v=spf1 -all"]  # noqa: E731
    r = verify_dns_txt(Target(url="https://app.example.com"), TOKEN, resolver=resolver)
    assert r.verified
    r2 = verify_dns_txt(Target(url="https://app.example.com"), "other", resolver=resolver)
    assert not r2.verified


def test_oidc_rejects_wrong_repo_and_accepts_right_one():
    ok = verify_oidc({"repository": "me/myapp"}, expected_repo="me/myapp")
    assert ok.verified
    bad = verify_oidc({"repository": "someone/else"}, expected_repo="me/myapp")
    assert not bad.verified


def test_oidc_reads_the_repository_from_the_issuers_own_claim():
    """GitLab names the project in `project_path`; GitHub in `repository`."""
    claims = {"project_path": "group/app"}
    assert verify_oidc(claims, "group/app", repo_claim="project_path").verified
    assert not verify_oidc(claims, "group/app").verified


# --------------------------------------------------------------------------- #
# Applicability cascade
# --------------------------------------------------------------------------- #
def test_rung1_signature_establishes_presence(vuln_repo):
    d = decide_plane(Plane.REQUEST, vuln_repo)  # no LLM needed; supabase signatures present
    assert d.applies and d.established
    assert d.provenance.origin == Register.STRUCTURE
    assert d.provenance.rung == 1


def test_no_signature_runs_under_doubt(tmp_path):
    # An empty repo: no signatures, no LLM, no target -> plane runs, absence NOT established.
    (tmp_path / "readme.md").write_text("hello")
    d = decide_plane(Plane.REQUEST, str(tmp_path))
    assert d.applies is True
    assert d.established is False  # never skipped on mere non-recognition


def test_behavioral_rung_flags_data_returned_to_nobody(tmp_path):
    (tmp_path / "readme.md").write_text("no signatures here")

    def handler(request):
        # An unauthenticated request returns protected-looking data.
        return httpx.Response(200, json=[{"id": 1, "secret": "leak"}])

    probe = BehavioralProbe(
        protected_paths=["/rest/v1/invoices"],
        client=httpx.Client(transport=httpx.MockTransport(handler)),
    )
    d = decide_plane(
        Plane.REQUEST,
        str(tmp_path),
        target=Target(url="http://localhost:54321"),
        behavioral_probe=probe,
    )
    assert d.applies and d.established
    assert d.provenance.rung == 3
    assert d.provenance.origin == Register.PROOF


# --------------------------------------------------------------------------- #
# Where a target sits
#
# The old `is_local` matched four literal strings and a `.local` suffix, so every other way
# of writing a loopback address went straight past it. And a hosted deployment read `is_local`
# as ownership, which on a server names its own loopback rather than the caller's machine.
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize(
    "url",
    [
        "http://localhost:3000",
        "http://127.0.0.1:54321",
        "http://127.0.0.2:9",
        "http://127.1:9",
        "http://2130706433:9",
        "http://0x7f000001:9",
        "http://[::1]:9",
        "http://[::ffff:127.0.0.1]:9",
        "http://0.0.0.0:9",
        "http://169.254.169.254/latest/meta-data/",
        "http://10.0.0.5/",
        "http://192.168.1.10/",
        "http://172.16.4.4/",
        "http://printer.local/",
        "http://svc.internal/",
    ],
)
def test_internal_addresses_are_recognised_however_they_are_written(url):
    assert Target(url=url).is_internal, url


@pytest.mark.parametrize(
    "url", ["https://app.example.com", "https://ledger-preview.vercel.app", "http://93.184.216.34/"]
)
def test_public_addresses_are_not_internal(url):
    assert not Target(url=url).is_internal, url


def test_a_public_name_pointing_at_loopback_is_still_internal():
    """The literal check passes and the name still resolves inward — which is the whole
    trick, so the resolved addresses are checked too."""
    target = Target(url="https://totally-public.example.com")
    assert not target.is_internal
    assert target.resolves_internal(resolver=lambda host: ["127.0.0.1"])
    assert not target.resolves_internal(resolver=lambda host: ["93.184.216.34"])


def test_a_name_that_cannot_be_resolved_counts_as_internal():
    """A host that cannot be resolved cannot be shown to be safe, and this gate refuses what
    it cannot vouch for."""

    def boom(host):
        raise OSError("no such host")

    assert Target(url="https://nope.example.com").resolves_internal(resolver=boom)
    assert Target(url="https://nope.example.com").resolves_internal(resolver=lambda h: [])


def test_localhost_proves_nothing_to_a_hosted_deployment():
    local = Target(url="http://127.0.0.1:54321")
    assert verify(local).verified  # a developer on their own machine
    assert not verify(local, trust_local=False).verified  # a hosted deployment


# --------------------------------------------------------------------------- #
# Publication must be exact
# --------------------------------------------------------------------------- #
def test_well_known_requires_equality_not_containment():
    """Containment let a caller pick a token that appears in any ordinary HTML body."""
    page = "<!doctype html><html><body><div id=root>Loading...</div></body></html>"
    client = httpx.Client(transport=httpx.MockTransport(lambda r: httpx.Response(200, text=page)))
    target = Target(url="https://app.example.com")
    for substring in ("html", "div", "a", "root", "doctype"):
        assert not verify_well_known(target, substring, client=client).verified, substring


def test_well_known_refuses_a_body_too_large_to_be_a_token():
    big = "x" * 10_000
    client = httpx.Client(transport=httpx.MockTransport(lambda r: httpx.Response(200, text=big)))
    assert not verify_well_known(Target(url="https://app.example.com"), big, client=client).verified


def test_dns_txt_requires_the_whole_record_to_match():
    resolver = lambda host: [f"tainted-verify={TOKEN}-and-then-some"]  # noqa: E731
    assert not verify_dns_txt(Target(url="https://app.example.com"), TOKEN, resolver=resolver).verified


def test_dns_verification_runs_its_own_resolver_when_none_is_injected(monkeypatch):
    """The default resolver was assigned uncalled, so this path failed on every real run."""
    import sys
    import types

    record = types.SimpleNamespace(strings=[f"tainted-verify={TOKEN}".encode()])
    fake = types.ModuleType("dns.resolver")
    fake.resolve = lambda host, kind: [record]  # type: ignore[attr-defined]
    package = types.ModuleType("dns")
    package.resolver = fake  # type: ignore[attr-defined]
    monkeypatch.setitem(sys.modules, "dns", package)
    monkeypatch.setitem(sys.modules, "dns.resolver", fake)

    assert verify_dns_txt(Target(url="https://app.example.com"), TOKEN).verified


def test_dns_verification_without_dnspython_says_so(monkeypatch):
    import sys

    monkeypatch.setitem(sys.modules, "dns", None)
    monkeypatch.setitem(sys.modules, "dns.resolver", None)
    r = verify_dns_txt(Target(url="https://app.example.com"), TOKEN)
    assert not r.verified
    assert "dnspython not installed" in r.detail
