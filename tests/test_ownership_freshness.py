"""Ownership hardening (A3): hidden path and proof freshness."""

from __future__ import annotations

import httpx

from tainted.dynamic.target import Target
from tainted.ownership import (
    DEFAULT_OWNERSHIP_TTL_SECONDS,
    OwnershipMethod,
    OwnershipProof,
    OwnershipResult,
    WELL_KNOWN_PATH,
    hidden_well_known_path,
    verify_well_known,
)


def test_hidden_path_is_derived_from_the_token():
    p1 = hidden_well_known_path("token-one")
    p2 = hidden_well_known_path("token-two")
    assert p1.startswith("/.well-known/tainted/") and p1.endswith(".txt")
    assert p1 != p2  # a different token -> a different, unguessable path


def test_hidden_path_is_tried_first():
    token = "the-expected-token"
    hidden = hidden_well_known_path(token)
    served: dict[str, str] = {hidden: token}

    def handler(request: httpx.Request) -> httpx.Response:
        body = served.get(request.url.path, "")
        return httpx.Response(200 if body else 404, text=body)

    client = httpx.Client(transport=httpx.MockTransport(handler))
    result = verify_well_known(Target(url="https://app.example.com"), token, client=client)
    assert result.verified is True


def test_fixed_path_still_verifies_for_backward_compatibility():
    token = "legacy-token"
    served = {WELL_KNOWN_PATH: token}  # only the old fixed path is published

    def handler(request: httpx.Request) -> httpx.Response:
        body = served.get(request.url.path, "")
        return httpx.Response(200 if body else 404, text=body)

    client = httpx.Client(transport=httpx.MockTransport(handler))
    assert verify_well_known(Target(url="https://app.example.com"), token, client=client).verified


def test_a_fresh_proof_passes_and_a_stale_one_does_not():
    proof = OwnershipProof(OwnershipResult(True, OwnershipMethod.DNS_TXT), verified_at=1000.0)
    assert proof.is_fresh(now=1000.0 + 10)
    assert not proof.is_fresh(now=1000.0 + DEFAULT_OWNERSHIP_TTL_SECONDS + 10)
    assert "stale" in proof.freshness_note(now=1000.0 + DEFAULT_OWNERSHIP_TTL_SECONDS + 10)


def test_an_unverified_proof_is_never_fresh():
    proof = OwnershipProof(OwnershipResult(False, OwnershipMethod.WELL_KNOWN))
    assert proof.is_fresh() is False
