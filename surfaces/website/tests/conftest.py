"""Shared setup for the website suite.

Most of these tests drive the backend the way a developer drives it locally: a filesystem
path as the repository, and `localhost` as a target that needs no ownership proof. Both are
now conditional on `TAINTED_LOCAL_MODE`, which defaults **off** so that a deployment which
never thought about it gets the safe answer.

So the suite turns it on for itself, and says why: these are the local-dev paths, and they
are still supported. What the hosted deployment does instead — refuse a filesystem path,
refuse localhost as proof, require a signed-in caller — is asserted in `test_api_gating.py`,
which turns the flag back off for the duration of each test.
"""

from __future__ import annotations

import pytest


@pytest.fixture(autouse=True)
def local_mode(monkeypatch):
    """Run every test as a developer's own machine unless the test says otherwise."""
    monkeypatch.setenv("TAINTED_LOCAL_MODE", "1")
