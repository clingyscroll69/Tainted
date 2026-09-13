"""OIDC ownership for CI, over the engine's `verify_oidc`.

GitHub Actions and GitLab CI mint short-lived signed identity tokens whose claims name the
repository and workflow run. Ownership is established by who the signed token says is running,
bound to the repo — so the copy-the-secret attack (put a reusable token in my pipeline, point it
at your URL) fails, because the token isn't reusable and its claims name someone else's repo.

Signature verification against the provider's JWKS is the security-critical half, and it is
**required**. Without it the claims are just a base64 string the caller wrote: `GITHUB_REPOSITORY`
is read from the same environment as the token, so an unsigned token naming any repository would
have opened the gate. Recording "signature not checked" in a detail string while still returning
verified=True was a caveat on a door that was already open.

So a run that cannot verify the signature is **refused**, and the reason says which of the two
failures it was — PyJWT missing (install it) or the JWKS unreachable (a network problem, retry) —
because those need different things from whoever reads the log.
"""

from __future__ import annotations

import base64
import json
import os
from typing import Any, Optional

from tainted.dynamic.target import Target
from tainted.ownership import OwnershipResult, verify_oidc

_GITHUB_JWKS = "https://token.actions.githubusercontent.com/.well-known/jwks"


def _b64url_json(segment: str) -> dict[str, Any]:
    padded = segment + "=" * (-len(segment) % 4)
    return json.loads(base64.urlsafe_b64decode(padded))


def decode_claims(token: str) -> dict[str, Any]:
    """Decode a JWT payload WITHOUT verifying the signature (claims only)."""
    try:
        _, payload, _ = token.split(".")
    except ValueError as exc:
        raise ValueError("not a JWT") from exc
    return _b64url_json(payload)


class SignatureUnavailable(RuntimeError):
    """The signature could not be checked. Distinct from "the signature was wrong"."""


def verify_signature(token: str, jwks_url: str = _GITHUB_JWKS) -> bool:
    """Verify the token against the provider's JWKS.

    Returns True when the signature is good and False when it is bad. Raises
    :class:`SignatureUnavailable` when it could not be checked at all — a missing library or
    an unreachable JWKS is not a verdict on the token, and callers must not read it as one.
    """
    try:
        import jwt  # PyJWT
        from jwt import PyJWKClient
    except Exception as exc:
        raise SignatureUnavailable(
            "PyJWT is not installed, so the OIDC signature cannot be checked. "
            "Install it with `pip install 'tainted-ci'` or `pip install 'pyjwt[crypto]'`."
        ) from exc
    try:
        signing_key = PyJWKClient(jwks_url).get_signing_key_from_jwt(token)
    except Exception as exc:
        raise SignatureUnavailable(
            f"could not fetch the provider signing key from {jwks_url}: {exc}"
        ) from exc
    try:
        jwt.decode(
            token, signing_key.key, algorithms=["RS256"], options={"verify_aud": False}
        )
        return True
    except Exception:
        return False


def verify_github_ownership(
    target: Target, token: Optional[str] = None, asserted_url: Optional[str] = None
) -> OwnershipResult:
    """Verify a GitHub Actions OIDC token names the repo in $GITHUB_REPOSITORY."""
    token = token or os.environ.get("TAINTED_OIDC_TOKEN", "")
    expected_repo = os.environ.get("GITHUB_REPOSITORY", "")
    if not token or not expected_repo:
        from tainted.ownership import OwnershipMethod

        return OwnershipResult(
            False, OwnershipMethod.OIDC, "missing OIDC token or GITHUB_REPOSITORY"
        )
    from tainted.ownership import OwnershipMethod

    claims = decode_claims(token)
    result = verify_oidc(claims, expected_repo=expected_repo, asserted_url=asserted_url)
    if not result.verified:
        return result

    # The claims name the right repo. That is only worth anything if the token is genuinely
    # the provider's, so the signature decides the result rather than annotating it.
    try:
        signed = verify_signature(token)
    except SignatureUnavailable as exc:
        return OwnershipResult(
            False,
            OwnershipMethod.OIDC,
            f"{result.detail} — but the signature could not be checked: {exc}",
        )
    if not signed:
        return OwnershipResult(
            False,
            OwnershipMethod.OIDC,
            f"{result.detail} — but the token's signature is not the provider's",
        )
    result.detail += " (signature verified via JWKS)"
    return result
