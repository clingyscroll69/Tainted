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
from dataclasses import dataclass
from typing import Any, Optional

from tainted.ownership import OwnershipMethod, OwnershipResult, verify_oidc

# The audience every Tainted OIDC token is minted for. A token minted for another audience
# (a cloud provider's, say) is a credential for something else, and accepting it would let a
# token the pipeline holds for one purpose open this gate too.
AUDIENCE = "tainted"


@dataclass(frozen=True)
class Issuer:
    name: str
    jwks_url: str
    repo_claim: str
    repo_env: tuple[str, ...]  # where the pipeline says which repository it is running


# The issuers whose signing keys are trusted, by exact `iss`. A token names its own issuer, so
# without an allowlist a token signed by a key server its minter controls would verify against
# that key server. GitLab tokens used to be checked against GitHub's keys and could never pass.
ISSUERS: dict[str, Issuer] = {
    "https://token.actions.githubusercontent.com": Issuer(
        name="GitHub Actions",
        jwks_url="https://token.actions.githubusercontent.com/.well-known/jwks",
        repo_claim="repository",
        repo_env=("GITHUB_REPOSITORY",),
    ),
    "https://gitlab.com": Issuer(
        name="GitLab",
        jwks_url="https://gitlab.com/oauth/discovery/keys",
        repo_claim="project_path",
        repo_env=("CI_PROJECT_PATH", "GITHUB_REPOSITORY"),
    ),
}


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


def verify_signature(token: str, issuer: Issuer, issuer_url: str) -> bool:
    """Verify the token's signature, issuer, audience and expiry against the issuer's JWKS.

    Returns True when all hold and False when any does not. Raises
    :class:`SignatureUnavailable` when the signature could not be checked at all — a missing
    library or an unreachable JWKS is not a verdict on the token, and callers must not read it
    as one.
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
        signing_key = PyJWKClient(issuer.jwks_url).get_signing_key_from_jwt(token)
    except Exception as exc:
        raise SignatureUnavailable(
            f"could not fetch the {issuer.name} signing key from {issuer.jwks_url}: {exc}"
        ) from exc
    try:
        jwt.decode(
            token,
            signing_key.key,
            algorithms=["RS256"],
            audience=AUDIENCE,
            issuer=issuer_url,
        )
        return True
    except Exception:
        return False


def verify_ci_ownership(token: Optional[str] = None) -> OwnershipResult:
    """Verify a CI OIDC token: a trusted issuer's signature, audience `tainted`, this repository.

    What this establishes is that the run belongs to the repository the pipeline says it is.
    It does not name the preview URL: neither GitHub nor GitLab lets a workflow put one in its
    token, so which host the preview runs on stays the workflow's own word, and the detail says
    so every time rather than leaving it to the docs.
    """
    token = token or os.environ.get("TAINTED_OIDC_TOKEN", "")
    if not token:
        return OwnershipResult(False, OwnershipMethod.OIDC, "no OIDC token (TAINTED_OIDC_TOKEN)")
    try:
        claims = decode_claims(token)
    except ValueError as exc:
        return OwnershipResult(False, OwnershipMethod.OIDC, f"TAINTED_OIDC_TOKEN is {exc}")

    issuer_url = str(claims.get("iss", ""))
    issuer = ISSUERS.get(issuer_url)
    if issuer is None:
        return OwnershipResult(
            False,
            OwnershipMethod.OIDC,
            f"issuer `{issuer_url}` is not trusted; Tainted accepts "
            + ", ".join(f"{i.name} ({u})" for u, i in ISSUERS.items()),
        )
    expected_repo = next((os.environ[e] for e in issuer.repo_env if os.environ.get(e)), "")
    if not expected_repo:
        return OwnershipResult(
            False,
            OwnershipMethod.OIDC,
            f"the pipeline does not say which repository it is ({' or '.join(issuer.repo_env)})",
        )

    result = verify_oidc(claims, expected_repo=expected_repo, repo_claim=issuer.repo_claim)
    if not result.verified:
        return result

    # The claims name the right repo. That is only worth anything if the token is genuinely
    # the issuer's, minted for Tainted, and still live, so the signature check decides.
    try:
        signed = verify_signature(token, issuer, issuer_url)
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
            f"{result.detail} — but the token is not a live {issuer.name} token for audience "
            f"`{AUDIENCE}`",
        )
    result.detail += (
        f" (signed by {issuer.name}, audience `{AUDIENCE}`). The token binds the run to the "
        f"repository, not to the preview URL: which host the preview runs on is the "
        f"workflow's own claim."
    )
    return result
