"""Ownership verification — the gate on `prove` when it fires at a URL rather than a container.

Two properties make the non-local half actually mean something, and both were once missing:

  * The published value must **equal** the expected token, not merely contain it. A
    containment test against a page the caller chose lets them pick a token that is a
    substring of any ordinary HTML body ("html", "div", "a") and claim a host they have
    never touched.
  * The expected token must be one the *verifier* issued to *this caller* for *this host*.
    Comparing against a token the caller also supplied proves only that they can echo
    themselves. Issuance lives in the surface that has a caller to bind to — see
    `surfaces/website/backend/ownership_token.py`; this module checks publication.

The rule is conditional on the target:
  * A **local** target needs nothing — reaching localhost implies control of the machine,
    but only when Tainted is the thing running on that machine. A hosted deployment passes
    `trust_local=False`, because there its own loopback is not the caller's.
  * A **stable non-local** target proves ownership by DNS TXT record or a
    `/.well-known/tainted-verify` file — the mechanism every domain-verification flow uses.
  * The **CI preview deploy** is neither (an ephemeral host where DNS TXT is impossible); it
    proves ownership by OIDC — a signed identity token whose claims name the repo and run.

`analyze` is never gated — it touches nothing.
"""

from __future__ import annotations

import secrets
from enum import Enum
from typing import Any, Callable, Optional

import httpx

from tainted.dynamic.target import Target


class OwnershipMethod(str, Enum):
    LOCAL = "local"
    DNS_TXT = "dns_txt"
    WELL_KNOWN = "well_known"
    OIDC = "oidc"


class OwnershipResult:
    def __init__(self, verified: bool, method: OwnershipMethod, detail: str = ""):
        self.verified = verified
        self.method = method
        self.detail = detail

    def __bool__(self) -> bool:
        return self.verified

    def __repr__(self) -> str:
        return f"OwnershipResult(verified={self.verified}, method={self.method.value})"


# --------------------------------------------------------------------------- #
# Stable non-local targets
# --------------------------------------------------------------------------- #
def verify_local(target: Target) -> OwnershipResult:
    return OwnershipResult(
        target.is_local, OwnershipMethod.LOCAL, "localhost implies machine control"
    )


# A published ownership token is one short line. Anything past this is not the file we asked
# for, and reading it whole would let a target decide how much memory the verifier spends.
_MAX_WELL_KNOWN_BYTES = 4096

WELL_KNOWN_PATH = "/.well-known/tainted-verify"


def verify_well_known(
    target: Target, expected_token: str, client: Optional[httpx.Client] = None
) -> OwnershipResult:
    """Fetch `https://<host>/.well-known/tainted-verify` and require it to *equal* the token.

    Equality, not containment: see the module docstring. Redirects are not followed, because
    a redirect means the answer came from somewhere other than the host being claimed, and
    the read is capped so the response cannot be unbounded.
    """
    client = client or httpx.Client(timeout=10.0)
    url = target.url.rstrip("/") + WELL_KNOWN_PATH
    try:
        with client.stream("GET", url, follow_redirects=False) as resp:
            if resp.status_code != 200:
                return OwnershipResult(
                    False, OwnershipMethod.WELL_KNOWN, f"GET {url} -> {resp.status_code}"
                )
            body = bytearray()
            for chunk in resp.iter_bytes():
                body += chunk
                if len(body) > _MAX_WELL_KNOWN_BYTES:
                    return OwnershipResult(
                        False,
                        OwnershipMethod.WELL_KNOWN,
                        f"GET {url} -> body larger than {_MAX_WELL_KNOWN_BYTES} bytes; "
                        "an ownership token is one short line",
                    )
    except httpx.HTTPError as exc:
        return OwnershipResult(False, OwnershipMethod.WELL_KNOWN, f"fetch failed: {exc}")
    published = bytes(body).decode("utf-8", "replace").strip()
    # Bytes, not str: `compare_digest` rejects non-ASCII str, and the body is whatever a
    # stranger's server chose to return.
    ok = secrets.compare_digest(published.encode("utf-8"), expected_token.strip().encode("utf-8"))
    return OwnershipResult(
        ok,
        OwnershipMethod.WELL_KNOWN,
        f"GET {url} -> 200, body {'matches' if ok else 'does not equal'} the expected token",
    )


def verify_dns_txt(
    target: Target,
    expected_token: str,
    resolver: Optional[Callable[[str], list[str]]] = None,
) -> OwnershipResult:
    """Look up TXT records on the target host for `tainted-verify=<token>`.

    `resolver(hostname) -> [txt strings]` is injectable so tests need no network. When omitted,
    dnspython is used if installed; without it, DNS verification is unavailable (not a failure —
    the caller can fall back to `.well-known`).
    """
    from urllib.parse import urlparse

    host = urlparse(target.url).hostname or ""
    if resolver is None:
        # Called, not referenced: `_default_dns_resolver` builds the resolver. Assigned bare,
        # the None check below could never fire, and the lookup called the factory with a
        # hostname, so every DNS verification without an injected resolver failed as
        # "lookup failed: takes 0 positional arguments", dnspython installed or not.
        resolver = _default_dns_resolver()
        if resolver is None:
            return OwnershipResult(
                False, OwnershipMethod.DNS_TXT, "dnspython not installed"
            )
    try:
        records = resolver(host)
    except Exception as exc:  # noqa: BLE001 - resolver-agnostic
        return OwnershipResult(False, OwnershipMethod.DNS_TXT, f"lookup failed: {exc}")
    # Equality on the whole record, not containment: a TXT record that merely *mentions* the
    # token is not the record we asked the owner to publish.
    needle = f"tainted-verify={expected_token.strip()}"
    wanted = needle.encode("utf-8")
    ok = any(secrets.compare_digest(r.strip().encode("utf-8"), wanted) for r in records)
    return OwnershipResult(
        ok, OwnershipMethod.DNS_TXT, f"{host} TXT records checked ({len(records)} found)"
    )


def _default_dns_resolver() -> Optional[Callable[[str], list[str]]]:
    try:
        import dns.resolver  # type: ignore
    except Exception:
        return None

    def _resolve(host: str) -> list[str]:
        answers = dns.resolver.resolve(host, "TXT")
        return [b"".join(r.strings).decode("utf-8", "replace") for r in answers]

    return _resolve


# --------------------------------------------------------------------------- #
# CI preview deploy — OIDC
# --------------------------------------------------------------------------- #
def verify_oidc(
    claims: dict[str, Any],
    expected_repo: str,
    asserted_url: Optional[str] = None,
) -> OwnershipResult:
    """Verify OIDC claims name the expected repository (and, if given, the preview URL).

    The token's *signature* must already have been checked against the provider's public keys
    by the caller (GitHub/GitLab JWKS) — this function checks the claims. Ownership is
    established by who the signed token says is running, bound to the repo, so a copied token
    naming someone else's repo fails.

    Stated residual gap: binding the workflow to the *specific* preview URL requires the
    workflow to assert that URL as a claim, which Tainted checks but cannot independently
    confirm.
    """
    repo_claim = claims.get("repository") or claims.get("project_path") or ""
    if repo_claim != expected_repo:
        return OwnershipResult(
            False,
            OwnershipMethod.OIDC,
            f"repo claim `{repo_claim}` != expected `{expected_repo}`",
        )
    if asserted_url is not None:
        url_claim = claims.get("preview_url") or claims.get("deployment_url")
        if url_claim != asserted_url:
            return OwnershipResult(
                False,
                OwnershipMethod.OIDC,
                "workflow did not assert the expected preview URL (residual gap)",
            )
    return OwnershipResult(
        True, OwnershipMethod.OIDC, f"repo `{repo_claim}` verified via signed OIDC claims"
    )


# --------------------------------------------------------------------------- #
# Convenience: pick the right method for a target
# --------------------------------------------------------------------------- #
def verify(
    target: Target,
    expected_token: Optional[str] = None,
    client: Optional[httpx.Client] = None,
    dns_resolver: Optional[Callable[[str], list[str]]] = None,
    *,
    trust_local: bool = True,
) -> OwnershipResult:
    """Verify ownership using the mechanism appropriate to the target.

    Local targets pass immediately **when `trust_local`**. Stable non-local targets try DNS
    TXT then `.well-known`. CI/OIDC is verified separately via `verify_oidc` (the caller
    holds the signed token).

    `trust_local` defaults True, which is right for every surface that runs on the
    developer's own machine (CLI, MCP, a local website). A hosted deployment must pass
    False: there, "localhost" is the server's own loopback and the caller is a stranger, so
    reading it as proof of ownership is how an unauthenticated caller aims the engine at
    internal services.
    """
    if trust_local and target.is_local:
        return verify_local(target)
    if not trust_local and target.is_local:
        return OwnershipResult(
            False,
            OwnershipMethod.LOCAL,
            "a local address cannot prove ownership to a hosted deployment",
        )
    if expected_token is None:
        return OwnershipResult(
            False, OwnershipMethod.DNS_TXT, "non-local target needs a verification token"
        )
    dns_result = verify_dns_txt(target, expected_token, resolver=dns_resolver)
    if dns_result.verified:
        return dns_result
    return verify_well_known(target, expected_token, client=client)
