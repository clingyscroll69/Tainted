"""Server-issued ownership tokens for the hosted website.

The gate this closes: `verify_well_known` used to compare the target's response against a
token *the caller also supplied*, which proves only that the caller can echo themselves. A
stranger could pick a token that appears in any ordinary HTML body and claim a host they had
never touched. A token has to come from the verifier, and it has to name who it was issued to
and what it was issued for, or checking it establishes nothing.

**Why a signature rather than a stored row.** This surface has no database, and on the
serverless host it is deployed to there is no process memory outliving a request either — the
property that used to break sign-in too, until `session_token` was written the same way. An
HMAC over the claim carries exactly the authority a lookup would and needs neither: the token
*is* the record. It costs one environment variable, `TAINTED_TOKEN_SECRET` — read here
through `keys`, which is also where sign-in gets its own key from the same string — and it
must be stable across instances or previously issued tokens stop verifying.

**Failure is closed.** With no secret configured, issuing raises and checking returns False.
A deployment that cannot bind a token to a caller has no business accepting one, and the
alternative — falling back to an unbound comparison — is the bug this module exists to remove.

Format: ``tv1.<expiry-epoch>.<base64url-hmac>``. One line, no padding, no characters that need
escaping in a DNS TXT record or a served file.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import time
from typing import Optional

from backend import keys

PREFIX = "tv1"
DEFAULT_TTL_SECONDS = 30 * 24 * 3600  # a DNS TXT record is not something to re-publish weekly
_SECRET_ENV = keys.SECRET_ENV


class TokenSecretMissing(RuntimeError):
    """Raised when a token is requested but no signing secret is configured."""


def _secret() -> Optional[bytes]:
    # Keyed on the master rather than a derived key, deliberately: tokens already published
    # in a DNS record or a .well-known file must keep verifying. Sign-in, which had nothing
    # in the world to invalidate, takes a derived key instead.
    return keys.master()


def configured() -> bool:
    """Whether this deployment can issue and check ownership tokens at all."""
    return keys.configured()


def _mac(secret: bytes, subject: str, host: str, expires: int) -> str:
    # The three facts the token asserts, joined by a character none of them may contain, so
    # no combination of subject and host can be re-cut into a different valid claim.
    claim = f"{subject}\n{host.lower()}\n{expires}".encode("utf-8")
    digest = hmac.new(secret, claim, hashlib.sha256).digest()
    return base64.urlsafe_b64encode(digest).decode("ascii").rstrip("=")


def issue(subject: str, host: str, ttl_seconds: int = DEFAULT_TTL_SECONDS) -> str:
    """Mint a token binding `subject` (the signed-in caller) to `host`.

    `subject` should be a stable identifier for the caller — the GitHub login. Two different
    users asking about the same host get two different tokens, and neither works for a host
    they did not ask about.
    """
    secret = _secret()
    if secret is None:
        raise TokenSecretMissing(
            f"Ownership tokens are unavailable: set {_SECRET_ENV} to a long random string. "
            "It must be the same value on every instance of this deployment."
        )
    if not subject or not host:
        raise ValueError("an ownership token needs both a subject and a host")
    expires = int(time.time()) + int(ttl_seconds)
    return f"{PREFIX}.{expires}.{_mac(secret, subject, host, expires)}"


def check(token: Optional[str], subject: str, host: str) -> bool:
    """Whether `token` is one we issued to `subject` for `host`, and has not expired.

    This is only half of the gate. It says the caller holds a token that is theirs for this
    host; `tainted.ownership.verify` separately says the host is publishing that same value.
    Both are required — the first stops a stranger claiming your host, the second stops you
    claiming a host you cannot publish to.
    """
    secret = _secret()
    if secret is None or not token or not subject or not host:
        return False
    parts = token.strip().split(".")
    if len(parts) != 3 or parts[0] != PREFIX:
        return False
    _, expiry_raw, mac = parts
    try:
        expires = int(expiry_raw)
    except ValueError:
        return False
    if expires < time.time():
        return False
    return hmac.compare_digest(mac, _mac(secret, subject, host, expires))
