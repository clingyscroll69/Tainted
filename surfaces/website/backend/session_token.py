"""Sign-in sessions that survive having no server to remember them.

The store this replaces was a dict in one process. On a single long-lived server that is
fine; on the serverless host this surface deploys to it is the same bug that
`ownership_token` exists to document — an instance handles the OAuth callback, writes the
session, and is gone before the browser comes back with the cookie. Every request after
sign-in then reads an empty dict and answers 401, so `repo` is unusable and the demo is the
only thing on the page that works.

**The session is the cookie.** There is nothing to look up: the cookie carries the GitHub
token and login, and an instance that has never seen this user before can still read it.
That is the same move `ownership_token` makes, with one difference that decides the
construction: an ownership token asserts a claim the holder already knows, so signing it is
enough, while a session *contains the user's GitHub access token*. A signed-but-readable
cookie would put that token in the browser's cookie jar in plain text, and the whole point
of fetching repositories server-side is that the token never goes there. So this is sealed,
not signed — AES-256-GCM, which also authenticates, so a tampered or truncated cookie fails
to open rather than decoding into something.

**What is given up, honestly.** A stored session could be revoked; a sealed one cannot.
`logout` deletes the cookie, which ends the session for the browser that had it, but a copy
taken beforehand stays good until the sealed expiry. That is why the lifetime is short and
why it is inside the sealed payload rather than only in the cookie's `Max-Age`, which the
client controls. The alternative — a shared session store — means standing up a database for
a demo, and buys revocation at the cost of the property that makes this deployable at all.

**Failure is closed.** With no secret configured and not in local mode, sealing raises and
unsealing returns None, so a deployment that cannot protect a token does not hold one. A
developer on their own machine gets a per-process key instead: sessions work, and they end
when the server stops — exactly what the in-memory store did for them.

Format: ``ts1.<base64url(nonce || ciphertext-with-tag)>``, http-only cookie, never logged.
"""

from __future__ import annotations

import base64
import json
import os
import secrets
import time
from dataclasses import dataclass
from typing import Optional

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from backend import github as github_access
from backend import keys

PREFIX = "ts1"
DEFAULT_TTL_SECONDS = 8 * 3600
_PURPOSE = b"tainted/website/session/v1"
_NONCE_BYTES = 12
_AAD = PREFIX.encode("ascii")

# A developer running this locally has no reason to invent a secret to get the behaviour they
# already had. One key per process: sign-in works, and a restart ends every session — which is
# what the dict did too. It is generated unconditionally at import but only ever *used* when
# local mode is on at call time, so a hosted process cannot fall into it.
_EPHEMERAL_KEY = AESGCM.generate_key(bit_length=256)


class SessionSecretMissing(RuntimeError):
    """Raised when a session is requested but this deployment cannot seal one."""


@dataclass(frozen=True)
class Session:
    """A signed-in caller. `token` is their GitHub access token — never render or log it."""

    token: str
    login: str
    created: float
    expires: float
    # "public" or "private": how far the grant behind `token` reaches, as GitHub reported it at
    # sign-in. Sealed alongside the token because it is a property *of* the token — a session
    # that forgot it would have to ask GitHub again on every request, or guess.
    access: str = github_access.ACCESS_PRIVATE

    @property
    def includes_private(self) -> bool:
        return self.access == github_access.ACCESS_PRIVATE


def _local_mode() -> bool:
    # Deliberately re-read rather than imported from `app`: this module is below it, and the
    # flag is a per-request question there for the same testability reason.
    return os.environ.get("TAINTED_LOCAL_MODE", "").strip().lower() in ("1", "true", "yes")


def _key() -> Optional[bytes]:
    derived = keys.derive(_PURPOSE)
    if derived is not None:
        return derived
    return _EPHEMERAL_KEY if _local_mode() else None


def available() -> bool:
    """Whether this deployment can sign anyone in at all."""
    return _key() is not None


def seal(
    token: str,
    login: str,
    ttl_seconds: int = DEFAULT_TTL_SECONDS,
    access: str = github_access.ACCESS_PRIVATE,
) -> str:
    """Mint the cookie value for a freshly signed-in caller.

    ``access`` defaults to the wider of the two because that is what a session that does not
    say is: every cookie minted before this field existed was sealed around a `repo`-scoped
    token. Claiming less for those would hide repositories the holder really can read.
    """
    key = _key()
    if key is None:
        raise SessionSecretMissing(
            f"Sign-in is unavailable: set {keys.SECRET_ENV} to a long random string. It must "
            "be the same value on every instance of this deployment, or a session created by "
            "one instance cannot be read by the next."
        )
    now = time.time()
    payload = json.dumps(
        {"t": token, "l": login, "c": int(now), "e": int(now + ttl_seconds), "a": access},
        separators=(",", ":"),
    ).encode("utf-8")
    nonce = secrets.token_bytes(_NONCE_BYTES)
    blob = nonce + AESGCM(key).encrypt(nonce, payload, _AAD)
    return f"{PREFIX}.{base64.urlsafe_b64encode(blob).decode('ascii').rstrip('=')}"


def unseal(cookie: Optional[str]) -> Optional[Session]:
    """The session this cookie carries, or None if there isn't a usable one.

    None covers every way this can go wrong — absent, malformed, sealed under a different
    key, tampered with, or expired — because none of them is a distinction a caller should
    act on differently, and saying which would tell an attacker what to change next.
    """
    key = _key()
    if key is None or not cookie:
        return None
    prefix, _, body = cookie.strip().partition(".")
    if prefix != PREFIX or not body:
        return None
    try:
        blob = base64.urlsafe_b64decode(body + "=" * (-len(body) % 4))
    except (ValueError, TypeError):
        return None
    if len(blob) <= _NONCE_BYTES:
        return None
    try:
        plain = AESGCM(key).decrypt(blob[:_NONCE_BYTES], blob[_NONCE_BYTES:], _AAD)
        data = json.loads(plain)
        session = Session(
            token=str(data["t"]),
            login=str(data["l"]),
            created=float(data["c"]),
            expires=float(data["e"]),
            # `.get`, not `[...]`: a cookie sealed before this field existed is still a valid
            # session, and it held a `repo`-scoped token. Absent means private, not broken.
            access=str(data.get("a") or github_access.ACCESS_PRIVATE),
        )
    except (InvalidTag, ValueError, TypeError, KeyError):
        return None
    if session.expires <= time.time():
        return None
    return session
