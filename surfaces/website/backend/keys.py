"""The one secret a deployment is configured with, and the keys derived from it.

Two things on this surface need to hold authority that outlives a request — an ownership
token, and a sign-in session — and both are deployed somewhere with no database and no
process memory that survives. Both therefore carry their own authority in a signed or
sealed blob rather than in a row someone can look up.

That could have been two secrets to configure. It is one, because a deployment with half of
them set is a deployment where one of the two features is quietly broken, and nothing about
running a demo justifies that failure mode. The separation the two uses need is done here
instead, with HKDF: each purpose gets a key derived from the master under its own label, so
the session key and the ownership key are unrelated values even though the operator typed a
single string. Use a fresh label for any future purpose; never key two things off the raw
master.

HKDF is spelled out from `hmac` rather than imported so this module — which every other
module here leans on to answer "is this deployment configured at all?" — stays stdlib-only.
"""

from __future__ import annotations

import hashlib
import hmac
import os
from typing import Optional

SECRET_ENV = "TAINTED_TOKEN_SECRET"


def master() -> Optional[bytes]:
    """The configured secret, or None if this deployment has none."""
    raw = os.environ.get(SECRET_ENV, "").strip()
    return raw.encode("utf-8") if raw else None


def configured() -> bool:
    return master() is not None


def derive(purpose: bytes, length: int = 32) -> Optional[bytes]:
    """A key for `purpose` alone, or None if there is no master secret to derive from.

    `purpose` is a domain separator: two callers passing different labels get keys that
    reveal nothing about each other, so a flaw in one construction cannot be turned against
    the other.
    """
    secret = master()
    if secret is None:
        return None
    return _hkdf(secret, purpose, length)


def _hkdf(secret: bytes, info: bytes, length: int) -> bytes:
    """RFC 5869 HKDF-SHA256 with an empty salt.

    The extract step is not skippable here: the master is whatever string an operator
    chose, which is not guaranteed to be uniformly random the way HKDF-Expand alone
    assumes its input is.
    """
    prk = hmac.new(b"\x00" * hashlib.sha256().digest_size, secret, hashlib.sha256).digest()
    out = b""
    block = b""
    counter = 1
    while len(out) < length:
        block = hmac.new(prk, block + info + bytes([counter]), hashlib.sha256).digest()
        out += block
        counter += 1
    return out[:length]
