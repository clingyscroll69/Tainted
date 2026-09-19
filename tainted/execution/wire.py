"""What crosses the container boundary, in both directions.

The run request goes in on stdin as one JSON object. Events come back on stdout as NDJSON —
one object per line, discriminated by `kind` — so the host can report a run while it happens
instead of only when it ends.

Everything here is plain JSON rather than pickle, because the thing on the other end of the
pipe is a process running untrusted code. Unpickling its output would hand it the host.
"""

from __future__ import annotations

import json
from typing import Any, Optional

from pydantic import BaseModel


class RunRequest(BaseModel):
    """One prove run, as it crosses into the container."""

    repo_path: str
    setup: dict[str, Any]
    ownership_verified: bool
    autodiscover: bool = False
    # The committed probe plan and its signature, for the surfaces that commit one. The run key
    # does NOT travel here: it goes as an env var, so it never lands in a process listing or in
    # whatever the caller logged the request into.
    plan: Optional[dict[str, Any]] = None
    plan_signature: Optional[str] = None
    # Whether the host that spawned this container had a usable LLM client. The container has
    # no way to see the host's own environment or config beyond what crossed with it, so this
    # is what lets it tell "no LLM configured anywhere" apart from "the key didn't cross the
    # boundary" — the second one must be a loud error, not a quietly thinner report ranked
    # without the meaning register the host already showed the user via `analyze`.
    llm_expected: bool = False


def encode_event(kind: str, **payload: Any) -> str:
    """One event as a single line. Never contains a newline, so the reader can split on them."""
    return json.dumps({"kind": kind, **payload}, separators=(",", ":"))


def decode_event(line: str) -> dict[str, Any]:
    """Parse one line, or raise.

    Loudly, on purpose. A container that writes a traceback to stdout would otherwise be read as
    a run that produced no findings — a silent false negative in a tool whose entire job is to
    not produce those.
    """
    try:
        obj = json.loads(line)
    except json.JSONDecodeError as exc:
        raise ValueError(
            f"The sandbox wrote a line that is not a JSON object: {line[:200]!r}"
        ) from exc
    if not isinstance(obj, dict):
        raise ValueError(f"The sandbox wrote a line that is not a JSON object: {line[:200]!r}")
    if "kind" not in obj:
        raise ValueError(f"The sandbox wrote an event with no `kind`: {line[:200]!r}")
    return obj
