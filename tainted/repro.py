"""Reproduction artifacts for a proven finding, with credentials scrubbed out.

A report says an exploit worked; the reader's first instinct is to try it, and how cheap that is
decides whether the finding is trusted. So every proven finding can emit two things built from
the exact request that was already sent:

  * a **curl line** — one pasteable command;
  * a **replay script** — standalone Python that imports nothing from Tainted, so it still runs
    after the tool is gone and can live beside the app as the record of the hole.

Both are generated from `Exploit`, which holds the method, URL, headers and body actually used.
Nothing here reconstructs or guesses a request.

**Credentials are scrubbed and read from the environment instead.** The stored exploit already
carries a masked bearer value because the probes redact before saving. The artifacts keep that
masking: a reproducer that baked a real token into a file someone commits would be a credential
leak manufactured by the security tool. The reader supplies the real value at run time through an
environment variable, so the secret never lands in the artifact.
"""

from __future__ import annotations

import shlex
from dataclasses import dataclass

from tainted.models import Exploit, Finding

# The env vars the reader fills in; the artifacts reference these rather than any real secret.
_TOKEN_ENV = "TAINTED_REPLAY_TOKEN"
_APIKEY_ENV = "TAINTED_REPLAY_APIKEY"

_CREDENTIAL_HEADERS = {"authorization", "apikey", "x-api-key", "cookie"}


class NotReproducible(ValueError):
    """Raised when a finding carries no executed request to reproduce.

    Command and template injection are demonstrated and never run, and a target Tainted could not
    reach has no request either. Both are legitimate states; inventing a plausible command for
    them would be the overclaim the proof labels exist to prevent.
    """


@dataclass(frozen=True)
class Reproducer:
    curl: str
    script: str
    filename: str
    scrubbed: bool  # True when a credential header was replaced by an env reference


def _header_for_artifact(name: str, value: str) -> tuple[str, bool]:
    """The header as it should appear in an emitted artifact, and whether it was scrubbed."""
    low = name.lower()
    if low not in _CREDENTIAL_HEADERS:
        return value, False
    if low == "authorization":
        scheme = value.split(" ", 1)[0] if " " in value else "Bearer"
        return f"{scheme} ${_TOKEN_ENV}", True
    return f"${_APIKEY_ENV}", True


def curl_for(exploit: Exploit) -> tuple[str, bool]:
    """One pasteable curl command, and whether any header was scrubbed."""
    if not exploit.url:
        raise NotReproducible("This exploit records no URL, so there is nothing to replay.")
    parts: list[str] = ["curl", "-i", "-sS"]
    method = (exploit.method or "GET").upper()
    if method != "GET":
        parts += ["-X", method]
    scrubbed = False
    for name, value in exploit.headers.items():
        shown, was = _header_for_artifact(name, value)
        scrubbed = scrubbed or was
        parts += ["-H", f"{name}: {shown}"]
    if exploit.body:
        parts += ["--data-raw", exploit.body]
    parts.append(exploit.url)
    rendered = " ".join(shlex.quote(p) if _needs_quote(p) else p for p in parts)
    return rendered, scrubbed


def _needs_quote(part: str) -> bool:
    return any(c in part for c in " \t'\"$&|;<>()") or ":" in part


_SCRIPT_TEMPLATE = '''\
#!/usr/bin/env python3
"""Standalone replay of a Tainted finding. No Tainted install required.

{title}
Proven against: {url}

This re-sends the exact request Tainted sent. It reads any credential from an environment
variable rather than carrying it in the file, so committing this script leaks no secret:

    export {token_env}=<a bearer token for the attacking account>
    export {apikey_env}=<the api key, if the target needs one>
    python {filename}

Exit code 0 means the response still looks like a leak (the hole is open). Exit code 1 means it
does not (it may be fixed, or the setup may be wrong — read the printed response to tell which).
"""
import os
import sys
import urllib.request

URL = {url!r}
METHOD = {method!r}
HEADERS = {headers!r}
BODY = {body!r}
LEAK_MARKER = {marker!r}


def _resolve(value: str) -> str:
    # Header values written as "$NAME" or "Bearer $NAME" pull the real secret from the env at
    # run time, so the file itself never holds one.
    for env in ({token_env!r}, {apikey_env!r}):
        token = "$" + env
        if token in value:
            actual = os.environ.get(env)
            if not actual:
                sys.exit(f"Set {{env}} before running this replay.")
            value = value.replace(token, actual)
    return value


def main() -> int:
    headers = {{k: _resolve(v) for k, v in HEADERS.items()}}
    data = BODY.encode() if BODY else None
    req = urllib.request.Request(URL, data=data, headers=headers, method=METHOD)
    try:
        with urllib.request.urlopen(req, timeout=20) as resp:
            status = resp.status
            body = resp.read(4096).decode("utf-8", "replace")
    except urllib.error.HTTPError as exc:
        status = exc.code
        body = exc.read(4096).decode("utf-8", "replace")
    except Exception as exc:  # noqa: BLE001 - a replay that cannot connect reports, never crashes
        print(f"Could not reach the target: {{exc}}")
        return 1
    print(f"HTTP {{status}}")
    print(body)
    leaked = status == 200 and (not LEAK_MARKER or LEAK_MARKER in body)
    print("\\nStill leaking." if leaked else "\\nDid not reproduce.")
    return 0 if leaked else 1


if __name__ == "__main__":
    raise SystemExit(main())
'''


def _scrubbed_headers(exploit: Exploit) -> tuple[dict, bool]:
    out: dict[str, str] = {}
    scrubbed = False
    for name, value in exploit.headers.items():
        shown, was = _header_for_artifact(name, value)
        scrubbed = scrubbed or was
        out[name] = shown
    return out, scrubbed


def script_for(finding: Finding) -> tuple[str, bool]:
    """A standalone replay script for a finding, and whether a credential was scrubbed."""
    exploit = finding.proof.exploit if finding.proof else None
    if exploit is None or not exploit.url:
        raise NotReproducible("This finding carries no executed request to replay.")
    headers, scrubbed = _scrubbed_headers(exploit)
    # The leak oracle: the seed id for a request-plane finding, else empty (any 200 counts).
    marker = str(finding.candidate.metadata.get("seed_id") or "")
    body = _SCRIPT_TEMPLATE.format(
        title=finding.candidate.title.replace("\n", " "),
        url=exploit.url,
        method=(exploit.method or "GET").upper(),
        headers=headers,
        body=exploit.body or "",
        marker=marker,
        filename=f"replay_{finding.candidate.id}.py",
        token_env=_TOKEN_ENV,
        apikey_env=_APIKEY_ENV,
    )
    return body, scrubbed


def reproducer_for(finding: Finding) -> Reproducer:
    """Both artifacts for one finding. Raises `NotReproducible` when there is no request."""
    exploit = finding.proof.exploit if finding.proof else None
    if exploit is None:
        raise NotReproducible(
            "This finding has no exploit to reproduce — it was argued from the code, "
            "demonstrated but not executed, or fired against a target that could not be reached."
        )
    if not exploit.executed:
        raise NotReproducible(
            "This exploit was demonstrated but deliberately not executed, so there is no real "
            "request to replay. Command and template injection are held here by design."
        )
    curl, curl_scrubbed = curl_for(exploit)
    script, script_scrubbed = script_for(finding)
    return Reproducer(
        curl=curl,
        script=script,
        filename=f"replay_{finding.candidate.id}.py",
        scrubbed=curl_scrubbed or script_scrubbed,
    )


def reproducer_dict(finding: Finding) -> dict:
    """The reproducer as plain data for a report or an API response; `None` when not reproducible."""
    try:
        r = reproducer_for(finding)
    except NotReproducible as exc:
        return {"available": False, "reason": str(exc)}
    return {
        "available": True,
        "curl": r.curl,
        "script": r.script,
        "filename": r.filename,
        "scrubbed": r.scrubbed,
    }
