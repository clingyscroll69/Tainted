"""A proven exploit, written out as a test in the repository's own framework.

`tainted.repro` already emits a standalone replay script: a thing a reader runs once, by hand, to
satisfy themselves the finding is real. This module answers the question that comes immediately
after — *how do I make sure this never comes back* — and the honest answer is not "keep paying for
the scanner." It is a test, in the suite that already exists, running in the CI that already runs.

So the output here is a file in the project's own idiom: `pytest` for a Python repo, `vitest` or
`jest` for a JavaScript one. It imports nothing from Tainted. If Tainted is uninstalled tomorrow,
the test keeps failing when the hole reopens, which is the only durable form this evidence can
take.

Two properties are carried over from `repro` deliberately, because they are the difference between
a test and a liability:

  * **Credentials are never written into the file.** They are read from the environment, so the
    emitted test is safe to commit — a security tool that plants a token in a repository has
    created the bug it was hired to find.
  * **A finding with no executed request produces nothing.** Command and template injection are
    demonstrated and never run, and an unreachable target has no request either. Inventing a
    plausible test for those would assert something nobody observed.

The test asserts the *attack fails*. That direction matters: it passes today, against the patched
code, and starts failing the day the hole reopens — which is what a regression test is. A test
asserting the attack succeeds would be a monument to the bug rather than a guard against it.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Optional
from urllib.parse import parse_qs, unquote, urlsplit

from tainted.models import Exploit, Finding, FindingStatus
from tainted.repro import NotReproducible, _header_for_artifact

_TOKEN_ENV = "TAINTED_REPLAY_TOKEN"
_APIKEY_ENV = "TAINTED_REPLAY_APIKEY"


@dataclass(frozen=True)
class RegressionTest:
    """One emitted test file: where it goes, what framework it speaks, and its source."""

    framework: str  # "pytest" | "vitest" | "jest"
    filename: str
    source: str
    marker: str  # the value whose reappearance in a response means the hole is back

    def as_dict(self) -> dict:
        return {
            "framework": self.framework,
            "filename": self.filename,
            "source": self.source,
            "marker": self.marker,
        }


def detect_framework(repo_path: str) -> Optional[str]:
    """Which test framework this repository already uses, or None when it is not clear.

    Read off the files a project keeps anyway. None is a legitimate answer and is handled by the
    caller emitting nothing — dropping a pytest file into a repository that has never run pytest
    produces a test nobody executes, which is worse than no test, because it looks like coverage.
    """
    root = Path(repo_path)

    pkg = root / "package.json"
    if pkg.exists():
        try:
            data = json.loads(pkg.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            data = {}
        deps = {
            **(data.get("dependencies") or {}),
            **(data.get("devDependencies") or {}),
        }
        if "vitest" in deps:
            return "vitest"
        if "jest" in deps:
            return "jest"
        script = str((data.get("scripts") or {}).get("test", ""))
        if "vitest" in script:
            return "vitest"
        if "jest" in script:
            return "jest"

    if any(
        (root / name).exists()
        for name in ("pytest.ini", "tox.ini", "setup.cfg", "pyproject.toml", "conftest.py")
    ):
        if (root / "pyproject.toml").exists():
            try:
                text = (root / "pyproject.toml").read_text(encoding="utf-8")
            except OSError:
                text = ""
            if "pytest" in text:
                return "pytest"
            if not any((root / n).exists() for n in ("pytest.ini", "conftest.py", "tox.ini")):
                return None
        return "pytest"
    if (root / "tests").is_dir() and any((root / "tests").glob("test_*.py")):
        return "pytest"
    return None


def emit_regression_test(
    finding: Finding, repo_path: str, framework: Optional[str] = None
) -> RegressionTest:
    """Build the test file for one proven finding, in the repository's own framework.

    Raises `NotReproducible` when the finding carries no request that was actually sent, and
    `ValueError` when no framework could be identified — both are refusals to invent something,
    not failures.
    """
    exploit = finding.proof.exploit if finding.proof else None
    if exploit is None or not exploit.url:
        raise NotReproducible(
            "This finding records no request that was actually sent, so there is no attack to "
            "turn into a test."
        )
    if not exploit.executed:
        raise NotReproducible(
            "This exploit was demonstrated and deliberately never executed, so no observed "
            "request exists to assert against."
        )
    if finding.status not in _PROOF_ESTABLISHING:
        raise NotReproducible(
            f"This finding is {finding.status.value}, not proven. A regression test guards a "
            f"hole that was seen open; this one never was."
        )
    marker = _marker_for(finding, exploit)
    if marker is None:
        raise NotReproducible(
            "No single value in this proof identifies the record that leaked, so a test could "
            "not tell the hole reopening from the hole staying shut. It would pass either way."
        )

    framework = framework or detect_framework(repo_path)
    if framework is None:
        raise ValueError(
            "No test framework was detected in this repository. Tainted will not add a test file "
            "in a framework the project does not run, because an unexecuted test reads as "
            "coverage that does not exist. Pass `framework=` to override."
        )

    slug = _slug(finding)
    builder = {
        "pytest": _pytest_source,
        "vitest": _js_source,
        "jest": _js_source,
    }[framework]
    filename = {
        "pytest": f"tests/test_tainted_{slug}.py",
        "vitest": f"tests/tainted_{slug}.test.js",
        "jest": f"tests/tainted_{slug}.test.js",
    }[framework]
    source = builder(finding, exploit, marker, framework)
    return RegressionTest(framework=framework, filename=filename, source=source, marker=marker)


# Statuses that mean an attack ran and the hole was real, as in `report.model` and `exposure`.
_PROOF_ESTABLISHING = frozenset(
    {FindingStatus.PROVEN, FindingStatus.FIXED, FindingStatus.BROKE_IT_SAFELY}
)


def _marker_for(finding: Finding, exploit: Exploit) -> Optional[str]:
    """The value whose reappearance means the hole is open again, or None when there is none.

    The leaked record's id is the right marker: the proof of this class of hole is that the
    attacking account received a record it does not own, and the id is the part of that record
    that identifies it without copying its contents into a committed file. Anything else, a
    table name or a query string, never appears in a response, so a test asserting its absence
    would pass whether the hole is open or not.
    """
    meta = finding.candidate.metadata
    for key in ("seed_id", "record_id"):
        if meta.get(key):
            return str(meta[key])
    kind = finding.proof.kind if finding.proof else ""
    url = urlsplit(exploit.url or "")
    if kind == "targeted_bola":
        # PostgREST filters on the record it asked for: `?id=eq.42`.
        for values in parse_qs(url.query).values():
            for value in values:
                if value.startswith("eq.") and len(value) > 3:
                    return value[3:]
    if kind == "route_bola":
        # The route was built with the record's id in its last segment: `/api/invoices/42`.
        tail = unquote(url.path.rstrip("/").rsplit("/", 1)[-1])
        if tail:
            return tail
    return None


def _slug(finding: Finding) -> str:
    base = re.sub(r"[^a-z0-9]+", "_", finding.candidate.title.lower()).strip("_")
    return f"{base[:40] or 'finding'}_{finding.candidate.id[:8]}"


def _artifact_headers(exploit: Exploit) -> dict[str, str]:
    return {k: _header_for_artifact(k, v)[0] for k, v in exploit.headers.items()}


_PY = '''\
"""Security regression test, generated by Tainted from an exploit it actually fired.

{title}
Location: {location}

This sends the exact request that once succeeded and asserts it now FAILS. It passes against the
fixed code and starts failing the day the hole reopens.

Credentials are read from the environment, never stored here:

    export {token_env}=<a bearer token for the attacking account>
    export {apikey_env}=<the api key, if the target needs one>
    export TAINTED_TARGET_URL=<the base URL of the running app>   # optional; defaults to URL below

The test skips when the target is not reachable. A test that cannot reach the app has not shown
the attack fails, and turning that into a pass would be the false all-clear this whole check
exists to prevent.
"""
import os
from urllib.parse import urlsplit, urlunsplit

import pytest

URL = {url!r}
if os.environ.get("TAINTED_TARGET_URL"):
    # Same path and query, aimed at wherever the app runs now.
    _base = urlsplit(os.environ["TAINTED_TARGET_URL"])
    URL = urlunsplit((_base.scheme, _base.netloc) + tuple(urlsplit(URL))[2:])
METHOD = {method!r}
HEADERS = {headers!r}
BODY = {body!r}
LEAK_MARKER = {marker!r}


def _resolve(value):
    for env in ({token_env!r}, {apikey_env!r}):
        token = "$" + env
        if token in value:
            actual = os.environ.get(env)
            if not actual:
                pytest.skip("{{}} is not set, so the attack could not be attempted".format(env))
            value = value.replace(token, actual)
    return value


def test_attack_does_not_succeed():
    import urllib.error
    import urllib.request

    headers = {{k: _resolve(v) for k, v in HEADERS.items()}}
    data = BODY.encode() if BODY else None
    req = urllib.request.Request(URL, data=data, headers=headers, method=METHOD)
    try:
        with urllib.request.urlopen(req, timeout=20) as resp:
            status, body = resp.status, resp.read(4096).decode("utf-8", "replace")
    except urllib.error.HTTPError as exc:
        status, body = exc.code, exc.read(4096).decode("utf-8", "replace")
    except Exception as exc:  # noqa: BLE001
        pytest.skip("target unreachable ({{}}), so the attack was never attempted".format(exc))

    leaked = 200 <= status < 300 and LEAK_MARKER in body
    assert not leaked, (
        "The attack succeeded again: {{}} returned {{}} carrying {{!r}}. "
        "This hole was closed and has reopened.".format(URL, status, LEAK_MARKER)
    )
'''

_JS = '''\
/**
 * Security regression test, generated by Tainted from an exploit it actually fired.
 *
 * {title}
 * Location: {location}
 *
 * This sends the exact request that once succeeded and asserts it now FAILS. It passes against
 * the fixed code and starts failing the day the hole reopens.
 *
 * Credentials are read from the environment, never stored here:
 *
 *   export {token_env}=<a bearer token for the attacking account>
 *   export {apikey_env}=<the api key, if the target needs one>
 *   export TAINTED_TARGET_URL=<the base URL of the running app>   # optional
 *
 * The test skips when a credential is missing or the target is not reachable: a test that
 * could not attempt the attack has not shown it fails, and recording that as a pass would be a
 * false all-clear.{skip_note}
 */
import {{ describe, it, expect }} from "{importer}";

const URL_ = process.env.TAINTED_TARGET_URL
  ? new URL(new URL({url}).pathname + new URL({url}).search, process.env.TAINTED_TARGET_URL).href
  : {url};
const METHOD = {method};
const HEADERS = {headers};
const BODY = {body};
const LEAK_MARKER = {marker};

function resolve(value) {{
  for (const env of [{token_env!r}, {apikey_env!r}]) {{
    const token = "$" + env;
    if (value.includes(token)) {{
      const actual = process.env[env];
      if (!actual) return null;
      value = value.split(token).join(actual);
    }}
  }}
  return value;
}}

const headers = {{}};
let missing = false;
for (const [k, v] of Object.entries(HEADERS)) {{
  const resolved = resolve(v);
  if (resolved === null) missing = true; // a missing credential is not a passed attack
  else headers[k] = resolved;
}}

describe("tainted regression", () => {{
  (missing ? it.skip : it)("the attack does not succeed", async ({ctx_param}) => {{

    let status, body;
    try {{
      const res = await fetch(URL_, {{
        method: METHOD,
        headers,
        body: BODY || undefined,
      }});
      status = res.status;
      body = await res.text();
    }} catch (err) {{
      // Unreachable target: nothing was attempted, so nothing is asserted.
      {unreachable}
    }}

    const leaked = status >= 200 && status < 300 && body.includes(LEAK_MARKER);
    // Thrown rather than passed to `expect`: Jest's `expect` takes one argument, not a message.
    if (leaked) {{
      throw new Error(
        `The attack succeeded again: ${{URL_}} returned ${{status}} carrying ${{LEAK_MARKER}}. ` +
          `This hole was closed and has reopened.`
      );
    }}
    expect(leaked).toBe(false);
  }});
}});
'''


def _pytest_source(finding: Finding, exploit: Exploit, marker: str, _framework: str) -> str:
    return _PY.format(
        title=finding.candidate.title,
        location=str(finding.candidate.location),
        url=exploit.url,
        method=(exploit.method or "GET").upper(),
        headers=_artifact_headers(exploit),
        body=exploit.body or "",
        marker=marker,
        token_env=_TOKEN_ENV,
        apikey_env=_APIKEY_ENV,
    )


def _js_source(finding: Finding, exploit: Exploit, marker: str, framework: str) -> str:
    return _JS.format(
        title=finding.candidate.title,
        location=str(finding.candidate.location),
        url=json.dumps(exploit.url),
        method=json.dumps((exploit.method or "GET").upper()),
        headers=json.dumps(_artifact_headers(exploit), indent=2),
        body=json.dumps(exploit.body or ""),
        marker=json.dumps(marker),
        token_env=_TOKEN_ENV,
        apikey_env=_APIKEY_ENV,
        importer="vitest" if framework == "vitest" else "@jest/globals",
        # Vitest can skip mid-test; Jest cannot, so there an unreachable target returns early
        # and the header says so, rather than the file claiming a skip it cannot perform.
        ctx_param="ctx" if framework == "vitest" else "",
        unreachable=(
            "ctx.skip();"
            if framework == "vitest"
            else 'console.warn(`tainted: ${URL_} unreachable (${err}); attack not attempted`);\n      return;'
        ),
        skip_note=(
            ""
            if framework == "vitest"
            else "\n *\n * Jest cannot skip a test once it has started, so an unreachable target is logged\n"
            " * as a warning and the test returns: read that warning as \"not attempted\", not as a pass."
        ),
    )
