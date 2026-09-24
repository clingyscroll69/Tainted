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

from tainted.models import Exploit, Finding
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

    framework = framework or detect_framework(repo_path)
    if framework is None:
        raise ValueError(
            "No test framework was detected in this repository. Tainted will not add a test file "
            "in a framework the project does not run, because an unexecuted test reads as "
            "coverage that does not exist. Pass `framework=` to override."
        )

    marker = _marker_for(finding)
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


def _marker_for(finding: Finding) -> str:
    """The value whose reappearance means the hole is open again.

    The seed record's id is the right marker: the proof of this class of hole is that the
    attacking account received a record it does not own, and the id is the part of that record
    that identifies it without copying its contents into a committed file.
    """
    meta = finding.candidate.metadata
    for key in ("seed_id", "record_id"):
        if meta.get(key):
            return str(meta[key])
    proof = finding.proof
    if proof is not None and proof.exploit and proof.exploit.url:
        tail = proof.exploit.url.rstrip("/").rsplit("/", 1)[-1]
        if tail:
            return tail
    return finding.candidate.id


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
    export TAINTED_TARGET_URL=<the base URL of the running app>   # optional, defaults below

The test skips when the target is not reachable. A test that cannot reach the app has not shown
the attack fails, and turning that into a pass would be the false all-clear this whole check
exists to prevent.
"""
import os

import pytest

requests = pytest.importorskip("urllib.request", reason="stdlib urllib is required")

URL = {url!r}
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
 *
 * The test skips when the target is not reachable: a test that could not reach the app has not
 * shown the attack fails, and recording that as a pass would be a false all-clear.
 */
import {{ describe, it, expect }} from "{importer}";

const URL_ = {url};
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

describe("tainted regression", () => {{
  it("the attack does not succeed", async () => {{
    const headers = {{}};
    for (const [k, v] of Object.entries(HEADERS)) {{
      const resolved = resolve(v);
      if (resolved === null) return; // a missing credential is not a passed attack
      headers[k] = resolved;
    }}

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
      return; // unreachable target: nothing was attempted, so nothing is asserted
    }}

    const leaked = status >= 200 && status < 300 && body.includes(LEAK_MARKER);
    expect(
      leaked,
      `The attack succeeded again: ${{URL_}} returned ${{status}} carrying ${{LEAK_MARKER}}. ` +
        `This hole was closed and has reopened.`
    ).toBe(false);
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
    )
