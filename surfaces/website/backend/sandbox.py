"""Where `prove` execution runs.

`prove` executes untrusted, network-active exploits. On the website that is the one part of the
architecture reckless to run on your own metal: the repository is a stranger's, the target is a
stranger's, and the payloads are generated. So production dispatches the run into Cloudflare's
sandboxed Browser Rendering / Containers infrastructure and marshals the findings back, while
`analyze` — read-only, no network, no execution — stays in-process because there is nothing to
contain.

The executor chosen is decided by configuration, not by preference: if the Cloudflare worker is
configured it is used, and if it is not, `LocalExecutor` says plainly in the report that the run
happened on this machine. What must never happen is a silent fallback that runs exploits locally
while the deployment believes it is sandboxed — so `require_sandbox()` exists for exactly that,
and the website's production entrypoint sets it.
"""

from __future__ import annotations

import os
from typing import Callable, Optional, Protocol

import httpx

from tainted import analyze as core_analyze
from tainted import prove as core_prove
from tainted.dynamic.target import ProveSetup
from tainted.llm.gemini import get_default_client
from tainted.models import Candidate, Finding
from tainted.report import Report, build_report

# The two progress observers a `prove` may accept. They are how a surface reports a run *while it
# happens*: `OnCandidates` fires once, with what the run is about to attempt; `OnFinding` fires
# once per result, as that result exists. Neither may influence the run — see
# `tainted.orchestrator.prove`. An executor that cannot observe its own run ignores both, and the
# caller must be able to tell the difference, which is what `streams` below is for.
OnCandidates = Callable[[list[Candidate]], None]
OnFinding = Callable[[Finding], None]

_DISPATCH_TIMEOUT_S = 600


class SandboxUnavailable(RuntimeError):
    """Raised when a sandboxed run was required and the sandbox could not be reached."""


class Executor(Protocol):
    # `streams` is the executor's own answer to "can you report this run as it happens?".
    # A surface reads it rather than inferring from whether callbacks fired, because "no events
    # yet" and "no events ever" are different things and a progress indicator that confuses them
    # claims to know something it does not.
    streams: bool

    def analyze(self, repo_path: str) -> Report: ...
    def prove(
        self,
        repo_path: str,
        setup: ProveSetup,
        ownership_verified: bool,
        on_candidates: Optional[OnCandidates] = None,
        on_finding: Optional[OnFinding] = None,
    ) -> Report: ...


def _llm_or_none():
    llm = get_default_client(reload=True)
    return llm if llm.available else None


class LocalExecutor:
    """Runs in-process. Correct for local dev and for `analyze`; not for untrusted `prove`."""

    sandboxed = False
    # In-process, so the run is observable: the candidates are known the moment the static pass
    # ends, and each finding as `core_prove` produces it.
    streams = True

    def analyze(self, repo_path: str) -> Report:
        return build_report(core_analyze(repo_path, llm=_llm_or_none()))

    def prove(
        self,
        repo_path: str,
        setup: ProveSetup,
        ownership_verified: bool,
        on_candidates: Optional[OnCandidates] = None,
        on_finding: Optional[OnFinding] = None,
    ) -> Report:
        llm = _llm_or_none()
        result = core_analyze(repo_path, llm=llm, target=setup.target)
        # In ranked order, because that is the order they will be attempted in. A surface that
        # draws them in some other order is drawing its own order, not the run's.
        if on_candidates is not None:
            on_candidates(result.ranked())
        findings: list[Finding] = core_prove(
            result, setup, ownership_verified=ownership_verified, llm=llm,
            on_finding=on_finding,
        )
        return build_report(result, findings)


class CloudflareExecutor:
    """Dispatches `prove` into a Cloudflare Worker backed by Browser Rendering / Containers.

    The worker runs the same engine against the same target and returns the same `Report` JSON,
    so nothing downstream knows or cares which side of the boundary the run happened on. What
    crosses is the setup and the repository reference; what comes back is findings.

    `analyze` deliberately stays local: it reads files and executes nothing, so sandboxing it
    would buy no safety and cost a round trip per request.

    **It cannot report progress.** The worker runs the whole engine behind one request/response
    and hands back a finished `Report`, so there is no per-candidate event to forward: the
    progress observers are accepted and ignored, and `streams` is False so the caller knows that
    rather than guessing from silence. A surface must degrade to saying nothing is known yet —
    which is the truth here — instead of animating toward a finish line nothing has reported.
    """

    sandboxed = True
    streams = False

    def __init__(
        self,
        worker_url: str,
        api_token: str,
        client: Optional[httpx.Client] = None,
        timeout: float = _DISPATCH_TIMEOUT_S,
    ):
        self.worker_url = worker_url.rstrip("/")
        self.api_token = api_token
        self._client = client or httpx.Client(timeout=timeout)

    def analyze(self, repo_path: str) -> Report:
        return LocalExecutor().analyze(repo_path)

    def prove(
        self,
        repo_path: str,
        setup: ProveSetup,
        ownership_verified: bool,
        on_candidates: Optional[OnCandidates] = None,
        on_finding: Optional[OnFinding] = None,
    ) -> Report:
        # Accepted and ignored — see the class docstring. Nothing crosses the worker boundary
        # until the run is over, so there is no honest event to emit before then.
        try:
            resp = self._client.post(
                f"{self.worker_url}/prove",
                headers={"Authorization": f"Bearer {self.api_token}"},
                json={
                    "repo_path": repo_path,
                    "setup": setup.model_dump(mode="json"),
                    "ownership_verified": ownership_verified,
                },
            )
        except httpx.HTTPError as exc:
            raise SandboxUnavailable(
                f"Could not reach the prove sandbox at {self.worker_url}: {exc}"
            ) from exc

        if resp.status_code >= 400:
            raise SandboxUnavailable(
                f"The prove sandbox returned {resp.status_code}: {resp.text[:300]}"
            )
        try:
            return Report.model_validate(resp.json())
        except Exception as exc:
            raise SandboxUnavailable(
                f"The prove sandbox returned a payload that is not a Report: {exc}"
            ) from exc

    def close(self) -> None:
        self._client.close()


def default_executor() -> Executor:
    """The executor this deployment is configured for.

    Set `TAINTED_SANDBOX_URL` and `TAINTED_SANDBOX_TOKEN` to dispatch `prove` into the sandbox.
    Without them the local executor runs, which is right for development and wrong for a public
    deployment — hence `require_sandbox()`.
    """
    url = os.environ.get("TAINTED_SANDBOX_URL", "").strip()
    token = os.environ.get("TAINTED_SANDBOX_TOKEN", "").strip()
    if url and token:
        return CloudflareExecutor(url, token)
    return LocalExecutor()


def require_sandbox() -> bool:
    """Whether this deployment refuses to run `prove` on its own metal."""
    return os.environ.get("TAINTED_REQUIRE_SANDBOX", "").lower() in ("1", "true", "yes")
