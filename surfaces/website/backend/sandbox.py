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
from typing import Optional

import httpx

from tainted.dynamic.target import ProveSetup
from tainted.models import Finding
from tainted.report import Report

from tainted.execution.base import (  # noqa: F401 - re-exported for this surface
    Executor,
    LocalExecutor,
    OnCandidates,
    OnFinding,
    ProveOutcome,
    SandboxUnavailable,
    _llm_or_none,
)

_DISPATCH_TIMEOUT_S = 600


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
    ) -> ProveOutcome:
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
            report = Report.model_validate(resp.json())
        except Exception as exc:
            raise SandboxUnavailable(
                f"The prove sandbox returned a payload that is not a Report: {exc}"
            ) from exc
        return ProveOutcome(report=report)

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
