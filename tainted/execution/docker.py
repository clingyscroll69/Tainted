"""One container per prove run.

A fresh container per run means one run's leftovers are never visible to the next. That is why
this is a per-run subprocess rather than a long-lived HTTP service: a service would have reused
the replaced Cloudflare wire contract verbatim and kept five existing tests, at the cost of the
property the work exists to provide.

**Docker is not a VM.** The container shares the host kernel. This is containment, not the
isolation the Cloudflare docstring this replaces used to claim. What it buys is filesystem and
process isolation while parsing a stranger's repository and driving Chromium — which is the part
that protects the machine.
"""

from __future__ import annotations

import json
import os
import subprocess
from typing import Iterator, Optional, Protocol

import tainted
from tainted.execution.base import (
    Executor,
    OnCandidates,
    OnFinding,
    ProveOutcome,
    SandboxUnavailable,
)
from tainted.execution.container_main import RUN_KEY_ENV
from tainted.execution.guard import new_run_key
from tainted.execution.wire import RunRequest, decode_event
from tainted.dynamic.target import ProveSetup
from tainted.models import Candidate, Finding
from tainted.report import Report
from tainted.selfdefense import PlanViolation, ProbePlan

DEFAULT_IMAGE_REPO = "ghcr.io/clingyscroll69/tainted-sandbox"

_MACOS_HOST_NETWORK_HINT = (
    "If you are on macOS, `--network=host` only reaches the Mac's localhost on Docker Desktop "
    "4.34+ with Settings → Resources → Network → 'Enable host networking' turned on (and a "
    "signed-in Docker account), or on OrbStack. Colima and Podman cannot do it at all."
)


class Runner(Protocol):
    """How the container is actually started. Injected so no test needs a daemon."""

    def run(self, argv: list[str], stdin: str, env: dict[str, str]) -> Iterator[str]: ...


class SubprocessRunner:
    def run(self, argv: list[str], stdin: str, env: dict[str, str]) -> Iterator[str]:
        proc = subprocess.Popen(
            argv,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            env={**os.environ, **env},
        )
        assert proc.stdin and proc.stdout
        try:
            proc.stdin.write(stdin)
            proc.stdin.close()
        except (BrokenPipeError, OSError):
            # The child may have already exited (e.g. an invalid image). Fall through to
            # draining stdout and checking the return code, so the real cause — surfaced via
            # the non-zero exit below — reaches the caller instead of this pipe error masking it.
            pass
        yield from proc.stdout
        stderr = proc.stderr.read() if proc.stderr else ""
        proc.wait()
        if proc.returncode:
            raise subprocess.CalledProcessError(proc.returncode, argv, output=None, stderr=stderr)


class DockerExecutor:
    sandboxed = True
    # The container writes events as it produces them, so this executor can report progress —
    # which the Cloudflare executor it replaces explicitly could not. A straight improvement
    # over the design being replaced, not a compromise against it.
    streams = True

    def __init__(
        self,
        network: str = "bridge",
        runner: Optional[Runner] = None,
        image: Optional[str] = None,
    ):
        self.network = network
        self._runner = runner or SubprocessRunner()
        # Pinned to the engine version, never `:latest`. A host running 0.2.0 against a sandbox
        # built from 0.1.1 produces findings from a different analyser than the one that ranked
        # the candidates — a skew near-impossible to diagnose from a report.
        self.image = image or f"{DEFAULT_IMAGE_REPO}:{tainted.__version__}"

    def analyze(self, repo_path: str, only=None, skip=None) -> Report:
        # `analyze` reads files and executes nothing, so containing it would buy no safety and
        # cost a container start per request.
        from tainted.execution.base import LocalExecutor

        return LocalExecutor().analyze(repo_path, only=only, skip=skip)

    def _argv(self, repo_path: str, has_key: bool) -> list[str]:
        argv = [
            "docker", "run", "--rm", "-i",
            f"--network={self.network}",
            "-v", f"{repo_path}:/repo:ro",
            "--read-only",
            "--cap-drop", "ALL",
            "--security-opt", "no-new-privileges",
            "--user", "10001",
        ]
        if has_key:
            # Bare `-e NAME` forwards NAME from this process's own environment. Appending it
            # only when a key was actually minted keeps an unguarded run (no plan, no key) from
            # picking up a stray TAINTED_RUN_KEY left set on the host — the same partial-guard
            # state correction 2 exists to keep out, reintroduced through the environment
            # instead of through code. Inline `-e NAME=value` is deliberately avoided: that
            # would put the key in this process's own argv, visible to `ps`, which is the whole
            # reason it travels as an env var rather than in the request body.
            argv += ["-e", RUN_KEY_ENV]
        argv.append(self.image)
        return argv

    def prove(
        self,
        repo_path: str,
        setup: ProveSetup,
        ownership_verified: bool,
        autodiscover: bool = False,
        plan: Optional[ProbePlan] = None,
        plan_signature: Optional[str] = None,
        run_key: Optional[bytes] = None,
        on_candidates: Optional[OnCandidates] = None,
        on_finding: Optional[OnFinding] = None,
    ) -> ProveOutcome:
        # A key only means something alongside a plan to sign. Minting one for an unguarded
        # run would hand the container a partial set of guard arguments, which `LocalExecutor`
        # now refuses outright rather than quietly running unguarded.
        key = run_key or (new_run_key() if plan is not None else None)
        req = RunRequest(
            repo_path="/repo",
            # The target URL crosses untouched. Rewriting it would make `Target.is_local` false
            # and the run would survive only by asserting ownership it had not derived.
            setup=setup.model_dump(mode="json"),
            ownership_verified=ownership_verified,
            autodiscover=autodiscover,
            plan=_plan_json(plan),
            plan_signature=plan_signature,
        )
        argv = self._argv(repo_path, has_key=key is not None)
        env = {RUN_KEY_ENV: key.hex()} if key is not None else {}
        try:
            lines = self._runner.run(argv, req.model_dump_json(), env)
            return self._consume(lines, on_candidates, on_finding)
        except FileNotFoundError as exc:
            raise SandboxUnavailable(
                "`prove` runs untrusted exploit code and requires Docker to contain it, but "
                "the `docker` command was not found. Install Docker Desktop or OrbStack, or "
                "set TAINTED_REQUIRE_SANDBOX=0 to say out loud that you accept an uncontained "
                f"run on this machine. ({exc})"
            ) from exc
        except subprocess.CalledProcessError as exc:
            raise SandboxUnavailable(
                f"The sandbox container failed to start: {exc}. If the image is absent, pull "
                f"`{self.image}` — the tag is pinned to this engine's version on purpose. "
                + _MACOS_HOST_NETWORK_HINT
            ) from exc

    def _consume(self, lines, on_candidates, on_finding) -> ProveOutcome:
        for raw in lines:
            raw = raw.strip()
            if not raw:
                continue
            try:
                event = decode_event(raw)
            except ValueError as exc:
                raise SandboxUnavailable(str(exc)) from exc

            kind = event["kind"]
            if kind == "candidates" and on_candidates is not None:
                on_candidates([Candidate.model_validate(c) for c in event["candidates"]])
            elif kind == "finding" and on_finding is not None:
                on_finding(Finding.model_validate(event["finding"]))
            elif kind == "refused":
                # The guard worked. Distinct from an error, so a refusal is never read as a
                # crash and quietly retried.
                raise PlanViolation(event["message"])
            elif kind == "error":
                raise SandboxUnavailable(f"The sandbox run failed: {event['message']}")
            elif kind == "report":
                return ProveOutcome(
                    report=Report.model_validate(event["report"]),
                    blocked_calls=event.get("blocked_calls", []),
                )
        raise SandboxUnavailable(
            "The sandbox run ended without reporting a result. The container was probably "
            "killed — a partial run must not be read as a clean one with no findings."
        )


def _plan_json(plan: Optional[ProbePlan]) -> Optional[dict]:
    if plan is None:
        return None
    return {
        "target_url": plan.target_url,
        "allowed": [
            {"tool": c.tool, "arg_constraints": c.arg_constraints} for c in plan.allowed
        ],
    }
