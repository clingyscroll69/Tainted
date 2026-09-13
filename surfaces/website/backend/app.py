"""FastAPI backend for the Tainted demonstration website."""

from __future__ import annotations

import json
import logging
import os
import queue
import re
import secrets
import threading
from collections import OrderedDict
from contextlib import ExitStack, contextmanager
from pathlib import Path
from typing import Any, Callable, Iterator, Optional

from fastapi import FastAPI, HTTPException, Request
from fastapi.middleware.gzip import GZipMiddleware
from starlette.middleware.gzip import DEFAULT_EXCLUDED_CONTENT_TYPES
from fastapi.openapi.docs import get_redoc_html, get_swagger_ui_html
from fastapi.responses import (
    FileResponse,
    JSONResponse,
    RedirectResponse,
    StreamingResponse,
)
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field, field_validator

from tainted import analyze as core_analyze
from tainted import fix as core_fix
from tainted.dynamic.target import Account, ProveSetup, SeedRecord, Target
from tainted.fix import InterviewAnswer, tool_plane_interview
from tainted.llm.gemini import get_default_client
from tainted.models import AnalysisResult, Candidate, Finding
from tainted.ownership import WELL_KNOWN_PATH, verify
from tainted.report import build_report
from backend import demo as demo_mode
from backend import github
from backend import keys
from backend import ownership_token
from backend import session_token
from backend.sandbox import SandboxUnavailable, default_executor, require_sandbox


# --------------------------------------------------------------------------- #
# Which deployment is this?
#
# One switch, read per request so it is testable, answering "is this process running on the
# developer's own machine?". Two things hang off it and both are safety boundaries:
#
#   * a filesystem path as the repository — a dev convenience that on a public deployment is
#     an arbitrary-directory read for anyone who can reach the port;
#   * `localhost` as proof of ownership — true on your laptop, and on a hosted deployment a
#     way for a stranger to aim the engine at the server's own internal services.
#
# It defaults **off**, so a deployment that forgets to think about this gets the safe answer.
# --------------------------------------------------------------------------- #
def _env_flag(name: str) -> bool:
    return os.environ.get(name, "").strip().lower() in ("1", "true", "yes")


def _local_mode() -> bool:
    """Whether this process is a developer running Tainted on their own machine."""
    return _env_flag("TAINTED_LOCAL_MODE")


# The interactive API docs describe, in executable form, every endpoint below. That is a gift
# to a developer and a map for anyone else, so they exist only in local mode. Disabled on the
# app itself and re-added as real routes, so the decision is made per request rather than at
# import — which is also what lets it be tested both ways.
app = FastAPI(
    title="Tainted",
    version="0.1.0",
    docs_url=None,
    redoc_url=None,
    openapi_url=None,
)
# The run view is a single self-contained document: ~110 KB of HTML, CSS and JS that
# compresses to about a fifth of that. It was being served raw on every load.
#
# The prove stream is excluded. A compressor holds bytes back until it has enough of them to be
# worth emitting, which is exactly the wrong behaviour for events whose entire value is arriving
# when they happen — it would turn a live descent back into one buffered lump at the end.
app.add_middleware(
    GZipMiddleware,
    minimum_size=1024,
    exclude_content_types=DEFAULT_EXCLUDED_CONTENT_TYPES + ("application/x-ndjson",),
)
_executor = default_executor()
_oauth = github.load_config()

SESSION_COOKIE = "tainted_session"
STATE_COOKIE = "tainted_oauth_state"

FRONTEND = Path(__file__).resolve().parent.parent / "frontend"


# --------------------------------------------------------------------------- #
# Request models (the first-run form), and what a repository may be called
#
# A request names its repo one of two ways: `repo` (a GitHub "owner/name" the signed-in user can
# reach — fetched server-side, private included) or `repo_path` (a local path, the dev fallback).
#
# `repo` and `ref` are pasted into a GitHub API path (`/repos/{repo}/tarball/{ref}`). Left
# unvalidated, a `..` segment normalises the URL onto a different endpoint entirely —
# `repo="../../user"` resolves to `https://api.github.com/user` — so the server issues an
# authenticated request the caller never named. The blast radius was small (the caller's own
# token, GET only) and the fix is smaller: say what these may contain.
#
# `repo` is GitHub's own `owner/name` shape. `ref` is a branch, tag or sha, which may contain
# slashes (`release/1.2`) but never a dot segment.
# --------------------------------------------------------------------------- #
_REPO_RE = re.compile(r"^[A-Za-z0-9._-]+/[A-Za-z0-9._-]+$")
_REF_RE = re.compile(r"^[A-Za-z0-9._/-]{1,255}$")


def _validate_repo(v: Optional[str]) -> Optional[str]:
    v = (v or "").strip()
    if not v:
        return None
    # The demo is not a repository and never reaches GitHub; it is spelled like one so the
    # field accepts it, and `demo.is_demo` short-circuits long before any fetch.
    if v == "demo/demo":
        return v
    if not _REPO_RE.match(v):
        raise ValueError("repository must be in GitHub `owner/name` form")
    return v


def _validate_ref(v: Optional[str]) -> Optional[str]:
    v = (v or "").strip()
    if not v:
        return None
    if not _REF_RE.match(v) or any(part in (".", "..") for part in v.split("/")):
        raise ValueError("ref must be a branch, tag or commit sha")
    return v


class RepoSelector(BaseModel):
    """The two ways a request names the code to analyse.

    Every endpoint that takes a repository inherits this, so the validation above happens once
    and cannot be forgotten on a new route.
    """

    repo_path: Optional[str] = None
    repo: Optional[str] = None
    ref: Optional[str] = None

    @field_validator("repo")
    @classmethod
    def _check_repo(cls, v: Optional[str]) -> Optional[str]:
        return _validate_repo(v)

    @field_validator("ref")
    @classmethod
    def _check_ref(cls, v: Optional[str]) -> Optional[str]:
        return _validate_ref(v)


class AnalyzeRequest(RepoSelector):
    """Nothing beyond the repository. `only` / `skip` were declared here and never read —
    `api_analyze` called `_executor.analyze(repo_path)` and passed neither, no client sent
    them, and no test covered them. They are removed rather than wired, because wiring them
    would have let a caller ask for `only=test_integrity`, which is the one check that runs a
    repository's own test suite — a stranger's code executing on the server."""


class ProveRequest(RepoSelector):
    url: str
    # Credentials arrive as four fields. `login_a` / `login_b` are the older single-field
    # `email:password` form and are still accepted, so a client that has not been updated
    # keeps working; `_build_setup` prefers the split fields when they are present.
    email_a: str = ""
    password_a: str = ""
    email_b: str = ""
    password_b: str = ""
    login_a: str = ""
    login_b: str = ""
    seed: Optional[str] = None
    anon_key: Optional[str] = None
    ownership_token: Optional[str] = None

    @field_validator("url")
    @classmethod
    def _http_url_only(cls, v: str) -> str:
        """The earliest place the target can be refused, so every caller inherits it.

        Only http and https. A scheme this engine cannot drive is not a target, and leaving
        the field an unvalidated string meant a malformed one surfaced as a stack trace from
        somewhere deep in the probe layer instead of a 422 naming the field.

        Empty passes here and is refused in the endpoint instead: the demo contacts nothing,
        so it legitimately has no target, and rejecting it at the model would mean the one
        run that fires nothing is the one that cannot start.
        """
        v = (v or "").strip()
        if not v:
            return v
        scheme = v.split("://", 1)[0].lower() if "://" in v else ""
        if scheme not in ("http", "https"):
            raise ValueError("target URL must start with http:// or https://")
        return v


class FixRequest(RepoSelector):
    # Which hole to fix. `finding_id` is the handle a client should send: it names the hole
    # itself, so it cannot drift. `index` is the older positional form, kept working for one
    # release — it now addresses the order the *report* published, which is what the browser
    # drew, rather than a second run's ranking. `ge=0` because a negative index used to be
    # accepted and wrapped, silently handing back the last candidate's patch.
    finding_id: Optional[str] = None
    index: int = Field(0, ge=0)
    # Tool-plane fixes are architecturally underdetermined; these are the interview's answers.
    answers: Optional[dict[str, str]] = None


# --------------------------------------------------------------------------- #
# GitHub authentication
# --------------------------------------------------------------------------- #
@app.get("/api/auth/status")
def auth_status(request: Request):
    """Whether this deployment can sign anyone in, and whether this caller is.

    `configured` answers the frontend's only question — show the sign-in box or not — so it
    has to mean "sign-in works", not "the OAuth app exists". A deployment with GitHub
    credentials but no signing secret can send a caller to GitHub and then has nowhere to put
    what comes back; offering the button there is worse than hiding it. `reason` says which
    half is missing, for whoever is looking at this with curl rather than a browser.
    """
    session = session_token.unseal(request.cookies.get(SESSION_COOKIE))
    return {
        "configured": _sign_in_available(),
        "authenticated": session is not None,
        "login": session.login if session else None,
        "reason": _sign_in_unavailable_reason(),
        # Whether a filesystem path is a usable way to name a repository here. It is the dev
        # fallback, refused by any deployment that is not the developer's own machine — and a
        # page that renders the field anyway is offering the one input the server will refuse.
        # With sign-in unconfigured *and* this false, the demo is all this deployment can do,
        # and saying so is better than a form that 403s.
        "local_paths": _local_mode(),
    }


@app.get("/api/auth/github/login")
def auth_login(request: Request):
    # Checked before the redirect, not after it: a caller who has already approved the app at
    # GitHub and comes back to a 503 has handed out access for nothing.
    reason = _sign_in_unavailable_reason()
    if reason:
        raise HTTPException(503, reason)
    state = secrets.token_urlsafe(24)
    url = github.authorize_url(_oauth, state, _redirect_uri(request))
    resp = RedirectResponse(url, status_code=302)
    resp.set_cookie(
        STATE_COOKIE, state, httponly=True, max_age=600, samesite="lax",
        secure=_cookies_secure(request),
    )
    return resp


@app.get("/api/auth/github/callback")
def auth_callback(request: Request, code: str = "", state: str = "", error: str = ""):
    if error:
        return RedirectResponse(f"/?auth_error={error}", status_code=302)
    expected = request.cookies.get(STATE_COOKIE)
    if not expected or not state or not secrets.compare_digest(expected, state):
        raise HTTPException(400, "OAuth state mismatch — restart sign-in.")
    if not code:
        raise HTTPException(400, "missing authorization code")
    try:
        token = github.exchange_code(_oauth, code, _redirect_uri(request))
        user = github.get_user(token)
    except github.GitHubError as exc:
        return RedirectResponse(f"/?auth_error={exc}", status_code=302)
    try:
        sealed = session_token.seal(token, user.get("login", ""))
    except session_token.SessionSecretMissing as exc:
        return RedirectResponse(f"/?auth_error={exc}", status_code=302)
    resp = RedirectResponse("/", status_code=302)
    # `Max-Age` matches the lifetime sealed inside the cookie, but only the sealed one is
    # binding — the client owns its own cookie jar and can keep sending an expired cookie.
    resp.set_cookie(
        SESSION_COOKIE, sealed, httponly=True,
        max_age=session_token.DEFAULT_TTL_SECONDS, samesite="lax",
        secure=_cookies_secure(request),
    )
    resp.delete_cookie(STATE_COOKIE)
    return resp


@app.post("/api/auth/logout")
def auth_logout(request: Request):
    """End the session by taking the cookie away, which is all there is to take.

    A sealed session has no server-side row to strike out, so this ends it for the browser
    that had it and not for a copy taken beforehand. `session_token` explains why that
    trade is the one that makes this deployable at all; the short lifetime is the other half
    of it.
    """
    resp = JSONResponse({"ok": True})
    resp.delete_cookie(SESSION_COOKIE)
    return resp


@app.get("/api/ownership/token")
def api_ownership_token(request: Request, url: str = ""):
    """Mint this caller's ownership token for one host, and say how to publish it.

    The token is bound to the signed-in login and to this host, so it is useless to anyone
    else and useless for anywhere else. Publishing it is what proves control of the host;
    holding it proves only that we issued it.
    """
    session = _require_session(request)
    try:
        target = Target(url=url.strip())
    except Exception:
        raise HTTPException(400, "give the target URL as ?url=")
    host = target.host
    if not host:
        raise HTTPException(400, "that URL names no host")
    if target.resolves_internal(_ADDR_RESOLVER):
        raise HTTPException(
            403,
            "That host is on an internal network. A hosted Tainted never fires at one, so "
            "there is no token to issue for it.",
        )
    try:
        token = ownership_token.issue(session.login, host)
    except ownership_token.TokenSecretMissing as exc:
        raise HTTPException(503, str(exc))
    return {
        "host": host,
        "token": token,
        "well_known_path": WELL_KNOWN_PATH,
        "dns_txt_record": f"tainted-verify={token}",
        "instructions": (
            f"Publish this exact line at https://{host}{WELL_KNOWN_PATH}, or as a DNS TXT "
            f"record on {host} reading `tainted-verify=<token>`. Then paste the token back "
            "here. Tainted checks the host is serving it before it fires anything."
        ),
    }


@app.get("/api/repos")
def api_repos(request: Request):
    session = _require_session(request)
    try:
        return {"repos": github.list_repos(session.token)}
    except github.GitHubError as exc:
        raise HTTPException(502, str(exc))


# --------------------------------------------------------------------------- #
# API
# --------------------------------------------------------------------------- #
@app.post("/api/analyze")
def api_analyze(req: AnalyzeRequest, request: Request):
    # The demo short-circuits before `_checkout`, which would (correctly) reject `demo/demo`
    # as a path that does not exist. Everything after this point is the real code path.
    if demo_mode.is_demo(req.repo_path, req.repo):
        return JSONResponse(demo_mode.demo_analyze_report().model_dump(mode="json"))
    with _checkout(req, request) as repo_path:
        report = _executor.analyze(repo_path)
    return JSONResponse(report.model_dump(mode="json"))


# --------------------------------------------------------------------------- #
# Watching a run instead of waiting for it
#
# `prove` blocks for as long as the real attacks take. A caller that asks for NDJSON gets the run
# reported as it happens — one event per candidate, in the order the engine attempts them — and a
# caller that does not gets exactly the single JSON body it always got. Same gate, same setup,
# same Report; only the delivery differs.
#
# The first event is always `open`, and it says whether progress is coming at all. That is not a
# nicety: an executor that cannot observe its own run (the sandboxed one — see
# `sandbox.CloudflareExecutor`) is silent for the same reason a slow one is, and a progress
# indicator unable to tell those apart will invent motion to cover the difference. Being told
# "no events are coming" is what lets a surface say plainly that nothing is known yet.
# --------------------------------------------------------------------------- #
NDJSON = "application/x-ndjson"

# --------------------------------------------------------------------------- #
# What one process will spend on `prove`
#
# A prove runs for as long as the real attacks take, on a worker thread, while its request
# holds a slot in the server's thread pool. Without a ceiling a modest number of concurrent
# runs exhausts the pool and the whole app — `/healthz` included — stops answering. Refusing
# the fourth concurrent run with a 429 is a better failure than that.
#
# This is per process. On a host that runs several instances it bounds each of them, not the
# deployment; a deployment-wide limit needs shared state this surface does not have.
# --------------------------------------------------------------------------- #
_MAX_CONCURRENT_PROVES = max(1, int(os.environ.get("TAINTED_MAX_CONCURRENT_PROVES", "4")))
_prove_slots = threading.BoundedSemaphore(_MAX_CONCURRENT_PROVES)
_PROVE_JOIN_TIMEOUT_S = float(os.environ.get("TAINTED_PROVE_TIMEOUT_S", "900"))
_STREAM_QUEUE_MAX = 1024
_STREAM_PUT_TIMEOUT_S = 30.0

# Tests inject a resolver here so the host policy needs no DNS. None means the system one.
_ADDR_RESOLVER: Optional[Callable[[str], list[str]]] = None


def _take_prove_slot() -> None:
    if not _prove_slots.acquire(blocking=False):
        raise HTTPException(
            429,
            f"This deployment is already running {_MAX_CONCURRENT_PROVES} proofs. "
            "Wait for one to finish and try again.",
        )


def _wants_stream(request: Request) -> bool:
    """Whether this caller asked to watch the run rather than wait for it."""
    return NDJSON in request.headers.get("accept", "")


def _line(event: str, **fields: Any) -> bytes:
    """One NDJSON event. Newline-delimited, so a reader needs no framing beyond splitting."""
    return (json.dumps({"event": event, **fields}, separators=(",", ":")) + "\n").encode()


def _stream_prove(
    run: Callable[..., Any],
    streams: bool,
    cleanup: Optional[Callable[[], None]] = None,
) -> StreamingResponse:
    """Run a blocking `prove` on a worker thread and emit its progress as NDJSON.

    `run` is handed the two observers and returns the finished `Report`. It blocks — that is what
    the thread is for — and everything it emits reaches the response through a queue, in order.

    An error after the first byte cannot become a status code, so it becomes an `error` event
    carrying the status it would have been. The gate and the checkout both run *before* this, on
    the request thread, so the failures most likely to happen (no session, bad path, GitHub
    unreachable) still arrive as real HTTP statuses.
    """
    # Bounded, so a reader that stops reading cannot make the run buffer without limit. A
    # candidate's worth of JSON is small and the cap is generous; `_emit` is what keeps the
    # worker from blocking on it forever if nobody is draining.
    q: "queue.Queue[Optional[bytes]]" = queue.Queue(maxsize=_STREAM_QUEUE_MAX)

    def _emit(item: Optional[bytes]) -> bool:
        """Hand one event to the reader. False when the reader has stopped keeping up."""
        try:
            q.put(item, timeout=_STREAM_PUT_TIMEOUT_S)
            return True
        except queue.Full:
            return False

    def worker() -> None:
        try:
            report = run(
                on_candidates=lambda cs: _emit(
                    _line("candidates", candidates=[c.model_dump(mode="json") for c in cs])
                ),
                on_finding=lambda f: _emit(_line("finding", finding=f.model_dump(mode="json"))),
            )
            _emit(_line("report", report=report.model_dump(mode="json")))
        except HTTPException as exc:
            _emit(_line("error", detail=str(exc.detail), status=exc.status_code))
        except SandboxUnavailable as exc:
            _emit(_line("error", detail=str(exc), status=502))
        except Exception as exc:  # noqa: BLE001 - the reader is owed an account of any failure
            _emit(_line("error", detail=f"{type(exc).__name__}: {exc}", status=500))
        finally:
            _emit(None)

    def gen() -> Iterator[bytes]:
        thread = threading.Thread(target=worker, daemon=True)
        thread.start()
        try:
            yield _line("open", streams=streams)
            while True:
                item = q.get()
                if item is None:
                    return
                yield item
        finally:
            # The checkout is a temporary directory the run is reading out of, so it may not be
            # removed while the run is still in it — including when the reader disconnects
            # halfway down and this generator is closed early.
            #
            # The join is bounded. An unbounded one hands a stuck run the power to hold this
            # request thread (and the slot below) for as long as it likes; past the timeout the
            # thread is a daemon and the process may still exit, and the temp directory is left
            # rather than pulled out from under a run that is still reading it.
            thread.join(timeout=_PROVE_JOIN_TIMEOUT_S)
            if cleanup is not None and not thread.is_alive():
                cleanup()
            _prove_slots.release()

    return StreamingResponse(
        gen(),
        media_type=NDJSON,
        # A progress stream that arrives in one buffered lump is not a progress stream.
        headers={"Cache-Control": "no-store", "X-Accel-Buffering": "no"},
    )


def _gate_ownership(req: ProveRequest, request: Request, setup: ProveSetup) -> None:
    """Refuse unless this caller has shown they own this target. Raises, or returns quietly.

    Three things had to change here, and the order they run in matters as much as the checks:

    1. **`localhost` is no longer self-certifying on a hosted deployment.** It means "the
       machine Tainted runs on", which on a server is not the caller's machine — it was a way
       for an anonymous request to aim the engine at internal services.
    2. **The token must be one this deployment issued to this caller for this host.** A token
       the caller also chose proves only that they can echo themselves.
    3. **The host must be publishing that same token.** Point 2 stops someone claiming your
       host; point 3 stops you claiming a host you cannot publish to.

    Cheap checks come first so that an anonymous caller cannot make the server perform DNS
    lookups or outbound fetches by asking. Nothing reaches the network until the caller has
    presented a token that is theirs.
    """
    target = setup.target
    local = _local_mode()

    # A developer on their own machine, pointed at their own machine. The one case where
    # reaching it really does imply controlling it.
    if local and target.is_local:
        return

    # Identity before ownership. A token is issued *to a caller* for a host, so there is
    # nothing to check against until we know who is asking — and a signed-out visitor was
    # being told to go fetch a token from an endpoint that would have answered 401. Say the
    # thing they have to do first. Still cheap: no DNS and no outbound request happens here.
    session = None if local else _require_session(request)

    if not req.ownership_token:
        raise HTTPException(
            403,
            "Ownership not verified. Get a token for this host from "
            "/api/ownership/token, publish it, and send it with the run."
            if not local
            else "Ownership not verified for a non-local target. Publish a DNS TXT or "
            ".well-known token, or point at localhost.",
        )

    if not local:
        assert session is not None  # _require_session raises rather than returning None
        if not ownership_token.configured():
            raise HTTPException(
                503,
                "This deployment cannot verify ownership: TAINTED_TOKEN_SECRET is not set.",
            )
        if not ownership_token.check(req.ownership_token, session.login, target.host):
            raise HTTPException(
                403,
                "That ownership token was not issued to you for this host, or it has "
                "expired. Request a new one from /api/ownership/token.",
            )
        # Only now, with a token we minted for this caller, is it worth resolving anything.
        if target.resolves_internal(_ADDR_RESOLVER):
            raise HTTPException(
                403,
                "That host is on an internal network (loopback, link-local, or a private "
                "range). A hosted Tainted never fires at one.",
            )

    if not verify(target, expected_token=req.ownership_token, trust_local=local):
        raise HTTPException(
            403,
            "The host is not publishing that token. Put it at "
            "/.well-known/tainted-verify, or in a DNS TXT record as "
            "`tainted-verify=<token>`, then run again.",
        )


@app.post("/api/prove")
def api_prove(req: ProveRequest, request: Request):
    stream = _wants_stream(request)

    # A slot is taken before anything else, including the demo: every path below either runs
    # the engine or spawns a streaming worker thread, and both are what the ceiling is for.
    # A streaming response hands its slot to the generator, which releases it when the run is
    # over; every other path releases it here.
    _take_prove_slot()
    handed_to_stream = False
    try:
        # Ahead of the ownership gate: the demo fires nothing at anything, so there is no
        # target whose ownership could be in question. It is exempt because it is inert, not
        # privileged — and it is the one thing on this surface open to everyone.
        if demo_mode.is_demo(req.repo_path, req.repo):
            if stream:
                handed_to_stream = True
                return _stream_prove(demo_mode.demo_prove_stream, streams=True)
            return JSONResponse(demo_mode.demo_prove_report().model_dump(mode="json"))

        # Past the demo, a run needs somewhere to fire. (The model lets this through so the
        # demo, which contacts nothing, is not rejected for having no target.)
        if not req.url.strip():
            raise HTTPException(
                400, "A target URL is required to prove a hole against a running app."
            )

        setup = _build_setup(req)
        _gate_ownership(req, request, setup)

        # A public deployment must never quietly run exploits on its own metal because the
        # sandbox was misconfigured. Refusing is the correct failure; falling back is not.
        if require_sandbox() and not getattr(_executor, "sandboxed", False):
            raise HTTPException(
                503,
                "This deployment requires sandboxed execution for `prove`, and no sandbox is "
                "configured (set TAINTED_SANDBOX_URL and TAINTED_SANDBOX_TOKEN).",
            )

        if stream:
            # The checkout is entered here, on the request thread, so its failures are still
            # status codes rather than events buried in a 200. The stack is closed once the
            # run is done with the directory — see `_stream_prove`.
            stack = ExitStack()
            repo_path = stack.enter_context(_checkout(req, request))
            handed_to_stream = True
            return _stream_prove(
                lambda **hooks: _executor.prove(
                    repo_path, setup, ownership_verified=True, **hooks
                ),
                streams=bool(getattr(_executor, "streams", False)),
                cleanup=stack.close,
            )

        try:
            with _checkout(req, request) as repo_path:
                report = _executor.prove(repo_path, setup, ownership_verified=True)
        except SandboxUnavailable as exc:
            raise HTTPException(502, str(exc))
        return JSONResponse(report.model_dump(mode="json"))
    finally:
        if not handed_to_stream:
            _prove_slots.release()


# --------------------------------------------------------------------------- #
# Naming one hole out of many
#
# A fix request has to say *which* hole across a request boundary. It used to say it by
# position, and position was wrong: `build_report` publishes candidates in discovery order,
# `AnalysisResult.ranked()` sorts them structural-first then by model score — two orders of one
# set — so the row a reader clicked and the candidate the endpoint fixed were different
# candidates whenever those orders disagreed. With the model enabled `rank_score` is not even
# stable between two runs, so the mismatch was unbounded.
#
# `Candidate.id` is the handle that replaces it. The positional form stays accepted for one
# release so an un-updated client keeps working, but it now indexes the order the report
# actually published — the same list the browser drew.
# --------------------------------------------------------------------------- #
def _published_order(result) -> list[Candidate]:
    """The candidates in the order a surface was shown them.

    `build_report` lists carried findings first, then everything untried, and the frontend
    concatenates the two in that order. Anything addressing "the nth row" has to mean this
    list and no other.
    """
    report = build_report(result)
    return [f.candidate for f in report.findings] + list(report.unproven_candidates)


def _select_candidate(result, finding_id: Optional[str], index: int) -> Candidate:
    if finding_id:
        for cand in result.candidates:
            if cand.id == finding_id:
                return cand
        raise HTTPException(
            400,
            f"no finding with id {finding_id} in this repository. Re-run the analysis — "
            "the code may have changed since that report was drawn.",
        )
    published = _published_order(result)
    if index >= len(published):
        raise HTTPException(400, f"no candidate at index {index}")
    return published[index]


# Bounded, so a long-lived process cannot accumulate results for checkouts that are long gone.
# Small on purpose: this is a within-request convenience, not a durable store.
_ANALYSIS_CACHE: "OrderedDict[str, AnalysisResult]" = OrderedDict()
_ANALYSIS_CACHE_MAX = 32
_ANALYSIS_LOCK = threading.Lock()


def _analysis_for(repo_path: str, llm) -> AnalysisResult:
    """One analysis per checkout, not one per click.

    `fix` re-ran the whole static pass — re-parsing the tree and re-calling the model to rank
    it — every time a reader asked for a patch, for data the server had computed moments
    earlier. On a large repo that is seconds and an API call per click.

    Keyed on the checkout path, which is unique per request (`tempfile.mkdtemp`) and removed
    after it, so an entry can never outlive the tree it describes or be returned for a
    different one. A local `repo_path` in dev is stable and may be edited between calls, which
    is why entries are evicted rather than kept indefinitely.
    """
    with _ANALYSIS_LOCK:
        cached = _ANALYSIS_CACHE.get(repo_path)
        if cached is not None:
            _ANALYSIS_CACHE.move_to_end(repo_path)
            return cached

    result = core_analyze(repo_path, llm=llm)

    with _ANALYSIS_LOCK:
        _ANALYSIS_CACHE[repo_path] = result
        _ANALYSIS_CACHE.move_to_end(repo_path)
        while len(_ANALYSIS_CACHE) > _ANALYSIS_CACHE_MAX:
            _ANALYSIS_CACHE.popitem(last=False)
    return result


@app.post("/api/fix")
def api_fix(req: FixRequest, request: Request):
    """Website degrades to patch-generation: it hands back the diff; the developer applies it.

    The loop cannot close here — there is no working tree to apply into and re-prove against —
    so this surface recommends and the developer applies. That is a property of the surface,
    not a missing feature, and the response says so rather than implying a fix was verified.
    """
    if demo_mode.is_demo(req.repo_path, req.repo):
        try:
            result = demo_mode.demo_fix_result(req.index, finding_id=req.finding_id)
        except KeyError:
            raise HTTPException(400, f"no finding with id {req.finding_id} in the demo run.")
        payload = result.model_dump(mode="json")
        payload["loop_closed"] = False
        return JSONResponse(payload)

    with _checkout(req, request) as repo_path:
        llm = _llm_or_none()
        result = _analysis_for(repo_path, llm)
        cand = _select_candidate(result, req.finding_id, req.index)

        answers = (
            [InterviewAnswer(key=k, choice=v) for k, v in req.answers.items()]
            if req.answers
            else None
        )
        try:
            fix_result = core_fix(Finding(candidate=cand), answers=answers, llm=llm)
        except ValueError:
            # The tool plane refusing to guess. Return the questions, not an error page.
            return JSONResponse(
                {
                    "interview": [
                        {"key": q.key, "question": q.question, "options": q.options}
                        for q in tool_plane_interview(cand)
                    ],
                    "notes": (
                        "This fix depends on facts only you hold. Answer these and call /api/fix "
                        "again with `answers`."
                    ),
                }
            )
        except NotImplementedError as exc:
            raise HTTPException(400, str(exc))

    payload = fix_result.model_dump(mode="json")
    payload["loop_closed"] = False
    return JSONResponse(payload)


# --------------------------------------------------------------------------- #
# What this deployment cannot do, said at startup
#
# Every switch here already fails closed on its own, which is right — but each failure arrives
# separately, at the moment a visitor trips over it, phrased for that one request. A deployment
# missing `TAINTED_TOKEN_SECRET` looks fine until someone tries to sign in; one missing the
# OAuth pair looks fine until someone tries to name a repository. The operator is the person
# who can fix either, and they are not watching that request.
#
# So: one statement, once, at import, listing what is missing and what it costs. It does not
# refuse to start — a demo-only deployment is a legitimate thing to run, and crashing on a
# missing optional key would make it impossible.
# --------------------------------------------------------------------------- #
def deployment_warnings() -> list[str]:
    """Every configuration gap that narrows what this process can do, in plain terms."""
    out: list[str] = []
    if _local_mode():
        return out  # a developer's own machine; none of the below is expected there

    if not keys.configured():
        out.append(
            f"{keys.SECRET_ENV} is not set. GitHub sign-in and ownership tokens are both "
            "unavailable, so this deployment can only run the demo. Generate one with: "
            'python -c "import secrets; print(secrets.token_urlsafe(48))" — and use the same '
            "value on every instance."
        )
    if not _oauth.configured:
        out.append(
            "GITHUB_CLIENT_ID / GITHUB_CLIENT_SECRET are not set. Nobody can sign in, and "
            "without sign-in there is no way to name a repository: filesystem paths are "
            "refused off a developer's own machine. The demo still works."
        )
    elif not _oauth.redirect_override:
        out.append(
            "GITHUB_OAUTH_REDIRECT is not set. Behind a proxy the callback URL is derived "
            "from the request and will not match the one registered with GitHub; sign-in "
            "will fail with an opaque error. Set it to "
            "https://<your-host>/api/auth/github/callback."
        )
    if require_sandbox() and not getattr(_executor, "sandboxed", False):
        out.append(
            "TAINTED_REQUIRE_SANDBOX is set but no sandbox is configured "
            "(TAINTED_SANDBOX_URL / TAINTED_SANDBOX_TOKEN). Every `prove` will be refused."
        )
    elif not require_sandbox() and not getattr(_executor, "sandboxed", False):
        out.append(
            "`prove` will execute untrusted exploits in this process: no sandbox is "
            "configured and TAINTED_REQUIRE_SANDBOX is not set. Set it to fail closed."
        )
    if not _env_flag("TAINTED_CSP_ENFORCE"):
        out.append(
            "TAINTED_CSP_ENFORCE is not set, so the Content-Security-Policy is sent "
            "report-only and nothing is actually blocked."
        )
    return out


def _announce_deployment() -> None:
    warnings = deployment_warnings()
    if not warnings:
        return
    log = logging.getLogger("tainted.website")
    log.warning("Tainted is starting with %d configuration gap(s):", len(warnings))
    for i, w in enumerate(warnings, 1):
        log.warning("  %d. %s", i, w)


_announce_deployment()


@app.get("/healthz")
def healthz():
    return {"ok": True, "llm": get_default_client(reload=True).available}


# --------------------------------------------------------------------------- #
# Frontend (served last so /api/* wins)
# --------------------------------------------------------------------------- #
@app.get("/")
def index():
    return FileResponse(FRONTEND / "index.html")


# Mounted per directory rather than over the whole frontend folder. A mount on the folder
# serves everything that ever lands in it — which is how a superseded prototype ended up
# publicly readable — so what is served is named here instead of inferred from the filesystem.
for _sub in ("fonts", "vendor"):
    _dir = FRONTEND / _sub
    if _dir.is_dir():
        app.mount(
            f"/static/{_sub}", StaticFiles(directory=str(_dir)), name=f"static-{_sub}"
        )


@app.get("/static/tutorial.js")
def tutorial_js():
    """The guided tour's content. The one loose script the page loads."""
    path = FRONTEND / "tutorial.js"
    if not path.is_file():
        raise HTTPException(404, "not found")
    return FileResponse(path, media_type="text/javascript")


# --------------------------------------------------------------------------- #
# Interactive API docs — local mode only
#
# They are a complete, executable description of every endpoint above. Useful at a terminal,
# and on a public deployment a map drawn for whoever else finds the port.
# --------------------------------------------------------------------------- #
def _require_local_mode() -> None:
    if not _local_mode():
        raise HTTPException(404, "not found")


@app.get("/openapi.json", include_in_schema=False)
def openapi_schema():
    _require_local_mode()
    return JSONResponse(app.openapi())


@app.get("/docs", include_in_schema=False)
def swagger_docs():
    _require_local_mode()
    return get_swagger_ui_html(openapi_url="/openapi.json", title="Tainted API")


@app.get("/redoc", include_in_schema=False)
def redoc_docs():
    _require_local_mode()
    return get_redoc_html(openapi_url="/openapi.json", title="Tainted API")


# The five self-hosted faces and the graph library are ~460 KB between them and change
# only when the build does. Without this they carry an ETag and nothing else, so every
# load spends a revalidation round-trip on each of them.
_IMMUTABLE = (".woff2", ".woff", ".ttf", ".js", ".css", ".png", ".svg", ".webp")


# Everything this page loads is same-origin and self-hosted — the fonts, the graph library,
# the stylesheet and the script are all served from here — so the policy can be closed almost
# completely. `unsafe-inline` is the one concession: the stylesheet and the two scripts live
# in the document, and nonce-ing them is a change to the page, not to this header. CSP is
# report-only until TAINTED_CSP_ENFORCE is set, so a deployment can watch before it blocks.
_CSP = (
    "default-src 'self'; "
    "script-src 'self' 'unsafe-inline'; "
    "style-src 'self' 'unsafe-inline'; "
    "img-src 'self' data:; "
    "font-src 'self'; "
    "connect-src 'self'; "
    "frame-ancestors 'none'; "
    "base-uri 'none'; "
    "form-action 'self'; "
    "object-src 'none'"
)


@app.middleware("http")
async def _response_headers(request: Request, call_next):
    response = await call_next(request)
    path = request.url.path
    if path.startswith("/static/") and path.endswith(_IMMUTABLE):
        response.headers.setdefault("Cache-Control", "public, max-age=604800")

    h = response.headers
    h.setdefault("X-Content-Type-Options", "nosniff")
    h.setdefault("Referrer-Policy", "strict-origin-when-cross-origin")
    h.setdefault("X-Frame-Options", "DENY")
    h.setdefault(
        "Permissions-Policy", "camera=(), microphone=(), geolocation=(), payment=()"
    )
    csp_header = (
        "Content-Security-Policy"
        if _env_flag("TAINTED_CSP_ENFORCE")
        else "Content-Security-Policy-Report-Only"
    )
    h.setdefault(csp_header, _CSP)
    if not _local_mode():
        h.setdefault(
            "Strict-Transport-Security", "max-age=31536000; includeSubDomains"
        )
    return response


# --------------------------------------------------------------------------- #
def _cookies_secure(request: Request) -> bool:
    """Whether cookies this deployment sets must carry `Secure`.

    Deriving this from the request's own scheme was wrong everywhere TLS is terminated
    upstream — which is every hosted deployment. Behind a proxy the app sees plain http and
    would drop `Secure` in exactly the environment that needs it. So the answer comes from
    the deployment, not the request: hosted is always Secure, and only a local dev server
    over plaintext is allowed to go without.
    """
    if not _local_mode():
        return True
    return request.url.scheme == "https"


def _redirect_uri(request: Request) -> str:
    if _oauth.redirect_override:
        return _oauth.redirect_override
    if not _local_mode():
        # Same reason as above: `base_url` behind a proxy reports the scheme and host the
        # proxy used to reach us, not the one the user typed, and a callback URL that does
        # not match the OAuth app's registered one fails at GitHub with an opaque error.
        raise HTTPException(
            503,
            "Set GITHUB_OAUTH_REDIRECT to this deployment's public callback URL "
            "(https://<your-host>/api/auth/github/callback).",
        )
    return str(request.base_url).rstrip("/") + "/api/auth/github/callback"


def _sign_in_unavailable_reason() -> Optional[str]:
    """Why this deployment cannot sign anyone in, or None if it can."""
    if not _oauth.configured:
        return "GitHub sign-in is not configured. Set GITHUB_CLIENT_ID and GITHUB_CLIENT_SECRET."
    if not session_token.available():
        return (
            f"GitHub sign-in is configured but sessions cannot be sealed: set "
            f"{keys.SECRET_ENV} to a long random string, the same value on every instance."
        )
    return None


def _sign_in_available() -> bool:
    return _sign_in_unavailable_reason() is None


def _require_session(request: Request) -> session_token.Session:
    session = session_token.unseal(request.cookies.get(SESSION_COOKIE))
    if session is None:
        raise HTTPException(401, "Sign in with GitHub first.")
    return session


@contextmanager
def _checkout(req, request: Request) -> Iterator[str]:
    """Resolve a request's repo to an on-disk path, cleaning up a fetched checkout afterwards.

    `repo` (a GitHub owner/name) is fetched server-side using the signed-in user's token;
    otherwise `repo_path` is used as a local directory. Exactly one must be provided.
    """
    repo = getattr(req, "repo", None)
    if repo:
        session = _require_session(request)
        try:
            checkout = github.fetch_repo(session.token, repo, getattr(req, "ref", None))
        except github.GitHubError as exc:
            raise HTTPException(502, str(exc))
        try:
            yield str(checkout.path)
        finally:
            checkout.cleanup()
        return

    repo_path = getattr(req, "repo_path", None)
    if not repo_path:
        raise HTTPException(
            400,
            "No repository given. Sign in with GitHub and pick one, or try `demo/demo`.",
        )
    # A filesystem path is a developer convenience. On a public deployment it is an
    # arbitrary-directory read for anyone who can reach this port — the analyzer reports the
    # source lines it finds — so it exists only where the caller owns the filesystem anyway.
    if not _local_mode():
        raise HTTPException(
            403,
            "A local repository path is only accepted by a local Tainted. Sign in with "
            "GitHub and pick a repository, or try `demo/demo`.",
        )
    if not Path(repo_path).is_dir():
        raise HTTPException(400, "repo_path is not a directory on this machine")
    yield repo_path


def _llm_or_none():
    llm = get_default_client(reload=True)
    return llm if llm.available else None


def _build_setup(req: ProveRequest) -> ProveSetup:
    def _acct(label, email, password, legacy_spec):
        """One account from either the split fields or the legacy `email:password` string."""
        if email or password:
            return Account(label=label, email=email.strip(), password=password)
        legacy_email, _, legacy_pw = (legacy_spec or "").partition(":")
        return Account(label=label, email=legacy_email.strip(), password=legacy_pw)

    seed_record = None
    if req.seed:
        table, _, rid = req.seed.partition(":")
        seed_record = SeedRecord(table=table, id=rid)
    return ProveSetup(
        target=Target(url=req.url, anon_key=req.anon_key),
        account_a=_acct("A", req.email_a, req.password_a, req.login_a),
        account_b=_acct("B", req.email_b, req.password_b, req.login_b),
        seed=seed_record,
    )
