"""The website's execution boundary, and the frontend actually being wired to the engine."""

from __future__ import annotations

import re
from pathlib import Path

import httpx
import pytest
from fastapi.testclient import TestClient

from backend import app as app_module
from backend.sandbox import (
    CloudflareExecutor,
    LocalExecutor,
    SandboxUnavailable,
    default_executor,
)
from tainted.dynamic.target import Account, ProveSetup, Target

FRONTEND = Path(__file__).resolve().parent.parent / "frontend" / "index.html"
FIXTURES = Path(__file__).resolve().parents[3] / "tests" / "fixtures"


def _setup() -> ProveSetup:
    return ProveSetup(
        target=Target(url="http://localhost:3000"),
        account_a=Account(label="A", email="a@x", password="p"),
        account_b=Account(label="B", email="b@x", password="p"),
    )


# --------------------------------------------------------------------------- #
# The execution boundary
# --------------------------------------------------------------------------- #
def test_executor_is_local_unless_the_sandbox_is_configured(monkeypatch):
    monkeypatch.delenv("TAINTED_SANDBOX_URL", raising=False)
    monkeypatch.delenv("TAINTED_SANDBOX_TOKEN", raising=False)
    assert isinstance(default_executor(), LocalExecutor)

    monkeypatch.setenv("TAINTED_SANDBOX_URL", "https://sandbox.example")
    monkeypatch.setenv("TAINTED_SANDBOX_TOKEN", "t")
    assert isinstance(default_executor(), CloudflareExecutor)


def test_local_executor_is_not_marked_sandboxed():
    """The flag the API gate reads must not lie about where exploits run."""
    assert LocalExecutor.sandboxed is False
    assert CloudflareExecutor.sandboxed is True


def test_cloudflare_executor_marshals_a_report_back():
    captured = {}

    def handler(request: httpx.Request) -> httpx.Response:
        captured["url"] = str(request.url)
        captured["auth"] = request.headers.get("authorization")
        return httpx.Response(
            200,
            json={
                "repo_path": "/repo",
                "summary": {"total_candidates": 1, "proven": 1},
                "findings": [],
                "unproven_candidates": [],
                "applicability": [],
                "coverage": [],
            },
        )

    executor = CloudflareExecutor(
        "https://sandbox.example", "tok",
        client=httpx.Client(transport=httpx.MockTransport(handler)),
    )
    outcome = executor.prove("/repo", _setup(), ownership_verified=True)

    assert outcome.report.summary.proven == 1
    assert captured["url"] == "https://sandbox.example/prove"
    assert captured["auth"] == "Bearer tok"


def test_unreachable_sandbox_raises_rather_than_running_locally():
    """Falling back to local execution here would run exploits on our own metal, silently."""

    def handler(request):
        raise httpx.ConnectError("refused")

    executor = CloudflareExecutor(
        "https://sandbox.example", "tok",
        client=httpx.Client(transport=httpx.MockTransport(handler)),
    )
    with pytest.raises(SandboxUnavailable):
        executor.prove("/repo", _setup(), ownership_verified=True)


def test_prove_is_refused_when_a_sandbox_is_required_but_absent(monkeypatch):
    monkeypatch.setenv("TAINTED_REQUIRE_SANDBOX", "1")
    monkeypatch.setattr(app_module, "_executor", LocalExecutor())
    client = TestClient(app_module.app)

    resp = client.post(
        "/api/prove",
        json={"repo_path": str(FIXTURES / "vulnerable_supabase"),
              "url": "http://localhost:54321", "login_a": "a:p", "login_b": "b:p"},
    )
    assert resp.status_code == 503
    assert "sandbox" in resp.json()["detail"].lower()


# --------------------------------------------------------------------------- #
# The frontend is connected to the backend
# --------------------------------------------------------------------------- #
def test_frontend_calls_the_engine_rather_than_animating_fixtures():
    """The demonstration has to demonstrate the engine, not a script of what it might say."""
    html = FRONTEND.read_text(encoding="utf-8")
    for endpoint in ("/api/analyze", "/api/prove", "/api/fix"):
        assert endpoint in html, f"frontend never calls {endpoint}"


def test_frontend_has_no_hardcoded_findings_left():
    html = FRONTEND.read_text(encoding="utf-8")
    assert '<article class="find' not in html
    assert "acme/ledger-web" not in html  # the synthetic repo name
    assert "synthetic demonstration data" not in html


def test_frontend_renders_the_tool_graph_with_cytoscape():
    html = FRONTEND.read_text(encoding="utf-8")
    # Vendored, not fetched: the page has to work with no network, and a security
    # product should not run a third party's unpinned script over its own findings.
    assert "/static/vendor/cytoscape.min.js" in html
    assert "cdnjs.cloudflare.com" not in html
    assert (FRONTEND.parent / "vendor" / "cytoscape.min.js").is_file()
    assert "renderToolGraph" in html
    # ...and only when a run actually produced agent scopes.
    assert "loadCytoscape" in html
    # Confirmed-exploitable scopes light red; that is the whole point of the picture.
    assert ".turned" in html


def test_frontend_escapes_engine_supplied_text():
    """Titles and response bodies come from a stranger's repository and a live server."""
    html = FRONTEND.read_text(encoding="utf-8")
    assert "const ESC" in html
    assert "ESC(c.title)" in html
    assert "ESC(p.response_body" in html or "ESC(p.notes)" in html


# --------------------------------------------------------------------------- #
# The sounding: the descent takes the screen
# --------------------------------------------------------------------------- #
def test_the_strata_are_named_once():
    """Depth means *which check*, so one table owns it and every picture reads that table.

    A second depth map is exactly how a check ends up one layer deep in the water column
    and another in the chart beside it.
    """
    html = FRONTEND.read_text(encoding="utf-8")
    assert "const LAYERS = [" in html
    assert "const CHECK_DEPTH" not in html
    for check in ("bola", "rls", "classic_injection", "agent_injection", "test_integrity"):
        assert f"check:'{check}'" in html, f"{check} has no stratum"
    # Every picture is built from this table rather than from a copy of it. The sounding used
    # to prove that by iterating LAYERS to build one shared water gradient; each world now
    # paints its own water, so the single reader is `stack()`, which starts from the table and
    # appends any check the table has never heard of. The invariant is unchanged: there is one
    # list of layers and everything that draws depth goes through it.
    assert "const out = LAYERS.slice();" in html
    assert "function stack(specs)" in html
    # a check the table has never heard of is still drawn somewhere
    assert "function layerFor" in html


def test_a_layer_and_a_pipeline_stage_never_share_a_name():
    """The rail names the engine's pipeline; the strata name classes of vulnerability.

    Two different things may not trade names on one surface.
    """
    html = FRONTEND.read_text(encoding="utf-8")
    zones = set(re.findall(r"zone:'([^']+)'", html))
    stages = set(re.findall(r'<span class="nm">([^<]+)</span>', html))
    assert zones and stages
    assert not zones & stages, f"a stratum and a pipeline stage share a name: {zones & stages}"


def test_the_descent_can_always_be_left():
    """A run the reader abandons stops being *run*, not merely stops being drawn."""
    html = FRONTEND.read_text(encoding="utf-8")
    assert 'id="sounding"' in html
    assert 'aria-modal="true"' in html
    assert "AbortController" in html
    assert "ctl.abort()" in html
    assert "'Escape'" in html
    # the two meanings of leaving, before and after the report
    assert "Abort & surface" in html
    assert "function skip()" in html
    # and the screen is genuinely handed over while it is up
    assert "is-diving" in html
    assert "function pageInert" in html


def test_the_scene_claims_no_more_than_the_run_has_returned():
    """The descent may never be deeper than the run has actually earned.

    `/api/prove` now reports each candidate as it lands, so the scene has more to go on than
    it used to — but the rule is unchanged and is now enforced in one place. `frontier()` is
    that place: a layer with anything outstanding stops the vehicle, and everything else in
    the scene is downstream of where the vehicle is.
    """
    html = FRONTEND.read_text(encoding="utf-8")
    assert "function frontier()" in html
    # a layer with an unattempted candidate holds the vehicle at that layer's own ceiling
    assert "if(done.length < c.pips.length)" in html
    assert "return done.length ? Math.max(c.layer.depth" in html
    # and a deployment that cannot report progress must say so rather than be read as slow
    assert "function streaming(on)" in html
    assert "nothing is proved yet" in html
    # the scene never writes a result: it calls the page's own writer and reads it back
    assert "ignite(p.find" in html
    assert "vEl.textContent = (v.textContent" in html
    # reduced motion resolves the run rather than becoming a slideshow of jumps
    assert "if(reduce){ skip(); return; }" in html


def test_the_surface_draws_no_second_depth_picture():
    """The sounding owns the depth axis. The water column used to draw a flat copy of the
    same account under the verdict - same ruler, same thermocline, same strata, same
    candidates - and two pictures of one run is one too many."""
    html = FRONTEND.read_text(encoding="utf-8")
    for gone in ('class="dive"', 'class="taint"', 'class="ruler"',
                 'class="thermocline"', 'class="glegend"', "drawTaint(", "syncTaint("):
        assert gone not in html, gone


def test_the_descent_is_reachable_after_the_run_that_produced_it():
    """Removing the flat copy is only an upgrade if the real one can be re-entered."""
    html = FRONTEND.read_text(encoding="utf-8")
    assert 'id="godeep-go"' in html
    assert "godeepGo.addEventListener('click', replayDescent)" in html
    # the doorway describes the run behind it and says which of the two dives it leads to
    assert "'Replay the descent' : 'Preview the descent'" in html


def test_a_replay_attempts_nothing_and_so_records_nothing():
    """The proof log records attempts. A replay makes none, so it may not write to it -
    otherwise re-watching a run doubles its own evidence."""
    html = FRONTEND.read_text(encoding="utf-8")
    # One gate, and every route to a log row goes through it: `lightPip` during the descent,
    # `resolveAll` on a skip, and `rebind` replaying the marks lit before the report landed.
    assert "function logPip(p)" in html
    assert "if(p.logged || mode !== 'run' || !p.find) return;" in html
    assert html.count("ignite(p.find, logN++)") == 1, "a second route into the proof log"
    # and it may not run a clock over a run that is already timed
    assert "if(mode !== 'replay') clockEl.textContent = elapsed();" in html


# --------------------------------------------------------------------------- #
# Reaching the page, and getting out of it
#
# These assert on the served document because that is the only seam this surface has: the
# whole frontend is one file with no module boundary. Where behaviour could be checked in a
# browser instead, it should be — see the audit's note on browser tests.
# --------------------------------------------------------------------------- #
def test_the_header_and_the_ladder_can_be_bypassed():
    """WCAG 2.4.1. Before this, a keyboard user tabbed the masthead and, on a narrow screen,
    an eight-stage ladder before reaching anything that does something."""
    html = FRONTEND.read_text(encoding="utf-8")
    assert '<a class="skip" href="#water">' in html
    # Inside the header, so the `inert` the scene and the tour apply covers it too. A loose
    # fixed-position link outside header/main/footer would be a way to tab out of a modal.
    assert html.index('class="skip"') > html.index('<header class="deck">')
    assert html.index('class="skip"') < html.index('<div class="mark">')


def test_a_run_announces_what_it_finds():
    """The proof log gained a row per candidate and the gate changed state, both silently."""
    html = FRONTEND.read_text(encoding="utf-8")
    assert 'id="prooflog" aria-live="polite" aria-relevant="additions"' in html
    assert 'id="gate-chip" aria-live="polite"' in html
    # A live region re-announces whatever is written to it, even the same words, and this
    # runs on every keystroke in the form.
    assert "if(chipEl.textContent !== chipText)" in html


def test_the_disabled_primary_is_not_printed_on_the_water():
    """`--wash-dim` over the top of the water gradient measures 3.83:1, and this button is
    disabled in the state every visitor sees first."""
    html = FRONTEND.read_text(encoding="utf-8")
    assert ".btn:disabled{\n  background:var(--field);color:var(--wash-dim)" in html


def test_the_tour_really_takes_the_screen():
    """It declared aria-modal while the page behind stayed clickable: the scrim is a shadow
    on a pointer-events:none ring, so a mouse went straight through to Arm & prove."""
    html = FRONTEND.read_text(encoding="utf-8")
    tour = html[html.index("---- the guided tour ----", html.index("<script>", html.index("</footer>"))):]
    assert "function pageInert(on)" in tour
    assert "pageInert(true);" in tour and "pageInert(false);" in tour


def test_the_escaper_covers_the_single_quote():
    html = FRONTEND.read_text(encoding="utf-8")
    assert "\"'\":'&#39;\"" not in html  # not the shape below, just guarding the assertion
    assert "/[&<>\"']/g" in html


# --------------------------------------------------------------------------- #
# What the form asks for, and in what order
# --------------------------------------------------------------------------- #
def test_the_private_fields_are_the_masked_ones():
    """The anon key is a value the browser already ships to anyone; the account passwords are
    not. Masking the public one and not the private ones had it backwards."""
    html = FRONTEND.read_text(encoding="utf-8")
    for field in ("f-a-pass", "f-b-pass"):
        assert f'id="{field}" type="password"' in html
    assert 'id="f-key" type="password"' not in html
    # `off` blocks a password manager on exactly the field that needs one (WCAG 2.2 SC 3.3.8).
    assert 'id="f-a-pass" type="password" autocomplete="new-password"' in html
    assert "email_a:" in html and "password_a:" in html


def test_the_form_comes_before_the_ladder_on_a_narrow_screen():
    """At 375x800 the repository field sat at y=1687, behind 810px of static ladder."""
    html = FRONTEND.read_text(encoding="utf-8")
    narrow = html[html.index("@media (max-width:860px)"):html.index("@media (max-width:460px)")]
    assert ".water{order:1;min-height:auto}" in narrow
    assert ".rail{order:2;" in narrow
    assert "order:3}" in narrow  # the descent, now last of the three


def test_only_the_demonstration_starts_itself_from_the_address_bar():
    """A link that makes the server go and read something is a request forged on the
    reader's behalf. The demo contacts nothing, so there is no work to trigger.

    With the free-text field gone, a `?repo=` link is weaker still: it cannot select anything
    the picker did not get from GitHub for this caller, so an unknown name is refused rather
    than loaded."""
    html = FRONTEND.read_text(encoding="utf-8")
    body = html.split("function fromAddress()", 1)[1].split("})();", 1)[0]
    assert "if(repo !== DEMO_REPO){" in body
    assert "pendingRepo = repo;" in body, "a link proposes; the picker is what confirms"
    assert "choose(DEMO_REPO);" in body
    # And the confirmation is a membership test against the list GitHub returned.
    load = html.split("async function loadRepos()", 1)[1].split("\n  }", 1)[0]
    assert "repos.some(r => r.full_name === pendingRepo)" in load


def test_an_ownership_token_is_asked_for_rather_than_invented():
    html = FRONTEND.read_text(encoding="utf-8")
    assert "/api/ownership/token?url=" in html
    assert 'id="gettoken"' in html
    # The path the UI names must be the one the engine fetches.
    from tainted.ownership import WELL_KNOWN_PATH
    assert "/.well-known/tainted<" not in html
    assert WELL_KNOWN_PATH.split("/")[-1] in html or "well_known_path" in html
