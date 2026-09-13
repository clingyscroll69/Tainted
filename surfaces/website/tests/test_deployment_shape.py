"""The page must never offer an input this deployment will refuse.

Three shapes exist, and only one of them was handled well. On a hosted deployment with no
GitHub OAuth configured, the sign-in box hid itself, the filesystem-path field stayed as the
only visible input, and submitting it answered *"Sign in with GitHub and pick a repository"* —
naming a control that was not on the page. The demo was the only thing that worked, and nothing
said so.

`/api/auth/status` now reports whether filesystem paths are accepted, so the form can match the
deployment it is in rather than guessing.
"""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from backend.app import app, deployment_warnings

client = TestClient(app)


@pytest.fixture
def hosted_no_oauth(monkeypatch):
    """The shape that was broken: a public deployment nobody finished configuring."""
    for var in (
        "TAINTED_LOCAL_MODE",
        "GITHUB_CLIENT_ID",
        "GITHUB_CLIENT_SECRET",
        "TAINTED_TOKEN_SECRET",
    ):
        monkeypatch.delenv(var, raising=False)


@pytest.fixture
def local_dev(monkeypatch):
    monkeypatch.setenv("TAINTED_LOCAL_MODE", "1")


# --------------------------------------------------------------------------- #
# What the status endpoint has to say
# --------------------------------------------------------------------------- #
def test_status_reports_whether_local_paths_are_usable(hosted_no_oauth):
    body = client.get("/api/auth/status").json()
    assert body["configured"] is False
    assert body["local_paths"] is False, (
        "the frontend decides whether to render the path field from this; "
        "without it the page can only guess"
    )
    assert body["reason"]


def test_status_reports_local_paths_on_a_developer_machine(local_dev):
    body = client.get("/api/auth/status").json()
    assert body["local_paths"] is True


# --------------------------------------------------------------------------- #
# The page carries the machinery to act on it
# --------------------------------------------------------------------------- #
def test_the_form_can_hide_the_path_field_and_explain_itself():
    html = (client.get("/").text)
    assert 'id="repowrap"' in html, "the path field needs a handle to be hidden by"
    assert 'id="demoonly"' in html, "there must be something to show in its place"
    assert "applyDeploymentShape" in html
    # The explanation names what is missing, so a reader can act or ask someone who can.
    assert "GITHUB_CLIENT_ID" in html
    assert "runs the demonstration only" in html.lower()


def test_the_demo_route_stays_available_in_every_shape(hosted_no_oauth):
    """Whatever else is unconfigured, the one open journey must still run."""
    r = client.post("/api/analyze", json={"repo": "demo/demo"})
    assert r.status_code == 200
    assert r.json()["demo"] is True


def test_the_arm_note_does_not_name_a_target_at_rest():
    """It used to read "Runs real exploits against localhost:54321" before hydration — the
    placeholder from the target field, not a value anyone entered, on the control that fires
    real attacks."""
    html = client.get("/").text
    note = html.split('id="armnote"', 1)[1].split("</span>", 1)[0]
    assert "localhost:54321" not in note
    assert "Analyze a repository first" in note


# --------------------------------------------------------------------------- #
# Saying it once, to the operator
# --------------------------------------------------------------------------- #
def test_a_misconfigured_hosted_deployment_names_every_gap(hosted_no_oauth):
    joined = " ".join(deployment_warnings())
    assert "TAINTED_TOKEN_SECRET" in joined
    assert "GITHUB_CLIENT_ID" in joined
    assert "TAINTED_CSP_ENFORCE" in joined
    assert "sandbox" in joined.lower()


def test_a_developer_machine_is_not_nagged(local_dev):
    assert deployment_warnings() == []


def test_the_warning_does_not_stop_the_app_from_serving(hosted_no_oauth):
    """A demo-only deployment is a legitimate thing to run; refusing to boot would make it
    impossible to run one."""
    assert client.get("/healthz").status_code == 200
    assert client.get("/").status_code == 200


# --------------------------------------------------------------------------- #
# The document names itself
# --------------------------------------------------------------------------- #
def test_the_page_has_one_heading_that_names_it():
    """The only h1 used to be the verdict — a value rewritten by every run ("Nothing analysed
    yet" / "9 candidates unproven" / "Do not ship"), so the outline had no stable root and a
    screen-reader user landed on a verdict with nothing saying what it judged."""
    html = client.get("/").text
    # Elements, not mentions: a CSS comment in the stylesheet says "the water column holds the
    # page's <h1>", which a naive substring count picks up.
    body = html.split("<body>", 1)[1]
    assert body.count("<h1") == 1
    assert '<h1 class="vh">Tainted' in body
    # The verdict keeps its visual treatment; only its level in the outline changed.
    assert 'class="verdict unproven" id="verdict"' in html
    assert "<h2 class=\"verdict unproven\"" in html


def test_the_disabled_reveal_button_does_not_use_a_fill_token_as_text():
    """`--wash-faint` is documented in the token block as "inactive fills only — never text";
    as text on the field ground it computes to 2.67:1."""
    html = client.get("/").text
    rule = html.split(".reveal:disabled{", 1)[1].split("}", 1)[0]
    assert "--wash-faint" not in rule
    assert "--wash-dim" in rule
