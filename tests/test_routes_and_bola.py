"""Route discovery and the BOLA detector — the request plane's headline bug.

The discriminating question throughout: does the *query predicate* name the owner? A handler
that reads the caller's identity and then queries by id alone is the bug; a handler that puts
the caller into the where clause is not. Every fixture here exists to hold that line.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from tainted.checks.bola import analyze_bola, bola_candidates
from tainted.models import Check, Severity
from tainted.static.routes import discover_routes

FIXTURE = str(Path(__file__).parent / "fixtures" / "vulnerable_routes")


@pytest.fixture(scope="module")
def routes():
    return discover_routes(FIXTURE)


def _by_path(routes, path):
    return [r for r in routes if r.path == path]


# --------------------------------------------------------------------------- #
# Discovery
# --------------------------------------------------------------------------- #
def test_discovers_routes_across_all_four_frameworks(routes):
    frameworks = {r.framework for r in routes}
    assert {"next-app", "express", "flask", "fastapi"} <= frameworks


def test_next_app_router_path_and_params_come_from_the_filesystem(routes):
    invoices = _by_path(routes, "/api/invoices/[id]")
    assert invoices, [r.path for r in routes]
    route = invoices[0]
    assert route.method == "GET"
    assert route.params == ["id"]
    assert route.tables == ["invoices"]


def test_express_route_params_are_recovered_from_the_pattern(routes):
    orders = _by_path(routes, "/orders/:orderId")
    assert orders
    assert orders[0].params == ["orderId"]
    assert orders[0].method == "GET"


def test_flask_converter_syntax_is_stripped_from_the_param_name(routes):
    docs = _by_path(routes, "/documents/<int:doc_id>")
    assert docs
    assert "doc_id" in docs[0].params


def test_fastapi_brace_params_are_recovered(routes):
    tickets = _by_path(routes, "/tickets/{ticket_id}")
    assert tickets
    assert "ticket_id" in tickets[0].params


def test_a_route_with_no_database_read_is_recovered_but_holds_nothing(routes):
    health = _by_path(routes, "/healthz")
    assert health
    assert health[0].reads_db is False


# --------------------------------------------------------------------------- #
# The predicate question
# --------------------------------------------------------------------------- #
def test_identity_read_without_scoping_is_not_mistaken_for_a_check(routes):
    """The whole bug in one assertion: identity present, predicate absent."""
    route = _by_path(routes, "/api/invoices/[id]")[0]
    assert route.identity_signals  # it does know who is calling
    assert route.has_ownership_check is False  # and does not use it in the query


def test_owner_in_the_predicate_counts_as_a_check(routes):
    assert _by_path(routes, "/api/receipts/[id]")[0].has_ownership_check is True
    assert _by_path(routes, "/carts/:cartId")[0].has_ownership_check is True
    assert _by_path(routes, "/notes/<note_id>")[0].has_ownership_check is True


# --------------------------------------------------------------------------- #
# Candidates
# --------------------------------------------------------------------------- #
def test_only_the_unscoped_routes_become_candidates(routes):
    titles = " | ".join(c.title for c in bola_candidates(routes))
    assert "invoices" in titles
    assert "orders" in titles.lower()
    assert "documents" in titles.lower()
    assert "tickets" in titles.lower()
    # The safe routes must be absent — a false positive here is worse than a miss.
    assert "receipts" not in titles
    assert "carts" not in titles.lower()
    assert "notes" not in titles.lower()


def test_identity_present_but_unused_ranks_above_a_route_with_no_identity(routes):
    cands = {c.metadata["route_path"]: c for c in bola_candidates(routes)}
    assert cands["/api/invoices/[id]"].severity == Severity.HIGH
    assert cands["/tickets/{ticket_id}"].severity == Severity.MEDIUM


def test_candidates_carry_the_request_shape_a_probe_needs():
    cands = analyze_bola(FIXTURE)
    invoice = [c for c in cands if c.metadata.get("route_path") == "/api/invoices/[id]"][0]
    assert invoice.check is Check.BOLA
    assert invoice.metadata["method"] == "GET"
    assert invoice.metadata["param"] == "id"
    assert invoice.metadata["table"] == "invoices"
    assert invoice.location.file.endswith("route.ts")


def test_the_model_reorders_the_queue_and_never_shortens_it(fake_llm):
    """The composition thesis, asserted: ranking moves candidates, it does not remove them."""
    unranked = analyze_bola(FIXTURE)

    class Dismissive(type(fake_llm)):
        def judge_ownership(self, candidate):
            return {
                "is_object_reference": False,
                "ownership_check_present": True,
                "likelihood": 0.0,
                "rationale": "the model thinks every one of these is fine",
            }

    ranked = analyze_bola(FIXTURE, llm=Dismissive())
    assert len(ranked) == len(unranked)  # membership untouched
    assert all(c.rank_score == 0.0 for c in ranked)  # order flattened to the bottom
