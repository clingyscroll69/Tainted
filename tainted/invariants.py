"""A rule the developer wrote in English, fired at their running app.

The developer knows something about their application that no static analysis can recover: what
must never happen. "Nobody should ever see another user's email address." "A cancelled
subscription must not reach the export endpoint." Those are the real requirements, and today they
live in somebody's head or in a review comment.

This module takes one such sentence and carries it through all three registers. **Structure**
supplies the routes the app actually declares, so the attack aims at a real door. **Meaning**
translates the sentence into one concrete request that would violate it — translation only; the
model is never asked whether the rule holds. **Proof** fires that request as the attacking account
and reads the answer.

The output is three-valued, and the third value is the reason this module exists:

  * `VIOLATED` — the request was sent and the response shows the rule broken.
  * `HELD` — the request was sent and it did not.
  * `NOT_TESTED` — no request was sent, and here is why.

Every comparable tool is binary. A binary verdict has to file "I could not build an attack for
this" as a pass, which turns the tool's own blind spot into the user's reassurance. A rule nobody
tested is not a rule that held, so it gets its own answer and the reason travels with it.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Optional

import httpx

from tainted.dynamic.route_probes import RouteProber, is_readable, send_verb
from tainted.dynamic.target import ProveSetup
from tainted.llm.client import LLMClient, LLMUnavailable
from tainted.static.routes import discover_routes


class InvariantVerdict(str, Enum):
    VIOLATED = "violated"  # fired, and the rule broke
    HELD = "held"  # fired, and the rule held
    NOT_TESTED = "not_tested"  # nothing was fired; the reason is attached

    @property
    def is_evidence(self) -> bool:
        """True only for the two verdicts a request was actually sent for."""
        return self in (InvariantVerdict.VIOLATED, InvariantVerdict.HELD)


@dataclass
class InvariantResult:
    """One rule, carried to a verdict."""

    rule: str
    verdict: InvariantVerdict
    detail: str
    route_path: str = ""
    method: str = ""
    url: str = ""
    response_status: Optional[int] = None
    response_body: str = ""
    violation_marker: str = ""

    def as_dict(self) -> dict:
        return {
            "rule": self.rule,
            "verdict": self.verdict.value,
            "detail": self.detail,
            "route_path": self.route_path,
            "method": self.method,
            "url": self.url,
            "response_status": self.response_status,
            "response_body": self.response_body[:2000],
            "violation_marker": self.violation_marker,
            "tested": self.verdict.is_evidence,
        }


@dataclass
class InvariantReport:
    results: list[InvariantResult] = field(default_factory=list)

    @property
    def violated(self) -> list[InvariantResult]:
        return [r for r in self.results if r.verdict is InvariantVerdict.VIOLATED]

    @property
    def not_tested(self) -> list[InvariantResult]:
        return [r for r in self.results if r.verdict is InvariantVerdict.NOT_TESTED]

    def as_dict(self) -> dict:
        return {
            "headline": self._headline(),
            "results": [r.as_dict() for r in self.results],
            "reminder": (
                "A rule under `not_tested` was never fired at. It is not a rule that held."
            ),
        }

    def _headline(self) -> str:
        held = len([r for r in self.results if r.verdict is InvariantVerdict.HELD])
        return (
            f"{len(self.violated)} violated; {held} held; {len(self.not_tested)} not tested."
        )


def check_invariants(
    rules: list[str],
    repo_path: str,
    setup: ProveSetup,
    llm: Optional[LLMClient] = None,
    ownership_verified: bool = False,
    prober: Optional[RouteProber] = None,
) -> InvariantReport:
    """Fire each rule at the running target and return a three-valued verdict for each.

    Ownership-gated exactly like `prove`, because it is `prove` — the same live requests at the
    same target, aimed by a sentence instead of by a static candidate.
    """
    report = InvariantReport()

    if not setup.target.is_local and not ownership_verified:
        for rule in rules:
            report.results.append(
                InvariantResult(
                    rule=rule,
                    verdict=InvariantVerdict.NOT_TESTED,
                    detail=(
                        "Non-local target without verified ownership. Nothing was sent, so "
                        "nothing is known about this rule."
                    ),
                )
            )
        return report

    if llm is None:
        for rule in rules:
            report.results.append(
                InvariantResult(
                    rule=rule,
                    verdict=InvariantVerdict.NOT_TESTED,
                    detail=(
                        "No model configured, so the sentence could not be turned into a "
                        "request. Set GEMINI_API_KEY to test rules written in English."
                    ),
                )
            )
        return report

    routes = _route_dicts(repo_path)
    if not routes:
        for rule in rules:
            report.results.append(
                InvariantResult(
                    rule=rule,
                    verdict=InvariantVerdict.NOT_TESTED,
                    detail=(
                        "No routes were recovered from this repository, so there is no declared "
                        "door to aim a request at."
                    ),
                )
            )
        return report

    prober = prober or RouteProber(setup)
    for rule in rules:
        report.results.append(_check_one(rule, routes, setup, llm, prober))
    return report


def _check_one(
    rule: str,
    routes: list[dict],
    setup: ProveSetup,
    llm: LLMClient,
    prober: RouteProber,
) -> InvariantResult:
    try:
        spec = llm.compile_invariant(rule, routes)
    except LLMUnavailable as exc:
        return InvariantResult(
            rule=rule,
            verdict=InvariantVerdict.NOT_TESTED,
            detail=f"The model was unavailable, so no request was built: {exc}",
        )
    except Exception as exc:  # noqa: BLE001 - a translation failure is a not-tested, never a pass
        return InvariantResult(
            rule=rule,
            verdict=InvariantVerdict.NOT_TESTED,
            detail=f"The rule could not be turned into a request: {exc}",
        )

    route_path = str(spec.get("route_path") or "").strip()
    marker = str(spec.get("violation_marker") or "").strip()
    if not route_path:
        return InvariantResult(
            rule=rule,
            verdict=InvariantVerdict.NOT_TESTED,
            violation_marker=marker,
            detail=(
                "No declared route could violate this rule, so nothing was fired. The rule may "
                "still be broken somewhere Tainted cannot see."
            ),
        )
    if not marker:
        return InvariantResult(
            rule=rule,
            verdict=InvariantVerdict.NOT_TESTED,
            route_path=route_path,
            detail=(
                "No marker was produced for what a violation would look like. Without one, a "
                "response cannot be judged, and guessing would make 'held' meaningless."
            ),
        )

    # Aim the request at the seed record when there is one, so a route with a parameter is asked
    # about a record that actually exists. Without that, a 404 would read as the rule holding.
    filler = setup.seed.id if setup.seed else "1"
    method = str(spec.get("method") or "GET").upper()
    body = spec.get("body") or None
    url = prober.build_url(route_path, str(filler))

    if not is_readable(method):
        # Live proof sends only reads: firing a write to test a rule would do what the rule
        # forbids to real data. Built and held, and never recorded as the rule holding.
        return InvariantResult(
            rule=rule,
            verdict=InvariantVerdict.NOT_TESTED,
            route_path=route_path,
            method=send_verb(method),
            url=url,
            violation_marker=marker,
            detail=(
                f"Built, not sent: {send_verb(method)} {url} as account {setup.account_b.label}. "
                f"Tainted sends only reads to a live app, because this request would run the "
                f"route's own write. Test this rule against a disposable database."
            ),
        )

    kwargs: dict = {}
    if body:
        kwargs["content"] = body
    try:
        resp = prober.request(method, url, setup.account_b, **kwargs)
    except httpx.HTTPError as exc:
        return InvariantResult(
            rule=rule,
            verdict=InvariantVerdict.NOT_TESTED,
            route_path=route_path,
            method=method,
            url=url,
            violation_marker=marker,
            detail=(
                f"The request could not be delivered ({exc}). Unreachable is not the same as "
                f"resistant, so this is not recorded as the rule holding."
            ),
        )

    violated = _marker_present(resp, marker)
    return InvariantResult(
        rule=rule,
        verdict=InvariantVerdict.VIOLATED if violated else InvariantVerdict.HELD,
        route_path=route_path,
        method=method,
        url=url,
        response_status=resp.status_code,
        response_body=resp.text[:2000],
        violation_marker=marker,
        detail=(
            f"{method} {url} as account {setup.account_b.label} returned {resp.status_code} and "
            f"the response contains `{marker}` — the rule is broken."
            if violated
            else (
                f"{method} {url} as account {setup.account_b.label} returned "
                f"{resp.status_code} and the response does not contain `{marker}`."
            )
        ),
    )


def _marker_present(resp: httpx.Response, marker: str) -> bool:
    """A violation needs a 2xx *and* the marker — an error page quoting it back is not a leak.

    Applications routinely echo a requested field name into a 403 or a validation error, and
    treating that as a violation would manufacture findings out of well-behaved refusals.
    """
    if not (200 <= resp.status_code < 300):
        return False
    return marker.lower() in resp.text.lower()


def _route_dicts(repo_path: str) -> list[dict]:
    """The declared routes, reduced to what the translation step needs to aim at one."""
    out: list[dict] = []
    for route in discover_routes(repo_path):
        out.append(
            {
                "method": route.method,
                "path": route.path,
                "params": list(route.params),
                "framework": route.framework,
                "tables": route.tables,
            }
        )
    return out
