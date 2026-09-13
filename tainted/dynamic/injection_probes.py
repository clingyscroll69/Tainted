"""Live proof for classic injection — and the line it refuses to cross.

Proof splits by danger, and the split is enforced here rather than merely documented:

  * **SQL injection is proven live**, using the request plane's own harness — a crafted input
    returning data a benign one does not. That is observable and reversible.
  * **Command and template injection are never executed.** A scanner that runs `; id #` on a
    staging box to prove a point is worse than the bug it found, and the difference between a
    payload that reads and a payload that destroys is one character of somebody else's input.
    So those stop at a demonstrated payload held at the static-plus-high-confidence line.

`prove_sql_injection` therefore returns REPORTED, not PROVEN, for a command or template
candidate — and the returned exploit carries `executed=False`, so a reader of the report can
never mistake what happened.
"""

from __future__ import annotations

from typing import Optional

import httpx

from tainted.dynamic.route_probes import RouteProber
from tainted.dynamic.target import ProveSetup
from tainted.models import (
    Candidate,
    Exploit,
    Finding,
    FindingStatus,
    ProbeResult,
    Provenance,
    Register,
)

# A benign control and a crafted probe. The pair is the proof: the same request shape, one
# character of difference, and a response that changes in a way only injection explains.
BENIGN_VALUE = "1"
TAUTOLOGY_PAYLOAD = "1' OR '1'='1"
ERROR_PAYLOAD = "1'"

# Fragments a database emits when it is handed broken SQL. Their appearance under the crafted
# input and absence under the benign one is the leak of the raw query.
_SQL_ERROR_MARKERS = (
    "syntax error at or near",
    "unterminated quoted string",
    "sqlite3.operationalerror",
    "you have an error in your sql syntax",
    "psycopg2",
    "sqlalchemy.exc",
    "pg_query",
    "unclosed quotation mark",
    "sql syntax",
)


def prove_sql_injection(
    candidate: Candidate, setup: ProveSetup, prober: Optional[RouteProber] = None
) -> Finding:
    """Prove SQL injection live; hold command and template injection at demonstration."""
    kind = candidate.metadata.get("kind", "sql")
    if kind != "sql":
        return _held_at_demonstration(candidate, kind)
    if not candidate.metadata.get("live_provable", True):
        return _held_at_demonstration(candidate, kind)

    route_path = candidate.metadata.get("route_path")
    if not route_path:
        # A sink found by file scan with no route attached has no address to send a request to.
        return _reported(
            candidate,
            "No route reaches this sink, so Tainted has nowhere to send a crafted request. "
            "Reported from static analysis only.",
        )

    prober = prober or RouteProber(setup)
    method = candidate.metadata.get("method") or "GET"

    try:
        benign = prober.request(
            method, prober.build_url(route_path, BENIGN_VALUE), setup.account_b
        )
        crafted = prober.request(
            method, prober.build_url(route_path, TAUTOLOGY_PAYLOAD), setup.account_b
        )
        broken = prober.request(
            method, prober.build_url(route_path, ERROR_PAYLOAD), setup.account_b
        )
    except httpx.HTTPError as exc:
        return _reported(candidate, f"Live SQLi probe could not reach the target: {exc}")

    verdict, why = _judge(benign, crafted, broken)
    exploit = Exploit(
        description=(
            f"Sent `{TAUTOLOGY_PAYLOAD}` where `{BENIGN_VALUE}` belongs, at "
            f"{method} {route_path}, and compared the responses."
        ),
        method=method if method != "*" else "GET",
        url=str(crafted.request.url),
        payload=TAUTOLOGY_PAYLOAD,
        executed=True,
    )
    finding = Finding(candidate=candidate)
    finding.proof = ProbeResult(
        succeeded=verdict,
        kind="sql_injection",
        exploit=exploit,
        response_status=crafted.status_code,
        response_body=crafted.text[:2000],
        notes=why,
    )
    if verdict:
        finding.status = FindingStatus.PROVEN
        finding.provenance.append(
            Provenance(origin=Register.PROOF, detail="live probe: sql_injection")
        )
    else:
        finding.status = FindingStatus.NOT_REPRODUCED
    return finding


def _judge(
    benign: httpx.Response, crafted: httpx.Response, broken: httpx.Response
) -> tuple[bool, str]:
    """Two independent signatures, either of which is conclusive on its own."""
    # 1. The database complained about *our* quote — the input reached the query unescaped.
    broken_body = (broken.text or "").lower()
    benign_body = (benign.text or "").lower()
    for marker in _SQL_ERROR_MARKERS:
        if marker in broken_body and marker not in benign_body:
            return True, (
                f"A single quote caused a database syntax error (`{marker}`). The benign input "
                f"did not. Your code concatenates the value into the query instead of binding it."
            )

    # 2. The tautology widened the result set — the predicate is attacker-controlled.
    if crafted.status_code == 200 and benign.status_code == 200:
        crafted_len, benign_len = len(crafted.text or ""), len(benign.text or "")
        if crafted_len > benign_len * 2 and crafted_len - benign_len > 100:
            return True, (
                f"`OR '1'='1` returned much more data than the benign input "
                f"({crafted_len} vs {benign_len} bytes). The WHERE clause is attacker-controlled."
            )
    return False, (
        "The crafted input caused no database error and no larger result. This query looks "
        "parameterized on this path."
    )


def _held_at_demonstration(candidate: Candidate, kind: str) -> Finding:
    """Command and template injection: demonstrated, never run."""
    demo = candidate.metadata.get("demonstrated_exploit") or {}
    exploit = Exploit(
        description=demo.get(
            "description",
            f"{kind} injection demonstrated. Not run, because Tainted only runs an attack it is highly confident in.",
        ),
        payload=demo.get("payload"),
        executed=False,
    )
    finding = Finding(candidate=candidate, status=FindingStatus.REPORTED)
    finding.proof = ProbeResult(
        succeeded=False,
        kind=f"{kind}_injection",
        exploit=exploit,
        notes=(
            f"{kind.capitalize()} injection is demonstrated, NOT executed, by design. Running it "
            f"could be worse than the bug. The payload that proves the hole and the payload "
            f"that destroys the box differ by one character of somebody else's input."
        ),
    )
    finding.provenance.append(
        Provenance(
            origin=Register.STRUCTURE,
            detail="demonstrated, not executed (danger split)",
        )
    )
    return finding


def _reported(candidate: Candidate, why: str) -> Finding:
    finding = Finding(candidate=candidate, status=FindingStatus.REPORTED)
    finding.proof = ProbeResult(succeeded=False, kind="sql_injection", notes=why)
    return finding
