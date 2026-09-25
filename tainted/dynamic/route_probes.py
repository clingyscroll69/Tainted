"""Proving a route-discovered finding through the app's own HTTP surface.

The PostgREST probes in `probes.py` address the database directly, which is the right proof for
an RLS hole — that *is* the exposed surface on the Supabase stack. But a BOLA candidate found by
route discovery names a URL, and the honest proof of "`GET /api/invoices/[id]` leaks" is to
request that URL as account B. Proving it against PostgREST instead would demonstrate something
adjacent to the finding rather than the finding itself, and the report would print a request the
reader never wrote.

So this prober speaks the app's language: it fills the route's parameter with the seed record's
id, sends the request as B, and reads the response for A's data.
"""

from __future__ import annotations

import re
from typing import Optional

import httpx

from tainted.dynamic.replay import SupabaseReplay
from tainted.dynamic.target import Account, ProveSetup
from tainted.models import (
    Candidate,
    Exploit,
    Finding,
    FindingStatus,
    ProbeResult,
    Provenance,
    Register,
)

# `[id]`, `:id`, `{id}`, `<int:id>` — the four dialects route discovery recovers.
_PARAM_TOKEN = re.compile(r"\[\.{0,3}(\w+)\]|:(\w+)|\{(\w+)\}|<(?:[^:>]+:)?([^>]+)>")

_MAX_BODY = 2000

# The one verb live proof sends to an app route. A route's own method is what the handler runs,
# so firing a BOLA probe at `DELETE /api/invoices/:id` deletes account A's record to prove B
# could, and a SQL tautology sent to a DELETE or PUT handler can widen the write to the whole
# table. Proof has to be reversible, so anything but a read is built and held, never sent.
# HEAD is safe too, but its response has no body to carry the record, so it proves nothing
# and would read as "the route held" when it was never really asked.
READ_METHOD = "GET"


def send_verb(method: Optional[str]) -> str:
    """The verb a route's declared method is sent as. A catch-all (`*`) is sent as a read."""
    return method.upper() if method and method != "*" else READ_METHOD


def is_readable(method: Optional[str]) -> bool:
    """Whether live proof may send this route's method at all."""
    return send_verb(method) == READ_METHOD


def held_write(candidate: Candidate, kind: str, method: str, url: str, payload=None) -> Finding:
    """A probe on a write route: built in full, deliberately not sent."""
    verb = send_verb(method)
    finding = Finding(candidate=candidate, status=FindingStatus.REPORTED)
    finding.proof = ProbeResult(
        succeeded=False,
        kind=kind,
        exploit=Exploit(
            description=(
                f"Built, not sent: {verb} {url} as account B. Tainted sends only reads to a "
                f"live app, because this request would run the route's own write."
            ),
            method=verb,
            url=url,
            payload=payload,
            executed=False,
        ),
        notes=(
            f"This route handles {verb}, which changes data. Sending it to prove the hole "
            f"would do the damage the hole allows, so the request is held. Prove it against a "
            f"disposable database, or read the handler."
        ),
    )
    finding.provenance.append(
        Provenance(origin=Register.STRUCTURE, detail=f"held: {verb} is not sent by live proof")
    )
    return finding


def _redact(token: Optional[str]) -> str:
    if not token:
        return "<none>"
    return f"{token[:8]}…{token[-4:]}" if len(token) > 16 else "<token>"


class RouteProber:
    """Sends real requests to the running app's routes as a chosen account."""

    def __init__(
        self,
        setup: ProveSetup,
        client: Optional[httpx.Client] = None,
        replay: Optional[SupabaseReplay] = None,
    ):
        self.setup = setup
        self._client = client or httpx.Client(timeout=20.0, follow_redirects=True)
        # Credentials come from the same place the request-plane probes get them, so the two
        # harnesses never disagree about who account B is.
        self._replay = replay or SupabaseReplay(setup.target, self._client)

    # ------------------------------------------------------------------ #
    # URL construction
    # ------------------------------------------------------------------ #
    def build_url(self, route_path: str, value: str) -> str:
        """Substitute every route parameter with `value` and join it to the target."""
        filled = _PARAM_TOKEN.sub(lambda _m: str(value), route_path)
        return self.setup.target.url.rstrip("/") + "/" + filled.lstrip("/")

    # ------------------------------------------------------------------ #
    # Authentication
    # ------------------------------------------------------------------ #
    def _authenticate(self, account: Account) -> Account:
        """Best-effort login. A pre-supplied token wins; otherwise GoTrue, if configured."""
        if account.authenticated:
            account.resolve_user_id()
            return account
        if self.setup.target.anon_key:
            try:
                return self._replay.authenticate(account)
            except Exception:
                pass  # fall through to an unauthenticated attempt, recorded in the notes
        return account

    def _headers(self, account: Account) -> dict[str, str]:
        headers = {"Accept": "application/json"}
        if account.access_token:
            headers["Authorization"] = f"Bearer {account.access_token}"
        if self.setup.target.anon_key:
            headers["apikey"] = self.setup.target.anon_key
        return headers

    def request(
        self, method: str, url: str, account: Account, **kwargs
    ) -> httpx.Response:
        verb = send_verb(method)
        if verb != READ_METHOD:
            # The callers hold writes before they get here; this is the backstop, so no future
            # probe can send one by forgetting to ask.
            raise ValueError(f"live proof sends only {READ_METHOD}, never {verb}")
        self._authenticate(account)
        return self._client.request(
            verb, url, headers=self._headers(account), **kwargs
        )

    # ------------------------------------------------------------------ #
    # The BOLA probe
    # ------------------------------------------------------------------ #
    def prove_route_bola(self, candidate: Candidate) -> Finding:
        """Account B requests account A's record through the route that fetches it."""
        finding = Finding(candidate=candidate)
        route_path = candidate.metadata.get("route_path")
        method = candidate.metadata.get("method") or "GET"
        seed = self.setup.seed

        # Neither early return sent a request, so neither may say NOT_REPRODUCED: that status
        # means the attack ran and held, and the report prints it as exactly that.
        if not route_path:
            finding.status = FindingStatus.REPORTED
            finding.proof = ProbeResult(
                succeeded=False, kind="route_bola", notes="This possible hole names no route to request."
            )
            return finding
        if seed is None:
            finding.status = FindingStatus.REPORTED
            finding.proof = ProbeResult(
                succeeded=False,
                kind="route_bola",
                notes=(
                    "No seed record given, so there is no id of A's to request as B. "
                    "Give one record id to make this possible hole provable."
                ),
            )
            return finding

        url = self.build_url(route_path, seed.id)
        if not is_readable(method):
            return held_write(candidate, "route_bola", method, url)
        try:
            resp = self.request(method, url, self.setup.account_b)
        except httpx.HTTPError as exc:
            # Unreachable is not the same as resistant — REPORTED says why, NOT_REPRODUCED
            # would claim the route held when it was never actually asked.
            finding.status = FindingStatus.REPORTED
            finding.proof = ProbeResult(
                succeeded=False, kind="route_bola", notes=f"Request failed: {exc}"
            )
            return finding

        leaked = self._response_carries_seed(resp, seed.id)
        exploit = Exploit(
            description=(
                f"Account {self.setup.account_b.label} requested account "
                f"{self.setup.account_a.label}'s record `{seed.id}` via {method} {route_path}."
            ),
            method=send_verb(method),
            url=url,
            headers={
                k: (_redact(v.split(" ", 1)[-1]) if k.lower() == "authorization" else v)
                for k, v in self._headers(self.setup.account_b).items()
            },
            executed=True,
        )
        finding.proof = ProbeResult(
            succeeded=leaked,
            kind="route_bola",
            exploit=exploit,
            response_status=resp.status_code,
            response_body=resp.text[:_MAX_BODY],
            notes=(
                f"{self.setup.account_b.label} received {self.setup.account_a.label}'s record "
                f"through the app's own route."
                if leaked
                else f"Route returned {resp.status_code} without A's record to B."
            ),
        )
        if leaked:
            finding.status = FindingStatus.PROVEN
            finding.provenance.append(
                Provenance(origin=Register.PROOF, detail="live probe: route_bola")
            )
            return finding

        # B was refused. That means the route checked ownership only if the owner is *not*
        # refused: a route that answers no one (wrong path, dead record, a fix that locked
        # everyone out) refuses B too, and calling that "held" would be a false all-clear.
        owner_ok, owner_detail = self._owner_reads(url, seed.id)
        finding.proof.notes += " " + owner_detail
        finding.status = FindingStatus.NOT_REPRODUCED if owner_ok else FindingStatus.REPORTED
        return finding

    def _owner_reads(self, url: str, seed_id: str) -> tuple[bool, str]:
        """The control: account A requests its own record through the same URL."""
        a = self.setup.account_a.label
        try:
            resp = self.request(READ_METHOD, url, self.setup.account_a)
        except httpx.HTTPError as exc:
            return False, f"Account {a}'s own request failed ({exc}), so the refusal proves nothing."
        if self._response_carries_seed(resp, seed_id):
            return True, f"Account {a} still reads its own record there, so the route checked."
        return False, (
            f"Account {a} cannot read its own record there either (status {resp.status_code}). "
            f"Nobody was let in, so the refusal proves nothing; if you just applied a fix, it "
            f"locked out the owner too."
        )

    def legitimate_access_survives(self, route_path: Optional[str] = None) -> tuple[bool, str]:
        """As account A, read A's own seed record through `route_path`, or the seed's own route.

        Asked on its own, with no finding behind it: by the preflight's positive control and by
        the lockout check. The probe itself asks the same question through `_owner_reads`.
        """
        seed = self.setup.seed
        if seed is None:
            return True, "No seed record supplied — legitimacy check skipped."
        route_path = route_path or seed.route_path
        if not route_path:
            return True, "No route recorded for the seed — legitimacy check skipped."
        a = self.setup.account_a.label
        url = self.build_url(route_path, seed.id)
        try:
            resp = self.request(READ_METHOD, url, self.setup.account_a)
        except httpx.HTTPError as exc:
            return False, f"Account {a}'s own request failed: {exc}"
        if self._response_carries_seed(resp, seed.id):
            return True, f"Account {a} still reads its own record."
        return False, (
            f"Account {a} can no longer read its own record (status {resp.status_code})."
        )

    def _response_carries_seed(self, resp: httpx.Response, seed_id: str) -> bool:
        """A leak is the seed's own id coming back in a successful response.

        Deliberately strict: a 200 alone proves nothing (many apps return an empty shell or an
        error envelope with a 200), and an id echoed inside a 403 body is not a leak either.
        """
        if resp.status_code != 200:
            return False
        body = resp.text or ""
        if str(seed_id) not in body:
            return False
        # Guard against the id merely being echoed back in an error message.
        lowered = body.lower()
        if any(
            marker in lowered
            for marker in ('"error"', "unauthorized", "forbidden", "not found", "not_found")
        ):
            return False
        return True

    def close(self) -> None:
        self._client.close()
