"""Drives the app in a real browser to find object ids the static route parser can't see.

A Supabase frontend often builds its request at runtime, so the id never appears in a route
file. This module logs in as account B, browses the app, and records every request, then finds
the id wherever it sits: URL path, query string, JSON body, or an RPC argument.

Playwright is optional. Without it, `discover()` just returns an empty, explained result, and
static candidates still get proven through the harnesses that don't need a browser.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any, Iterable, Optional
from urllib.parse import parse_qsl, urlparse

from tainted.dynamic.target import Account, ProveSetup

if TYPE_CHECKING:  # the annotation below names it; the import would be circular at runtime
    from tainted.dynamic.target import SeedRecord

# Values that look like an id worth trying: uuids, long digit strings, nanoid/cuid-ish tokens.
_UUID = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$", re.I)
_NUMERIC_ID = re.compile(r"^\d{1,19}$")
_OPAQUE_ID = re.compile(r"^[A-Za-z0-9_-]{12,36}$")

# Keys whose values are ids by name. Kept narrow on purpose: a false "reference" costs a probe.
_ID_KEYS = re.compile(
    r"^(id|_id|uuid|guid|.*_id|.*Id|slug|key|record|ref)$",
)

_IGNORED_HOSTS = ("googletagmanager.com", "google-analytics.com", "sentry.io", "vercel-insights")
_ASSET_SUFFIXES = (".js", ".css", ".png", ".jpg", ".svg", ".woff", ".woff2", ".ico", ".map")


@dataclass
class ObjectReference:
    """One place a request carries something that names a record."""

    where: str  # "path" | "query" | "body" | "rpc_arg"
    name: str  # parameter/field name ("id", "invoice_id", …)
    value: str
    request_url: str
    method: str

    def __str__(self) -> str:
        return f"{self.method} {self.request_url} [{self.where}:{self.name}={self.value}]"


@dataclass
class CapturedRequest:
    method: str
    url: str
    headers: dict[str, str] = field(default_factory=dict)
    post_data: Optional[str] = None

    @property
    def is_data_call(self) -> bool:
        """Data traffic, not assets or third-party telemetry."""
        parsed = urlparse(self.url)
        if any(host in parsed.netloc for host in _IGNORED_HOSTS):
            return False
        if parsed.path.endswith(_ASSET_SUFFIXES):
            return False
        return True


@dataclass
class DiscoveryResult:
    available: bool
    requests: list[CapturedRequest] = field(default_factory=list)
    references: list[ObjectReference] = field(default_factory=list)
    visited: list[str] = field(default_factory=list)
    note: str = ""

    @property
    def tables(self) -> list[str]:
        """PostgREST table names seen in captured traffic — `/rest/v1/<table>`."""
        found: list[str] = []
        for req in self.requests:
            m = re.search(r"/rest/v1/([A-Za-z_][\w]*)", req.url)
            if m and m.group(1) not in found and m.group(1) != "rpc":
                found.append(m.group(1))
        return found


def playwright_available() -> bool:
    try:
        import playwright.sync_api  # noqa: F401
    except Exception:
        return False
    return True


# --------------------------------------------------------------------------- #
# Reference extraction — pure, so it is testable without a browser
# --------------------------------------------------------------------------- #
def _looks_like_id(value: Any) -> bool:
    if not isinstance(value, (str, int)):
        return False
    text = str(value)
    return bool(_UUID.match(text) or _NUMERIC_ID.match(text) or _OPAQUE_ID.match(text))


def extract_references(req: CapturedRequest) -> list[ObjectReference]:
    """Every id-shaped value this request carries, wherever it sits.

    Four places, because a client library will use any of them: the path segment (clearest to
    show in a report), the query string (the PostgREST `id=eq.…` shape), the JSON body of a
    POST/PATCH, and an RPC argument.
    """
    refs: list[ObjectReference] = []
    parsed = urlparse(req.url)

    # 1. Path segments.
    segments = [s for s in parsed.path.split("/") if s]
    for i, segment in enumerate(segments):
        if _looks_like_id(segment):
            name = segments[i - 1] if i else "path"
            refs.append(
                ObjectReference("path", name, segment, req.url, req.method)
            )

    # 2. Query string, including PostgREST's `column=eq.<value>` operator syntax.
    for key, value in parse_qsl(parsed.query):
        raw = value.split(".", 1)[1] if value.startswith(("eq.", "in.")) else value
        if _looks_like_id(raw) and (_ID_KEYS.match(key) or value.startswith("eq.")):
            refs.append(ObjectReference("query", key, raw, req.url, req.method))

    # 3 & 4. JSON body — plain fields, and RPC arguments (which are just a body by convention).
    where = "rpc_arg" if "/rpc/" in parsed.path else "body"
    for name, value in _json_fields(req.post_data):
        if _looks_like_id(value) and _ID_KEYS.match(name):
            refs.append(ObjectReference(where, name, str(value), req.url, req.method))

    return _dedupe(refs)


def _json_fields(payload: Optional[str]) -> Iterable[tuple[str, Any]]:
    if not payload:
        return []
    try:
        data = json.loads(payload)
    except (json.JSONDecodeError, TypeError):
        return []
    out: list[tuple[str, Any]] = []

    def _walk(obj: Any, prefix: str = "") -> None:
        if isinstance(obj, dict):
            for k, v in obj.items():
                if isinstance(v, (dict, list)):
                    _walk(v, k)
                else:
                    out.append((k, v))
        elif isinstance(obj, list):
            for item in obj[:20]:  # bounded: a bulk payload is not 10k references
                _walk(item, prefix)

    _walk(data)
    return out


def _dedupe(refs: list[ObjectReference]) -> list[ObjectReference]:
    seen: set[tuple[str, str, str]] = set()
    out: list[ObjectReference] = []
    for r in refs:
        key = (r.where, r.name, r.value)
        if key in seen:
            continue
        seen.add(key)
        out.append(r)
    return out


# --------------------------------------------------------------------------- #
# The browser walk
# --------------------------------------------------------------------------- #
def discover(
    setup: ProveSetup,
    account: Optional[Account] = None,
    max_pages: int = 12,
    timeout_ms: int = 15000,
) -> DiscoveryResult:
    """Drive the app as an account and capture the traffic its own frontend generates."""
    if not playwright_available():
        return DiscoveryResult(
            available=False,
            note=(
                "Playwright is not installed, so Tainted skipped traffic discovery. It still "
                "proves possible holes through the HTTP and PostgREST harnesses. What it misses "
                "is object references that only show up in requests your frontend makes itself. "
                "Install with `pip install 'tainted[dynamic]' && playwright install chromium`."
            ),
        )

    from playwright.sync_api import sync_playwright

    account = account or setup.account_b
    result = DiscoveryResult(available=True)
    base = setup.target.url.rstrip("/")

    with sync_playwright() as p:
        browser = p.chromium.launch(headless=True)
        context = browser.new_context(ignore_https_errors=True)
        page = context.new_page()

        def _on_request(request) -> None:
            captured = CapturedRequest(
                method=request.method,
                url=request.url,
                headers={
                    k: v
                    for k, v in request.headers.items()
                    if k.lower() in ("authorization", "apikey", "content-type")
                },
                post_data=request.post_data,
            )
            if captured.is_data_call:
                result.requests.append(captured)

        page.on("request", _on_request)

        try:
            page.goto(base, timeout=timeout_ms, wait_until="networkidle")
            _sign_in(page, account, timeout_ms)
            _walk_app(page, base, result, max_pages, timeout_ms)
        except Exception as exc:  # noqa: BLE001 — a partial walk is still useful
            result.note = f"Walk ended early: {type(exc).__name__}: {exc}"
        finally:
            context.close()
            browser.close()

    for req in result.requests:
        result.references.extend(extract_references(req))
    result.references = _dedupe(result.references)
    return result


# --------------------------------------------------------------------------- #
# Emptying a form field, when it can be emptied
# --------------------------------------------------------------------------- #
def seed_from_discovery(setup: ProveSetup) -> tuple[Optional["SeedRecord"], str]:
    """Recover a seed record by walking the app **as account A**.

    The direction matters and is easy to get backwards. Discovery has to run as A, because the
    probe's whole question is whether B can read something *of A's*; a record id harvested while
    browsing as B is B's own, and B reading it proves nothing at all.

    This is the autonomy that empties a form field when it can. It is the optimization, not the
    happy path — a walk that fails leaves the field where it was, for the owner to fill in.
    """
    from tainted.dynamic.target import SeedRecord

    result = discover(setup, account=setup.account_a)
    if not result.available:
        return None, result.note
    if not result.references:
        return None, (
            "Walked the app as account A but found no id-shaped value in its traffic — "
            "supply one record id to make the targeted probe possible."
        )

    tables = result.tables
    for ref in result.references:
        table = _table_for(ref, tables)
        if table:
            return (
                SeedRecord(table=table, id=ref.value, id_column=_id_column(ref)),
                f"Seed discovered by walking as account {setup.account_a.label}: "
                f"`{table}` record `{ref.value}` seen at {ref}.",
            )
    return None, (
        f"Found {len(result.references)} id-shaped value(s) as account "
        f"{setup.account_a.label} but could not tell which table any of them belongs to."
    )


def _table_for(ref: "ObjectReference", tables: list[str]) -> Optional[str]:
    """The table a reference addresses, when the request says so."""
    m = re.search(r"/rest/v1/([A-Za-z_][\w]*)", ref.request_url)
    if m and m.group(1) != "rpc":
        return m.group(1)
    for table in tables:
        if f"/{table}" in urlparse(ref.request_url).path:
            return table
    return None


def _id_column(ref: "ObjectReference") -> str:
    """The column an id-shaped query parameter refers to."""
    if ref.where == "query" and ref.name:
        return ref.name
    return "id"


def _sign_in(page, account: Account, timeout_ms: int) -> None:
    """Best-effort login through the app's own form.

    Deliberately best-effort: signing in through an unknown UI fails more often than it lands,
    which is exactly why the two logins are a form field rather than an autonomy claim. A failed
    sign-in leaves the walk unauthenticated, which is recorded and still informative.
    """
    if not account.email:
        return
    for email_sel in ('input[type="email"]', 'input[name="email"]', "#email"):
        if page.locator(email_sel).count():
            page.fill(email_sel, account.email)
            break
    else:
        return
    for pw_sel in ('input[type="password"]', 'input[name="password"]', "#password"):
        if page.locator(pw_sel).count():
            page.fill(pw_sel, account.password)
            break
    else:
        return
    for submit in ('button[type="submit"]', 'input[type="submit"]', "button:has-text('Sign in')"):
        if page.locator(submit).count():
            page.click(submit)
            page.wait_for_load_state("networkidle", timeout=timeout_ms)
            return


def _walk_app(page, base: str, result: DiscoveryResult, max_pages: int, timeout_ms: int) -> None:
    """Follow same-origin links breadth-first, capturing what each page fetches."""
    seen: set[str] = set()
    queue: list[str] = [base]
    host = urlparse(base).netloc

    while queue and len(seen) < max_pages:
        url = queue.pop(0)
        if url in seen:
            continue
        seen.add(url)
        try:
            page.goto(url, timeout=timeout_ms, wait_until="networkidle")
        except Exception:
            continue
        result.visited.append(url)
        try:
            hrefs = page.eval_on_selector_all(
                "a[href]", "els => els.map(e => e.href)"
            )
        except Exception:
            hrefs = []
        for href in hrefs:
            parsed = urlparse(href)
            if parsed.netloc == host and href not in seen and len(queue) < max_pages * 2:
                queue.append(href.split("#")[0])
