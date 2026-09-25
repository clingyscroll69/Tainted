"""The running target and the first-run setup form.

Tainted never resurrects a repository — it points at the instance the owner already runs. The
first run is a short form by design: a URL, two logins, and one seed record id. Autonomy can
empty those fields when it can; they are the honest normal path, not a failure state.
"""

from __future__ import annotations

import base64
import ipaddress
import json
import socket
from typing import Callable, Optional
from urllib.parse import urlparse

from pydantic import BaseModel, Field


class Account(BaseModel):
    """One logged-in account. `access_token` is filled in by authentication if absent."""

    label: str  # "A" or "B"
    email: str = ""
    password: str = ""
    access_token: Optional[str] = None  # a pre-supplied JWT skips the login step
    # The account's own user id, recovered at authentication from the token's `sub` claim.
    # Row attribution depends on it: a row is only *someone else's* if we know who we are.
    user_id: Optional[str] = None

    @property
    def authenticated(self) -> bool:
        return bool(self.access_token)

    def resolve_user_id(self) -> Optional[str]:
        """Recover `user_id` from the JWT `sub` claim if it wasn't supplied."""
        if self.user_id:
            return self.user_id
        self.user_id = jwt_subject(self.access_token)
        return self.user_id


def jwt_subject(token: Optional[str]) -> Optional[str]:
    """Read the `sub` claim from a JWT **without verifying the signature**.

    The claim is only used to attribute rows to the account that fetched them ("is this row
    mine?"), never to make a trust decision, so an unverified read is appropriate here — the
    token came from our own authentication call in the first place.
    """
    if not token:
        return None
    parts = token.split(".")
    if len(parts) < 2:
        return None
    payload = parts[1]
    payload += "=" * (-len(payload) % 4)  # restore base64url padding
    try:
        claims = json.loads(base64.urlsafe_b64decode(payload.encode("ascii")))
    except Exception:
        return None
    sub = claims.get("sub")
    return str(sub) if sub else None


# --------------------------------------------------------------------------- #
# Where a target sits
#
# Two different questions get asked about a host, and conflating them is what made the
# ownership gate bypassable:
#
#   "is this my own machine?"      -> is_local.   Only a *locally run* Tainted may read this
#                                     as proof of ownership. On a hosted deployment the
#                                     caller is a stranger and this names the server's own
#                                     loopback, which is the opposite of the caller
#                                     controlling the machine.
#   "is this somewhere a public    -> is_internal / resolves_internal. Refused outright,
#    deployment must never fire       whatever the caller claims to own.
#    at?"
# --------------------------------------------------------------------------- #
_INTERNAL_SUFFIXES = (".local", ".localhost", ".internal", ".home.arpa")


def _as_ip(host: str):
    """The host as an IP address, or None if it is a name.

    Handles the shorthand forms a URL parser passes through untouched but
    `ipaddress.ip_address` rejects — `127.1`, `2130706433`, `0x7f000001` — because a host
    policy that only recognises dotted quads is a policy with a documented way around it.
    IPv4-mapped IPv6 (`::ffff:127.0.0.1`) is unwrapped for the same reason.
    """
    h = (host or "").strip("[]")
    if not h:
        return None
    ip = None
    try:
        ip = ipaddress.ip_address(h)
    except ValueError:
        try:
            ip = ipaddress.IPv4Address(socket.inet_aton(h))
        except (OSError, ipaddress.AddressValueError, UnicodeEncodeError):
            return None
    mapped = getattr(ip, "ipv4_mapped", None)
    return mapped or ip


def _ip_is_internal(ip) -> bool:
    return bool(
        ip is not None
        and (
            ip.is_loopback
            or ip.is_private
            or ip.is_link_local  # includes 169.254.169.254, the cloud metadata address
            or ip.is_reserved
            or ip.is_unspecified
            or ip.is_multicast
        )
    )


def _default_addr_resolver(host: str) -> list[str]:
    # `sockaddr[0]` is always the address string; the tuple's type is wider only because of
    # its later members (port, flow info, scope id).
    return [str(info[4][0]) for info in socket.getaddrinfo(host, None)]


class SeedRecord(BaseModel):
    """One record whose id is known — the target of the surgical BOLA probe.

    Owned by account A; the probe checks whether account B can read it.
    """

    table: str
    id: str
    id_column: str = "id"
    owner_column: Optional[str] = None  # e.g. "owner" / "user_id", when known
    # The app route this record is reachable through, when known (e.g. "/api/invoices/[id]").
    # Lets the positive control and the lockout check ask as A through the door B is tried at,
    # rather than through PostgREST alone, which proves less about the app's own route.
    route_path: Optional[str] = None


class Target(BaseModel):
    """The running app. For Supabase, `supabase_url` + `anon_key` reach PostgREST directly."""

    url: str  # the app's base URL (or the Supabase project URL)
    supabase_url: Optional[str] = None  # PostgREST/GoTrue base; defaults to `url`
    anon_key: Optional[str] = None  # the public anon key the browser uses

    @property
    def rest_base(self) -> str:
        return (self.supabase_url or self.url).rstrip("/")

    @property
    def host(self) -> str:
        """The target's hostname, lowercased. Empty when the URL names none."""
        return (urlparse(self.url).hostname or "").lower()

    @property
    def hosts(self) -> list[str]:
        """Every host this target can cause a request to reach.

        `url` is not the whole answer. Probes connect to `rest_base`, which is
        `supabase_url or url` — so a gate that judged `host` alone was judging one of the two
        places the engine actually goes. No surface sets `supabase_url` today, which is the
        only reason that was not a live bypass; this makes the gate cover the field rather
        than depend on nobody using it.
        """
        out = []
        for raw in (self.url, self.supabase_url):
            if not raw:
                continue
            h = (urlparse(raw).hostname or "").lower()
            if h and h not in out:
                out.append(h)
        return out

    @property
    def is_local(self) -> bool:
        """Whether the URL names the machine Tainted is running on.

        Reaching localhost implies control of the machine **only when Tainted is the thing
        running on it**. Callers must not read this as ownership on their own — pass it
        through `tainted.ownership.verify(trust_local=...)`, which a hosted surface sets to
        False. `.local` is kept here, as it always was, because a developer pointing the CLI
        at `myapp.local` is on their own network; a hosted deployment refuses it via
        `is_internal`.
        """
        h = self.host
        if not h:
            return False
        if h == "localhost" or h.endswith(".localhost") or h.endswith(".local"):
            return True
        ip = _as_ip(h)
        return bool(ip is not None and (ip.is_loopback or ip.is_unspecified))

    @property
    def is_internal(self) -> bool:
        """Whether this host is one a public deployment must never fire at.

        Loopback, the unspecified address, link-local (cloud metadata included), private
        ranges, reserved and multicast space, and the mDNS/internal name suffixes. This is
        the literal reading of the host; `resolves_internal` also checks where a name points.

        Judged over `hosts`, not `host`: one internal address among the places this target can
        send a request is enough to refuse the target.
        """
        names = self.hosts
        if not names:
            return True
        return any(self._name_is_internal(h) for h in names)

    @staticmethod
    def _name_is_internal(h: str) -> bool:
        if not h:
            return True
        if h == "localhost" or h.endswith(_INTERNAL_SUFFIXES):
            return True
        return _ip_is_internal(_as_ip(h))

    def resolves_internal(
        self, resolver: Optional[Callable[[str], list[str]]] = None
    ) -> bool:
        """`is_internal`, plus every address the name actually resolves to.

        A name that looks public can point at 127.0.0.1, so the literal check is not enough.
        `resolver(host) -> [ip strings]` is injectable so tests need no DNS. A lookup that
        fails or returns nothing counts as internal: a host that cannot be resolved cannot be
        shown to be safe, and this gate exists to refuse what it cannot vouch for.
        """
        if self.is_internal:
            return True
        for h in self.hosts:
            if _as_ip(h) is not None:
                continue  # a literal address, already judged above
            try:
                addrs = (resolver or _default_addr_resolver)(h)
            except Exception:  # noqa: BLE001 - resolver-agnostic; any failure is a refusal
                return True
            if not addrs:
                return True
            if any(_ip_is_internal(_as_ip(a)) for a in addrs):
                return True
        return False


class Tenant(BaseModel):
    """One tenant of a shared tool backend, as the backend knows them.

    `headers` carry the identity (usually `Authorization`). `url` overrides the backend's
    endpoint for this tenant alone: a stdio MCP server takes its identity from its process
    environment rather than a header, so reaching it as two tenants means two HTTP bridges,
    each started with one tenant's environment.
    """

    label: str
    headers: dict[str, str] = Field(default_factory=dict)
    url: Optional[str] = None


class ToolTenancy(BaseModel):
    """What proving `tool_tenancy` needs: a reachable tool backend and two of its tenants."""

    url: str  # the MCP endpoint (streamable HTTP), e.g. http://localhost:3000/api/mcp
    tenant_a: Tenant
    tenant_b: Tenant
    # One record of tenant A's. Without it, A is asked to list its own records, which a lookup
    # tool that requires an identifier cannot do.
    record_id: Optional[str] = None
    # The argument that carries the identifier. None reads it off the tool's input schema.
    id_arg: Optional[str] = None

    def endpoint(self, tenant: Tenant) -> str:
        return tenant.url or self.url

    @property
    def urls(self) -> list[str]:
        """Every endpoint a tenancy proof may send to."""
        out: list[str] = []
        for u in (self.url, self.tenant_a.url, self.tenant_b.url):
            if u and u not in out:
                out.append(u)
        return out


def parse_tenant(label: str, spec: str, url: Optional[str] = None) -> Tenant:
    """A tenant from a surface's text: `Name: value` headers, one per line, or a bare token.

    A bare token is sent as `Authorization: Bearer <token>`, the shape almost every HTTP MCP
    server authenticates with.
    """
    headers: dict[str, str] = {}
    for line in (spec or "").splitlines():
        line = line.strip()
        if not line:
            continue
        name, sep, value = line.partition(":")
        if sep and name.strip() and " " not in name.strip() and value.startswith(" "):
            headers[name.strip()] = value.strip()
        elif line.lower().startswith("bearer "):
            headers["Authorization"] = line
        else:
            headers["Authorization"] = f"Bearer {line}"
    return Tenant(label=label, headers=headers, url=url or None)


class ProveSetup(BaseModel):
    """Everything `prove` needs beyond the repository: two accounts and one seed record."""

    target: Target
    account_a: Account
    account_b: Account
    seed: Optional[SeedRecord] = None
    row_cap: int = 5  # unfiltered-RLS probe pulls a handful of rows, never a table
    # Two tenants of a shared tool backend, for `tool_tenancy`. None leaves it reported.
    tenancy: Optional[ToolTenancy] = None

    def model_post_init(self, __context) -> None:  # noqa: D401
        # Label the accounts defensively so downstream messages are unambiguous.
        self.account_a.label = self.account_a.label or "A"
        self.account_b.label = self.account_b.label or "B"
