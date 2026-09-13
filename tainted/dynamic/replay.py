"""httpx replay against Supabase — authentication and PostgREST queries.

Kept transport-injectable so the probe logic can be exercised against a mock in tests without a
live server. Against a real target these hit GoTrue (`/auth/v1/token`) and PostgREST (`/rest/v1`).
"""

from __future__ import annotations

from typing import Any, Optional

import httpx

from tainted.dynamic.target import Account, Target


class SupabaseReplay:
    """A thin PostgREST/GoTrue client bound to one target."""

    def __init__(self, target: Target, client: Optional[httpx.Client] = None):
        self.target = target
        self._client = client or httpx.Client(timeout=20.0)

    # ------------------------------------------------------------------ #
    # Authentication
    # ------------------------------------------------------------------ #
    def authenticate(self, account: Account) -> Account:
        """Fill `account.access_token` via GoTrue password grant, if not already supplied.

        Also records the account's own user id — from GoTrue's `user.id`, falling back to the
        token's `sub` claim. Row attribution depends on it: the unfiltered probe can only call a
        row *someone else's* if it knows whose the caller is.
        """
        if account.authenticated:
            account.resolve_user_id()
            return account
        url = f"{self.target.rest_base}/auth/v1/token"
        resp = self._client.post(
            url,
            params={"grant_type": "password"},
            headers=self._anon_headers(),
            json={"email": account.email, "password": account.password},
        )
        resp.raise_for_status()
        body = resp.json()
        account.access_token = body.get("access_token")
        if not account.access_token:
            raise RuntimeError(f"No access_token returned for account {account.label}")
        user = body.get("user")
        if isinstance(user, dict) and user.get("id"):
            account.user_id = str(user["id"])
        else:
            account.resolve_user_id()
        return account

    # ------------------------------------------------------------------ #
    # PostgREST reads
    # ------------------------------------------------------------------ #
    def select_by_id(
        self, account: Account, table: str, record_id: str, id_column: str = "id"
    ) -> httpx.Response:
        """As `account`, request one row by id — the surgical BOLA probe."""
        return self._client.get(
            f"{self.target.rest_base}/rest/v1/{table}",
            params={id_column: f"eq.{record_id}", "select": "*"},
            headers=self._auth_headers(account),
        )

    def select_unfiltered(
        self, account: Account, table: str, limit: int
    ) -> httpx.Response:
        """As `account`, request rows with no ownership filter, row-capped — the RLS probe."""
        return self._client.get(
            f"{self.target.rest_base}/rest/v1/{table}",
            params={"select": "*", "limit": str(limit)},
            headers=self._auth_headers(account),
        )

    # ------------------------------------------------------------------ #
    # Headers
    # ------------------------------------------------------------------ #
    def _anon_headers(self) -> dict[str, str]:
        headers = {"Content-Type": "application/json"}
        if self.target.anon_key:
            headers["apikey"] = self.target.anon_key
        return headers

    def _auth_headers(self, account: Account) -> dict[str, str]:
        headers = self._anon_headers()
        if account.access_token:
            headers["Authorization"] = f"Bearer {account.access_token}"
        return headers

    @staticmethod
    def rows(resp: httpx.Response) -> list[dict[str, Any]]:
        """PostgREST returns a JSON array; normalize to a list of dicts (empty on non-JSON)."""
        try:
            body = resp.json()
        except Exception:
            return []
        if isinstance(body, list):
            return [r for r in body if isinstance(r, dict)]
        if isinstance(body, dict):
            return [body]
        return []

    def close(self) -> None:
        self._client.close()
