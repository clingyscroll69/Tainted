"""GitHub OAuth + repo access for the website surface.

Turns the demo's repo input from a local path into a *verified* GitHub identity: sign in with
GitHub, pick a repo you actually have access to (private included), and Tainted fetches that repo
server-side to analyze. This lives in the website surface only — the CLI works a local tree, CI
works its checkout, MCP works the client's filesystem; only the hosted demo needs to prove the
caller is allowed to see the code it scans.

Two deliberate choices keep this cheap and safe to run:

* **No git binary, no persistent clone.** A selected repo is fetched via the GitHub tarball API
  with the user's token and extracted into a temp dir for the life of one request, then removed.
* **The token never reaches the browser in the clear.** It rides in a sealed, http-only
  cookie (see `session_token`) that only this deployment's key can open; nothing is written
  to disk and no git remote embeds it.
"""

from __future__ import annotations

import os
import shutil
import tarfile
import tempfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional
from urllib.parse import urlencode

import httpx

AUTHORIZE_URL = "https://github.com/login/oauth/authorize"
TOKEN_URL = "https://github.com/login/oauth/access_token"
API = "https://api.github.com"
DEFAULT_SCOPES = "repo read:user"


class GitHubNotConfigured(RuntimeError):
    """Raised when an OAuth flow is attempted without client id/secret configured."""


class GitHubError(RuntimeError):
    """A GitHub API / OAuth call failed."""


def _env(name: str) -> Optional[str]:
    v = os.environ.get(name)
    return v.strip() if v and v.strip() else None


def _auth_headers(token: str) -> dict:
    return {
        "Authorization": f"Bearer {token}",
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
    }


# --------------------------------------------------------------------------- #
# Configuration
# --------------------------------------------------------------------------- #
@dataclass
class OAuthConfig:
    client_id: Optional[str] = field(default_factory=lambda: _env("GITHUB_CLIENT_ID"))
    client_secret: Optional[str] = field(default_factory=lambda: _env("GITHUB_CLIENT_SECRET"))
    scopes: str = field(default_factory=lambda: _env("GITHUB_SCOPES") or DEFAULT_SCOPES)
    # Set GITHUB_OAUTH_REDIRECT when the public callback URL differs from the request's own
    # base URL (behind a proxy / custom domain). Otherwise it is derived per-request.
    redirect_override: Optional[str] = field(default_factory=lambda: _env("GITHUB_OAUTH_REDIRECT"))

    @property
    def configured(self) -> bool:
        return bool(self.client_id and self.client_secret)


def load_config() -> OAuthConfig:
    return OAuthConfig()


# --------------------------------------------------------------------------- #
# OAuth flow
# --------------------------------------------------------------------------- #
def authorize_url(cfg: OAuthConfig, state: str, redirect_uri: str) -> str:
    if not cfg.configured:
        raise GitHubNotConfigured(
            "GitHub OAuth is not configured. Set GITHUB_CLIENT_ID and GITHUB_CLIENT_SECRET."
        )
    query = urlencode(
        {
            "client_id": cfg.client_id,
            "redirect_uri": redirect_uri,
            "scope": cfg.scopes,
            "state": state,
            "allow_signup": "false",
        }
    )
    return f"{AUTHORIZE_URL}?{query}"


def exchange_code(cfg: OAuthConfig, code: str, redirect_uri: str) -> str:
    """Trade the callback ``code`` for an access token."""
    if not cfg.configured:
        raise GitHubNotConfigured("GitHub OAuth is not configured.")
    try:
        r = httpx.post(
            TOKEN_URL,
            data={
                "client_id": cfg.client_id,
                "client_secret": cfg.client_secret,
                "code": code,
                "redirect_uri": redirect_uri,
            },
            headers={"Accept": "application/json"},
            timeout=15,
        )
        r.raise_for_status()
        data = r.json()
    except httpx.HTTPError as exc:  # pragma: no cover - network failure path
        raise GitHubError(f"token exchange failed: {exc}") from exc
    token = data.get("access_token")
    if not token:
        raise GitHubError(data.get("error_description") or "no access_token in response")
    return token


def get_user(token: str) -> dict:
    try:
        r = httpx.get(f"{API}/user", headers=_auth_headers(token), timeout=15)
        r.raise_for_status()
        return r.json()
    except httpx.HTTPError as exc:  # pragma: no cover - network failure path
        raise GitHubError(f"could not read user: {exc}") from exc


def list_repos(token: str, *, max_pages: int = 10) -> list[dict]:
    """Repos the user can reach (owned, collaborator, org member), most-recently-updated first."""
    out: list[dict] = []
    page = 1
    while page <= max_pages:
        try:
            r = httpx.get(
                f"{API}/user/repos",
                headers=_auth_headers(token),
                params={
                    "per_page": 100,
                    "page": page,
                    "sort": "updated",
                    "affiliation": "owner,collaborator,organization_member",
                },
                timeout=20,
            )
            r.raise_for_status()
            batch = r.json()
        except httpx.HTTPError as exc:  # pragma: no cover - network failure path
            raise GitHubError(f"could not list repos: {exc}") from exc
        if not batch:
            break
        out.extend(batch)
        if len(batch) < 100:
            break
        page += 1
    return [
        {
            "full_name": x["full_name"],
            "private": x["private"],
            "default_branch": x.get("default_branch"),
            "updated_at": x.get("updated_at"),
            "html_url": x.get("html_url"),
        }
        for x in out
    ]


# --------------------------------------------------------------------------- #
# Fetching a repo to analyze
# --------------------------------------------------------------------------- #
# What one fetch is allowed to cost this machine. A repository is a stranger's, so its size
# is a stranger's choice; without a ceiling a large repo or a crafted archive fills the disk.
# The limits are generous — a monorepo fits — and refusing past them is a better failure than
# running out of space for everyone.
MAX_ARCHIVE_BYTES = int(os.environ.get("TAINTED_MAX_ARCHIVE_MB", "250")) * 1024 * 1024
MAX_EXTRACTED_BYTES = int(os.environ.get("TAINTED_MAX_EXTRACTED_MB", "1024")) * 1024 * 1024
MAX_ENTRIES = 200_000


@dataclass
class Checkout:
    """A temporary on-disk checkout. ``path`` is the source root; ``cleanup()`` removes it."""

    path: Path
    root: Path

    def cleanup(self) -> None:
        shutil.rmtree(self.root, ignore_errors=True)


def fetch_repo(token: str, full_name: str, ref: Optional[str] = None) -> Checkout:
    """Download ``full_name`` (optionally at ``ref``) as a tarball and extract it to a temp dir.

    Uses the authenticated tarball endpoint, so private repos the token can see are fetchable.
    Returns a :class:`Checkout`; the caller must ``cleanup()`` it.
    """
    ref_path = f"/{ref}" if ref else ""
    url = f"{API}/repos/{full_name}/tarball{ref_path}"
    root = Path(tempfile.mkdtemp(prefix="tainted-repo-"))
    archive = root / "repo.tar.gz"
    try:
        with httpx.stream(
            "GET", url, headers=_auth_headers(token), follow_redirects=True, timeout=60
        ) as r:
            r.raise_for_status()
            downloaded = 0
            with open(archive, "wb") as fh:
                for chunk in r.iter_bytes():
                    downloaded += len(chunk)
                    if downloaded > MAX_ARCHIVE_BYTES:
                        raise GitHubError(
                            f"{full_name} is larger than "
                            f"{MAX_ARCHIVE_BYTES // (1024 * 1024)} MB compressed; "
                            "Tainted stopped fetching it."
                        )
                    fh.write(chunk)
        with tarfile.open(archive, "r:gz") as tar:
            # filter="data" (py3.12+) blocks path-traversal / device / link escapes. The
            # counters are the other half: that filter says *where* a member may land, not
            # how much of it there is, so a small archive can still ask for an unbounded
            # amount of disk. Members are extracted one at a time so the running total can
            # refuse before the bytes are written rather than after.
            extracted = 0
            entries = 0
            for member in tar:
                entries += 1
                if entries > MAX_ENTRIES:
                    raise GitHubError(
                        f"{full_name} contains more than {MAX_ENTRIES} files; "
                        "Tainted stopped extracting it."
                    )
                extracted += max(getattr(member, "size", 0) or 0, 0)
                if extracted > MAX_EXTRACTED_BYTES:
                    raise GitHubError(
                        f"{full_name} expands to more than "
                        f"{MAX_EXTRACTED_BYTES // (1024 * 1024)} MB; "
                        "Tainted stopped extracting it."
                    )
                tar.extract(member, root, filter="data")
        archive.unlink(missing_ok=True)
    except GitHubError:
        shutil.rmtree(root, ignore_errors=True)
        raise
    except (httpx.HTTPError, tarfile.TarError, OSError) as exc:
        shutil.rmtree(root, ignore_errors=True)
        raise GitHubError(f"could not fetch {full_name}: {exc}") from exc

    # GitHub tarballs wrap everything in a single "<owner>-<repo>-<sha>/" directory.
    subdirs = [p for p in root.iterdir() if p.is_dir()]
    checkout = subdirs[0] if len(subdirs) == 1 else root
    return Checkout(path=checkout, root=root)
