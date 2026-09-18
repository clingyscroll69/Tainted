"""GitHub OAuth + repo access for the website surface.

This is how the website names code to analyse. There is no other way and no text field: a
visitor either runs the built-in demonstration, or signs in with GitHub and picks a repository
Tainted then *detects* on their behalf. Nobody types a repository name, so nobody can name one
they cannot read — the list comes from their own token, and the token is the authorization.
This lives in the website surface only — the CLI works a local tree, CI works its checkout, MCP
works the client's filesystem; only the hosted demo needs to prove the caller is allowed to see
the code it scans.

**How much access to ask for is the visitor's choice, made before the redirect.** Asking every
signer-in for `repo` — read *and write* on every private repository they can reach — to run a
read-only scan is more than the job needs, and it is the kind of consent screen people back out
of. So sign-in comes in two strengths:

* **public only** (`read:user`) — the default. The token cannot open a private repository at
  all; GitHub enforces that, not this code.
* **private included** (`repo`) — asked for only when the visitor says so, because it is the
  only scope GitHub offers that can read a private repository's tarball.

What lands in the session is what GitHub **granted**, read back off the token response, not
what we asked for. A visitor can narrow the grant on the consent screen and an org can narrow
it further, so the request is a wish and the response is the fact.

Two more deliberate choices keep this cheap and safe to run:

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

# The two strengths of sign-in, and the whole difference between them.
#
# `read:user` is what the page needs to say "signed in as <you>" and to list public
# repositories; it cannot open a private one. `repo` is the only scope GitHub has that can, and
# it is coarse — read *and* write, every private repository the account can reach, no way to
# ask for less. Tainted never writes (the website hands back a patch; it has no working tree),
# but it cannot ask for a token that only reads. So the honest thing is to make the visitor
# choose, default to the narrow one, and say plainly what the wide one carries.
PUBLIC_SCOPES = "read:user"
PRIVATE_SCOPES = "repo read:user"
DEFAULT_SCOPES = PUBLIC_SCOPES

# What a session records about its own reach. Derived from the *granted* scope, never from the
# one requested — see `access_for_scopes`.
ACCESS_PUBLIC = "public"
ACCESS_PRIVATE = "private"


def access_for_scopes(granted: str) -> str:
    """Which access level a granted scope string actually amounts to.

    GitHub returns the scopes it issued on the token response, comma-separated. A visitor can
    narrow the grant on the consent screen and an org can narrow it further, so this reads the
    answer rather than assuming the question was honoured. `repo` is the only scope that opens
    a private repository, so it is the only one that counts here.
    """
    scopes = {s.strip() for s in (granted or "").replace(" ", ",").split(",") if s.strip()}
    return ACCESS_PRIVATE if "repo" in scopes else ACCESS_PUBLIC


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
    # An operator override that pins the scope string for every sign-in, whatever the visitor
    # chose. Unset by default — and it has to be, because a default here would silently win
    # over the public/private choice and make the choice decorative. Set it only to *narrow*
    # what this deployment may ever ask for.
    scopes: Optional[str] = field(default_factory=lambda: _env("GITHUB_SCOPES"))
    # Set GITHUB_OAUTH_REDIRECT when the public callback URL differs from the request's own
    # base URL (behind a proxy / custom domain). Otherwise it is derived per-request.
    redirect_override: Optional[str] = field(default_factory=lambda: _env("GITHUB_OAUTH_REDIRECT"))

    @property
    def configured(self) -> bool:
        return bool(self.client_id and self.client_secret)

    def scopes_for(self, include_private: bool) -> str:
        """The scope string one sign-in should ask for."""
        if self.scopes:
            return self.scopes
        return PRIVATE_SCOPES if include_private else PUBLIC_SCOPES


def load_config() -> OAuthConfig:
    return OAuthConfig()


# --------------------------------------------------------------------------- #
# OAuth flow
# --------------------------------------------------------------------------- #
def authorize_url(
    cfg: OAuthConfig, state: str, redirect_uri: str, *, include_private: bool = False
) -> str:
    """Where to send a visitor to sign in. ``include_private`` picks which scope to ask for."""
    if not cfg.configured:
        raise GitHubNotConfigured(
            "GitHub OAuth is not configured. Set GITHUB_CLIENT_ID and GITHUB_CLIENT_SECRET."
        )
    query = urlencode(
        {
            "client_id": cfg.client_id,
            "redirect_uri": redirect_uri,
            "scope": cfg.scopes_for(include_private),
            "state": state,
            "allow_signup": "false",
        }
    )
    return f"{AUTHORIZE_URL}?{query}"


@dataclass(frozen=True)
class Grant:
    """A token and the scopes GitHub actually issued with it.

    The pair travels together because the scope is not a detail about the token, it *is* what
    the token can do — and it is the only trustworthy answer to "may this session see private
    repositories". Asking for `repo` and receiving `read:user` is a normal outcome (the visitor
    declined on the consent screen), and a session that recorded the request instead of the
    response would then offer a private repository it cannot fetch.
    """

    token: str
    scopes: str

    @property
    def access(self) -> str:
        return access_for_scopes(self.scopes)


def exchange_code(cfg: OAuthConfig, code: str, redirect_uri: str) -> Grant:
    """Trade the callback ``code`` for an access token and the scopes it carries."""
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
    # An empty `scope` is GitHub saying "no scopes", which is the narrow grant, not an unknown
    # one. Reading it as unknown and defaulting to private would hand the session a reach it
    # was never given.
    return Grant(token=token, scopes=str(data.get("scope") or ""))


def get_user(token: str) -> dict:
    try:
        r = httpx.get(f"{API}/user", headers=_auth_headers(token), timeout=15)
        r.raise_for_status()
        return r.json()
    except httpx.HTTPError as exc:  # pragma: no cover - network failure path
        raise GitHubError(f"could not read user: {exc}") from exc


def list_repos(token: str, *, include_private: bool = True, max_pages: int = 10) -> list[dict]:
    """Repos the user can reach (owned, collaborator, org member), most-recently-updated first.

    This *is* the repository picker: the website offers no way to name a repository by hand, so
    whatever comes back here is the entire set a visitor can choose from.

    ``include_private`` is belt and braces, and worth being clear about which half does the
    work. The real boundary is the token — a `read:user` token cannot read a private repository
    or its tarball, and GitHub is what enforces that. This parameter only makes the *list*
    agree with the grant, so a session that chose public-only is never shown a private
    repository it would then be refused when it picked one.
    """
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
                    "visibility": "all" if include_private else "public",
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
