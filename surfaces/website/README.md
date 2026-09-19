# Tainted website

The demonstration front end. A FastAPI backend wraps the engine — you give it a
repo for `analyze`, and a first-run form for `prove` — and the frontend draws the
findings and the agent's tool graph (with cytoscape), with any scope Tainted
proved exploitable lit up red.

Where you see the whole result at once: account B, live, holding account A's
rows, with the request that did it printed underneath.

## The tour

**Take the tour** in the header walks a first-time visitor through the page in the order it
should be read: the demonstration first, then a real repo, then what each proof strength
means, then the ownership check, then arming. It moves one spotlight and one card over the
real page rather than replacing it with slides, so each step lands on the control it
describes. The content is `frontend/tutorial.js`; if that file is missing the button stays
hidden and nothing else on the page notices.

## Execution sandbox

`prove` runs untrusted, network-active exploits — the one part of this surface
that's reckless to run on your own machine. `backend/sandbox.py` is the seam:
`LocalExecutor` runs in-process (for dev and demos), and `CloudflareExecutor` is where
production sends the run into Cloudflare Browser Rendering / Containers instead. The
backend only depends on the `Executor` protocol, so swapping one for the other is a
one-line change.

## Where the loop stops short

`fix` produces a **downloadable patch**. The website has no working tree to write to,
so it can't apply the fix and re-check it the way the CLI and CI surfaces do. It
hands you the patch and you apply it yourself.

## Deploy

**This surface needs a long-lived container, not a serverless function.** A `prove` holds a
worker thread for up to `TAINTED_PROVE_TIMEOUT_S` (900 s by default) while it streams progress;
the concurrency ceiling is a per-process semaphore; and a fetched repository may expand to
`TAINTED_MAX_EXTRACTED_MB` (1024 by default) of writable temp space. Those three assumptions
are what the Dockerfile below is for. On a platform with a short function timeout or a small
`/tmp`, `analyze` will work and `prove` will not — lower the two limits and expect the rest to
need re-architecting into a queued job.

**This surface is not on PyPI**, unlike the CLI and MCP ones. Nobody installs the website by
name — it is run by whoever deploys it — so it ships as a wheel on the GitHub Release and as the
container image below. Its wheel still pins the engine, so `tainted` comes with it:

```bash
pip install https://github.com/OWNER/tainted/releases/download/vX.Y.Z/tainted_website-X.Y.Z-py3-none-any.whl \
            "tainted[dynamic]"                   # + the browser prove drives
export GEMINI_API_KEY=...                        # optional
tainted-web                                      # serves http://127.0.0.1:8000
```

From a checkout instead:

```bash
pip install -e ".[dynamic]"          # core engine (+ the Playwright extra, for prove)
pip install -e surfaces/website       # this surface
```

Or containerized (build context = repo root):

```bash
docker build -f surfaces/website/Dockerfile -t tainted-web .
docker run -p 8000:8000 -e GEMINI_API_KEY=$GEMINI_API_KEY tainted-web
```

`tainted-web` defaults **`TAINTED_REQUIRE_SANDBOX=1`** whichever way it is started, so a real
`prove` is refused until `TAINTED_SANDBOX_URL` / `TAINTED_SANDBOX_TOKEN` point at a sandbox.
**The worker they point at is not in this repository** — `backend/sandbox.py` is the client for
it. The bundled demo contacts nothing and is exempt, so the whole loop still demonstrates
untouched. To accept in-process execution on your own metal, set `TAINTED_REQUIRE_SANDBOX=0` and
say so out loud. That default lives in `backend/run.py` rather than in the image on purpose: as
a property of the image it would have been deleted along with it.

It defaults **`TAINTED_CSP_ENFORCE=1`** the same way and for the same reason, so the CSP blocks
rather than only reporting. The policy already allows `unsafe-inline` for the inline script and
style this page carries, so there is nothing for a watching period to find; `=0` asks for
report-only.

The image differs from the dev server on two further points, each a deployment decision rather
than a preference:

- it ships the **Chromium** `prove` drives, not only the Playwright client that drives it;
- it runs as an **unprivileged user** — `prove` executes untrusted, network-active code, and as
  uid 0 a process escape and a container escape are the same event.

`PUBLISHING.md` §5 has the full `docker run`, and what each variable costs to get wrong.

## Two ways to name code, and no third

The page offers the **demonstration** and a **repository picked from GitHub**. There is no
field for typing a repository name or a filesystem path, deliberately: a name you type is a
name you may not be able to read, and the picker cannot produce one GitHub did not just hand
us. The token is the authorization rather than the honour system.

So a visitor **signs in with GitHub**, and Tainted lists the repositories their own token can
reach. A selected repo is pulled server-side through the GitHub **tarball API** (no `git`, no
lasting clone) into a temp directory for the length of one request, then deleted. The OAuth
token rides in an http-only cookie **sealed** with a key only this deployment holds — the
browser cannot read it, and nothing is written to disk.

`repo_path` survives in the API as the local-mode entry point that `curl` and this surface's
test suite use. It is refused off a developer's own machine and no UI renders a control for
it.

### How much access to ask for

Sign-in comes in two strengths, and the visitor chooses **before** the redirect, because
after it there is only GitHub's consent screen:

| Choice | Scope | What it reaches |
| --- | --- | --- |
| **Public only** (default) | `read:user` | Public repositories. A private one cannot be listed *or* fetched — GitHub enforces that, not this code. |
| **Public and private** | `repo` | Everything the account can reach. `repo` is the only scope GitHub has that opens a private repository, and it is read **and** write. Tainted never writes: the fix comes back as a patch. |

What the session records is what GitHub **granted**, read off the token response — not what
was asked for. A visitor who declines private on the consent screen gets a public session and
the page says so, instead of offering a repository the token would be refused at.

One-time setup — register an [OAuth App](https://github.com/settings/developers)
(or an org one):

- **Authorization callback URL:** `http://127.0.0.1:8000/api/auth/github/callback`
  (match your host; behind a proxy, set `GITHUB_OAUTH_REDIRECT` to the public callback
  URL).
- Then run the server with:

```bash
export GITHUB_CLIENT_ID=...      # from the OAuth App
export GITHUB_CLIENT_SECRET=...
export TAINTED_TOKEN_SECRET=...  # long random string; required on any hosted deployment
# optional: export GITHUB_SCOPES="read:user"
#   Pins the scope for every sign-in, whatever the visitor chose. Unset by default — a
#   default here would win over the choice above and make it decorative. Set it only to
#   *narrow* what this deployment may ever ask for.
tainted-web
```

Without the OAuth variables set, sign-in is turned off and the page says so. The
demonstration still runs — and it is then the only thing that does.

### `TAINTED_TOKEN_SECRET`, and why it is not optional in production

There is no session table and no process memory to keep one in: a **serverless deployment
starts a fresh instance whenever it likes**, and the instance that handles the OAuth
callback is generally not the one the browser comes back to. So a session carries its own
authority — `backend/session_token.py` seals the GitHub token and login into the cookie
itself with AES-GCM, and any instance with the same key can open it. `TAINTED_TOKEN_SECRET`
is that key (and, separately derived, the ownership-token key too — one variable, two
unrelated keys, see `backend/keys.py`).

It must be **the same value on every instance**, and it must be **stable across deploys**, or
everyone is signed out and every published ownership token stops verifying. Generate one
with `python -c "import secrets; print(secrets.token_urlsafe(48))"`.

Set it, or the deployment fails closed: sign-in is reported as unconfigured, the button
stays hidden, and `/api/auth/status` says which variable is missing. Running locally with
`TAINTED_LOCAL_MODE=1` you can skip it — sessions then use a per-process key and end when
the server stops, which is fine on your own machine and is exactly the behaviour that broke
in production.

Logging out deletes the cookie. Because there is nothing stored server-side, it cannot
invalidate a copy taken beforehand; the session lifetime is 8 hours for that reason.

## API

- `GET  /api/auth/status` — `{configured, authenticated, login, access, local_paths}`
  for the frontend; `access` is `"public"` / `"private"` / `null`
- `GET  /api/auth/github/login?access=public|private` — 302 to GitHub, asking for that
  much (503 if unconfigured; anything but `private` means public)
- `GET  /api/auth/github/callback` — exchanges the code for a token, records the scopes
  GitHub granted, sets the session cookie, redirects to `/`
- `POST /api/auth/logout` — clears the session
- `GET  /api/repos` — `{repos, access}`: every repository the session may pick, scoped
  to what it was granted (401 without a session)
- `POST /api/analyze` — `{repo}` + `{ref?}` (GitHub) **or** `{repo_path}` (local mode
  only, no UI) → report JSON
- `POST /api/prove` — the first-run form (same repo selectors) → report JSON
  (gated by an ownership check once the target isn't localhost)
- `POST /api/fix` — repo selector + `{index}` → a patch (edits) to download
- `GET  /healthz` — liveness, plus whether the LLM key is configured
