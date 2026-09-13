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

From a repo that has the core (`tainted/`, root `pyproject.toml`) plus this folder:

```bash
pip install -e ".[dynamic]"          # core engine (+ the Playwright extra, for prove)
pip install -e surfaces/website       # this surface
export GEMINI_API_KEY=...              # optional
tainted-web                            # serves http://127.0.0.1:8000
```

Or containerized (build context = repo root):

```bash
docker build -f surfaces/website/Dockerfile -t tainted-web .
docker run -p 8000:8000 -e GEMINI_API_KEY=$GEMINI_API_KEY tainted-web
```

## Sign in with GitHub

Instead of typing a filesystem path, a visitor can **sign in with GitHub** and pick a
repo they actually have access to, private repos included. This adds a check a public
link can't: the backend only ever fetches a repo the caller's own token can
see. A selected repo is pulled server-side through the GitHub **tarball API** (no
`git`, no lasting clone) into a temp directory for the length of one request, then
deleted. The OAuth token rides in an http-only cookie **sealed** with a key only this
deployment holds — the browser cannot read it, and nothing is written to disk. The local
path still works too, as a dev fallback.

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
# optional: export GITHUB_SCOPES="repo read:user"  (default; drop `repo` for public-only)
tainted-web
```

Without the OAuth variables set, sign-in is turned off and the button says so. The
local-path demo still runs.

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

- `GET  /api/auth/status` — `{configured, authenticated, login}` for the frontend
- `GET  /api/auth/github/login` — 302 to GitHub (503 if unconfigured)
- `GET  /api/auth/github/callback` — exchanges the code for a token, sets the
  session cookie, redirects to `/`
- `POST /api/auth/logout` — clears the session
- `GET  /api/repos` — repos the signed-in user can reach (401 without a session)
- `POST /api/analyze` — `{repo}` + `{ref?}` (GitHub) **or** `{repo_path}` (local)
  → report JSON
- `POST /api/prove` — the first-run form (same repo selectors) → report JSON
  (gated by an ownership check once the target isn't localhost)
- `POST /api/fix` — repo selector + `{index}` → a patch (edits) to download
- `GET  /healthz` — liveness, plus whether the LLM key is configured
