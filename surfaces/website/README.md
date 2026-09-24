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
that's reckless to run in-process. `backend/sandbox.py` is the seam: `default_executor()`
always returns `DockerExecutor`, which spawns one `tainted-sandbox` container per run, as a
sibling of the server process. There is no configuration that makes this deployment run
`prove` in-process instead — `TAINTED_REQUIRE_SANDBOX` only governs whether the app offers
`prove` at all when Docker turns out not to be available (see below), it does not select an
executor. `LocalExecutor` still exists in the engine, but only the sandbox container itself
runs it (that is what "in-process IS the containment" means once you're already inside).

**macOS: `prove` needs host networking.** The sandbox container reaches your app on
`localhost`, which on macOS crosses a VM boundary. Docker Desktop 4.34+ can do it (sign in, then
Settings → Resources → Network → *Enable host networking*, then restart) and so can OrbStack.
Colima and Podman cannot. Linux needs none of this.

## Where the loop stops short

`fix` produces a **downloadable patch**. The website has no working tree to write to,
so it can't apply the fix and re-check it the way the CLI and CI surfaces do. It
hands you the patch and you apply it yourself. An `agent_injection` fix is asked for twice:
the first answer is a few questions (which remedy fits depends on facts only the developer
holds), and the page sends the answers back for the patch.

It runs four of the five checks. `test_integrity` mutates the code and re-runs the repository's
own test suite, which is executing a stranger's code on this host, so the API has no way to ask
for it; only the demonstration shows that layer of the descent. Measure it with the CLI.

## Deploy

**This surface needs a long-lived process, not a serverless function.** A `prove` holds a
worker thread for up to `TAINTED_PROVE_TIMEOUT_S` (900 s by default) while it streams progress;
the concurrency ceiling is a per-process semaphore; and a fetched repository may expand to
`TAINTED_MAX_EXTRACTED_MB` (1024 by default) of writable temp space. Those three assumptions are
why it runs as a long-lived process on a host with Docker rather than as a function. On a
platform with a short function timeout or a small `/tmp`, `analyze` will work and `prove` will
not — lower the two limits and expect the rest to need re-architecting into a queued job.

**This surface is not on PyPI**, unlike the CLI and MCP ones, and it is not a container image
either. Nobody installs the website by name — it is run by whoever deploys it — so it ships as
a wheel on the GitHub Release, meant to run as a process on a host with a working Docker daemon
(`prove` spawns one sandbox container per run, as a sibling process — not a container image
itself, because that would need the host's Docker socket mounted into it, and socket access is
root-equivalent). Its wheel still pins the engine, so `tainted` comes with it:

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

`tainted-web` defaults **`TAINTED_REQUIRE_SANDBOX=1`** whichever way it is started, so a real
`prove` is refused unless the host has Docker: `DockerExecutor` runs one container per `prove`
from the sandbox image `ghcr.io/OWNER/tainted-sandbox:X.Y.Z`, pinned to `tainted.__version__`
(never `:latest`). It does not build or pull that image itself — `docker run` fails if the
image is not already present, so pull it onto the host before the first `prove`:

```bash
docker pull ghcr.io/OWNER/tainted-sandbox:X.Y.Z
```

The bundled demo contacts nothing and is exempt, so the whole loop still demonstrates without
Docker. There is no setting that accepts an in-process run instead: `TAINTED_REQUIRE_SANDBOX=0`
only turns off the pre-check that refuses `prove` with a 503 when Docker is missing — it never
makes `default_executor()` return anything but `DockerExecutor`. If Docker is not available on
this host, `prove` fails; the fix is to install Docker and pull the image, not to flip this
variable. That default lives in `backend/run.py`'s `apply_deployment_defaults()` rather than in
any image, so it holds however the server is started.

It defaults **`TAINTED_CSP_ENFORCE=1`** the same way and for the same reason, so the CSP blocks
rather than only reporting. The policy already allows `unsafe-inline` for the inline script and
style this page carries, so there is nothing for a watching period to find; `=0` asks for
report-only.

The sandbox image runs as an **unprivileged user** — `prove` executes untrusted, network-active
code, and as uid 0 a process escape and a container escape are the same event — and ships the
**Chromium** `prove` drives.

`PUBLISHING.md` §5 has the full deployment command, and what each variable costs to get wrong.

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
