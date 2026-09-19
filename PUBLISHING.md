# Publishing the four surfaces

Each surface is a different **kind** of artifact, so each has a different publish. They share
one version (`tainted/__init__.py`) and one tag, and `.github/workflows/release.yml` does all
four from that tag. This document is what that workflow does, in the order it does it, plus the
one-time setup each surface needs before the first release.

| Surface | Artifact | Consumer writes | Published by |
|---|---|---|---|
| **CLI** | a PyPI package (`tainted-cli`) | `pip install tainted-cli` | PyPI, plus Release assets |
| **CI** | a GitHub Action at this repo's root | `uses: OWNER/tainted@v0` | the git tag + Release |
| **MCP** | a PyPI package (`tainted-mcp`) | `pip install tainted-mcp` | PyPI, plus Release assets |
| **Website** | a wheel | run on a host with Docker | GitHub Release |

The website is the one surface **not** on PyPI: nobody installs it by name. It is run by whoever
deploys it, from the Release wheel or a checkout, so a PyPI project for it would be a name to
maintain for an install path no one takes. It is also not a container image: a containerised
website would need the host's Docker socket mounted in so it could spawn sandbox siblings, and
socket access is root-equivalent — handed to the very process that runs strangers' generated
exploits. Running as a plain process that spawns sibling containers is strictly better.

Everywhere below, **`OWNER`** is your GitHub user or org and **`X.Y.Z`** the version.

---

## 0. Once, before the first release

```bash
git remote add origin git@github.com:OWNER/tainted.git   # this repo has no remote yet
git push -u origin main
```

Then in **Settings → Actions → General**, set workflow permissions to **Read and write**, so
the release job can create the Release and push the moving major tag.

### Claim the names on PyPI

The surfaces pin `tainted==X.Y.Z` exactly, so they are only installable if the engine is on PyPI
under that name. Four names are published — `tainted`, `tainted-cli`, `tainted-ci`,
`tainted-mcp` — and `tainted-website` is not, for the reason in the table above.

Claim `tainted-website` anyway if you want it reserved; a name you did not take is one someone
else can, and pip will happily install theirs. It is a defensive registration, not a
publication, and `release.yml` will never upload to it.

**Expect to be rate-limited.** PyPI throttles *new project creation* far more tightly than
ordinary uploads — creating four projects in one `twine upload` returns `429 Too Many Requests`
partway through. Uploads to projects that already exist are unaffected, so the way through is to
create them a few at a time and re-run with `--skip-existing`, which passes over whatever
already landed.

`release.yml` uploads with **trusted publishing**, so there is no API token to store anywhere. For
each of the four, on PyPI → *Your projects* → *Publishing* (or *Pending publishers* for a name
that has never been uploaded to), add a publisher with:

| Field | Value |
|---|---|
| Owner | `OWNER` |
| Repository | `tainted` |
| Workflow | `release.yml` |

A name whose publisher is missing fails the upload job and nothing reaches PyPI — which is the
right failure, since a half-published release is the one state pip cannot resolve.

Note that PyPI allows only one *pending* publisher per configuration, so several names cannot be
pre-registered against the same owner/repo/workflow at once. Publishing a project by hand once
turns its pending entry into an ordinary per-project publisher and frees the slot — which is why
the four above were bootstrapped with a manual `twine upload` rather than by tag.

## 1. Every release

```bash
# One number. Five manifests plus the engine; the test names any you miss.
$EDITOR tainted/__init__.py pyproject.toml surfaces/*/pyproject.toml
PYTHONPATH=. pytest tests/test_release_shape.py -q

git commit -am "Release vX.Y.Z"
git tag -a vX.Y.Z -m "vX.Y.Z" && git push origin main --tags
```

The tag starts `release.yml`, which refuses to publish anything if the tag and
`tainted/__init__.py` disagree, runs all four suites, then does sections 2–5 below. Everything
after this point is what to do when you want one surface published on its own, by hand.

---

## 2. CLI — a pip install and a pre-commit hook

`tainted-cli` depends on `tainted==X.Y.Z`, so a consumer names one package and pip fetches
both. To publish by hand — core first, always, or the surface is briefly unresolvable:

```bash
python -m build --outdir dist .                 # tainted
python -m build --outdir dist surfaces/cli      # tainted-cli
twine upload dist/tainted-X.Y.Z*                # the engine, alone and first
twine upload dist/tainted_cli-X.Y.Z*
gh release upload vX.Y.Z dist/*                 # the readable copy, not the install path
```

What you tell a user:

```bash
pip install tainted-cli
tainted analyze ./my-app
```

For `prove`, they also want the browser the engine's `dynamic` extra carries — a surface cannot
ask for an extra of its own dependency, so it stays a second command:

```bash
pip install "tainted[dynamic]" && playwright install chromium
```

**The pre-commit hook rides on the same tag.** `.pre-commit-hooks.yaml` is at the repository
root — the only place pre-commit reads it — and is a `language: system` hook, so it runs the
`tainted-gate` the user installed above. Nothing extra to publish; a consumer adds:

```yaml
-   repo: https://github.com/OWNER/tainted
    rev: vX.Y.Z
    hooks:
      - id: tainted
```

That pin is a fifth copy of the version number, alongside the four manifests.
`tests/test_release_shape.py` checks it with the rest, so a forgotten bump fails the release
rather than shipping a surface pinned to last month's engine.

## 3. CI — a GitHub Action

**The tag is the publication.** `uses: OWNER/tainted@vX.Y.Z` resolves to `action.yml` at this
repository's root at that tag; there is nothing to upload. Two things make it work, and both
are held by `tests/test_action_contract.py`:

* `action.yml` is at the **root**. GitHub looks nowhere else, and a Docker action's build
  context is the directory holding it — which is what `surfaces/ci/Dockerfile` needs, since it
  copies the engine from the repo root.
* the moving major tag. `release.yml` force-pushes `v0` at every release so a consumer pinned
  to `@v0` follows along; pinning `@vX.Y.Z` is the safer advice to give.

```bash
git tag -f v0 && git push -f origin refs/tags/v0
```

**Marketplace listing** (optional, one-time): open the release on GitHub → *Edit* → tick
**Publish this Action to the GitHub Marketplace**. It requires the root `action.yml`, a unique
`name:`, and `branding:` — all present.

**Pre-built image** (optional, recommended). As written, every consumer job builds the image
from source — a few minutes on each run. Push it once and point the action at it instead:

```bash
docker build -f surfaces/ci/Dockerfile -t ghcr.io/OWNER/tainted-ci:X.Y.Z .   # context = root
docker push ghcr.io/OWNER/tainted-ci:X.Y.Z
```

then in `action.yml`: `image: "docker://ghcr.io/OWNER/tainted-ci:X.Y.Z"`. Make the package
public, or consumers get an unauthenticated pull failure. Note that this pins the image to a
version by hand — which is the cost of the speed, and why it is not the default here.

## 4. MCP — a pip install and a client entry

Same shape as the CLI — core first:

```bash
python -m build --outdir dist . && python -m build --outdir dist surfaces/mcp
twine upload dist/tainted-X.Y.Z* && twine upload dist/tainted_mcp-X.Y.Z*
gh release upload vX.Y.Z dist/*
```

What a user puts in their client config, after `pip install tainted-mcp`:

```json
{ "mcpServers": { "tainted": { "command": "tainted-mcp" } } }
```

`tainted-mcp` is a stdio server, so "publishing" it is only ever distributing the package —
there is no service to run. If you host it over SSE or streamable-HTTP instead, it becomes the
website's problem shape: a long-lived process, and the job table's ceiling
(`TAINTED_MCP_MAX_JOBS`, `TAINTED_MCP_JOB_TTL_S`) starts mattering.

## 5. Website — a wheel

```bash
python -m build --wheel surfaces/website
```

Upload the wheel to the GitHub Release for the tag. Whoever deploys it installs it on a host
that has a working Docker daemon:

```bash
pip install tainted_web-X.Y.Z-py3-none-any.whl
TAINTED_TOKEN_SECRET="$(python -c 'import secrets;print(secrets.token_urlsafe(48))')" \
  GITHUB_CLIENT_ID=... GITHUB_CLIENT_SECRET=... \
  GITHUB_OAUTH_REDIRECT=https://your-host/api/auth/github/callback \
  FORWARDED_ALLOW_IPS=... \
  tainted-web
```

Run it somewhere that gives it a **long-lived process** — not a serverless function. `prove`
holds a worker thread for up to `TAINTED_PROVE_TIMEOUT_S` (900 s) and a fetched repo may expand
to `TAINTED_MAX_EXTRACTED_MB` (1024) of writable temp space. Fly.io, Railway, Render, or plain
Docker on a VM all work, as long as the host (or, for Docker-in-Docker setups, a Docker daemon
reachable from inside it) can run containers.

Four things about that command are the difference between a demo and a deployment:

* **`TAINTED_TOKEN_SECRET` is not optional and must not change.** There is no session table:
  sign-in sessions are sealed into the cookie and ownership tokens are signed, both with keys
  derived from this one value. The same value on every instance, stable across deploys — change
  it and everyone is signed out and every published ownership token stops verifying. Without
  it the deployment fails closed and says so on `/api/auth/status`.
* **`GITHUB_OAUTH_REDIRECT` is required behind a proxy**, which is every hosted deployment.
  Derived from the request, the callback URL is the proxy's, not the one registered with
  GitHub, and sign-in fails with an opaque error.
* **The host needs Docker, and `prove` is refused without it.** `tainted-web` defaults
  `TAINTED_REQUIRE_SANDBOX` to `1`, carried by `run.apply_deployment_defaults()` rather than by
  an image, so it holds however the server is started. Each `prove` run spawns one
  `ghcr.io/OWNER/tainted-sandbox:X.Y.Z` container, as a sibling of the server process — never a
  child, because that would need the root-equivalent Docker socket inside the very process that
  runs strangers' exploits. `DockerExecutor` only runs that image; it does not build or pull it,
  so pull it onto the host before the first `prove`:
  `docker pull ghcr.io/OWNER/tainted-sandbox:X.Y.Z`.
* **`FORWARDED_ALLOW_IPS`** must name your proxy (or `*` only when nothing else can reach the
  port), or uvicorn ignores `X-Forwarded-*` and the app builds http URLs behind your https.

`tainted-web` also defaults **`TAINTED_CSP_ENFORCE`** to `1`, so the Content-Security-Policy
blocks rather than only reporting; set it to `0` to watch before blocking. Like the sandbox
default it belongs to `run.apply_deployment_defaults()`, not to any image, so it survives
however you start the server. `.env.example` documents every remaining variable.

---

## What a publish does not fix

Two limits are worth stating to whoever deploys this, because no amount of configuration closes
them:

* **Docker is not a VM.** `prove` runs in a container that shares the host kernel. This is
  containment — filesystem and process isolation while parsing a stranger's repository and
  driving Chromium — not the isolation a managed sandbox on someone else's infrastructure would
  give. If this is ever deployed publicly, that limit is real and belongs in the reader's head.
* **A sealed session cannot be revoked.** Logout deletes the cookie; a copy taken beforehand
  stays valid until the 8-hour expiry. That is the trade that makes a stateless deployment
  possible, and `backend/session_token.py` argues it out in full.
