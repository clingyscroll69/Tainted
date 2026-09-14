# Publishing the four surfaces

Each surface is a different **kind** of artifact, so each has a different publish. They share
one version (`tainted/__init__.py`) and one tag, and `.github/workflows/release.yml` does all
four from that tag. This document is what that workflow does, in the order it does it, plus the
one-time setup each surface needs before the first release.

| Surface | Artifact | Consumer writes | Published by |
|---|---|---|---|
| **CLI** | wheels (`tainted` + `tainted-cli`) | `pip install …` | GitHub Release assets |
| **CI** | a GitHub Action at this repo's root | `uses: OWNER/tainted@v0` | the git tag + Release |
| **MCP** | wheels (`tainted` + `tainted-mcp`) | `"command": "tainted-mcp"` | GitHub Release assets |
| **Website** | a container image | `docker run ghcr.io/OWNER/tainted-web` | GHCR |

Everywhere below, **`OWNER`** is your GitHub user or org and **`X.Y.Z`** the version.

---

## 0. Once, before the first release

```bash
git remote add origin git@github.com:OWNER/tainted.git   # this repo has no remote yet
git push -u origin main
```

Then in **Settings → Actions → General**, set workflow permissions to **Read and write**, so
the release job can create the Release and push the moving major tag.

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

The engine is **not on PyPI** (it is proprietary), so the CLI is not installed by name from
there either. Both wheels ship together on the Release, and a consumer installs both URLs:

```bash
python -m build --outdir dist .                 # tainted
python -m build --outdir dist surfaces/cli      # tainted-cli
gh release upload vX.Y.Z dist/tainted-X.Y.Z-py3-none-any.whl \
                         dist/tainted_cli-X.Y.Z-py3-none-any.whl
```

What you tell a user:

```bash
B=https://github.com/OWNER/tainted/releases/download/vX.Y.Z
pip install "$B/tainted-X.Y.Z-py3-none-any.whl" "$B/tainted_cli-X.Y.Z-py3-none-any.whl"
tainted analyze ./my-app
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

To publish on PyPI instead, the core has to go there too (`twine upload dist/*` for both, core
first) and `surfaces/cli/pyproject.toml` gains `tainted==X.Y.Z` as a real dependency. Nothing
else about the package changes.

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

Same two-wheel shape as the CLI:

```bash
python -m build --outdir dist . && python -m build --outdir dist surfaces/mcp
gh release upload vX.Y.Z dist/tainted-X.Y.Z-py3-none-any.whl \
                         dist/tainted_mcp-X.Y.Z-py3-none-any.whl
```

What a user puts in their client config, after installing both wheels:

```json
{ "mcpServers": { "tainted": { "command": "tainted-mcp" } } }
```

`tainted-mcp` is a stdio server, so "publishing" it is only ever distributing the package —
there is no service to run. If you host it over SSE or streamable-HTTP instead, it becomes the
website's problem shape: a long-lived process, and the job table's ceiling
(`TAINTED_MCP_MAX_JOBS`, `TAINTED_MCP_JOB_TTL_S`) starts mattering.

## 5. Website — a container image

```bash
docker build -f surfaces/website/Dockerfile -t ghcr.io/OWNER/tainted-web:X.Y.Z .  # context = root
echo "$GITHUB_TOKEN" | docker login ghcr.io -u OWNER --password-stdin
docker push ghcr.io/OWNER/tainted-web:X.Y.Z
```

Then run it somewhere that gives it a **long-lived container** — not a serverless function.
`prove` holds a worker thread for up to `TAINTED_PROVE_TIMEOUT_S` (900 s) and a fetched repo may
expand to `TAINTED_MAX_EXTRACTED_MB` (1024) of writable temp space. Fly.io, Railway, Render,
Cloud Run with a long request timeout, or plain Docker on a VM all work.

```bash
docker run -p 8000:8000 \
  -e TAINTED_TOKEN_SECRET="$(python -c 'import secrets;print(secrets.token_urlsafe(48))')" \
  -e GITHUB_CLIENT_ID=... -e GITHUB_CLIENT_SECRET=... \
  -e GITHUB_OAUTH_REDIRECT=https://your-host/api/auth/github/callback \
  -e FORWARDED_ALLOW_IPS=... \
  ghcr.io/OWNER/tainted-web:X.Y.Z
```

Four things about that command are the difference between a demo and a deployment:

* **`TAINTED_TOKEN_SECRET` is not optional and must not change.** There is no session table:
  sign-in sessions are sealed into the cookie and ownership tokens are signed, both with keys
  derived from this one value. The same value on every instance, stable across deploys — change
  it and everyone is signed out and every published ownership token stops verifying. Without
  it the deployment fails closed and says so on `/api/auth/status`.
* **`GITHUB_OAUTH_REDIRECT` is required behind a proxy**, which is every hosted deployment.
  Derived from the request, the callback URL is the proxy's, not the one registered with
  GitHub, and sign-in fails with an opaque error.
* **The image sets `TAINTED_REQUIRE_SANDBOX=1`, and `prove` will be refused until you stand up
  the sandbox.** That is deliberate: `prove` runs untrusted, network-active exploits, and
  `backend/sandbox.py` holds the client for a Cloudflare Browser Rendering / Containers worker
  **that is not in this repository** — you write the service, set `TAINTED_SANDBOX_URL` and
  `TAINTED_SANDBOX_TOKEN`, and the refusal lifts. The bundled `demo/demo` run contacts nothing
  and works either way, so the container demonstrates the whole loop out of the box. If you
  accept in-process execution on your own metal, set `TAINTED_REQUIRE_SANDBOX=0` — say it out
  loud rather than discovering it.
* **`FORWARDED_ALLOW_IPS`** must name your proxy (or `*` only when nothing else can reach the
  port), or uvicorn ignores `X-Forwarded-*` and the app builds http URLs behind your https.

The image also runs as an unprivileged user, ships the Chromium `prove` drives, enforces the
CSP rather than only reporting it, and has a `HEALTHCHECK` on `/healthz`. `.env.example`
documents every remaining variable.

---

## What a publish does not fix

Two limits are worth stating to whoever deploys this, because no amount of configuration closes
them:

* **The prove sandbox has no server side in this repository.** See section 5.
* **A sealed session cannot be revoked.** Logout deletes the cookie; a copy taken beforehand
  stays valid until the 8-hour expiry. That is the trade that makes a stateless deployment
  possible, and `backend/session_token.py` argues it out in full.
