# Containing `prove`: a Docker execution sandbox

- **Status**: DESIGN — approved in conversation 2026-09-19, not yet implemented
- **Supersedes**: the Cloudflare Browser Rendering / Containers worker promised by
  `surfaces/website/backend/sandbox.py`, `README.md`, `PUBLISHING.md` §5 and `.env.example`

## Problem

`prove` executes untrusted, network-active exploit code. Today three of the four surfaces run it
in-process with nothing between the payload and the machine:

| Surface | Call site | Containment today |
|---|---|---|
| CLI | `surfaces/cli/tainted_cli/main.py:106` | none — in-process |
| MCP | `surfaces/mcp/tainted_mcp/server.py:221` | none — in-process |
| CI | `surfaces/ci/tainted_ci/entrypoint.py:94` | **the GitHub Actions runner** — an ephemeral VM, destroyed after the job |
| Website | `surfaces/website/backend/app.py:669`, `:677` | none — so it refuses outright |

The website alone has an `Executor` seam, and it points at a Cloudflare worker that does not
exist and now never will.

### Why Cloudflare is closed

Cloudflare Containers has no free tier. The pricing table reads `Free | N/A | N/A`; the 25
GiB-hours / 375 vCPU-minutes / 200 GB-hours allowance is *included in* the $5/month Workers Paid
plan, not available without it. The Sandbox SDK is built on Containers, so it is closed for the
same reason. The project constraint is that no service may be paid for, so the entire
`CloudflareExecutor` path is unreachable by definition.

Alternatives considered and rejected:

- **GitHub Actions as a dispatched sandbox.** Free and genuinely disposable, but the Terms for
  Additional Products and Features state Actions "should not be used for any activity unrelated
  to the production, testing, deployment, or publication of the software project associated with
  the repository where GitHub Actions are used," naming account suspension as a consequence.
  Dispatching runs in one repo to scan another is squarely that. It remains legitimate for the CI
  surface, which runs inside the user's own repository — which is why CI already works and needs
  nothing from this design.
- **E2B / Daytona free credits** ($100 / $200, no card). Credits are not a free tier: they run
  out, and the sandbox then silently stops being available. Acceptable for a one-off validation,
  not a foundation.
- **In-process hardening** without a container. Does not contain network-active code, which is
  the entire point.

## Scope

CI is **out of scope** and unchanged: it runs in a disposable runner, against the repository it
lives in. That is already a free sandbox.

CLI, MCP and the website are in scope. CLI and MCP are internal-use tools pointed at
in-development instances, so **their targets are always localhost**; the website's targets are
always remote.

## Architecture

### Hoist the seam into the engine

`Executor` and `LocalExecutor` move from `surfaces/website/backend/sandbox.py` into a new engine
package `tainted/execution/`, so all three surfaces can depend on the protocol rather than on
`core_prove` directly.

The package is deliberately **not** called `sandbox`: `tainted/dynamic/sandbox.py` already owns
that word for the agent-plane logging-stub sandbox, which is a different concept (an equivalent
agent stood up from a manifest, not OS-level containment). Two things called "sandbox" in one
engine is how the next reader loses an hour.

### `DockerExecutor`

One container per run, nothing long-lived:

```
docker run --rm -i \
  --network <host|bridge> \
  -v <repo>:/repo:ro \
  --read-only \
  --cap-drop ALL \
  --security-opt no-new-privileges \
  --user <non-root> \
  tainted-sandbox
```

`ProveSetup` and the run options cross as JSON on **stdin**. Progress events and the final
`Report` come back as **NDJSON on stdout**, one object per line, discriminated by a `kind` field.

A fresh container per run means one run's leftovers are never visible to the next. This is why
the per-run subprocess model was chosen over a long-lived HTTP service that would have reused
`CloudflareExecutor`'s wire contract verbatim: reusing the contract would have preserved five
existing tests at the cost of the property the work exists to provide.

**`streams = True`.** Because the container writes events as it produces them, `DockerExecutor`
can report progress — which `CloudflareExecutor` explicitly could not (`streams = False`, one
request/response, observers accepted and ignored). The website's progress UI stops having to
degrade to "nothing is known yet." This is a straight improvement over the design being
replaced, not a compromise against it.

### The network split

The two cases have opposite network needs and never collide:

| | Target | Network | Consequence |
|---|---|---|---|
| CLI / MCP | always localhost | `--network=host` | `localhost` in the container **is** the host's localhost |
| Website | always remote (internal refused at `app.py:363`, `:605`) | default bridge | full network isolation |

Host networking for CLI/MCP is what keeps the rest of the design honest. Because no URL is
rewritten:

- `Target.url` stays `http://localhost:3000`, so `Target.is_local` (`tainted/dynamic/target.py:176`)
  is **genuinely** true and the ownership gate at `tainted/orchestrator.py:173` passes on the
  facts rather than on an asserted boolean;
- findings name the real target instead of `host.docker.internal`.

The rejected alternative was bridge networking plus `--add-host=host.docker.internal:host-gateway`
and a URL rewrite. It fails on a trap worth recording: `host.docker.internal` ends in `.internal`,
which is in `_INTERNAL_SUFFIXES` (`target.py:80`), so the rewritten target reads as
`is_local == False` and `is_internal == True`. The run would only survive by passing
`ownership_verified=True` — replacing a derived safety property with an asserted one — and the
rewritten host would leak into the evidence. A third option, mapping `localhost` at the resolver
level inside both httpx and Chromium (`--host-resolver-rules`), keeps the URL honest but must
patch two subsystems, and any outbound path missed by the mapping (for example `Target.rest_base`
reaching PostgREST) fails silently.

What host networking gives up is network isolation between the container and a host the payloads
are deliberately aimed at anyway. Filesystem and process isolation — the parts that protect the
machine while parsing a stranger's repository and driving Chromium — are untouched.

**Accepted cost:** on macOS, host networking is opt-in. It requires Docker Desktop 4.34 or later,
a signed-in Docker account, and Settings → Resources → Network → *Enable host networking*,
followed by a restart. Linux requires nothing. This is a documented one-time setup step, and
`DockerExecutor` must detect its absence and say so rather than producing an unreachable target.

### Widening the protocol

The current protocol carries only `(repo_path, setup, ownership_verified)`. The three surfaces do
not call `prove` the same way, so it must also carry:

- `autodiscover` — CLI (`main.py:86`, passed at `:111`)
- `only` / `skip` — CLI check overrides
- `replay`, and the committed probe plan plus its signature — MCP
- `on_candidates` / `on_finding` — website progress observers, now actually deliverable

#### The MCP guard crosses the boundary

MCP passes `prober=guarded_prober(setup, guard)` — an in-process closure whose
`guard.blocked_calls` is read after the run (`server.py:221-229`). A closure cannot cross a
container boundary, so the guard moves **inside**: the plan and its signature cross as JSON,
`guarded_replay` and `guarded_prober` are constructed in the container, and `blocked_calls`
returns in the result payload.

This is an improvement rather than a workaround — the plan is re-verified across a process and
container boundary instead of a thread boundary.

`PlanViolation` must survive the trip as a **distinct outcome**, not an exception. The container
emits a terminal event of kind `refused`, and `DockerExecutor` raises `PlanViolation` on the host
side, preserving the distinction `server.py:230-236` is careful about: a refusal is the guard
working, and must never be read as a crash and quietly retried.

### The image

A new `Dockerfile.sandbox` at the repository root: the engine, Semgrep, and Chromium, running as
a non-root user. The website image already proves this builds on arm64 and documents the two
traps — `pip install playwright` is not the browser (`playwright install --with-deps chromium` is
required), and `PLAYWRIGHT_BROWSERS_PATH` must land somewhere a non-root user can read.

## Degradation

When Docker is missing, its daemon is down, or host networking is unavailable on macOS, a surface
**refuses and says why**. It never falls back to running exploits in-process.

This matches the argument already made in `sandbox.py`: what must never happen is a silent
fallback that runs exploits locally while the caller believes the run was contained. The refusal
names the missing piece — daemon, image, or the macOS host-networking toggle — so it is
actionable rather than merely negative. Semgrep's optional-dependency handling is the model:
absence degrades legibly.

`TAINTED_REQUIRE_SANDBOX` keeps its name and meaning; it now means "require Docker."

## Per-surface changes

**CLI** — route `prove` through `DockerExecutor`. Remove the `--ownership-token` option
(`main.py:83`) and the non-local branch at `main.py:100-104`: under localhost-only they are dead.
The gate becomes "local, or refused, with a reason."

**MCP** — route `_run_prove` through `DockerExecutor`. Remove the `ownership_token` parameter from
`tainted_prove_start` (`server.py:155`) and the token branch at `server.py:160-165`, same
reasoning. The guard moves into the container as above.

**Website** — `default_executor()` returns `DockerExecutor` in bridge mode. The progress path at
`app.py:667-671` now receives real events, because `streams` is finally true.

**Engine** — `tainted.ownership` stays. CI (OIDC) and the website still verify ownership; only the
CLI and MCP flags go.

## Deletions

`CloudflareExecutor`, `SandboxUnavailable`'s Cloudflare-specific messages, and the five tests in
`surfaces/website/tests/test_sandbox_and_frontend.py:36-110` are removed. Keeping a configured
path that requires a paid plan would leave a live-looking option nobody can take.

The properties those tests pinned are re-pinned against `DockerExecutor`, including the most
important one: `test_unreachable_sandbox_raises_rather_than_running_locally`.

Documentation stops promising Cloudflare: the `sandbox.py` module docstring, `README.md`,
`surfaces/website/README.md` (Execution sandbox and Deploy sections), `PUBLISHING.md` §5 and its
"What a publish does not fix" entry, and `.env.example:64-79`. `TAINTED_SANDBOX_URL` and
`TAINTED_SANDBOX_TOKEN` are removed.

## Testing

Hermetic throughout, consistent with the existing suite — the Docker invocation is injectable, so
no test shells out to a real daemon.

Named tests, each pinning a decision made above:

1. A missing Docker daemon refuses and names Docker — it never runs in-process.
2. CLI and MCP build the run with `--network=host`; the website builds it with bridge.
3. The target URL crossing into the container is unmodified — `localhost` stays `localhost`.
   This is the regression guard for the `.internal` trap.
4. A non-local target is refused by CLI and by MCP, with no ownership-token path to reach.
5. A `PlanViolation` inside the container returns as `refused`, distinct from `error`.
6. `blocked_calls` survives the boundary and reaches `tainted_prove_status`.
7. `DockerExecutor.streams` is `True`, and `on_candidates` / `on_finding` fire in order.
8. The repo is mounted read-only.
9. A malformed line on stdout fails loudly rather than being parsed as a partial `Report`.

## Known limits, stated rather than papered over

- **Docker is not a VM.** The container shares the host kernel. This is containment, not the
  isolation the replaced Cloudflare docstring claimed, and the documentation must say so.
- **CLI/MCP give up network isolation** by design, per the split above.
- **The website's guarantee is weaker than the architecture originally argued for.** A public
  deployment scanning strangers' repositories on Docker-on-your-own-host is a real reduction from
  a managed sandbox on someone else's infrastructure. If the website is ever deployed publicly,
  this limit belongs in `PUBLISHING.md` in plain words.
- **macOS requires a manual one-time toggle** for CLI/MCP, which cannot be automated.
