# Containing `prove`: a Docker execution sandbox

- **Status**: IMPLEMENTED 2026-09-19. See `docs/superpowers/plans/2026-09-19-docker-prove-sandbox.md`.
  Three deviations from this design, each argued in that plan: the probe-plan key is per-run
  rather than per-process (a per-process key cannot verify across a container boundary),
  `guard.py` moved into the engine (the sandbox image does not install surface packages), and
  `only`/`skip` are analyze options rather than prove options.
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
  --tmpfs /tmp \
  --tmpfs /home/tainted \
  --shm-size=1g \
  --cap-drop ALL \
  --security-opt no-new-privileges \
  --user <non-root> \
  ghcr.io/<owner>/tainted-sandbox:<version>
```

`--read-only` makes the whole root filesystem read-only, and `prove` drives Chromium, which
needs a writable profile directory under the user's home, a writable `/tmp`, and more than the
64 MB Docker gives `/dev/shm` by default. Without the two `--tmpfs` mounts and `--shm-size`,
every `prove` that reaches Playwright dies at browser launch — quietly, since the httpx-only
probes still succeed and the run reports a subset of findings rather than an error.

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

### The macOS runtime requirement

On macOS Docker does not run natively; it runs a Linux VM. `--network=host` therefore normally
means *the VM's* host, not the Mac. Only runtimes that deliberately bridge that gap work:

| Runtime | Works | Notes |
|---|---|---|
| **Docker Desktop** 4.34+ | yes | Opt-in: signed-in Docker account, Settings → Resources → Network → *Enable host networking*, restart. Layer 4 only — fine for HTTP. |
| **OrbStack** | yes | Bidirectional `--net=host` with no toggle. Free for personal use, paid for commercial. |
| **Colima** | **no** | Host networking is unidirectional — a container cannot reach a server on the Mac's localhost. |
| **Podman on macOS** | **no** | Same VM boundary, no equivalent bridge. |

Linux requires none of this. Colima is a common free CLI-only choice, so `DockerExecutor` must
detect the unreachable-target case and name the runtime as the likely cause rather than reporting
a generic connection failure.

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
side, preserving the distinction `server.py:232-237` is careful about: a refusal is the guard
working, and must never be read as a crash and quietly retried.

## The sandbox image

A new `Dockerfile.sandbox`: the engine, Semgrep, and Chromium, running as a non-root user. The
existing website image already proves this builds on arm64 and documents the two traps —
`pip install playwright` is not the browser (`playwright install --with-deps chromium` is
required), and `PLAYWRIGHT_BROWSERS_PATH` must land somewhere a non-root user can read.

**One image serves all three surfaces**, published to GHCR as `tainted-sandbox`. This replaces
`tainted-web` in the release matrix rather than adding to it, so the number of images the project
ships stays at two.

**The image tag is pinned to `tainted.__init__.__version__`.** A host running engine `0.2.0`
against a sandbox image built from `0.1.0` would produce findings from a different analyser than
the one that ranked the candidates — a skew that would be near-impossible to diagnose from a
report. `DockerExecutor` names the exact tag it requires, never `:latest`, and fails with a
legible message when that tag is absent locally and cannot be pulled.

## Degradation

When Docker is missing, its daemon is down, the image is absent, or host networking is
unavailable, a surface **refuses and says why**. It never falls back to running exploits
in-process.

This matches the argument already made in `sandbox.py`: what must never happen is a silent
fallback that runs exploits locally while the caller believes the run was contained. The refusal
names the missing piece — daemon, image, version skew, or the macOS host-networking toggle — so
it is actionable rather than merely negative. Semgrep's optional-dependency handling is the
model: absence degrades legibly.

`TAINTED_REQUIRE_SANDBOX` keeps its name and meaning; it now means "require Docker."

**Accepted cost, stated plainly:** a macOS user of the CLI or MCP must install Docker Desktop or
OrbStack, and on Docker Desktop must additionally sign in and enable host networking, before
`prove` runs at all. This is a real onboarding tax on an internal-use tool, accepted deliberately
in favour of a guarantee that holds.

## Per-surface changes

**CLI** — route `prove` through `DockerExecutor`. Remove the `--ownership-token` option
(`main.py:83`) and the non-local branch at `main.py:100-104`: under localhost-only they are dead.
The gate becomes "local, or refused, with a reason."

**MCP** — route `_run_prove` through `DockerExecutor`. Remove the `ownership_token` parameter from
`tainted_prove_start` (`server.py:155`) and the token branch at `server.py:160-165`, same
reasoning. The guard moves into the container as above.

**Engine** — `tainted.ownership` stays. CI (OIDC) and the website still verify ownership; only the
CLI and MCP flags go.

### The website stops shipping as a container

A containerised website cannot safely spawn sandbox containers. Doing so requires mounting the
host's Docker socket into it, and socket access is root-equivalent on the host — granted to the
exact process that runs strangers' generated exploits. That is **strictly worse than the
in-process run it would replace**, so it is rejected outright and recorded here so it is not
re-proposed.

The website therefore ships as a **wheel**, run as the `tainted-web` process on a host that has
Docker, spawning sandbox containers as **siblings** rather than children.

Consequences, each of which is work:

- **`surfaces/website/Dockerfile` is deleted**, and the release matrix entry
  `website → tainted-web` is replaced by `sandbox → tainted-sandbox`
  (`.github/workflows/release.yml:100-127`).
- **`run.py` must set `TAINTED_REQUIRE_SANDBOX=1`** — *done ahead of the rest of this change.*
  The default used to live only in the Dockerfile (`surfaces/website/Dockerfile:45`), so deleting
  the image would have silently turned the website's fail-closed posture into a fail-open one.
  `run.apply_deployment_defaults()` now carries it, guarded by `tests/test_entrypoint_defaults.py`
  — which asserts against the entrypoint rather than the Dockerfile, so it does not get deleted by
  the commit that would cause the regression.
- `TAINTED_CSP_ENFORCE` moved to `run.apply_deployment_defaults()` alongside the sandbox
  default and is covered by the same tests — *done*. **Running as an unprivileged user is not**,
  and is the last image-only guarantee still needing a home in the entrypoint or the docs.
- `default_executor()` returns `DockerExecutor` in bridge mode.
- The progress path at `app.py:667-671` now receives real events, because `streams` is finally
  true.

The website **wheel** is unchanged in shape, and the sibling-directory packaging trap still
applies: `frontend*` in `packages.find`, `namespaces = true`, and `package-data`, or the server
ships without the page it serves.

## Deletions

`CloudflareExecutor`, `SandboxUnavailable`'s Cloudflare-specific messages, and the five tests in
`surfaces/website/tests/test_sandbox_and_frontend.py:36-110` are removed. Keeping a configured
path that requires a paid plan would leave a live-looking option nobody can take.

The properties those tests pinned are re-pinned against `DockerExecutor`, including the most
important one: `test_unreachable_sandbox_raises_rather_than_running_locally`.

Documentation stops promising Cloudflare and stops promising a website image: the `sandbox.py`
module docstring, `README.md`, `surfaces/website/README.md` (Execution sandbox and Deploy
sections), `PUBLISHING.md` §5 and its "What a publish does not fix" entry, the `docker run`
line in the release notes (`release.yml:160`), and `.env.example:64-79`. `TAINTED_SANDBOX_URL`
and `TAINTED_SANDBOX_TOKEN` are removed.

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
10. The image tag `DockerExecutor` requests equals `tainted.__version__` — never `:latest`.
11. **`tainted-web` requires the sandbox by default**, with no Dockerfile to set it. The
    fail-open regression guard.

### Migrating the container contract tests

`surfaces/website/tests/test_container_contract.py` splits:

- **Move to the sandbox image** — `test_the_image_installs_the_browser_and_not_just_its_client`,
  `test_the_browsers_live_somewhere_an_unprivileged_process_can_read`,
  `test_the_server_does_not_run_as_root`, `test_the_build_context_is_not_the_whole_working_tree`.
- **Keep, retargeted at the wheel and entrypoint** —
  `test_the_image_fails_closed_on_sandboxing` becomes test 11 above;
  `test_the_demo_still_runs_when_sandboxing_is_required` and
  `test_a_real_prove_is_refused_rather_than_run_on_our_own_metal` are about app behaviour, not the
  image, and stay as they are.
- **Keep unchanged** — `test_the_page_the_server_serves_is_declared_as_package_data` and
  `test_everything_the_page_loads_is_on_disk_where_the_app_looks`. The wheel is still the
  website's artifact, so the packaging trap is still live.

## Known limits, stated rather than papered over

- **Docker is not a VM.** The container shares the host kernel. This is containment, not the
  isolation the replaced Cloudflare docstring claimed, and the documentation must say so.
- **CLI/MCP give up network isolation** by design, per the split above.
- **macOS requires Docker Desktop or OrbStack**, plus a manual one-time toggle on Docker Desktop.
  Colima does not work. None of this can be automated.
- **The website is no longer a one-command deployment.** It becomes a wheel plus a host with
  Docker, and the fail-closed defaults move from the image into the entrypoint and the docs,
  where they are easier to get wrong.
- **The website's guarantee is still weaker than the original architecture argued for.** Docker
  on your own host is a real reduction from a managed sandbox on someone else's infrastructure.
  If the website is ever deployed publicly, this limit belongs in `PUBLISHING.md` in plain words.
