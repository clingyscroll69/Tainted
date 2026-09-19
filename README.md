# Tainted

Tainted scans your app for the places where a stranger's data can reach something
dangerous: a database query, a shell command, another user's records. Then it proves
each hole is real by actually running the attack against your app. Where the fix is safe
to make, it writes the fix and runs the attack again to show it now fails.

Tainted only says **proven** when it actually broke in.

This repository is the **engine**: a Python library. Every surface under `surfaces/`
— CLI, CI, MCP, website — is a thin front end over it. None of them
reimplements the analysis.

## The three registers

- **Structure** — static analysis (tree-sitter, Python `ast`, sqlglot, and Semgrep
  in taint mode). Reads facts straight from the code: routes, parameters, queries, RLS
  policies, tool graphs. Fast and exhaustive. It cannot tell what any of it means.
- **Meaning** — a language model (Gemini) answers the question static analysis
  can't: is this `id` someone's property, and did anyone check ownership?
- **Proof** — live execution (httpx, Playwright). A possible hole is not a finding.
  Tainted confirms it by running the real attack against the app you already run.

The three registers combine differently depending on where the hole is. On the
**request plane** (a URL a stranger can call) Tainted still tries every possible hole
the model ranked, because proof only costs one HTTP request — a bad ranking just
means a possible hole waits longer, it's still tried. On the dynamic half of the
**tool plane** (an AI agent's tools) the model filters instead, because starting up
a live agent to test it is expensive. What the model skips there leaves no trace, so
Tainted states plainly how far it reached rather than assuming it reached everything.

## Operations

- `analyze(repo)` — static, read-only, works on any repo. Returns ranked possible
  holes.
- `prove(analysis, setup)` — runs the running app, fires the real exploit, returns
  confirmed findings. Gated by ownership checks once the target isn't localhost.
- `fix(finding)` — writes the fix and re-checks it with whatever proof that kind of
  hole supports.

## Checks, and how far each one is proven

| Check | Static | Dynamic proof |
|---|---|---|
| **BOLA** | Finds routes (Flask, FastAPI, Express, Next App/Pages) + Semgrep taint | Account B requests account A's record through the route that leaks it |
| **RLS** | Checks migrations and client reads against `auth.uid()` policies | Reads a capped number of rows over PostgREST; only counts as proven when a returned row is clearly not the caller's |
| **Classic injection** | Regex pass, confirmed by Semgrep taint | SQL injection is proven live. Command and template injection are demonstrated with a real payload but never executed |
| **Agent injection** | Reads the tool graph across MCP, n8n, Flowise, LangChain (Python/JS), CrewAI | A configured agent is proven in a sandbox with logging-stub tools. A coded agent is reported from the code only, never run |
| **Test integrity** | — | The mutant that survives (via Stryker / mutmut) is itself the proof |

Every report says which checks were proven and which were only analyzed. Without that,
a report with no proof column reads as a clean bill of health when it might just mean
nothing was tried.

## Install

```bash
pip install tainted-cli          # the local loop: analyze / watch / fix / pre-commit gate
pip install tainted-mcp          # the same operations as tools for a coding agent
pip install "tainted[dynamic]"   # + the browser `prove` drives, for either of the above
```

Each surface pins the engine, so `tainted` arrives with it. The CI surface is a GitHub Action
rather than a package — `surfaces/ci/README.md`.

**macOS: `prove` needs host networking.** The sandbox container reaches your app on
`localhost`, which on macOS crosses a VM boundary. Docker Desktop 4.34+ can do it (sign in, then
Settings → Resources → Network → *Enable host networking*, then restart) and so can OrbStack.
Colima and Podman cannot. Linux needs none of this.

## Setup (from a checkout)

```bash
pip install -e ".[dev]"          # core engine + tests
pip install -e ".[all,dev]"      # + Playwright, Semgrep, OIDC, DNS
playwright install chromium      # only if you want traffic discovery
cp .env.example .env             # then fill in GEMINI_API_KEY
```

To run **every** suite, including the surfaces, install the surface packages too. Each surface
has its own dependencies (Typer, the MCP SDK, FastAPI), and the core install does not pull
them — without this step the CLI and MCP suites below fail at collection:

```bash
pip install -e ".[dev-all]"                      # core + pytest + ruff + mypy
pip install -e surfaces/cli -e surfaces/ci \
            -e surfaces/mcp -e surfaces/website  # the four surfaces
```

The core goes first and that is now load-bearing: each surface declares `tainted==X.Y.Z`,
so a surface installed into an empty environment fetches the engine from PyPI instead of
using the checkout you are editing.

Tainted reads the Gemini key from the `GEMINI_API_KEY` environment variable or `.env`.
It is never hardcoded. Without it, static analysis still runs in full; only the
meaning register is missing, and the report says so instead of hiding it.

Every optional dependency degrades the same way: what Tainted can check narrows, and
the report says which parts it skipped.

## Tests

```bash
PYTHONPATH=. pytest tests/                                   # engine
PYTHONPATH=.:surfaces/cli     pytest surfaces/cli/tests      # each surface is
PYTHONPATH=.:surfaces/ci      pytest surfaces/ci/tests       # independently deployable
PYTHONPATH=.:surfaces/mcp     pytest surfaces/mcp/tests
PYTHONPATH=.:surfaces/website pytest surfaces/website/tests
```

Every test is hermetic: the LLM, the HTTP transport, the mutation runner, Semgrep and
the agent driver are all fakeable. The suite needs no API key, no network, and no
browser.

All four run on every push — see `.github/workflows/test.yml`, which installs exactly the
two lines from Setup above, so a command that works in CI works on your machine.

## Shipping it

Each surface is a different kind of artifact: the CLI and MCP server are PyPI packages, the CI
surface is a GitHub Action, the website ships as a wheel on the GitHub Release, meant to run on
a host with Docker. **`PUBLISHING.md`** has one section per surface and the single tag that
publishes all four (`.github/workflows/release.yml`).

## License

MIT — see `LICENSE`. Use it, fork it, sell it; keep the copyright notice with it.
