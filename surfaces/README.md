# Surfaces

Every surface is a **thin front end over the core engine** (`tainted/`). The analysis
lives in one place; nothing here reimplements it. Each surface is a self-contained
folder you can deploy on its own.

## The deployment contract

A deployable repo for one surface = **the core** + **that surface's folder**:

```
your-deploy-repo/
├── tainted/                  # the core engine package  (copy verbatim)
├── pyproject.toml            # the core package manifest (copy verbatim)
├── action.yml                # CLI surface: omit. CI surface: required, and at the ROOT
├── .pre-commit-hooks.yaml    # CLI surface: required, and at the ROOT. Others: omit
└── surfaces/<name>/          # exactly one surface folder
```

Two files sit at the root rather than inside a surface folder, and neither is a style choice:
GitHub finds an action only as `action.yml` at a repository root, and pre-commit finds a hook
only as `.pre-commit-hooks.yaml` at one. Kept under `surfaces/`, both were unreachable — and in
the action's case unbuildable too, since a Docker action's build context is the directory
holding its manifest, and this one needs the repo root to copy the engine from.
`tests/test_action_contract.py` and `surfaces/cli/tests/test_hook_contract.py` keep them there.

Nothing else is required, and no surface imports another. Each surface folder has its
own `pyproject.toml` (that surface's own dependencies), its own entry point, its
own deploy files (Dockerfile / GitHub Action / etc.), and a README with the one-command
deploy.

Install order is always: **core first, then the surface.**

```bash
pip install -e .                    # the core engine (from repo root)
pip install -e surfaces/<name>      # the surface
```

The surface `pyproject.toml` files do **not** list `tainted` as a PyPI dependency
— it isn't published to PyPI. You install the core alongside it from the
same repo, exactly as shown above. Every Dockerfile copies `tainted/` plus the surface
folder and runs those two installs.

## The four surfaces

| Folder | Surface | Operations | Deploy target |
|---|---|---|---|
| `cli/` | Local developer loop (Typer) | `analyze`, `watch`, `prove`, interactive `fix`, pre-commit gate | developer machine |
| `ci/` | CI — where proof happens | `analyze` + `prove` + `fix`-as-PR | GitHub Actions / GitLab CI |
| `mcp/` | The agent (MCP) | sync `analyze` tools, async `prove` job, interactive `fix` | stdio / SSE MCP server |
| `website/` | The demonstration (FastAPI) | `analyze` + `prove` + patch download | long-lived container |

## The checks on each surface

Five checks, one engine: `bola`, `rls`, `classic_injection`, `agent_injection`,
`test_integrity`. Every surface finds, proves and fixes the first four. `test_integrity`
mutates the code and re-runs the repository's own test suite, so it runs only where running
that suite is the caller's own choice:

| Surface | `test_integrity` |
|---|---|
| CLI | `tainted analyze --only test_integrity`; refused under `watch`, whose writes would retrigger it |
| CI | named in `only`, and measured only where the tests can run: the action's container says *Not measured*, so use the CLI in a step after your install step |
| MCP | refused: `tainted_analyze` is advertised to a calling agent as read-only |
| Website | not offered: it would run a stranger's code on the host; the demo shows the layer |

`agent_injection` is the one fix no surface writes unasked: which remedy fits depends on facts
only the developer holds, so each surface interviews first (CLI prompt, `tainted_fix_interview`,
the website's questions). CI never auto-fixes it.

**Publishing any of them: `PUBLISHING.md`** — one section per surface, plus the tag that does all four.

Only **CI** reliably has a running app to attack, so it's the surface where
`prove` runs by default; the CLI has `tainted prove` too, but you point it at a target
yourself. The **CLI** and **website** work fine with no target: the CLI falls back to
`analyze` and `watch`, and the website hands back a patch instead of applying it. The
**MCP** `prove` tool is guarded by the engine's plan-commitment self-defense
(`tainted/selfdefense/`).
