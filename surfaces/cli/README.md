# Tainted CLI

The local developer loop. One surface, three ways to run `analyze` (static, fast, no
target or credentials needed):

- **on demand** — `tainted analyze <repo>`
- **on save** — `tainted watch <repo>` (re-runs analyze on every file change)
- **on commit** — the pre-commit hook (`tainted-gate`), which blocks the commit
  on a high-severity possible hole

It also runs the interactive `fix` and can `prove` against a running target.

## Deploy

From a repo that has the core (`tainted/`, root `pyproject.toml`) plus this folder:

```bash
pip install -e .                 # the core engine (repo root)
pip install -e surfaces/cli      # this surface
export GEMINI_API_KEY=...         # optional: turns on the LLM "meaning" register
```

## Use

```bash
tainted analyze ./my-app                         # ranked possible holes in the terminal
tainted analyze ./my-app --only bola,rls --json  # narrow the checks + machine-readable output
tainted watch ./my-app                           # re-analyze on every save
tainted fix ./my-app --index 0 --apply           # write the fix to disk
tainted prove ./my-app \                          # drive a running target
  --url http://localhost:54321 --anon-key "$ANON" \
  --login-a a@x.com:pw --login-b b@x.com:pw --seed invoices:<id>
```

`tainted tutorial` walks through all of this from inside the terminal: run it with no
argument to list the lessons, or `tainted tutorial proving-it` to read one.

```bash
tainted tutorial                 # first-scan, reading-a-report, on-save, on-commit, proving-it, fixing-it
tainted tutorial first-scan      # one lesson, with the commands to run and what to expect back
```

`prove` is gated by an ownership check: a `localhost` target needs nothing; a remote
target needs `--ownership-token` (checked via a DNS TXT record or a
`/.well-known/tainted-verify` file).

## Pre-commit

Add this to a project's `.pre-commit-config.yaml`:

```yaml
-   repo: <this repo>
    rev: v0.1.0
    hooks:
      - id: tainted
```

`tainted analyze` exits 0 or 1. `prove` exits 1 when a high-severity finding is
proven, and 2 when the ownership check fails — both usable directly in scripts.
