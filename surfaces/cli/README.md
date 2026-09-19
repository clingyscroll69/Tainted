# Tainted CLI

The local developer loop. One surface, three ways to run `analyze` (static, fast, no
target or credentials needed):

- **on demand** — `tainted analyze <repo>`
- **on save** — `tainted watch <repo>` (re-runs analyze on every file change)
- **on commit** — the pre-commit hook (`tainted-gate`), which blocks the commit
  on a high-severity possible hole

It also runs the interactive `fix` and can `prove` against a running target.

## Install

```bash
pip install tainted-cli            # the engine comes with it, pinned to this version
export GEMINI_API_KEY=...          # optional: turns on the LLM "meaning" register
```

`prove` additionally needs the browser the engine's `dynamic` extra carries. A package cannot
request an extra of its own dependency, so that is a second command rather than a flag:

```bash
pip install "tainted[dynamic]" && playwright install chromium
```

From a checkout instead — the core is a sibling directory, not a release:

```bash
pip install -e .                 # the core engine (repo root)
pip install -e surfaces/cli      # this surface
```

## Use

```bash
tainted analyze ./my-app                         # ranked possible holes in the terminal
tainted analyze ./my-app --only bola,rls --json  # narrow the checks + machine-readable output
tainted watch ./my-app                           # re-analyze on every save
tainted fix ./my-app --finding-id 1db5cbc5 --apply  # write the fix to disk
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

## Which hole is `fix` fixing?

`analyze` prints a `#` and an `ID` for every row, and `fix` takes either:

```bash
tainted fix ./my-app --finding-id 1db5cbc5350811b5   # the hole itself; survives a re-run
tainted fix ./my-app --index 0                        # the row number from that one run
```

Prefer the id. `#` is a position in the report that run drew, and both the code and the model's
ranking move underneath it.

## Pre-commit

The hook manifest is `.pre-commit-hooks.yaml` at the **repository root** — pre-commit reads it
from there and nowhere else — and it is a `language: system` hook, so it runs the `tainted-gate`
you installed above rather than building an environment of its own. (It cannot build one: a
`language: python` hook installs *this repo's root package*, which is the engine, and the engine
has no `tainted-gate` script and none of this surface's dependencies.)

So: install Tainted, then add this to the project's `.pre-commit-config.yaml`:

```yaml
-   repo: https://github.com/OWNER/tainted
    rev: v0.1.1
    hooks:
      - id: tainted
```

Or skip the clone entirely and run the command already on your PATH:

```yaml
-   repo: local
    hooks:
      - id: tainted
        name: Tainted security gate
        entry: tainted-gate
        language: system
        pass_filenames: false
        always_run: true
```

`tainted analyze` exits 0 or 1. `prove` exits 1 when a high-severity finding is
proven, and 2 when the ownership check fails — both usable directly in scripts.
