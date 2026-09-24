# Tainted CI

The one surface where Tainted's dynamic **proof** step reliably has a real app to
attack, because the pipeline already builds a preview deployment — a running app
you own. Ownership here is not DNS (the preview host is thrown away after the run, so a
DNS TXT record can't point at it) but **OIDC**: GitHub Actions and GitLab CI mint
short-lived signed identity tokens whose claims name the repository and run. `analyze`
reports what it finds, `prove` runs the attack against the preview, and the job fails
when a high-severity finding is proven.

## How it runs

Everything is configured through environment variables (see
`tainted_ci/entrypoint.py`), so GitHub and GitLab share one runner. The entrypoint:

1. runs `analyze` on the checkout, always;
2. if `TAINTED_TARGET_URL` is set, checks ownership (local, or an OIDC repo-claim check
   via `tainted_ci/oidc.py`) and, if that passes, runs `prove` against the preview;
3. writes a markdown report to `$GITHUB_STEP_SUMMARY` and to stdout;
4. exits non-zero when a finding at or above `TAINTED_FAIL_ON` (default `high`) is
   proven.

One gap, stated plainly: to bind the verified workflow to the *specific* preview URL,
the workflow has to claim that URL itself. Tainted checks that claim but cannot
independently confirm it.

## The checks

All five run here, from the same engine as every other surface:

| Check | Proved in CI when |
|---|---|
| `bola` — one account reads another's record | `target-url`, `login-a`, `login-b` (a `seed` sharpens it) |
| `rls` — a row policy lets the read through | the same |
| `classic_injection` — a SQL query, shell command or template built from input | `target-url` (and `login-b` if the route needs a sign-in); only SQL is fired, command and template injection are built and held |
| `agent_injection` — one agent can both read untrusted content and act | `gemini-api-key`; without it, reported from the code |
| `test_integrity` — a line no test notices changing | named in `only`, and run where the tests can run (below) |

`only` and `skip` (`TAINTED_ONLY` / `TAINTED_SKIP`) take comma-separated check names; a
misspelt one fails the job. `test_integrity` mutates the code and re-runs its own suite, so it
needs the repository's test dependencies and mutmut or Stryker. The action's container has
none of those, and says *Not measured* if asked; run `tainted analyze . --only test_integrity`
(from `tainted-cli`) in a step after your install step instead.

## The walkthrough

`TAINTED_TUTORIAL=1` prints the setup walkthrough and exits without scanning — useful from
inside the job container while the pipeline is still half-wired. Set it to a topic slug
(`analyze-only`, `prove-the-preview`, `ownership`, `the-gate`, `auto-fix-pr`,
`choose-checks`) to print just
that lesson.

Every report also ends with a **Next steps** block saying how far this particular run
reached and what to set to reach further — a summary with no proof column reads as a clean
bill of health when it may only mean nothing was tried.

## Ownership verification

Tainted always checks the claims (`repository` must match `$GITHUB_REPOSITORY`). It
verifies the **signature** against the provider's JWKS when `PyJWT` is installed
(it is, as one of this surface's dependencies). If it can't verify the
signature, the report says so instead of pretending it checked.

## Auto-fix PR

`fix: "true"` (or `TAINTED_FIX=1`) takes every finding this run *proved* whose repair the code
fully determines, writes it, and opens one PR carrying the request that proved each hole. It
is not re-proved in the run that opens the PR: that run's preview is the unfixed app, where the
attack only succeeds again. The PR's own CI run is the proof — its preview is the patched app,
and Tainted sends the same attacks there, as B and as the owner. A PR opened with the default
`GITHUB_TOKEN` starts no workflow, so pass a token that can. Tool-plane findings are reported,
never auto-fixed — their repair depends on answers only a person has.

It needs `permissions: contents: write` and a `github-token`, and it shells out to `git` and
`gh`; the action's image installs both.

## Deploy

- **GitHub Actions:** `uses: OWNER/tainted@v0`. The manifest is `action.yml` at the
  **repository root**, which is where GitHub looks and — because a Docker action's build context
  is the directory holding its manifest — also the context `Dockerfile` below needs. See
  `examples/github-workflow.yml` for the whole job (`permissions: id-token: write` and the
  OIDC-token minting step are the two easy things to leave out).
- **GitLab CI:** see `examples/gitlab-ci.yml` (uses the `id_tokens` keyword).
- **Container:** `docker build -f surfaces/ci/Dockerfile -t tainted-ci .` (build
  context = repo root, so the core is included), then run it with the `TAINTED_*`
  environment variables.

`PUBLISHING.md` §3 covers tagging, the moving `v0` tag, the Marketplace listing, and pushing a
pre-built image so consumer jobs stop rebuilding it.
