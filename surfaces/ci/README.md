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

## The walkthrough

`TAINTED_TUTORIAL=1` prints the setup walkthrough and exits without scanning — useful from
inside the job container while the pipeline is still half-wired. Set it to a topic slug
(`analyze-only`, `prove-the-preview`, `ownership`, `the-gate`, `auto-fix-pr`) to print just
that lesson.

Every report also ends with a **Next steps** block saying how far this particular run
reached and what to set to reach further — a summary with no proof column reads as a clean
bill of health when it may only mean nothing was tried.

## Ownership verification

Tainted always checks the claims (`repository` must match `$GITHUB_REPOSITORY`). It
verifies the **signature** against the provider's JWKS when `PyJWT` is installed
(it is, as one of this surface's dependencies). If it can't verify the
signature, the report says so instead of pretending it checked.

## Deploy

- **GitHub Actions:** use `surfaces/ci` as a Docker action — see
  `examples/github-workflow.yml` (note `permissions: id-token: write` and the
  OIDC-token minting step).
- **GitLab CI:** see `examples/gitlab-ci.yml` (uses the `id_tokens` keyword).
- **Container:** `docker build -f surfaces/ci/Dockerfile -t tainted-ci .` (build
  context = repo root, so the core is included), then run it with the `TAINTED_*`
  environment variables.
