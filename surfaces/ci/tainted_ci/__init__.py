"""Tainted CI — the surface where dynamic proof reliably meets a real target.

The pipeline already builds a preview deployment (a running, owned URL). Ownership here is not
DNS but OIDC: GitHub Actions / GitLab CI mint short-lived signed identity tokens whose claims
name the repository and run. Within that bound, `analyze` reports, `prove` fires against the
preview, and `fix` opens a PR that re-proves against its own preview. It is the only
non-optional surface — it runs whether or not anyone remembers.
"""
