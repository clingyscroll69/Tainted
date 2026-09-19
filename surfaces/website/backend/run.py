"""Uvicorn entry point: `tainted-web`."""

from __future__ import annotations

import os


def apply_deployment_defaults() -> None:
    """Establish the defaults a deployment must not have to remember.

    `require_sandbox()` reads `TAINTED_REQUIRE_SANDBOX`, and an unset variable means **false**
    — it has to, because absence is indistinguishable from a developer's own machine. So the
    fail-closed posture is not a property of the code; it is a property of whoever sets the
    variable. Until now that was one `ENV` line in `surfaces/website/Dockerfile`, which made
    the guarantee belong to the image rather than to the server. Deleting the image — and the
    image is going away, because a container cannot spawn sandbox containers without being
    handed the root-equivalent Docker socket — would have taken the line with it, silently, and
    a deployment that never set the variable itself would go back to reading **false**. That
    no longer changes which executor `prove` runs in — `default_executor()` always returns
    `DockerExecutor` — but it does turn off the pre-check that fails a request with a legible
    502/503 when Docker turns out not to be reachable, which is worth keeping loud on its own.

    `TAINTED_CSP_ENFORCE` sat on the very next line of that same `ENV` block and fails the same
    silent way: report-only keeps sending the header and keeps blocking nothing, so an
    unenforced deployment is indistinguishable from an enforced one without reading the
    response. The policy was report-only by default so a deployment could watch before it
    blocked, but there is no longer anything to watch — it allows `unsafe-inline` for exactly
    the inline script and style the page carries, and the image has enforced it in production
    all along. Watching is now the thing you ask for.

    `setdefault` throughout, never assignment: `=0` is the documented way to turn off the
    Docker-availability pre-check, or to say you want to watch the CSP policy rather than
    enforce it, and a default you cannot override is not a default. Neither `=0` produces an
    in-process `prove` — there is no configuration that does. The bundled demo contacts nothing
    and is exempt either way, so a server started with no configuration at all still
    demonstrates the whole loop.
    """
    os.environ.setdefault("TAINTED_REQUIRE_SANDBOX", "1")
    os.environ.setdefault("TAINTED_CSP_ENFORCE", "1")


def main() -> None:
    import uvicorn

    # Before uvicorn, which imports `backend.app` by string from inside `run()` — and that
    # import is where `_executor` is bound and the configuration gaps are announced. A default
    # applied after this call, or beside it, reads correctly and does nothing.
    apply_deployment_defaults()

    uvicorn.run(
        "backend.app:app",
        host=os.environ.get("HOST", "127.0.0.1"),
        port=int(os.environ.get("PORT", "8000")),
        reload=bool(os.environ.get("TAINTED_RELOAD")),
        # Behind a TLS-terminating proxy the app otherwise sees plain http on every request
        # and would build the wrong absolute URLs. `forwarded_allow_ips` is what stops any
        # client claiming to be that proxy: set it to the proxy's address, or "*" only when
        # nothing can reach this port except the proxy.
        proxy_headers=True,
        forwarded_allow_ips=os.environ.get("FORWARDED_ALLOW_IPS", "127.0.0.1"),
    )


if __name__ == "__main__":
    main()
