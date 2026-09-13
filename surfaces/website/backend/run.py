"""Uvicorn entry point: `tainted-web`."""

from __future__ import annotations

import os


def main() -> None:
    import uvicorn

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
