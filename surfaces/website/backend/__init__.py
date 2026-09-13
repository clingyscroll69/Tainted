"""Tainted website — the demonstration front-end.

A FastAPI backend wraps the engine, taking a repository for `analyze` and the first-run form for
`prove`. Its untrusted, network-active exploit execution is the one part reckless to run on your
own metal, so in production the `prove` backend runs in Cloudflare's sandboxed browser-rendering
and container infrastructure (see `sandbox.py`). `fix` here produces a downloadable patch; the
loop closes only where there's a working tree, so the website recommends and the developer applies.
"""
