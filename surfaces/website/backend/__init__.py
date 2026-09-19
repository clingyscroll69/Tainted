"""Tainted website — the demonstration front-end.

A FastAPI backend wraps the engine, taking a repository for `analyze` and the first-run form for
`prove`. Its untrusted, network-active exploit execution is the one part reckless to run
in-process, so `prove` runs each attempt in its own Docker container, a sibling of this process
(see `sandbox.py`). `fix` here produces a downloadable patch; the loop closes only where there's
a working tree, so the website recommends and the developer applies.
"""
