"""Tainted CLI. The local developer loop.

Three triggers run `analyze`: on demand (`tainted analyze`), on save (`tainted watch`), and on
commit (the pre-commit hook). None needs a target or credentials. This surface catches possible
holes as you write them and hosts the interactive `fix`, but does not prove anything by itself.
"""

from tainted_cli.main import app

__all__ = ["app"]
