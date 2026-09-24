"""Where a fix's edits may land on disk.

Two surfaces write a `FileEdit` into a working tree — the CLI's `--apply` and CI's auto-fix PR —
and both have to answer the same two questions, so the answers live here once.

  * **Whole file or beside it?** An edit with an `original` replaces a snippet inside an existing
    file. Its `replacement` is only that snippet, so writing it over the file would replace a
    whole handler with a few lines. It goes to a sibling `<file>.tainted-fix` instead, for a
    person to splice; an edit with no `original` is a new file and is written whole.
  * **Inside the repository?** A generated path carries names read out of the repository under
    analysis — an agent's scope name, a table name — so it is attacker-influenced text. A path
    that resolves outside the repository is refused rather than written.
"""

from __future__ import annotations

import re
from pathlib import Path

from tainted.models import FileEdit

SIBLING_SUFFIX = ".tainted-fix"

_UNSAFE = re.compile(r"[^A-Za-z0-9_.-]+")


def safe_segment(name: str) -> str:
    """`name` as one path segment: no separators, no leading dots, never empty."""
    return _UNSAFE.sub("_", name).lstrip(".") or "_"


def edit_target(repo: str | Path, edit: FileEdit) -> Path:
    """The path this edit is written to, or ValueError if it would leave the repository."""
    root = Path(repo).resolve()
    path = (root / edit.file).resolve()
    if not path.is_relative_to(root) or path == root:
        raise ValueError(
            f"Refusing to write `{edit.file}`: it resolves outside the repository at {root}."
        )
    if edit.original:
        path = path.with_name(path.name + SIBLING_SUFFIX)
    return path
