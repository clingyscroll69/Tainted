"""Path exclusion for the static pass.

The static walkers already skip machine-generated trees (`node_modules`, `.git`, `dist`, …)
via each module's `_SKIP_DIRS`. This is the *caller's* list on top of that: the demo, fixture
and specimen directories a developer knows are deliberately-vulnerable sample code and does not
want reported as if the running app were vulnerable. Pointing Tainted at its own repository is
the motivating case — `tests/fixtures/` is full of intentional holes, and the fix engine stores
its own remediation snippets as strings, all of which a naive scan reports right back.

Matching is intentionally simple and predictable, closer to a short glob list than to full
gitignore semantics:

  * a pattern is matched against each file's path relative to the repo root, POSIX-style;
  * `fnmatch` does the globbing, and its `*` spans `/`, so `tests/*` and `**/fixtures/*` both
    reach arbitrarily deep;
  * a bare name with no slash or glob metacharacter (e.g. `fixtures`, `demo.py`) matches that
    path segment *anywhere* in the tree — the common "ignore every directory called X" case,
    which `fnmatch` alone cannot express because it has no leading-`**` shorthand.

A pattern that matches nothing is silently inert; excluding is never an error.
"""

from __future__ import annotations

from fnmatch import fnmatch
from typing import Iterable, Sequence

_GLOB_CHARS = set("*?[")


def normalize_patterns(patterns: Iterable[str]) -> list[str]:
    """Trim whitespace and surrounding slashes; drop blanks. Order is irrelevant to matching."""
    out: list[str] = []
    for raw in patterns:
        pat = raw.strip().strip("/")
        if pat:
            out.append(pat)
    return out


def is_excluded(rel_path: str, patterns: Sequence[str]) -> bool:
    """True when `rel_path` (relative to the repo root) is covered by any exclude pattern."""
    if not patterns:
        return False
    rel = rel_path.replace("\\", "/").strip("/")
    parts = rel.split("/")
    for pat in patterns:
        if fnmatch(rel, pat):
            return True
        # Directory prefix: the pattern names a folder, exclude everything beneath it.
        if fnmatch(rel, f"{pat}/*"):
            return True
        # Bare, literal name → match that segment anywhere in the path.
        if "/" not in pat and not (_GLOB_CHARS & set(pat)) and pat in parts:
            return True
    return False
